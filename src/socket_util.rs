use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::mem::ManuallyDrop;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_family = "unix")]
use std::path::Path;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
        false,
    )?;

    into_tokio_udp_socket(socket)
}

fn get_unspecified_socket_addr(is_ipv6: bool) -> SocketAddr {
    if !is_ipv6 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    } else {
        "[::]:0".parse().unwrap()
    }
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    new_socket2_udp_socket_with_buffer_size(is_ipv6, bind_interface, bind_address, reuse_port, None)
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    // Set socket buffer sizes if specified.
    // This helps prevent packet drops during bursts for high-throughput connections.
    if let Some(size) = buffer_size {
        // Ignore errors - kernel may cap the value
        let _ = socket.set_recv_buffer_size(size);
        let _ = socket.set_send_buffer_size(size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        panic!("Cannot support reuse sockets");
    }

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

fn into_tokio_udp_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        let raw_fd = socket.into_raw_fd();
        let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
    #[cfg(windows)]
    {
        let std_udp_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
}

pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    let tcp_socket = if is_ipv6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };

    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    Ok(tcp_socket)
}

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: std::time::Duration,
    send_interval: std::time::Duration,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let raw_fd = tcp_stream.as_raw_fd();
        let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
        if idle_time.is_zero() && send_interval.is_zero() {
            socket2_socket.set_keepalive(false)?;
        } else {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(idle_time)
                .with_interval(send_interval);
            socket2_socket.set_keepalive(true)?;
            socket2_socket.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (tcp_stream, idle_time, send_interval);
        Ok(())
    }
}

/// How many accept loops to run for one bind address.
///
/// One listener is one accept loop on one worker: it runs the syscall, sets the
/// socket options and spawns the task for every arrival, and if that worker is
/// busy serving connections the accept queue backs up behind it. Splitting the
/// bind across workers with `SO_REUSEPORT` lets the kernel hash arrivals into
/// independent queues instead.
///
/// Capped well below the worker count: the gain flattens quickly, and each
/// listener carries its own backlog.
pub fn accept_loop_count() -> usize {
    #[cfg(target_family = "unix")]
    {
        crate::thread_util::get_num_threads().clamp(1, 8)
    }
    #[cfg(not(target_family = "unix"))]
    {
        1
    }
}

/// Bind `count` listeners to the same address.
///
/// With `count > 1` every socket sets `SO_REUSEPORT`, which has one consequence
/// worth stating plainly: binding no longer fails when *another process* already
/// holds the port -- it silently joins the group and takes a share of the
/// arriving connections. That EADDRINUSE was a useful way to notice a duplicate
/// instance, so `count == 1` deliberately keeps the old behaviour untouched.
pub fn new_tcp_listeners(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
    count: usize,
) -> std::io::Result<Vec<tokio::net::TcpListener>> {
    // Port 0 means "any free port", which every socket would resolve
    // independently -- a group bound to different ports is not a group.
    let count = if bind_address.port() == 0 {
        1
    } else {
        count.max(1)
    };
    if count == 1 {
        return Ok(vec![new_tcp_listener(
            bind_address,
            backlog,
            bind_interface,
        )?]);
    }
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        match new_tcp_listener_inner(bind_address, backlog, bind_interface.clone(), true) {
            Ok(listener) => listeners.push(listener),
            Err(error) => {
                // Anything already bound is dropped with the vector, so a
                // partial group never lingers holding the port.
                if listeners.is_empty() {
                    return Err(error);
                }
                log::warn!(
                    "only bound {} of {count} accept loops on {bind_address}: {error}",
                    listeners.len()
                );
                break;
            }
        }
    }
    Ok(listeners)
}

// TODO: change backlog to Option<u32> and make configuration, backlog -1 uses somaxconn on linux
// https://github.com/rust-lang/rust/blob/3534594029ed1495290e013647a1f53da561f7f1/library/std/src/os/unix/net/listener.rs#L93
pub fn new_tcp_listener(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    new_tcp_listener_inner(bind_address, backlog, bind_interface, false)
}

fn new_tcp_listener_inner(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
    reuse_port: bool,
) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if bind_address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    if reuse_port {
        // Must precede bind, and every socket in the group has to set it.
        #[cfg(target_family = "unix")]
        socket.set_reuse_port(true)?;
    }

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    socket.bind(&SockAddr::from(bind_address))?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

/// Raise the open-file soft limit to the hard limit.
///
/// A proxy holds two descriptors per proxied TCP connection plus one per UDP
/// session, so the usual 1024 soft limit is exhausted by a few hundred
/// concurrent users. Past that point `accept` and UDP socket creation fail with
/// `EMFILE`: the process keeps running but silently refuses new connections and
/// cannot resolve DNS. The hard limit is normally several hundred thousand, so
/// adopting it removes the ceiling at no cost.
///
/// Returns the soft limit in effect afterwards, or `None` if it is unknown.
#[cfg(unix)]
pub fn raise_open_file_limit() -> Option<u64> {
    // Cap the request when the hard limit is unbounded (as on macOS), because
    // setrlimit rejects RLIM_INFINITY for RLIMIT_NOFILE there.
    const MAX_REQUESTED: libc::rlim_t = 1_048_576;

    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }

    let target = if limit.rlim_max == libc::RLIM_INFINITY {
        MAX_REQUESTED
    } else {
        limit.rlim_max
    };
    if limit.rlim_cur >= target {
        return Some(limit.rlim_cur);
    }

    let desired = libc::rlimit {
        rlim_cur: target,
        rlim_max: limit.rlim_max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &desired) } == 0 {
        Some(target)
    } else {
        Some(limit.rlim_cur)
    }
}

#[cfg(not(unix))]
pub fn raise_open_file_limit() -> Option<u64> {
    None
}

#[cfg(target_family = "unix")]
pub fn new_unix_listener<P: AsRef<Path>>(
    path: P,
    backlog: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    let path = path.as_ref();

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    socket.bind(&addr)?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::os::unix::net::UnixListener = socket.into();
    tokio::net::UnixListener::from_std(std_listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reuse_port_puts_every_accept_loop_on_the_same_port() {
        // Take a port first, then rebind it as a group.
        let probe = new_tcp_listener("127.0.0.1:0".parse().unwrap(), 128, None).unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let listeners = new_tcp_listeners(addr, 128, None, 4).unwrap();
        assert_eq!(listeners.len(), 4);
        for listener in &listeners {
            assert_eq!(
                listener.local_addr().unwrap(),
                addr,
                "every accept loop must share the bind address, not pick its own"
            );
        }
    }

    #[tokio::test]
    async fn an_ephemeral_port_falls_back_to_a_single_accept_loop() {
        // Each socket would resolve port 0 to a different port, so a group
        // here would silently listen on addresses nobody was told about.
        let listeners = new_tcp_listeners("127.0.0.1:0".parse().unwrap(), 128, None, 4).unwrap();
        assert_eq!(listeners.len(), 1);
    }

    #[tokio::test]
    async fn a_single_listener_still_reports_a_conflicting_bind() {
        let held = new_tcp_listener("127.0.0.1:0".parse().unwrap(), 128, None).unwrap();
        let addr = held.local_addr().unwrap();
        // Without SO_REUSEPORT this is the signal that something else already
        // owns the port, which is why count == 1 keeps the old behaviour.
        assert!(new_tcp_listeners(addr, 128, None, 1).is_err());
    }
}
