use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::str;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error};
use lru::LruCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, SniffedProtocol};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::protocol_sniff::{sniff_tcp_protocol, sniff_udp_protocol};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_single_address};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::AuthenticatedUser;
use crate::tcp::tcp_server::{AuthenticatedConnectionScope, setup_client_tcp_stream};
use crate::util::{allocate_vec, write_all};

const COMMAND_TYPE_AUTHENTICATE: u8 = 0x00;
const COMMAND_TYPE_CONNECT: u8 = 0x01;
const COMMAND_TYPE_PACKET: u8 = 0x02;
const COMMAND_TYPE_DISSOCIATE: u8 = 0x03;
const COMMAND_TYPE_HEARTBEAT: u8 = 0x04;

// hostname case: type (1) + hostname length (1) + hostname bytes (255) + port (2)
const MAX_ADDRESS_BYTES_LEN: usize = 1 + 1 + 255 + 2;
// version (1) + command (1) + assoc id (2) + packet id (2)
// + fragment total/id (2) + payload size (2) + address
const MAX_HEADER_LEN: usize = 1 + 1 + 2 + 2 + 1 + 1 + 2 + MAX_ADDRESS_BYTES_LEN;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
/// A reassembled TUIC packet is still one UDP datagram and cannot exceed the
/// protocol's 16-bit payload length.
const MAX_REASSEMBLED_UDP_PACKET_SIZE: usize = u16::MAX as usize;
/// Bound bytes retained by incomplete packets independently of the LRU key
/// count. This is per QUIC connection.
const MAX_FRAGMENT_CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum number of unidirectional tasks accepted before authentication.
///
/// TUIC v5 permits clients to send task headers before AUTH (notably with
/// resumed QUIC sessions). Those tasks must be paused rather than discarded,
/// but keeping their streams alive consumes QUIC flow-control and heap state.
const MAX_PENDING_UNI_TASKS: usize = 32;

/// Heartbeat interval - server sends heartbeat datagrams to client at this interval.
/// Default is 10 seconds per sing-box reference implementation.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const PROTOCOL_SNIFF_MAX_BYTES: usize = 2048;
const PROTOCOL_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);

type UdpSessionMap = Arc<DashMap<u16, UdpSession>>;
type UdpFragmentMap = LruCache<UdpFragmentKey, FragmentedPacket>;
type UdpFragmentCache = Arc<Mutex<UdpFragmentMap>>;
type PreAuthParser =
    Pin<Box<dyn Future<Output = std::io::Result<PreAuthUniStream>> + Send + 'static>>;
type PreAuthParsers = FuturesUnordered<PreAuthParser>;

#[derive(Clone)]
struct TuicUniStreamContext {
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    udp_fragments: UdpFragmentCache,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
}

struct TuicAuthenticationResult {
    authenticated_user: Option<AuthenticatedUser>,
    pending_uni_tasks: Vec<PendingTuicUniTask>,
    pending_parsers: PreAuthParsers,
}

enum PreAuthUniStream {
    Authenticate {
        specified_uuid: [u8; 16],
        token: [u8; 32],
    },
    Task(PendingTuicUniTask),
}

struct PendingTuicUniTask {
    recv_stream: quinn::RecvStream,
    stream_reader: StreamReader,
    header: TuicUniTaskHeader,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TuicUniTaskHeader {
    Dissociate {
        assoc_id: u16,
    },
    Packet {
        assoc_id: u16,
        packet_id: u16,
        frag_total: u8,
        frag_id: u8,
        payload_size: u16,
        remote_location: Option<NetLocation>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFragmentKey {
    assoc_id: u16,
    packet_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TuicCongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

#[derive(Clone, Debug)]
pub struct TuicServerUser {
    pub uuid: [u8; 16],
    pub password: String,
    pub authenticated_user: Option<AuthenticatedUser>,
}

impl TuicServerUser {
    pub fn new(
        uuid: [u8; 16],
        password: String,
        authenticated_user: Option<AuthenticatedUser>,
    ) -> Self {
        Self {
            uuid,
            password,
            authenticated_user,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TuicServerUsers {
    users_by_uuid: Arc<HashMap<[u8; 16], TuicServerUser>>,
}

impl TuicServerUsers {
    pub fn new(users: Vec<TuicServerUser>) -> std::io::Result<Self> {
        if users.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tuic server requires at least one user",
            ));
        }

        let mut users_by_uuid = HashMap::with_capacity(users.len());
        for user in users {
            if user.password.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "tuic user password must not be empty",
                ));
            }
            if users_by_uuid.insert(user.uuid, user).is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "duplicate tuic user uuid",
                ));
            }
        }

        Ok(Self {
            users_by_uuid: Arc::new(users_by_uuid),
        })
    }

    fn get(&self, uuid: &[u8; 16]) -> Option<&TuicServerUser> {
        self.users_by_uuid.get(uuid)
    }
}

fn parse_tuic_congestion_control(value: Option<&str>) -> std::io::Result<TuicCongestionControl> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(TuicCongestionControl::Cubic);
    };
    match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "cubic" => Ok(TuicCongestionControl::Cubic),
        "newreno" | "reno" => Ok(TuicCongestionControl::NewReno),
        "bbr" => Ok(TuicCongestionControl::Bbr),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported tuic congestion_control `{value}`"),
        )),
    }
}

fn apply_tuic_congestion_control(
    transport: &mut quinn::TransportConfig,
    congestion_control: TuicCongestionControl,
) {
    match congestion_control {
        TuicCongestionControl::Cubic => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        TuicCongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        TuicCongestionControl::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }
}

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    users: TuicServerUsers,
    conn: quinn::Incoming,
    zero_rtt_handshake: bool,
) -> std::io::Result<()> {
    // Accept the incoming connection. When 0-RTT is enabled, use into_0rtt() to
    // allow 0.5-RTT data transmission before the handshake fully completes.
    // This reduces latency at the cost of some security (0-RTT data is vulnerable
    // to replay attacks, though for incoming server connections it's 0.5-RTT which
    // is safer but still shouldn't be used for client-authenticated data).
    let connection = if zero_rtt_handshake {
        let connecting = conn
            .accept()
            .map_err(|e| std::io::Error::other(format!("QUIC accept failed: {e}")))?;
        // For incoming connections, into_0rtt() always succeeds per quinn docs
        let (connection, _zero_rtt_accepted) = connecting
            .into_0rtt()
            .map_err(|_| std::io::Error::other("failed to enable 0-RTT"))?;
        connection
    } else {
        conn.await?
    };

    // Authentication with timeout - per sing-box reference, default 3 seconds.
    // This prevents malicious clients from holding connections open without authenticating.
    let auth_result = match timeout(AUTH_TIMEOUT, auth_connection(&connection, &users)).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            connection.close(0u32.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(0u32.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    };

    let connection_scope = Arc::new(AuthenticatedConnectionScope::start(
        &auth_result.authenticated_user,
        Some(connection.remote_address()),
    )?);

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions, cleanup task, heartbeat) will terminate gracefully.
    let cancel_token = CancellationToken::new();

    // this allows for:
    // 1. multiple threads can read different sessions concurrently
    // 2. multiple threads can modify different sessions concurrently
    // 3. the outer write lock is only needed for adding/removing sessions
    let udp_session_map = Arc::new(DashMap::new());

    // Clone what we need for each loop before creating async blocks
    let heartbeat_connection = connection.clone();
    let heartbeat_cancel_token = cancel_token.clone();

    let bi_connection = connection.clone();
    let bi_client_proxy_selector = client_proxy_selector.clone();
    let bi_resolver = resolver.clone();
    let bi_connection_scope = connection_scope.clone();

    let uni_context = TuicUniStreamContext {
        connection: connection.clone(),
        client_proxy_selector: client_proxy_selector.clone(),
        resolver: resolver.clone(),
        udp_session_map: udp_session_map.clone(),
        udp_fragments: Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap(),
        ))),
        cancel_token: cancel_token.clone(),
        connection_scope: connection_scope.clone(),
    };

    let datagram_connection = connection.clone();
    let datagram_cancel_token = cancel_token.clone();
    let datagram_connection_scope = connection_scope.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let heartbeat_loop = run_heartbeat_loop(heartbeat_connection, heartbeat_cancel_token);

    let bi_loop = run_bidirectional_loop(
        bi_connection,
        bi_client_proxy_selector,
        bi_resolver,
        bi_connection_scope,
    );

    let uni_loop = run_unidirectional_loop(
        uni_context,
        auth_result.pending_uni_tasks,
        auth_result.pending_parsers,
    );

    let datagram_loop = run_datagram_loop(
        datagram_connection,
        client_proxy_selector,
        resolver,
        udp_session_map,
        datagram_cancel_token,
        datagram_connection_scope,
    );

    let result = tokio::try_join!(heartbeat_loop, bi_loop, uni_loop, datagram_loop);

    // Cancel all remaining tasks (UDP session loops, cleanup task, heartbeat)
    cancel_token.cancel();

    // Per sing-box reference (service.go:382-398), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(0u32.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Sends periodic heartbeat datagrams to the client to maintain connection liveness.
/// Per sing-box reference implementation (service.go:366-380).
/// Returns an error if heartbeat fails, which will cause the connection to close.
async fn run_heartbeat_loop(
    connection: quinn::Connection,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    // Skip the first immediate tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            _ = interval.tick() => {
                // Send heartbeat datagram: [version, command_heartbeat]
                let heartbeat = bytes::Bytes::from_static(&[5, COMMAND_TYPE_HEARTBEAT]);
                if let Err(e) = connection.send_datagram(heartbeat) {
                    // Per sing-box reference, heartbeat failure should close the connection
                    return Err(std::io::Error::other(format!("heartbeat failed: {e}")));
                }
            }
        }
    }
}

async fn auth_connection(
    connection: &quinn::Connection,
    users: &TuicServerUsers,
) -> std::io::Result<TuicAuthenticationResult> {
    // Loop until we receive an AUTH command.
    // TUIC v5 requires task headers received before AUTH to be parsed and
    // paused. This is important for resumed sessions, where task streams can
    // race the AUTH stream. No task body is processed or forwarded here.
    // The outer timeout in process_connection ensures we don't wait forever.
    let mut pending_uni_tasks = Vec::new();
    let mut parsers: PreAuthParsers = FuturesUnordered::new();
    let mut accepted_streams = 0usize;
    loop {
        tokio::select! {
            Some(parsed) = parsers.next(), if !parsers.is_empty() => {
                match parsed? {
                    PreAuthUniStream::Task(task) => {
                        push_pending_uni_task(&mut pending_uni_tasks, task)?;
                        debug!(
                            "Paused TUIC task before auth ({} pending)",
                            pending_uni_tasks.len()
                        );
                    }
                    PreAuthUniStream::Authenticate {
                        specified_uuid,
                        token,
                    } => {
                        let user = users.get(&specified_uuid).ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("incorrect uuid: {specified_uuid:?}"),
                            )
                        })?;
                        let mut expected_token_bytes = [0u8; 32];
                        connection
                            .export_keying_material(
                                &mut expected_token_bytes,
                                specified_uuid.as_ref(),
                                user.password.as_bytes(),
                            )
                            .map_err(|e| {
                                std::io::Error::other(format!(
                                    "Failed to export keying material: {e:?}"
                                ))
                            })?;
                        if token != expected_token_bytes {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "incorrect token",
                            ));
                        }
                        return Ok(TuicAuthenticationResult {
                            authenticated_user: user.authenticated_user.clone(),
                            pending_uni_tasks,
                            pending_parsers: parsers,
                        });
                    }
                }
            }
            accepted = connection.accept_uni(),
                if accepted_streams < MAX_PENDING_UNI_TASKS + 1 =>
            {
                accepted_streams += 1;
                parsers.push(Box::pin(parse_pre_auth_uni_stream(accepted?)));
            }
        }
    }
}

async fn parse_pre_auth_uni_stream(
    mut recv_stream: quinn::RecvStream,
) -> std::io::Result<PreAuthUniStream> {
    let mut stream_reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);
    let command_type = read_uni_stream_command_type(&mut recv_stream, &mut stream_reader).await?;
    if command_type == COMMAND_TYPE_AUTHENTICATE {
        let specified_uuid: [u8; 16] = stream_reader
            .read_slice(&mut recv_stream, 16)
            .await?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid uuid length")
            })?;
        let token: [u8; 32] = stream_reader
            .read_slice(&mut recv_stream, 32)
            .await?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid token length")
            })?;
        return Ok(PreAuthUniStream::Authenticate {
            specified_uuid,
            token,
        });
    }

    let header = read_uni_task_header(&mut recv_stream, &mut stream_reader, command_type).await?;
    Ok(PreAuthUniStream::Task(PendingTuicUniTask {
        recv_stream,
        stream_reader,
        header,
    }))
}

fn push_pending_uni_task<T>(pending: &mut Vec<T>, task: T) -> std::io::Result<()> {
    if pending.len() >= MAX_PENDING_UNI_TASKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("too many TUIC tasks before authentication (maximum {MAX_PENDING_UNI_TASKS})"),
        ));
    }
    pending.push(task);
    Ok(())
}

async fn run_bidirectional_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let conn = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let connection_scope = connection_scope.clone();
        tokio::spawn(async move {
            match process_tcp_stream(
                client_proxy_selector,
                resolver,
                connection_scope,
                send_stream,
                recv_stream,
            )
            .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    // Per official TUIC reference (handle_stream.rs:127-135),
                    // header parsing errors close the connection
                    error!("Error parsing TCP stream header, closing connection: {e}");
                    conn.close(0u32.into(), b"");
                }
                Err(e) => {
                    // TCP proxying errors are just logged (handle_task.rs:238-246)
                    error!("Error processing TCP stream: {e}");
                }
            }
        });
    }
    Ok(())
}

async fn read_uni_stream_command_type<T>(
    recv_stream: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u8>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let tuic_version = stream_reader.read_u8(recv_stream).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::other(format!(
            "invalid tuic version: {tuic_version}"
        )));
    }
    stream_reader.read_u8(recv_stream).await
}

async fn read_uni_task_header<T>(
    recv_stream: &mut T,
    stream_reader: &mut StreamReader,
    command_type: u8,
) -> std::io::Result<TuicUniTaskHeader>
where
    T: tokio::io::AsyncRead + Unpin,
{
    if command_type == COMMAND_TYPE_DISSOCIATE {
        return Ok(TuicUniTaskHeader::Dissociate {
            assoc_id: stream_reader.read_u16_be(recv_stream).await?,
        });
    }

    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "invalid uni stream command type: {command_type}"
        )));
    }

    Ok(TuicUniTaskHeader::Packet {
        assoc_id: stream_reader.read_u16_be(recv_stream).await?,
        packet_id: stream_reader.read_u16_be(recv_stream).await?,
        frag_total: stream_reader.read_u8(recv_stream).await?,
        frag_id: stream_reader.read_u8(recv_stream).await?,
        payload_size: stream_reader.read_u16_be(recv_stream).await?,
        remote_location: read_address(recv_stream, stream_reader).await?,
    })
}

async fn read_address<T>(
    recv: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<Option<NetLocation>>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let address_type = stream_reader.read_u8(recv).await?;
    let address = match address_type {
        0xff => {
            return Ok(None);
        }
        0x00 => {
            let address_len = stream_reader.read_u8(recv).await? as usize;
            let address_bytes = stream_reader.read_slice(recv, address_len).await?;
            let address_str = str::from_utf8(address_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid address: {e}"),
                )
            })?;
            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Address::from(address_str)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        }
        0x01 => {
            let ipv4_bytes = stream_reader.read_slice(recv, 4).await?;
            let ipv4_addr =
                Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
            Address::Ipv4(ipv4_addr)
        }
        0x02 => {
            let ipv6_bytes = stream_reader.read_slice(recv, 16).await?;
            let ipv6_bytes: [u8; 16] = ipv6_bytes.try_into().unwrap();
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Address::Ipv6(ipv6_addr)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid address type: {address_type}"),
            ));
        }
    };

    let port = stream_reader.read_u16_be(recv).await?;

    Ok(Some(NetLocation::new(address, port)))
}

fn serialize_address(location: &NetLocation) -> Vec<u8> {
    let mut address_bytes = match location.address() {
        Address::Hostname(hostname) => {
            let mut res = Vec::with_capacity(1 + 1 + hostname.len() + 2);
            res.push(0x00); // address type
            let hostname_bytes = hostname.as_bytes();
            res.push(hostname_bytes.len() as u8);
            res.extend_from_slice(hostname_bytes);
            res
        }
        Address::Ipv4(ipv4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type
            res.extend_from_slice(&ipv4.octets());
            res
        }
        Address::Ipv6(ipv6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type
            res.extend_from_slice(&ipv6.octets());
            res
        }
    };

    address_bytes.extend_from_slice(&location.port().to_be_bytes());

    address_bytes
}

fn serialize_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut res = match addr {
        SocketAddr::V4(addr_v4) => {
            let mut res = Vec::with_capacity(1 + 4 + 2);
            res.push(0x01); // address type for IPv4
            res.extend_from_slice(&addr_v4.ip().octets());
            res
        }
        SocketAddr::V6(addr_v6) => {
            let mut res = Vec::with_capacity(1 + 16 + 2);
            res.push(0x02); // address type for IPv6
            res.extend_from_slice(&addr_v6.ip().octets());
            res
        }
    };

    res.extend_from_slice(&addr.port().to_be_bytes());
    res
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    connection_scope: Arc<AuthenticatedConnectionScope>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let mut stream_reader = StreamReader::new_with_buffer_size(1024);
    let tuic_version = stream_reader.read_u8(&mut recv).await?;
    if tuic_version != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tuic version: {tuic_version}"),
        ));
    }
    let command_type = stream_reader.read_u8(&mut recv).await?;
    if command_type != COMMAND_TYPE_CONNECT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid command type: {command_type}"),
        ));
    }

    let remote_location = read_address(&mut recv, &mut stream_reader)
        .await?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty address"))?;

    let mut server_stream: Box<dyn AsyncStream> =
        connection_scope.wrap_stream(Box::new(QuicStream::from(send, recv)));
    let mut initial_remote_data = stream_reader.unparsed_data_owned().map(Vec::from);
    let sniffed_protocol = if client_proxy_selector.requires_protocol_sniff() {
        sniff_tcp_forward_protocol(&mut server_stream, &mut initial_remote_data).await?
    } else {
        None
    };

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(
            &mut server_stream,
            client_proxy_selector,
            resolver,
            remote_location.clone(),
            sniffed_protocol,
            None,
        ),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    let unparsed_before_wrap_len = stream_reader.unparsed_data().len();
    if unparsed_before_wrap_len > 0 {
        connection_scope
            .throttle_upload_bytes(unparsed_before_wrap_len)
            .await;
    }
    let client_requires_flush = match initial_remote_data {
        Some(data) if !data.is_empty() => {
            write_all(&mut client_stream, &data).await?;
            if unparsed_before_wrap_len > 0 {
                connection_scope.record_upload_bytes(unparsed_before_wrap_len);
            }
            true
        }
        _ => false,
    };
    drop(stream_reader);

    // Use 32KB buffers to match reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        false, // no need to flush since it's QUIC
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

async fn sniff_tcp_forward_protocol(
    server_stream: &mut Box<dyn AsyncStream>,
    initial_remote_data: &mut Option<Vec<u8>>,
) -> std::io::Result<Option<SniffedProtocol>> {
    if let Some(protocol) = sniff_tcp_protocol(initial_remote_data.as_deref().unwrap_or_default()) {
        return Ok(Some(protocol));
    }

    let started_at = std::time::Instant::now();
    while initial_remote_data.as_ref().map_or(0, Vec::len) < PROTOCOL_SNIFF_MAX_BYTES {
        let remaining_timeout = PROTOCOL_SNIFF_TIMEOUT
            .checked_sub(started_at.elapsed())
            .unwrap_or_default();
        if remaining_timeout.is_zero() {
            break;
        }

        let read_capacity = PROTOCOL_SNIFF_MAX_BYTES
            .saturating_sub(initial_remote_data.as_ref().map_or(0, Vec::len))
            .min(512);
        let mut buf = vec![0; read_capacity];
        match timeout(remaining_timeout, server_stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.truncate(n);
                match initial_remote_data {
                    Some(data) => data.extend_from_slice(&buf),
                    None => *initial_remote_data = Some(buf),
                }
                if let Some(protocol) =
                    sniff_tcp_protocol(initial_remote_data.as_deref().unwrap_or_default())
                {
                    return Ok(Some(protocol));
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }

    Ok(None)
}

struct UdpSession {
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    // Cancellation token for this session's background task
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
}

struct ReassembledPacket {
    remote_location: NetLocation,
    payload: Bytes,
}

struct PreparedUdpPacket<'a> {
    remote_location: NetLocation,
    payload: UdpPayload<'a>,
}

enum UdpPayload<'a> {
    Borrowed(&'a [u8]),
    Owned(Bytes),
}

impl AsRef<[u8]> for UdpPayload<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(payload) => payload,
            Self::Owned(payload) => payload.as_ref(),
        }
    }
}

impl UdpSession {
    #[allow(clippy::too_many_arguments)]
    fn start_with_send_stream(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
        connection_scope: Arc<AuthenticatedConnectionScope>,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_stream_loop(
                assoc_id,
                connection,
                client_socket,
                override_local_write_location,
                session_cancel_token,
                connection_scope,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_datagram(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
        connection_scope: Arc<AuthenticatedConnectionScope>,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_datagram_loop(
                assoc_id,
                connection,
                client_socket,
                override_local_write_location,
                session_cancel_token,
                connection_scope,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }

    #[inline]
    async fn resolve_address(
        &self,
        location: &NetLocation,
        payload: &[u8],
        client_proxy_selector: &Arc<ClientProxySelector>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(SocketAddr, bool)> {
        let (addr, is_updated) = match self.override_remote_write_address {
            Some(addr) => (addr, false),
            None => {
                if location == &self.last_location {
                    (self.last_socket_addr, false)
                } else {
                    let sniffed_protocol = if client_proxy_selector.requires_protocol_sniff() {
                        sniff_udp_protocol(payload)
                    } else {
                        None
                    };
                    let action = client_proxy_selector
                        .judge_with_protocol(location.clone().into(), resolver, sniffed_protocol)
                        .await?;

                    let updated_location = match action {
                        ConnectDecision::Allow {
                            chain_group: _,
                            remote_location,
                        } => remote_location,
                        ConnectDecision::Block => {
                            return Err(std::io::Error::other(format!(
                                "Blocked UDP forward to {location}"
                            )));
                        }
                    };
                    let updated_address =
                        match resolve_single_address(resolver, updated_location.location()).await {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to resolve updated remote location {location}: {e}");
                                return Err(e);
                            }
                        };

                    (updated_address, true)
                }
            }
        };

        Ok((addr, is_updated))
    }

    fn update_last_location(&mut self, location: NetLocation, socket_addr: SocketAddr) {
        self.last_location = location;
        self.last_socket_addr = socket_addr;
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    let original_address_bytes: Option<Bytes> =
        override_local_write_address.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(MAX_HEADER_LEN + 65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf[MAX_HEADER_LEN..]) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Use select! to allow cancellation while waiting for socket to be readable
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);
        connection_scope.throttle_download_bytes(payload_len).await;

        let address_bytes = match original_address_bytes {
            Some(ref a) => a.clone(),
            None => serialize_socket_addr(&src_addr).into(),
        };

        let start_offset = encode_udp_stream_packet_prefix(
            &mut buf,
            assoc_id,
            packet_id,
            payload_len,
            &address_bytes,
        )?;
        let end_offset = MAX_HEADER_LEN + payload_len;

        let mut send_stream = connection.open_uni().await?;
        send_stream
            .write_all(&buf[start_offset..end_offset])
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC stream write failed: {e}")))?;
        send_stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("TUIC stream finish failed: {e}")))?;
        connection_scope.record_download_bytes(payload_len);
    }
}

fn encode_udp_stream_packet_prefix(
    buf: &mut [u8],
    assoc_id: u16,
    packet_id: u16,
    payload_len: usize,
    address_bytes: &[u8],
) -> std::io::Result<usize> {
    if payload_len > u16::MAX as usize {
        return Err(std::io::Error::other(format!(
            "TUIC UDP stream payload too large: {payload_len}"
        )));
    }

    // version(1) + command(1) + assoc_id(2) + packet_id(2)
    // + fragment total(1) + fragment id(1) + payload size(2) + address bytes
    let header_len = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes.len();
    if header_len > MAX_HEADER_LEN || buf.len() < MAX_HEADER_LEN {
        return Err(std::io::Error::other(format!(
            "TUIC UDP stream header too large: {header_len}"
        )));
    }

    let start_offset = MAX_HEADER_LEN - header_len;
    buf[start_offset] = 5;
    buf[start_offset + 1] = COMMAND_TYPE_PACKET;
    buf[start_offset + 2..start_offset + 4].copy_from_slice(&assoc_id.to_be_bytes());
    buf[start_offset + 4..start_offset + 6].copy_from_slice(&packet_id.to_be_bytes());
    buf[start_offset + 6] = 1;
    buf[start_offset + 7] = 0;
    buf[start_offset + 8..start_offset + 10].copy_from_slice(&(payload_len as u16).to_be_bytes());
    buf[start_offset + 10..start_offset + 10 + address_bytes.len()].copy_from_slice(address_bytes);

    Ok(start_offset)
}

async fn run_udp_remote_to_local_datagram_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    client_socket: Arc<UdpSocket>,
    override_local_write_location: Option<NetLocation>,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    use bytes::BufMut;

    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<Bytes> =
        override_local_write_location.map(|a| serialize_address(&a).into());

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match client_socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Use select! to allow cancellation while waiting for socket to be readable
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = client_socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);
        connection_scope.throttle_download_bytes(payload_len).await;

        let address_bytes: Bytes = match &original_address_bytes {
            Some(a) => a.clone(),
            None => serialize_socket_addr(&src_addr).into(),
        };
        let address_bytes_len = address_bytes.len();

        // Header format:
        // tuic_version (1 byte) + command_type (1 byte)
        // + assoc_id (2 bytes) + packet_id (2 bytes)
        // + frag_total (1 byte) + frag_id (1 byte)
        // + payload_size (2 bytes) + address_bytes
        let header_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
            datagram.put_u8(5); // tuic version
            datagram.put_u8(COMMAND_TYPE_PACKET); // command type
            datagram.extend_from_slice(&assoc_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.put_u8(1); // frag_total = 1
            datagram.put_u8(0); // frag_id = 0
            datagram.extend_from_slice(&(payload_len as u16).to_be_bytes());
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
            connection_scope.record_download_bytes(payload_len);
        } else {
            // Calculate header sizes for first fragment and subsequent fragments.
            let first_overhead = header_overhead; // full address included in the first fragment
            let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1; // 0xff marker instead of full address
            if max_datagram_size <= first_overhead {
                return Err(std::io::Error::other(format!(
                    "max datagram size ({max_datagram_size}) is smaller than TUIC first-fragment header overhead ({first_overhead})"
                )));
            }
            if max_datagram_size <= other_overhead {
                return Err(std::io::Error::other(format!(
                    "max datagram size ({max_datagram_size}) is smaller than TUIC continuation-fragment header overhead ({other_overhead})"
                )));
            }
            let first_capacity = max_datagram_size - first_overhead;
            let other_capacity = max_datagram_size - other_overhead;

            let remaining = payload_len.saturating_sub(first_capacity);
            let additional_fragments = remaining.div_ceil(other_capacity);
            let fragment_count = u8::try_from(1 + additional_fragments).map_err(|_| {
                std::io::Error::other(format!(
                    "TUIC UDP payload length {payload_len} requires too many fragments"
                ))
            })?;

            let mut offset = 0;
            for fragment_id in 0..fragment_count {
                let (fragment_payload_len, header_size) = if fragment_id == 0 {
                    let len = std::cmp::min(first_capacity, payload_len);
                    (len, first_overhead)
                } else {
                    let len = std::cmp::min(other_capacity, payload_len - offset);
                    (len, other_overhead)
                };

                let mut datagram = BytesMut::with_capacity(header_size + fragment_payload_len);
                datagram.extend_from_slice(&[5, COMMAND_TYPE_PACKET]);
                datagram.extend_from_slice(&assoc_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram.extend_from_slice(&[fragment_count, fragment_id]);
                datagram.extend_from_slice(&(fragment_payload_len as u16).to_be_bytes());
                if fragment_id == 0 {
                    datagram.extend_from_slice(&address_bytes);
                } else {
                    datagram.put_u8(0xff);
                }
                datagram.extend_from_slice(&buf[offset..offset + fragment_payload_len]);
                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
                offset += fragment_payload_len;
            }
            connection_scope.record_download_bytes(payload_len);
        }
    }
}
async fn run_unidirectional_loop(
    uni_context: TuicUniStreamContext,
    pending_uni_tasks: Vec<PendingTuicUniTask>,
    mut pending_parsers: PreAuthParsers,
) -> std::io::Result<()> {
    // Spawn a cleanup task for UDP sessions that terminates when connection closes
    let cleanup_session_map = uni_context.udp_session_map.clone();
    let cleanup_cancel_token = uni_context.cancel_token.clone();
    let connection = uni_context.connection.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    cleanup_session_map.retain(|assoc_id, session| {
                        if session.last_activity.elapsed() > IDLE_TIMEOUT {
                            // Cancel the session's background task before removing
                            session.cancel_token.cancel();
                            debug!("Removing inactive UDP session {assoc_id}");
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
    });

    // Authentication and the per-user connection scope are established before
    // this loop starts. Resume pre-auth tasks through the exact same processing
    // path used for newly accepted streams.
    for pending_task in pending_uni_tasks {
        spawn_uni_task(uni_context.clone(), pending_task);
    }

    loop {
        tokio::select! {
            Some(parsed) = pending_parsers.next(), if !pending_parsers.is_empty() => {
                match parsed? {
                    PreAuthUniStream::Task(task) => {
                        spawn_uni_task(uni_context.clone(), task);
                    }
                    PreAuthUniStream::Authenticate { .. } => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "duplicate TUIC authentication stream",
                        ));
                    }
                }
            }
            accepted = connection.accept_uni() => {
                let recv_stream = match accepted {
                    Ok(recv_stream) => recv_stream,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "failed to accept unidirectional stream: {e}"
                        )));
                    }
                };
                spawn_new_uni_stream(uni_context.clone(), recv_stream);
            }
        }
    }
    Ok(())
}

fn spawn_new_uni_stream(context: TuicUniStreamContext, recv_stream: quinn::RecvStream) {
    let connection = context.connection.clone();
    tokio::spawn(async move {
        let result = async {
            let pending_task = parse_uni_stream(recv_stream).await?;
            process_pending_uni_task(context, pending_task).await
        }
        .await;
        if let Err(e) = result {
            error!("Error processing uni stream, closing connection: {e}");
            connection.close(0u32.into(), b"");
        }
    });
}

fn spawn_uni_task(context: TuicUniStreamContext, pending_task: PendingTuicUniTask) {
    let connection = context.connection.clone();
    tokio::spawn(async move {
        // Per TUIC protocol, each uni stream carries exactly ONE command.
        // The reference implementation (handle_stream.rs) handles one task per stream.
        if let Err(e) = process_pending_uni_task(context, pending_task).await {
            // Per official TUIC reference (handle_stream.rs:70-78),
            // uni stream errors close the connection.
            error!("Error processing uni stream, closing connection: {e}");
            connection.close(0u32.into(), b"");
        }
    });
}

/// Process a single uni stream command. Per TUIC protocol, each uni stream
/// carries exactly one command (PACKET or DISSOCIATE on server side).
async fn parse_uni_stream(
    mut recv_stream: quinn::RecvStream,
) -> std::io::Result<PendingTuicUniTask> {
    let mut stream_reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);
    let command_type = read_uni_stream_command_type(&mut recv_stream, &mut stream_reader).await?;
    let header = read_uni_task_header(&mut recv_stream, &mut stream_reader, command_type).await?;
    Ok(PendingTuicUniTask {
        recv_stream,
        stream_reader,
        header,
    })
}

async fn process_pending_uni_task(
    context: TuicUniStreamContext,
    pending_task: PendingTuicUniTask,
) -> std::io::Result<()> {
    let PendingTuicUniTask {
        mut recv_stream,
        mut stream_reader,
        header,
    } = pending_task;

    let (assoc_id, packet_id, frag_total, frag_id, payload_size, remote_location) = match header {
        TuicUniTaskHeader::Dissociate { assoc_id } => {
            // Remove and cancel the session's background task.
            // Per official TUIC Rust reference (handle_task.rs:154-165).
            if let Some((_, session)) = context.udp_session_map.remove(&assoc_id) {
                session.cancel_token.cancel();
            }
            let mut fragments = context.udp_fragments.lock().await;
            remove_udp_fragments_for_assoc(&mut fragments, assoc_id);
            // Session not found is normal - it may have already timed out or been closed.
            return Ok(());
        }
        TuicUniTaskHeader::Packet {
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            payload_size,
            remote_location,
        } => (
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            payload_size,
            remote_location,
        ),
    };

    let payload_fragment =
        read_uni_task_payload(&mut recv_stream, &mut stream_reader, payload_size as usize).await?;

    let prepared = {
        let mut fragments = context.udp_fragments.lock().await;
        prepare_udp_packet(
            &mut fragments,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            &payload_fragment,
        )?
    };
    let Some(prepared) = prepared else {
        return Ok(());
    };
    let PreparedUdpPacket {
        remote_location,
        payload,
    } = prepared;

    forward_udp_packet(
        &context.connection,
        &context.client_proxy_selector,
        &context.resolver,
        &context.udp_session_map,
        assoc_id,
        remote_location,
        payload.as_ref(),
        true,
        &context.cancel_token,
        &context.connection_scope,
    )
    .await
}

async fn read_uni_task_payload<T>(
    recv_stream: &mut T,
    stream_reader: &mut StreamReader,
    payload_size: usize,
) -> std::io::Result<Vec<u8>>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let buffered = stream_reader.unparsed_data();
    if buffered.len() > payload_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "TUIC unidirectional task contains {} trailing bytes after a {payload_size}-byte payload",
                buffered.len() - payload_size
            ),
        ));
    }

    let mut payload = Vec::with_capacity(payload_size);
    payload.extend_from_slice(buffered);
    let buffered_len = buffered.len();
    stream_reader.consume(buffered_len);
    if payload.len() < payload_size {
        let old_len = payload.len();
        payload.resize(payload_size, 0);
        recv_stream.read_exact(&mut payload[old_len..]).await?;
    }
    Ok(payload)
}

// TODO: fix too many arguments warning
#[allow(clippy::too_many_arguments)]
#[inline]
async fn process_udp_packet(
    connection: &quinn::Connection,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    fragments: &mut UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
    connection_scope: &Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    let prepared = prepare_udp_packet(
        fragments,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    )?;
    let Some(prepared) = prepared else {
        return Ok(());
    };
    let PreparedUdpPacket {
        remote_location,
        payload,
    } = prepared;

    forward_udp_packet(
        connection,
        client_proxy_selector,
        resolver,
        udp_session_map,
        assoc_id,
        remote_location,
        payload.as_ref(),
        is_uni_stream,
        cancel_token,
        connection_scope,
    )
    .await
}

fn prepare_udp_packet<'a>(
    fragments: &mut UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &'a [u8],
) -> std::io::Result<Option<PreparedUdpPacket<'a>>> {
    if frag_total == 0 {
        return Err(std::io::Error::other(
            "Ignoring packet with empty fragment total",
        ));
    }

    // Bounds check: frag_id must be less than frag_total to avoid panic
    // Per sing-box reference (packet.go:394)
    if frag_id >= frag_total {
        return Err(std::io::Error::other(format!(
            "Invalid fragment id {frag_id} >= total {frag_total}"
        )));
    }

    if frag_total == 1 {
        let remote_location = remote_location.ok_or_else(|| {
            std::io::Error::other("Ignoring packet with single fragment and no address")
        })?;
        return Ok(Some(PreparedUdpPacket {
            remote_location,
            payload: UdpPayload::Borrowed(payload_fragment),
        }));
    }

    let Some(reassembled) = reassemble_udp_fragment(
        fragments,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    )?
    else {
        return Ok(None);
    };

    Ok(Some(PreparedUdpPacket {
        remote_location: reassembled.remote_location,
        payload: UdpPayload::Owned(reassembled.payload),
    }))
}

// TODO: fix too many arguments warning
#[allow(clippy::too_many_arguments)]
#[inline]
async fn forward_udp_packet(
    connection: &quinn::Connection,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    assoc_id: u16,
    remote_location: NetLocation,
    payload: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
    connection_scope: &Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    let session = {
        match udp_session_map.get(&assoc_id) {
            Some(s) => s,
            None => {
                let sniffed_protocol = if client_proxy_selector.requires_protocol_sniff() {
                    sniff_udp_protocol(payload)
                } else {
                    None
                };
                let action = client_proxy_selector
                    .judge_with_protocol(remote_location.clone().into(), resolver, sniffed_protocol)
                    .await;

                let (_chain_group, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    }) => (chain_group, remote_location),
                    Ok(ConnectDecision::Block) => {
                        return Err(std::io::Error::other(format!(
                            "Blocked UDP forward to {remote_location}"
                        )));
                    }
                    Err(e) => {
                        return Err(std::io::Error::other(format!(
                            "Failed to judge UDP forward to {remote_location}: {e}"
                        )));
                    }
                };

                let resolved_address =
                    resolve_single_address(resolver, updated_location.location())
                        .await
                        .map_err(|e| {
                            std::io::Error::other(format!(
                                "Failed to resolve initial remote location {}: {e}",
                                updated_location.location()
                            ))
                        })?;

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        // since we don't replace addresses, support the case where a future
                        // address is ipv6
                        (None, None)
                    };

                // Use IPv6 dual-stack socket for direct UDP
                let client_socket = crate::socket_util::new_udp_socket(true, None)?;

                let session = if is_uni_stream {
                    UdpSession::start_with_send_stream(
                        assoc_id,
                        connection.clone(),
                        Arc::new(client_socket),
                        remote_location.clone(),
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        cancel_token,
                        connection_scope.clone(),
                    )
                } else {
                    UdpSession::start_with_datagram(
                        assoc_id,
                        connection.clone(),
                        Arc::new(client_socket),
                        remote_location.clone(),
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        cancel_token,
                        connection_scope.clone(),
                    )
                };

                // it's possible that the session is already on the map since we last checked.
                // TODO: why is there no way to get a Ref<_> from an Entry<_>? see if we can
                // do better than converting into a RefMut<_> and then downgrading.
                match udp_session_map.entry(assoc_id) {
                    dashmap::mapref::entry::Entry::Occupied(entry) => entry.into_ref().downgrade(),
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert_entry(session).into_ref().downgrade()
                    }
                }
            }
        }
    };

    let (socket_addr, is_updated) = session
        .resolve_address(&remote_location, payload, client_proxy_selector, resolver)
        .await
        .map_err(|e| {
            std::io::Error::other(format!(
                "Failed to resolve remote location {remote_location}: {e}"
            ))
        })?;

    connection_scope.throttle_upload_bytes(payload.len()).await;
    if let Err(e) = session.send_socket.send_to(payload, socket_addr).await {
        error!("Failed to forward UDP payload for session {assoc_id}: {e}");
        drop(session);
        udp_session_map.remove(&assoc_id);
        return Ok(());
    } else {
        connection_scope.record_upload_bytes(payload.len());
    }

    drop(session);
    if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
        session.last_activity = std::time::Instant::now();
        if is_updated {
            session.update_last_location(remote_location, socket_addr);
        }
    }

    Ok(())
}

fn reassemble_udp_fragment(
    fragments: &mut UdpFragmentMap,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
) -> std::io::Result<Option<ReassembledPacket>> {
    let key = UdpFragmentKey {
        assoc_id,
        packet_id,
    };
    let is_new = !fragments.contains(&key);

    if is_new {
        fragments.put(
            key,
            FragmentedPacket {
                fragment_count: frag_total,
                fragment_received: 0,
                packet_len: 0,
                received: vec![None; frag_total as usize],
                remote_location: None,
            },
        );
    }

    let fragment_error = {
        let packet = fragments
            .get(&key)
            .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;
        if packet.fragment_count != frag_total {
            Some(std::io::Error::other(format!(
                "Mismatched fragment count for session {assoc_id} packet {packet_id}"
            )))
        } else if packet.received[frag_id as usize].is_some() {
            Some(std::io::Error::other(format!(
                "Duplicate fragment for session {assoc_id} packet {packet_id}"
            )))
        } else if frag_id == 0 && remote_location.is_none() {
            Some(std::io::Error::other(format!(
                "Ignoring packet with empty first fragment address for session {assoc_id}"
            )))
        } else if packet
            .packet_len
            .checked_add(payload_fragment.len())
            .is_none_or(|len| len > MAX_REASSEMBLED_UDP_PACKET_SIZE)
        {
            Some(std::io::Error::other(format!(
                "Reassembled UDP packet exceeds {MAX_REASSEMBLED_UDP_PACKET_SIZE} bytes for session {assoc_id} packet {packet_id}"
            )))
        } else {
            None
        }
    };

    if let Some(err) = fragment_error {
        fragments.pop(&key);
        return Err(err);
    }

    let cached_bytes = fragments
        .iter()
        .map(|(_, packet)| packet.packet_len)
        .sum::<usize>();
    if cached_bytes
        .checked_add(payload_fragment.len())
        .is_none_or(|len| len > MAX_FRAGMENT_CACHE_BYTES)
    {
        fragments.pop(&key);
        return Err(std::io::Error::other(format!(
            "TUIC UDP fragment cache exceeds {MAX_FRAGMENT_CACHE_BYTES} bytes"
        )));
    }

    let is_complete = {
        let packet = fragments
            .get_mut(&key)
            .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;
        if frag_id == 0 {
            packet.remote_location = remote_location;
        }
        packet.fragment_received += 1;
        packet.packet_len += payload_fragment.len();
        packet.received[frag_id as usize] = Some(Bytes::copy_from_slice(payload_fragment));
        packet.fragment_received == packet.fragment_count
    };

    if !is_complete {
        return Ok(None);
    }

    let FragmentedPacket {
        remote_location,
        received,
        packet_len,
        ..
    } = fragments
        .pop(&key)
        .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;

    let remote_location = remote_location.ok_or_else(|| {
        std::io::Error::other(format!(
            "Missing first fragment address for session {assoc_id} packet {packet_id}"
        ))
    })?;

    let mut complete_payload = BytesMut::with_capacity(packet_len);
    for fragment in received {
        let fragment = fragment.ok_or_else(|| {
            std::io::Error::other(format!(
                "Missing fragment for session {assoc_id} packet {packet_id}"
            ))
        })?;
        complete_payload.extend_from_slice(&fragment);
    }

    Ok(Some(ReassembledPacket {
        remote_location,
        payload: complete_payload.freeze(),
    }))
}

fn remove_udp_fragments_for_assoc(fragments: &mut UdpFragmentMap, assoc_id: u16) {
    let keys: Vec<UdpFragmentKey> = fragments
        .iter()
        .filter_map(|(key, _)| (key.assoc_id == assoc_id).then_some(*key))
        .collect();
    for key in keys {
        fragments.pop(&key);
    }
}

async fn run_datagram_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    // Use LRU cache for fragment reassembly to prevent unbounded memory growth.
    let mut fragments: UdpFragmentMap =
        LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap());
    let mut last_cleanup = std::time::Instant::now();

    loop {
        let now = std::time::Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            udp_session_map.retain(|assoc_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    // Cancel the session's background task before removing
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {assoc_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

        let data = connection
            .read_datagram()
            .await
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // Per official TUIC reference (handle_stream.rs:172-180), protocol errors close the connection
        if data.len() < 2 {
            return Err(std::io::Error::other("invalid message: too short"));
        }

        let tuic_version = data[0];
        if tuic_version != 5 {
            return Err(std::io::Error::other(format!(
                "unknown version: {tuic_version}"
            )));
        }

        let command_type = data[1];
        if command_type == COMMAND_TYPE_HEARTBEAT {
            continue;
        } else if command_type != COMMAND_TYPE_PACKET {
            return Err(std::io::Error::other(format!(
                "unknown command: {command_type}"
            )));
        }

        let data_len = data.len();
        if data_len < 11 {
            return Err(std::io::Error::other("decode UDP message: too short"));
        }

        let assoc_id = u16::from_be_bytes([data[2], data[3]]);
        let packet_id = u16::from_be_bytes([data[4], data[5]]);
        let frag_total = data[6];
        let frag_id = data[7];
        let payload_size = u16::from_be_bytes([data[8], data[9]]) as usize;

        let address_type = data[10];

        let (remote_location, offset) = match address_type {
            0xff => (None, 11),
            0x00 => {
                if data_len < 14 {
                    return Err(std::io::Error::other(
                        "decode UDP message: hostname too short",
                    ));
                }
                let address_len = data[11] as usize;
                if data_len < 12 + address_len + 2 + payload_size {
                    return Err(std::io::Error::other(
                        "decode UDP message: truncated hostname",
                    ));
                }
                let address_bytes = &data[12..12 + address_len];
                let address_str = str::from_utf8(address_bytes).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid UTF-8: {e}"))
                })?;
                // Although this is supposed to be a hostname, some clients will pass
                // ipv4 and ipv6 addresses as well, so parse it rather than directly
                // using Address:Hostname enum.
                let address = Address::from(address_str).map_err(|e| {
                    std::io::Error::other(format!("decode UDP message: invalid address: {e}"))
                })?;
                let port = u16::from_be_bytes([data[12 + address_len], data[12 + address_len + 1]]);
                (Some(NetLocation::new(address, port)), 12 + address_len + 2)
            }
            0x01 => {
                if data_len < 17 + payload_size {
                    return Err(std::io::Error::other("decode UDP message: IPv4 too short"));
                }
                let ipv4_addr = Ipv4Addr::new(data[11], data[12], data[13], data[14]);
                let port = u16::from_be_bytes([data[15], data[16]]);
                (Some(NetLocation::new(Address::Ipv4(ipv4_addr), port)), 17)
            }
            0x02 => {
                if data_len < 29 + payload_size {
                    return Err(std::io::Error::other("decode UDP message: IPv6 too short"));
                }
                let ipv6_bytes: [u8; 16] = data[11..27].try_into().unwrap();
                let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([data[27], data[28]]);
                (Some(NetLocation::new(Address::Ipv6(ipv6_addr), port)), 29)
            }
            _ => {
                return Err(std::io::Error::other(format!(
                    "decode UDP message: invalid address type: {address_type}"
                )));
            }
        };

        if data_len < offset + payload_size {
            return Err(std::io::Error::other(
                "decode UDP message: truncated payload",
            ));
        }

        let payload_fragment = &data[offset..offset + payload_size];

        if let Err(e) = process_udp_packet(
            &connection,
            &client_proxy_selector,
            &resolver,
            &udp_session_map,
            &mut fragments,
            assoc_id,
            packet_id,
            frag_total,
            frag_id,
            remote_location,
            payload_fragment,
            false,
            &cancel_token,
            &connection_scope,
        )
        .await
        {
            error!("Failed to process datagram UDP packet: {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_tuic_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    users: TuicServerUsers,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    zero_rtt_handshake: bool,
    congestion_control: Option<String>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let congestion_control = parse_tuic_congestion_control(congestion_control.as_deref())?;
    let mut endpoints = Vec::with_capacity(num_endpoints);
    for _ in 0..num_endpoints {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());

        let transport = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| std::io::Error::other("failed to configure TUIC transport"))?;
        apply_tuic_congestion_control(transport, congestion_control);
        transport
            .max_concurrent_bidi_streams(4096_u32.into())
            .max_concurrent_uni_streams(4096_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid TUIC idle timeout: {e}"),
                )
            })?))
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            // MTU settings per official TUIC reference
            .initial_mtu(1200)
            .min_mtu(1200)
            // Enable MTU discovery for larger packets on capable networks
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            // Enable GSO (Generic Segmentation Offload) for better throughput
            .enable_segmentation_offload(true)
            // Lower initial RTT estimate for faster initial window growth
            .initial_rtt(Duration::from_millis(100));

        // Use 7.5MB socket buffers for high-throughput QUIC (8.625MB on BSD for 15% kernel overhead)
        // https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes
        let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            true,
            Some(8_625_000),
        )?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoints.push(endpoint);
    }

    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let resolver = resolver.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let users = users.clone();

        let join_handle = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let cloned_selector = client_proxy_selector.clone();
                let cloned_resolver = resolver.clone();
                let users = users.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(
                        cloned_selector,
                        cloned_resolver,
                        users,
                        conn,
                        zero_rtt_handshake,
                    )
                    .await
                    {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    fn fragment_cache() -> UdpFragmentMap {
        LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap())
    }

    struct TestStream {
        read: Vec<u8>,
        read_offset: usize,
    }

    impl TestStream {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read,
                read_offset: 0,
            }
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining = self.read.len().saturating_sub(self.read_offset);
            if remaining == 0 || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = remaining.min(buf.remaining());
            let start = self.read_offset;
            let end = start + n;
            buf.put_slice(&self.read[start..end]);
            self.read_offset = end;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn test_location(last_octet: u8) -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, last_octet)), 443)
    }

    #[tokio::test]
    async fn parses_tuic_pre_auth_packet_header_without_consuming_payload() {
        let payload = b"pre-auth-payload";
        let mut frame = vec![
            5,
            COMMAND_TYPE_PACKET,
            0x12,
            0x34, // assoc_id
            0xab,
            0xcd, // packet_id
            1,
            0, // fragment total/id
            0,
            payload.len() as u8,
            0x01, // IPv4
            192,
            0,
            2,
            42,
            0x01,
            0xbb, // port 443
        ];
        frame.extend_from_slice(payload);
        let mut stream = TestStream::new(frame);
        let mut reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);

        let command = read_uni_stream_command_type(&mut stream, &mut reader)
            .await
            .unwrap();
        let header = read_uni_task_header(&mut stream, &mut reader, command)
            .await
            .unwrap();

        assert_eq!(
            header,
            TuicUniTaskHeader::Packet {
                assoc_id: 0x1234,
                packet_id: 0xabcd,
                frag_total: 1,
                frag_id: 0,
                payload_size: payload.len() as u16,
                remote_location: Some(NetLocation::new(
                    Address::Ipv4(Ipv4Addr::new(192, 0, 2, 42)),
                    443,
                )),
            }
        );
        assert_eq!(reader.unparsed_data(), payload);
    }

    #[tokio::test]
    async fn reads_large_uni_task_payload_only_after_header_parsing() {
        let payload = vec![0x5a; 1024];
        let mut frame = vec![
            5,
            COMMAND_TYPE_PACKET,
            0x12,
            0x34,
            0xab,
            0xcd,
            1,
            0,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
            0x01,
            192,
            0,
            2,
            42,
            0x01,
            0xbb,
        ];
        frame.extend_from_slice(&payload);
        let mut stream = TestStream::new(frame);
        let mut reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);

        let command = read_uni_stream_command_type(&mut stream, &mut reader)
            .await
            .unwrap();
        let header = read_uni_task_header(&mut stream, &mut reader, command)
            .await
            .unwrap();
        let payload_size = match header {
            TuicUniTaskHeader::Packet { payload_size, .. } => payload_size as usize,
            _ => panic!("expected packet task"),
        };

        assert!(reader.unparsed_data().len() < payload.len());
        let received = read_uni_task_payload(&mut stream, &mut reader, payload_size)
            .await
            .unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn parses_tuic_pre_auth_dissociate_header() {
        let mut stream = TestStream::new(vec![
            5,
            COMMAND_TYPE_DISSOCIATE,
            0xca,
            0xfe, // assoc_id
        ]);
        let mut reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);

        let command = read_uni_stream_command_type(&mut stream, &mut reader)
            .await
            .unwrap();
        let header = read_uni_task_header(&mut stream, &mut reader, command)
            .await
            .unwrap();

        assert_eq!(header, TuicUniTaskHeader::Dissociate { assoc_id: 0xcafe });
    }

    #[test]
    fn preserves_pre_auth_task_order_and_enforces_bound() {
        let mut pending = Vec::new();
        for task_id in 0..MAX_PENDING_UNI_TASKS {
            push_pending_uni_task(&mut pending, task_id).unwrap();
        }

        assert_eq!(pending, (0..MAX_PENDING_UNI_TASKS).collect::<Vec<usize>>());
        let err = push_pending_uni_task(&mut pending, MAX_PENDING_UNI_TASKS).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too many TUIC tasks"));
        assert_eq!(pending.len(), MAX_PENDING_UNI_TASKS);
    }

    #[tokio::test]
    async fn rejects_invalid_pre_auth_uni_task_header() {
        let mut stream = TestStream::new(vec![5, COMMAND_TYPE_CONNECT]);
        let mut reader = StreamReader::new_with_buffer_size(MAX_HEADER_LEN);

        let command = read_uni_stream_command_type(&mut stream, &mut reader)
            .await
            .unwrap();
        let err = read_uni_task_header(&mut stream, &mut reader, command)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("invalid uni stream command type"));
    }

    #[test]
    fn parses_tuic_congestion_control_aliases() {
        assert_eq!(
            parse_tuic_congestion_control(None).unwrap(),
            TuicCongestionControl::Cubic
        );
        assert_eq!(
            parse_tuic_congestion_control(Some("cubic")).unwrap(),
            TuicCongestionControl::Cubic
        );
        assert_eq!(
            parse_tuic_congestion_control(Some("new_reno")).unwrap(),
            TuicCongestionControl::NewReno
        );
        assert_eq!(
            parse_tuic_congestion_control(Some("newreno")).unwrap(),
            TuicCongestionControl::NewReno
        );
        assert_eq!(
            parse_tuic_congestion_control(Some("reno")).unwrap(),
            TuicCongestionControl::NewReno
        );
        assert_eq!(
            parse_tuic_congestion_control(Some("bbr")).unwrap(),
            TuicCongestionControl::Bbr
        );
    }

    #[test]
    fn rejects_unknown_tuic_congestion_control() {
        let err = parse_tuic_congestion_control(Some("invalid-cc")).unwrap_err();

        assert!(
            err.to_string()
                .contains("unsupported tuic congestion_control `invalid-cc`")
        );
    }

    #[tokio::test]
    async fn tuic_tcp_protocol_sniff_preserves_bytes_read_from_stream() {
        let payload = b"GET /payload.bin HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream::new(payload.clone()));
        let mut initial_remote_data = None;

        let protocol = sniff_tcp_forward_protocol(&mut stream, &mut initial_remote_data)
            .await
            .unwrap();

        assert_eq!(protocol, Some(SniffedProtocol::Http));
        assert_eq!(initial_remote_data.unwrap(), payload);

        let mut rest = [0; 1];
        assert_eq!(stream.read(&mut rest).await.unwrap(), 0);
    }

    #[test]
    fn reassembles_tuic_fragments_independently_per_assoc_id() {
        let mut fragments = fragment_cache();
        let first_location = test_location(1);
        let second_location = test_location(2);

        assert!(
            reassemble_udp_fragment(
                &mut fragments,
                10,
                7,
                2,
                0,
                Some(first_location.clone()),
                b"he",
            )
            .unwrap()
            .is_none()
        );
        assert!(
            reassemble_udp_fragment(
                &mut fragments,
                11,
                7,
                2,
                0,
                Some(second_location.clone()),
                b"wo",
            )
            .unwrap()
            .is_none()
        );

        let first = reassemble_udp_fragment(&mut fragments, 10, 7, 2, 1, None, b"llo")
            .unwrap()
            .unwrap();
        let second = reassemble_udp_fragment(&mut fragments, 11, 7, 2, 1, None, b"rld")
            .unwrap()
            .unwrap();

        assert_eq!(first.remote_location, first_location);
        assert_eq!(first.payload.as_ref(), b"hello");
        assert_eq!(second.remote_location, second_location);
        assert_eq!(second.payload.as_ref(), b"world");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn reassembles_tuic_fragments_when_first_fragment_arrives_last() {
        let mut fragments = fragment_cache();
        let location = test_location(3);

        assert!(
            reassemble_udp_fragment(&mut fragments, 20, 9, 2, 1, None, b"tail")
                .unwrap()
                .is_none()
        );
        let packet = reassemble_udp_fragment(
            &mut fragments,
            20,
            9,
            2,
            0,
            Some(location.clone()),
            b"head-",
        )
        .unwrap()
        .unwrap();

        assert_eq!(packet.remote_location, location);
        assert_eq!(packet.payload.as_ref(), b"head-tail");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn bounds_tuic_fragmented_udp_packet_and_connection_cache_bytes() {
        let mut fragments = fragment_cache();
        let location = test_location(4);
        let half = vec![0u8; 32 * 1024];
        assert!(
            reassemble_udp_fragment(&mut fragments, 40, 1, 2, 0, Some(location.clone()), &half,)
                .unwrap()
                .is_none()
        );
        let error = match reassemble_udp_fragment(&mut fragments, 40, 1, 2, 1, None, &half) {
            Err(error) => error,
            Ok(_) => panic!("oversized TUIC UDP packet must be rejected"),
        };
        assert!(error.to_string().contains("exceeds 65535 bytes"));

        let mut fragments = fragment_cache();
        let maximum_fragment = vec![0u8; MAX_REASSEMBLED_UDP_PACKET_SIZE];
        for packet_id in 0..64 {
            assert!(
                reassemble_udp_fragment(
                    &mut fragments,
                    41,
                    packet_id,
                    2,
                    0,
                    Some(location.clone()),
                    &maximum_fragment,
                )
                .unwrap()
                .is_none()
            );
        }
        let error = match reassemble_udp_fragment(
            &mut fragments,
            41,
            64,
            2,
            0,
            Some(location),
            &maximum_fragment,
        ) {
            Err(error) => error,
            Ok(_) => panic!("over-budget TUIC fragment cache must be rejected"),
        };
        assert!(error.to_string().contains("fragment cache exceeds"));
    }

    #[test]
    fn prepares_tuic_fragmented_packet_before_session_exists() {
        let mut fragments = fragment_cache();
        let location = test_location(4);

        assert!(
            prepare_udp_packet(&mut fragments, 30, 5, 2, 1, None, b"tail")
                .unwrap()
                .is_none()
        );
        let packet = prepare_udp_packet(
            &mut fragments,
            30,
            5,
            2,
            0,
            Some(location.clone()),
            b"head-",
        )
        .unwrap()
        .unwrap();

        assert_eq!(packet.remote_location, location);
        assert_eq!(packet.payload.as_ref(), b"head-tail");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn encodes_tuic_udp_stream_packet_with_version_and_command() {
        let address_bytes = serialize_socket_addr(&SocketAddr::from(([127, 0, 0, 1], 5353)));
        let payload = b"dns-query";
        let mut buf = allocate_vec(MAX_HEADER_LEN + payload.len());
        buf[MAX_HEADER_LEN..].copy_from_slice(payload);

        let start_offset = encode_udp_stream_packet_prefix(
            &mut buf,
            0x1234,
            0xabcd,
            payload.len(),
            &address_bytes,
        )
        .unwrap();
        let frame = &buf[start_offset..MAX_HEADER_LEN + payload.len()];

        assert_eq!(&frame[0..2], &[5, COMMAND_TYPE_PACKET]);
        assert_eq!(&frame[2..4], &0x1234u16.to_be_bytes());
        assert_eq!(&frame[4..6], &0xabcdu16.to_be_bytes());
        assert_eq!(frame[6], 1);
        assert_eq!(frame[7], 0);
        assert_eq!(&frame[8..10], &(payload.len() as u16).to_be_bytes());
        assert_eq!(
            &frame[10..10 + address_bytes.len()],
            address_bytes.as_slice()
        );
        assert_eq!(&frame[10 + address_bytes.len()..], payload);
    }
}
