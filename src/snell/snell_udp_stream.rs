use futures::ready;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSourcedMessage,
    AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncSourcedMessageStream,
    AsyncTargetedMessageStream, AsyncWriteMessage, AsyncWriteSourcedMessage,
    AsyncWriteTargetedMessage,
};
use crate::util::allocate_vec;

fn snell_udp_packet_too_large_error(
    payload_len: usize,
    header_len: usize,
    max_payload_size: usize,
) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!(
            "Snell UDP packet length {} exceeds max encrypted message payload length {}",
            payload_len.saturating_add(header_len),
            max_payload_size
        ),
    )
}

fn validate_snell_udp_write_len(
    payload_len: usize,
    header_len: usize,
    max_payload_size: usize,
    write_buf_len: usize,
) -> std::io::Result<()> {
    let packet_len = payload_len.checked_add(header_len).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Snell UDP packet length overflows usize",
        )
    })?;
    if packet_len > max_payload_size {
        return Err(snell_udp_packet_too_large_error(
            payload_len,
            header_len,
            max_payload_size,
        ));
    }
    if packet_len > write_buf_len {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Snell UDP packet length {packet_len} exceeds write buffer {write_buf_len}"),
        ));
    }
    Ok(())
}

fn validate_snell_udp_read_capacity(payload_len: usize, remaining: usize) -> std::io::Result<()> {
    if payload_len > remaining {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Snell UDP payload length {payload_len} exceeds read buffer {remaining}"),
        ));
    }
    Ok(())
}

pub struct SnellUdpStream {
    stream: Box<dyn AsyncMessageStream>,
    max_payload_size: usize,

    read_buf: Box<[u8]>,

    write_buf: Box<[u8]>,
    write_buf_end_offset: usize,

    is_eof: bool,
}

impl SnellUdpStream {
    pub fn new(stream: Box<dyn AsyncMessageStream>, max_payload_size: usize) -> Self {
        Self {
            stream,
            max_payload_size,

            read_buf: allocate_vec(65535).into_boxed_slice(),

            write_buf: allocate_vec(65535).into_boxed_slice(),
            write_buf_end_offset: 0,

            is_eof: false,
        }
    }
}

impl AsyncReadTargetedMessage for SnellUdpStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        let mut read_buf = ReadBuf::new(&mut this.read_buf);
        ready!(Pin::new(&mut this.stream).poll_read_message(cx, &mut read_buf))?;

        let len = read_buf.filled().len();
        if len == 0 {
            this.is_eof = true;
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        if len < 4 {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too small")));
        }

        if len > this.max_payload_size {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too big")));
        }

        let cmd = this.read_buf[0];
        if cmd != 1 {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid snell command: {cmd}"
            ))));
        }

        let address_len = this.read_buf[1] as usize;
        let (location, data_offset) = if address_len == 0 {
            let ip_version = this.read_buf[2];
            if ip_version == 4 {
                if len < 9 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv4 target",
                    )));
                }
                let ip_bytes: [u8; 4] = this.read_buf[3..7].try_into().unwrap();
                let ip_addr = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[7..9].try_into().unwrap());
                (NetLocation::new(Address::Ipv4(ip_addr), port), 9)
            } else if ip_version == 6 {
                if len < 21 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv6 target",
                    )));
                }
                let ip_bytes: [u8; 16] = this.read_buf[3..19].try_into().unwrap();
                let ip_addr = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[19..21].try_into().unwrap());
                (NetLocation::new(Address::Ipv6(ip_addr), port), 21)
            } else {
                return Poll::Ready(Err(std::io::Error::other(format!(
                    "invalid ip version: {ip_version}"
                ))));
            }
        } else {
            if len < 4 + address_len {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell packet size for host target",
                )));
            }
            let hostname_bytes = &this.read_buf[2..2 + address_len];
            let hostname = std::str::from_utf8(hostname_bytes)
                .map_err(|e| std::io::Error::other(format!("could not parse hostname: {e}")))?;
            let port = u16::from_be_bytes(
                this.read_buf[2 + address_len..4 + address_len]
                    .try_into()
                    .unwrap(),
            );
            (
                NetLocation::new(Address::Hostname(hostname.to_string()), port),
                4 + address_len,
            )
        };

        validate_snell_udp_read_capacity(len - data_offset, buf.remaining())?;
        buf.put_slice(&this.read_buf[data_offset..len]);
        Poll::Ready(Ok(location))
    }
}

impl AsyncWriteSourcedMessage for SnellUdpStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.write_buf_end_offset > 0 {
            // Buffer may be written but flush incomplete; continues in that case.
            match Pin::new(&mut this).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let buf_len = buf.len();
        let header_len = match source {
            SocketAddr::V4(_) => 7,
            SocketAddr::V6(_) => 19,
        };
        if let Err(e) = validate_snell_udp_write_len(
            buf_len,
            header_len,
            this.max_payload_size,
            this.write_buf.len(),
        ) {
            return Poll::Ready(Err(e));
        }

        let offset = match source {
            SocketAddr::V4(socket_addr) => {
                this.write_buf[0] = 4;
                this.write_buf[1..5].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[5..7].copy_from_slice(&socket_addr.port().to_be_bytes());
                7
            }
            SocketAddr::V6(socket_addr) => {
                this.write_buf[0] = 6;
                this.write_buf[1..17].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[17..19].copy_from_slice(&socket_addr.port().to_be_bytes());
                19
            }
        };

        this.write_buf[offset..offset + buf_len].copy_from_slice(buf);
        this.write_buf_end_offset = offset + buf_len;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for SnellUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf_end_offset > 0 {
            ready!(
                Pin::new(&mut this.stream)
                    .poll_write_message(cx, &this.write_buf[0..this.write_buf_end_offset])
            )?;
            this.write_buf_end_offset = 0;
        }
        Pin::new(&mut this.stream).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for SnellUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown_message(cx)
    }
}

impl AsyncPing for SnellUdpStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    /// Writes a ping message to the highest level stream abstraction that supports pings.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncTargetedMessageStream for SnellUdpStream {}

/// Client-side Snell UDP stream.
/// Writes requests with target (cmd + address format) and reads responses with source (ip_version format).
pub struct SnellUdpClientStream {
    stream: Box<dyn AsyncMessageStream>,
    max_payload_size: usize,

    read_buf: Box<[u8]>,

    write_buf: Box<[u8]>,
    write_buf_end_offset: usize,

    is_eof: bool,
}

impl SnellUdpClientStream {
    pub fn new(stream: Box<dyn AsyncMessageStream>, max_payload_size: usize) -> Self {
        Self {
            stream,
            max_payload_size,

            read_buf: allocate_vec(65535).into_boxed_slice(),

            write_buf: allocate_vec(65535).into_boxed_slice(),
            write_buf_end_offset: 0,

            is_eof: false,
        }
    }
}

/// Reads response format: ip_version(1) + ip(4/16) + port(2) + data
/// Returns the source SocketAddr
impl AsyncReadSourcedMessage for SnellUdpClientStream {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )));
        }

        let mut read_buf = ReadBuf::new(&mut this.read_buf);
        ready!(Pin::new(&mut this.stream).poll_read_message(cx, &mut read_buf))?;

        let len = read_buf.filled().len();
        if len == 0 {
            this.is_eof = true;
            return Poll::Ready(Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
            )));
        }

        // Response format: ip_version(1) + ip(4/16) + port(2) + data
        if len < 7 {
            return Poll::Ready(Err(std::io::Error::other(
                "snell response packet too small",
            )));
        }

        if len > this.max_payload_size {
            return Poll::Ready(Err(std::io::Error::other("snell response packet too big")));
        }

        let ip_version = this.read_buf[0];
        let (source_addr, data_offset) = if ip_version == 4 {
            if len < 7 {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell response packet size for ipv4",
                )));
            }
            let ip_bytes: [u8; 4] = this.read_buf[1..5].try_into().unwrap();
            let ip_addr = Ipv4Addr::from(ip_bytes);
            let port = u16::from_be_bytes(this.read_buf[5..7].try_into().unwrap());
            (SocketAddr::new(std::net::IpAddr::V4(ip_addr), port), 7)
        } else if ip_version == 6 {
            if len < 19 {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell response packet size for ipv6",
                )));
            }
            let ip_bytes: [u8; 16] = this.read_buf[1..17].try_into().unwrap();
            let ip_addr = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes(this.read_buf[17..19].try_into().unwrap());
            (SocketAddr::new(std::net::IpAddr::V6(ip_addr), port), 19)
        } else {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid snell response ip version: {ip_version}"
            ))));
        };

        validate_snell_udp_read_capacity(len - data_offset, buf.remaining())?;
        buf.put_slice(&this.read_buf[data_offset..len]);
        Poll::Ready(Ok(source_addr))
    }
}

/// Writes request format: cmd(1=0x01) + address_len(1) + [hostname bytes | ip_version(1) + ip(4/16)] + port(2) + data
impl AsyncWriteTargetedMessage for SnellUdpClientStream {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.write_buf_end_offset > 0 {
            match Pin::new(&mut this).poll_flush_message(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let buf_len = buf.len();
        let header_len = match target.address() {
            Address::Ipv4(_) => 9,
            Address::Ipv6(_) => 21,
            Address::Hostname(hostname) => {
                let hostname_len = hostname.len();
                if hostname_len > 255 {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidInput,
                        "hostname too long",
                    )));
                }
                2 + hostname_len + 2
            }
        };
        if let Err(e) = validate_snell_udp_write_len(
            buf_len,
            header_len,
            this.max_payload_size,
            this.write_buf.len(),
        ) {
            return Poll::Ready(Err(e));
        }

        this.write_buf[0] = 1; // cmd = data
        let offset = match target.address() {
            Address::Ipv4(ip) => {
                // address_len = 0 means IP address follows
                this.write_buf[1] = 0;
                this.write_buf[2] = 4; // ip_version
                this.write_buf[3..7].copy_from_slice(&ip.octets());
                this.write_buf[7..9].copy_from_slice(&target.port().to_be_bytes());
                9
            }
            Address::Ipv6(ip) => {
                this.write_buf[1] = 0;
                this.write_buf[2] = 6; // ip_version
                this.write_buf[3..19].copy_from_slice(&ip.octets());
                this.write_buf[19..21].copy_from_slice(&target.port().to_be_bytes());
                21
            }
            Address::Hostname(hostname) => {
                let hostname_bytes = hostname.as_bytes();
                let hostname_len = hostname_bytes.len();
                this.write_buf[1] = hostname_len as u8;
                this.write_buf[2..2 + hostname_len].copy_from_slice(hostname_bytes);
                let port_offset = 2 + hostname_len;
                this.write_buf[port_offset..port_offset + 2]
                    .copy_from_slice(&target.port().to_be_bytes());
                port_offset + 2
            }
        };

        this.write_buf[offset..offset + buf_len].copy_from_slice(buf);
        this.write_buf_end_offset = offset + buf_len;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for SnellUdpClientStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf_end_offset > 0 {
            ready!(
                Pin::new(&mut this.stream)
                    .poll_write_message(cx, &this.write_buf[0..this.write_buf_end_offset])
            )?;
            this.write_buf_end_offset = 0;
        }
        Pin::new(&mut this.stream).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for SnellUdpClientStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown_message(cx)
    }
}

impl AsyncPing for SnellUdpClientStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncSourcedMessageStream for SnellUdpClientStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct TestMessageIo {
        reads: Arc<Mutex<VecDeque<Vec<u8>>>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl TestMessageIo {
        fn with_read(packet: Vec<u8>) -> Self {
            let this = Self::default();
            this.reads.lock().unwrap().push_back(packet);
            this
        }

        fn written(&self) -> Vec<Vec<u8>> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl AsyncReadMessage for TestMessageIo {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(packet) = self.reads.lock().unwrap().pop_front() else {
                return Poll::Ready(Ok(()));
            };
            if packet.len() > buf.remaining() {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::InvalidInput,
                    "test packet exceeds read buffer",
                )));
            }
            buf.put_slice(&packet);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWriteMessage for TestMessageIo {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for TestMessageIo {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for TestMessageIo {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TestMessageIo {
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

    impl AsyncMessageStream for TestMessageIo {}

    #[tokio::test]
    async fn server_read_parses_hostname_target() {
        let mut packet = vec![1, 11];
        packet.extend_from_slice(b"example.com");
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(b"query");

        let io = TestMessageIo::with_read(packet);
        let mut stream = SnellUdpStream::new(Box::new(io), 0x3fff);

        let mut read_buf = [0u8; 32];
        let mut read = ReadBuf::new(&mut read_buf);
        let target = poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read))
            .await
            .unwrap();

        assert_eq!(
            target,
            NetLocation::new(Address::Hostname("example.com".to_string()), 53)
        );
        assert_eq!(read.filled(), b"query");
    }

    #[tokio::test]
    async fn server_write_sourced_message_encodes_ipv4_response() {
        let io = TestMessageIo::default();
        let writes = io.clone();
        let mut stream = SnellUdpStream::new(Box::new(io), 0x3fff);
        let source: SocketAddr = "127.0.0.1:5300".parse().unwrap();

        poll_fn(|cx| Pin::new(&mut stream).poll_write_sourced_message(cx, b"answer", &source))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();

        assert_eq!(
            writes.written(),
            vec![vec![
                4, 127, 0, 0, 1, 0x14, 0xb4, b'a', b'n', b's', b'w', b'e', b'r'
            ]]
        );
    }

    #[tokio::test]
    async fn server_write_sourced_message_rejects_oversized_packet_without_panic() {
        let io = TestMessageIo::default();
        let writes = io.clone();
        let mut stream = SnellUdpStream::new(Box::new(io), 12);
        let source: SocketAddr = "127.0.0.1:5300".parse().unwrap();

        let err =
            poll_fn(|cx| Pin::new(&mut stream).poll_write_sourced_message(cx, b"123456", &source))
                .await
                .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(writes.written().is_empty());
    }

    #[tokio::test]
    async fn client_read_sourced_message_parses_ipv6_response() {
        let source: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut packet = vec![6];
        packet.extend_from_slice(&source.octets());
        packet.extend_from_slice(&853u16.to_be_bytes());
        packet.extend_from_slice(b"answer");

        let io = TestMessageIo::with_read(packet);
        let mut stream = SnellUdpClientStream::new(Box::new(io), 0x3fff);

        let mut read_buf = [0u8; 32];
        let mut read = ReadBuf::new(&mut read_buf);
        let got_source =
            poll_fn(|cx| Pin::new(&mut stream).poll_read_sourced_message(cx, &mut read))
                .await
                .unwrap();

        assert_eq!(got_source, SocketAddr::new(source.into(), 853));
        assert_eq!(read.filled(), b"answer");
    }

    #[tokio::test]
    async fn client_write_targeted_message_encodes_domain_request() {
        let io = TestMessageIo::default();
        let writes = io.clone();
        let mut stream = SnellUdpClientStream::new(Box::new(io), 0x3fff);
        let target = NetLocation::new(Address::Hostname("dns.example".to_string()), 53);

        poll_fn(|cx| Pin::new(&mut stream).poll_write_targeted_message(cx, b"query", &target))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();

        let mut expected = vec![1, 11];
        expected.extend_from_slice(b"dns.example");
        expected.extend_from_slice(&53u16.to_be_bytes());
        expected.extend_from_slice(b"query");
        assert_eq!(writes.written(), vec![expected]);
    }

    #[tokio::test]
    async fn client_write_targeted_message_rejects_oversized_packet_without_panic() {
        let io = TestMessageIo::default();
        let writes = io.clone();
        let mut stream = SnellUdpClientStream::new(Box::new(io), 10);
        let target = NetLocation::new(Address::Hostname("a".to_string()), 53);

        let err =
            poll_fn(|cx| Pin::new(&mut stream).poll_write_targeted_message(cx, b"123456", &target))
                .await
                .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(writes.written().is_empty());
    }

    #[tokio::test]
    async fn read_rejects_payload_larger_than_caller_buffer_without_panic() {
        let mut packet = vec![1, 0, 4, 8, 8, 8, 8];
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(b"abcdef");

        let io = TestMessageIo::with_read(packet);
        let mut stream = SnellUdpStream::new(Box::new(io), 0x3fff);

        let mut read_buf = [0u8; 3];
        let mut read = ReadBuf::new(&mut read_buf);
        let err = poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}
