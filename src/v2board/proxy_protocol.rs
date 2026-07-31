use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const V1_PREFIX_REST: &[u8] = b"ROXY ";
const V1_MAX_LINE_LEN: usize = 108;
const V2_SIGNATURE_REST: &[u8] = b"\n\r\n\0\r\nQUIT\n";
const V2_VERSION: u8 = 0x20;
const V2_CMD_LOCAL: u8 = 0x00;
const V2_CMD_PROXY: u8 = 0x01;
const V2_AF_UNSPEC: u8 = 0x00;
const V2_AF_INET: u8 = 0x10;
const V2_AF_INET6: u8 = 0x20;
const V2_AF_UNIX: u8 = 0x30;
const V2_PROTO_STREAM: u8 = 0x01;

#[derive(Debug)]
pub struct ProxyProtocolServerHandler {
    inner: Arc<dyn TcpServerHandler>,
}

impl ProxyProtocolServerHandler {
    pub fn new(inner: Arc<dyn TcpServerHandler>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl TcpServerHandler for ProxyProtocolServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(server_stream, None)
            .await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let (server_stream, proxy_peer_addr) =
            read_proxy_protocol_header(server_stream, peer_addr).await?;
        let effective_peer_addr = proxy_peer_addr.or(peer_addr);
        let result = self
            .inner
            .setup_server_stream_with_peer_addr(server_stream, effective_peer_addr)
            .await?;

        Ok(TcpServerSetupResult::PeerAddressOverride {
            peer_addr: effective_peer_addr,
            result: Box::new(result),
        })
    }
}

async fn read_proxy_protocol_header(
    mut stream: Box<dyn AsyncStream>,
    fallback_peer_addr: Option<SocketAddr>,
) -> std::io::Result<(Box<dyn AsyncStream>, Option<SocketAddr>)> {
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first).await?;

    let peer_addr = match first[0] {
        b'P' => read_proxy_v1_header(&mut stream).await?,
        b'\r' => read_proxy_v2_header(&mut stream).await?,
        byte => {
            return invalid(format!(
                "missing PROXY protocol header before V2Board inbound data: first byte 0x{byte:02x}"
            ));
        }
    }
    .or(fallback_peer_addr);

    Ok((stream, peer_addr))
}

async fn read_proxy_v1_header(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<Option<SocketAddr>> {
    let mut prefix_rest = [0_u8; V1_PREFIX_REST.len()];
    stream.read_exact(&mut prefix_rest).await?;
    if prefix_rest != V1_PREFIX_REST {
        return invalid("invalid PROXY protocol v1 signature");
    }

    let mut line = b"P".to_vec();
    line.extend_from_slice(&prefix_rest);
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX_LINE_LEN {
            return invalid("PROXY protocol v1 header exceeds maximum length");
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
    }

    parse_proxy_v1_line(&line)
}

async fn read_proxy_v2_header(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<Option<SocketAddr>> {
    let mut signature_rest = [0_u8; V2_SIGNATURE_REST.len()];
    stream.read_exact(&mut signature_rest).await?;
    if signature_rest != V2_SIGNATURE_REST {
        return invalid("invalid PROXY protocol v2 signature");
    }

    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let ver_cmd = header[0];
    if ver_cmd & 0xf0 != V2_VERSION {
        return invalid("invalid PROXY protocol v2 version");
    }
    let command = ver_cmd & 0x0f;
    let family_protocol = header[1];
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;

    match command {
        V2_CMD_LOCAL => Ok(None),
        V2_CMD_PROXY => parse_proxy_v2_payload(family_protocol, &payload),
        _ => invalid("invalid PROXY protocol v2 command"),
    }
}

fn parse_proxy_v1_line(line: &[u8]) -> std::io::Result<Option<SocketAddr>> {
    let line = std::str::from_utf8(line).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PROXY protocol v1 header is not UTF-8: {e}"),
        )
    })?;
    let line = line.strip_suffix("\r\n").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY protocol v1 header missing CRLF",
        )
    })?;
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return invalid("invalid PROXY protocol v1 header");
    }

    match parts[1] {
        "UNKNOWN" => Ok(None),
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return invalid("invalid PROXY protocol v1 TCP header field count");
            }
            let src_ip = parts[2].parse::<IpAddr>().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid PROXY protocol v1 source address: {e}"),
                )
            })?;
            let dst_ip = parts[3].parse::<IpAddr>().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid PROXY protocol v1 destination address: {e}"),
                )
            })?;
            validate_v1_family(parts[1], src_ip, dst_ip)?;
            let src_port = parse_port(parts[4], "source")?;
            parse_port(parts[5], "destination")?;
            Ok(Some(SocketAddr::new(src_ip, src_port)))
        }
        protocol => invalid(format!(
            "unsupported PROXY protocol v1 protocol `{protocol}`"
        )),
    }
}

fn validate_v1_family(protocol: &str, src_ip: IpAddr, dst_ip: IpAddr) -> std::io::Result<()> {
    match (protocol, src_ip, dst_ip) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => Ok(()),
        _ => invalid("PROXY protocol v1 address family does not match protocol"),
    }
}

fn parse_proxy_v2_payload(
    family_protocol: u8,
    payload: &[u8],
) -> std::io::Result<Option<SocketAddr>> {
    let family = family_protocol & 0xf0;
    let protocol = family_protocol & 0x0f;
    if protocol != V2_PROTO_STREAM {
        return invalid("PROXY protocol v2 header is not for a TCP stream");
    }

    match family {
        V2_AF_INET => {
            if payload.len() < 12 {
                return invalid("truncated PROXY protocol v2 IPv4 address block");
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                payload[0], payload[1], payload[2], payload[3],
            ));
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(src_ip, src_port)))
        }
        V2_AF_INET6 => {
            if payload.len() < 36 {
                return invalid("truncated PROXY protocol v2 IPv6 address block");
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[0..16]).expect("slice length checked"),
            ));
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(src_ip, src_port)))
        }
        V2_AF_UNSPEC | V2_AF_UNIX => Ok(None),
        _ => invalid("unsupported PROXY protocol v2 address family"),
    }
}

fn parse_port(value: &str, label: &str) -> std::io::Result<u16> {
    value.parse::<u16>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid PROXY protocol v1 {label} port: {e}"),
        )
    })
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        msg.into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

    use crate::async_stream::AsyncPing;

    use super::*;

    struct TestStream(tokio::io::DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
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
            unreachable!("test stream does not support ping")
        }
    }

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct CapturingHandler {
        peer_addr: Arc<Mutex<Option<SocketAddr>>>,
        first_payload_byte: Arc<Mutex<Option<u8>>>,
    }

    #[async_trait]
    impl TcpServerHandler for CapturingHandler {
        async fn setup_server_stream(
            &self,
            server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            self.setup_server_stream_with_peer_addr(server_stream, None)
                .await
        }

        async fn setup_server_stream_with_peer_addr(
            &self,
            mut server_stream: Box<dyn AsyncStream>,
            peer_addr: Option<SocketAddr>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut byte = [0_u8; 1];
            server_stream.read_exact(&mut byte).await?;
            *self.peer_addr.lock().unwrap() = peer_addr;
            *self.first_payload_byte.lock().unwrap() = Some(byte[0]);
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[tokio::test]
    async fn proxy_protocol_handler_overrides_peer_and_preserves_payload() {
        let (server, mut client) = tokio::io::duplex(128);
        let peer_addr = Arc::new(Mutex::new(None));
        let first_payload_byte = Arc::new(Mutex::new(None));
        let handler = ProxyProtocolServerHandler::new(Arc::new(CapturingHandler {
            peer_addr: peer_addr.clone(),
            first_payload_byte: first_payload_byte.clone(),
        }));

        client
            .write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 42300 443\r\nx")
            .await
            .unwrap();
        let result = handler
            .setup_server_stream_with_peer_addr(
                Box::new(TestStream(server)),
                Some("127.0.0.1:50000".parse().unwrap()),
            )
            .await
            .unwrap();

        assert!(matches!(
            result,
            TcpServerSetupResult::PeerAddressOverride { .. }
        ));
        assert_eq!(
            *peer_addr.lock().unwrap(),
            Some("203.0.113.7:42300".parse().unwrap())
        );
        assert_eq!(*first_payload_byte.lock().unwrap(), Some(b'x'));
    }

    #[test]
    fn parses_proxy_v1_tcp4_source_addr() {
        let parsed = parse_proxy_v1_line(b"PROXY TCP4 203.0.113.7 10.0.0.1 42300 443\r\n")
            .unwrap()
            .unwrap();

        assert_eq!(parsed, "203.0.113.7:42300".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_proxy_v1_tcp6_source_addr() {
        let parsed = parse_proxy_v1_line(b"PROXY TCP6 2001:db8::7 2001:db8::1 42300 443\r\n")
            .unwrap()
            .unwrap();

        assert_eq!(parsed, "[2001:db8::7]:42300".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_proxy_v1_unknown_without_override() {
        assert!(parse_proxy_v1_line(b"PROXY UNKNOWN\r\n").unwrap().is_none());
    }

    #[test]
    fn rejects_proxy_v1_family_mismatch() {
        let err =
            parse_proxy_v1_line(b"PROXY TCP4 2001:db8::7 10.0.0.1 42300 443\r\n").unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("address family does not match protocol")
        );
    }

    #[test]
    fn parses_proxy_v2_ipv4_source_addr() {
        let payload = [203, 0, 113, 7, 10, 0, 0, 1, 0xa5, 0x3c, 0x01, 0xbb];
        let parsed = parse_proxy_v2_payload(V2_AF_INET | V2_PROTO_STREAM, &payload)
            .unwrap()
            .unwrap();

        assert_eq!(parsed, "203.0.113.7:42300".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_proxy_v2_ipv6_source_addr() {
        let mut payload = [0_u8; 36];
        payload[0..16].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        payload[16..32].copy_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        payload[32..34].copy_from_slice(&42300_u16.to_be_bytes());
        payload[34..36].copy_from_slice(&443_u16.to_be_bytes());
        let parsed = parse_proxy_v2_payload(V2_AF_INET6 | V2_PROTO_STREAM, &payload)
            .unwrap()
            .unwrap();

        assert_eq!(parsed, "[::1]:42300".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_proxy_v2_non_stream_protocol() {
        let err = parse_proxy_v2_payload(V2_AF_INET | 0x02, &[0_u8; 12]).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("not for a TCP stream"));
    }
}
