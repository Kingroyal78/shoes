use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::{HttpLimits, HttpRequest, host_matches_optional_port, normalize_path};
use crate::async_stream::AsyncStream;
use crate::h2mux::PrependStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Clone, Debug)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub limits: HttpLimits,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: HashMap::new(),
            limits: HttpLimits::default(),
        }
    }
}

pub struct HttpUpgradeServerHandler {
    config: HttpUpgradeConfig,
    inner: Arc<dyn TcpServerHandler>,
}

impl fmt::Debug for HttpUpgradeServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpUpgradeServerHandler")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .finish()
    }
}

impl HttpUpgradeServerHandler {
    pub fn new(mut config: HttpUpgradeConfig, inner: Arc<dyn TcpServerHandler>) -> Self {
        config.path = normalize_path(config.path);
        config.headers = config
            .headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        Self { config, inner }
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        mut stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let request = HttpRequest::read(&mut stream, self.config.limits).await?;
        if request.version != "HTTP/1.1" {
            return invalid("HTTP Upgrade requires HTTP/1.1");
        }
        if request.method != "GET" {
            return invalid("HTTP Upgrade requires GET");
        }
        if request.path() != self.config.path {
            return invalid(format!(
                "HTTP Upgrade path `{}` does not match `{}`",
                request.path(),
                self.config.path
            ));
        }
        if let Some(expected_host) = self.config.host.as_deref()
            && !request
                .header("host")?
                .is_some_and(|actual| host_matches_optional_port(actual, expected_host))
        {
            return invalid("HTTP Upgrade Host does not match configuration");
        }
        if !request.header_contains_token("connection", "upgrade")
            || !request.header_contains_token("upgrade", "websocket")
        {
            return invalid("HTTP Upgrade headers are incomplete");
        }
        if request.header("sec-websocket-key")?.is_some() {
            return invalid("received RFC6455 handshake in raw HTTP Upgrade mode");
        }
        for (name, expected) in &self.config.headers {
            if request.header(name)? != Some(expected.as_str()) {
                return invalid(format!("HTTP Upgrade header `{name}` does not match"));
            }
        }

        stream.write_all(RESPONSE).await?;
        stream.flush().await?;
        let stream: Box<dyn AsyncStream> = if request.unparsed_data.is_empty() {
            stream
        } else {
            Box::new(PrependStream::new(
                stream,
                Some(request.unparsed_data.into_boxed_slice()),
            ))
        };
        self.inner
            .setup_server_stream_with_peer_addr(stream, peer_addr)
            .await
    }
}

fn invalid<T>(message: impl Into<String>) -> std::io::Result<T> {
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use crate::async_stream::AsyncPing;

    struct TestStream(DuplexStream);

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
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct RejectInner;

    #[async_trait]
    impl TcpServerHandler for RejectInner {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            panic!("HTTP/1.0 request reached the inner handler")
        }
    }

    #[test]
    fn host_matching_accepts_port_but_not_suffix_attack() {
        assert!(host_matches_optional_port("example.com", "example.com"));
        assert!(host_matches_optional_port("example.com:443", "example.com"));
        assert!(!host_matches_optional_port(
            "example.com.attacker",
            "example.com"
        ));
    }

    #[tokio::test]
    async fn rejects_http_1_0_upgrade_requests() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler =
            HttpUpgradeServerHandler::new(HttpUpgradeConfig::default(), Arc::new(RejectInner));
        client
            .write_all(b"GET / HTTP/1.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();

        let error = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .err()
            .expect("HTTP/1.0 request must be rejected");
        assert!(error.to_string().contains("HTTP/1.1"));
    }
}
