use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::h2mux::PrependStream;
use crate::ss_plugins::transport::{
    HttpLimits, HttpRequest, host_matches_optional_port, normalize_path,
};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Clone, Debug)]
pub struct ObfsHttpConfig {
    pub expected_hosts: Vec<String>,
    pub path: Option<String>,
    pub limits: HttpLimits,
    pub max_initial_payload: usize,
}

impl Default for ObfsHttpConfig {
    fn default() -> Self {
        Self {
            expected_hosts: Vec::new(),
            path: None,
            limits: HttpLimits::default(),
            max_initial_payload: 64 * 1024,
        }
    }
}

pub struct ObfsHttpServerHandler {
    config: ObfsHttpConfig,
    inner: Arc<dyn TcpServerHandler>,
}

impl fmt::Debug for ObfsHttpServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsHttpServerHandler")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .finish()
    }
}

impl ObfsHttpServerHandler {
    pub fn new(mut config: ObfsHttpConfig, inner: Arc<dyn TcpServerHandler>) -> Self {
        config.expected_hosts = config
            .expected_hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        config.path = config.path.map(normalize_path);
        Self { config, inner }
    }
}

#[async_trait]
impl TcpServerHandler for ObfsHttpServerHandler {
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
        if self.config.max_initial_payload == 0 {
            return invalid_input("simple-obfs HTTP initial payload limit cannot be zero");
        }
        let request = HttpRequest::read(&mut stream, self.config.limits).await?;
        if request.method != "GET" {
            return invalid_data("simple-obfs HTTP request must use GET");
        }
        if let Some(expected_path) = self.config.path.as_deref()
            && request.path() != expected_path
        {
            return invalid_data(format!(
                "simple-obfs HTTP path `{}` does not match `{expected_path}`",
                request.path()
            ));
        }
        if !self.config.expected_hosts.is_empty() {
            let host = request
                .header("host")?
                .ok_or_else(|| invalid_data_error("simple-obfs HTTP Host is missing"))?;
            if !self
                .config
                .expected_hosts
                .iter()
                .any(|expected| host_matches_optional_port(host, expected))
            {
                return invalid_data("simple-obfs HTTP Host does not match configuration");
            }
        }
        if let Some(content_length) = request.header("content-length")? {
            let content_length = content_length.parse::<usize>().map_err(|_| {
                invalid_data_error("simple-obfs HTTP Content-Length is not an integer")
            })?;
            if content_length > self.config.max_initial_payload {
                return invalid_data("simple-obfs HTTP initial payload exceeds configured limit");
            }
        }
        if request.unparsed_data.len() > self.config.max_initial_payload {
            return invalid_data("simple-obfs HTTP initial payload exceeds configured limit");
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

fn invalid_data<T>(message: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_data_error(message))
}

fn invalid_data_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn invalid_input<T>(message: impl Into<String>) -> std::io::Result<T> {
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

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
    struct AssertPayloadHandler;

    #[async_trait]
    impl TcpServerHandler for AssertPayloadHandler {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut payload = [0u8; 10];
            stream.read_exact(&mut payload).await?;
            assert_eq!(&payload, b"ss-payload");
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[derive(Debug)]
    struct RejectInner;

    #[async_trait]
    impl TcpServerHandler for RejectInner {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            panic!("oversized read-ahead payload reached the inner handler")
        }
    }

    #[test]
    fn host_matching_handles_case_and_optional_port_without_suffix_confusion() {
        assert!(host_matches_optional_port("EXAMPLE.com", "example.com"));
        assert!(host_matches_optional_port(
            "example.com:8443",
            "example.com"
        ));
        assert!(!host_matches_optional_port(
            "example.com.invalid",
            "example.com"
        ));
        assert!(!host_matches_optional_port("example.co:443", "example.com"));
    }

    #[tokio::test]
    async fn accepts_fragmented_request_and_preserves_coalesced_payload() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = ObfsHttpServerHandler::new(
            ObfsHttpConfig {
                expected_hosts: vec!["example.com".to_string()],
                path: Some("/obfs".to_string()),
                ..ObfsHttpConfig::default()
            },
            Arc::new(AssertPayloadHandler),
        );
        let accept = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .unwrap()
        });
        let request =
            b"GET /obfs HTTP/1.1\r\nHost: Example.com:443\r\nContent-Length: 10\r\n\r\nss-payload";
        for chunk in request.chunks(3) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut response = vec![0u8; RESPONSE.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, RESPONSE);
        assert!(matches!(
            accept.await.unwrap(),
            TcpServerSetupResult::AlreadyHandled
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_declared_initial_payload() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = ObfsHttpServerHandler::new(
            ObfsHttpConfig {
                max_initial_payload: 4,
                ..ObfsHttpConfig::default()
            },
            Arc::new(AssertPayloadHandler),
        );
        client
            .write_all(b"GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
            .await
            .unwrap();
        let error = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn rejects_oversized_actual_read_ahead_without_content_length() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = ObfsHttpServerHandler::new(
            ObfsHttpConfig {
                max_initial_payload: 4,
                ..ObfsHttpConfig::default()
            },
            Arc::new(RejectInner),
        );
        client
            .write_all(b"GET / HTTP/1.1\r\n\r\n12345")
            .await
            .unwrap();

        let error = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .err()
            .expect("oversized actual read-ahead must be rejected");
        assert!(error.to_string().contains("exceeds"));
    }
}
