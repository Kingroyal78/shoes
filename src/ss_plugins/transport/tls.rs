use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

/// Terminates ordinary TLS and dispatches the plaintext stream to another
/// server handler.  The caller owns certificate selection in `ServerConfig`.
pub struct TlsTerminatingServerHandler {
    server_config: Arc<rustls::ServerConfig>,
    inner: Arc<dyn TcpServerHandler>,
    handshake_buffer_size: usize,
}

impl fmt::Debug for TlsTerminatingServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTerminatingServerHandler")
            .field("inner", &self.inner)
            .field("handshake_buffer_size", &self.handshake_buffer_size)
            .finish_non_exhaustive()
    }
}

impl TlsTerminatingServerHandler {
    pub fn new(server_config: Arc<rustls::ServerConfig>, inner: Arc<dyn TcpServerHandler>) -> Self {
        Self {
            server_config,
            inner,
            handshake_buffer_size: 16 * 1024,
        }
    }

    pub fn with_handshake_buffer_size(mut self, size: usize) -> Self {
        self.handshake_buffer_size = size.max(1024);
        self
    }
}

#[async_trait]
impl TcpServerHandler for TlsTerminatingServerHandler {
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
        let server_connection =
            rustls::ServerConnection::new(self.server_config.clone()).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("failed to create plugin TLS server connection: {error}"),
                )
            })?;
        let mut connection = CryptoConnection::new_rustls_server(server_connection);
        perform_crypto_handshake(&mut connection, &mut stream, self.handshake_buffer_size).await?;
        let stream: Box<dyn AsyncStream> = Box::new(CryptoTlsStream::new(stream, connection));
        let mut result = self
            .inner
            .setup_server_stream_with_peer_addr(stream, peer_addr)
            .await?;
        result.set_need_initial_flush(true);
        Ok(result)
    }
}
