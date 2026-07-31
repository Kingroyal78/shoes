use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

/// Adapts an `Arc<dyn TcpServerHandler>` to APIs which own a boxed handler.
///
/// Plugin transports need shared ownership because multiplexed physical
/// connections can create many independently serviced logical connections.
pub struct ArcTcpServerHandler(pub Arc<dyn TcpServerHandler>);

impl fmt::Debug for ArcTcpServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ArcTcpServerHandler").field(&self.0).finish()
    }
}

#[async_trait]
impl TcpServerHandler for ArcTcpServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.0.setup_server_stream(stream).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.0
            .setup_server_stream_with_peer_addr(stream, peer_addr)
            .await
    }
}
