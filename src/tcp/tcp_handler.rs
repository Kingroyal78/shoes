use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::v2board::outbound::dispatcher::OutboundDispatcher;

pub trait TrafficRecorder: Send + Sync + Debug {
    fn add_traffic(&self, node_tag: &str, uid: u64, upload: u64, download: u64);
    fn flush_pending_traffic(&self) {}
    fn add_alive_ip_and_check_limit(
        &self,
        node_tag: &str,
        uid: u64,
        ip: std::net::IpAddr,
        device_limit: Option<u64>,
    ) -> bool;
    fn remove_alive_ip(&self, node_tag: &str, uid: u64, ip: std::net::IpAddr);
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    /// Shared with every other user of the same node and with every connection
    /// they open. As a `String` this was one heap allocation per user in the
    /// table plus one more for each of the several clones a connection makes.
    pub node_tag: Arc<str>,
    pub uid: u64,
    pub user_key: String,
    pub speed_limit: Option<u64>,
    pub device_limit: Option<u64>,
    pub recorder: Option<Arc<dyn TrafficRecorder>>,
}

#[derive(Clone, Debug)]
pub struct ServerUser {
    pub credential: String,
    pub authenticated_user: AuthenticatedUser,
}

pub enum TcpServerSetupResult {
    PeerAddressOverride {
        peer_addr: Option<SocketAddr>,
        result: Box<TcpServerSetupResult>,
    },
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,
        /// Response to write to the server stream after connection to remote location succeeds
        connection_success_response: Option<Box<[u8]>>,
        /// Initial data to send to the remote location
        initial_remote_data: Option<Box<[u8]>>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
        /// Node-side outbound dispatcher for local routing rules; `None`
        /// keeps the legacy selector direct-dial behavior.
        outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
        authenticated_user: Option<AuthenticatedUser>,
    },
    BidirectionalUdp {
        need_initial_flush: bool,
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
        /// Node-side outbound dispatcher for local routing rules; `None`
        /// keeps the legacy selector chain-group dial.
        outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
        authenticated_user: Option<AuthenticatedUser>,
    },
    MultiDirectionalUdp {
        need_initial_flush: bool,
        stream: Box<dyn AsyncTargetedMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
        /// Node-side outbound dispatcher for local routing rules; `None`
        /// keeps the legacy selector chain-group dial.
        outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
        authenticated_user: Option<AuthenticatedUser>,
    },
    SessionBasedUdp {
        need_initial_flush: bool,
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        /// The proxy selector to use for routing this connection
        proxy_selector: Arc<ClientProxySelector>,
        /// Node-side outbound dispatcher for local routing rules; `None`
        /// keeps the legacy selector chain-group dial.
        outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
        authenticated_user: Option<AuthenticatedUser>,
    },
    /// The handler consumed the stream and returned the rest of its connection
    /// lifecycle to the caller.
    ///
    /// This future is deliberately owned and awaited by the same task that
    /// accepted the stream. The old `AlreadyHandled` marker encouraged handlers
    /// to detach work with `tokio::spawn`; callers then had no completion,
    /// cancellation or error handle, and connection accounting ended while the
    /// physical session was still alive.
    ConnectionTask(Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'static>>),
}

impl TcpServerSetupResult {
    pub fn connection_task<F>(future: F) -> Self
    where
        F: Future<Output = std::io::Result<()>> + Send + 'static,
    {
        Self::ConnectionTask(Box::pin(future))
    }

    pub fn completed() -> Self {
        Self::connection_task(std::future::ready(Ok(())))
    }

    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::PeerAddressOverride { result, .. } => {
                result.set_need_initial_flush(need_initial_flush);
            }
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::BidirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: flush,
                ..
            }
            | TcpServerSetupResult::SessionBasedUdp {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
            TcpServerSetupResult::ConnectionTask(_) => {}
        }
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        _peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream(server_stream).await
    }
}

pub struct TcpClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
    /// Early application data that was buffered during protocol handshake.
    /// Only expected from the final destination - intermediate hops should not
    /// return early data (all proxy protocols are client-initiated).
    pub early_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync + Debug {
    /// Setup a client connection through this proxy.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `remote_location` - The destination to connect to through the proxy.
    ///                       May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// * `client_stream` - The wrapped stream ready for application data
    /// * `early_data` - Any application data received during handshake (from final destination)
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Returns true if this handler supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    /// Setup a bidirectional UDP message stream over a TCP connection.
    /// Only called if `supports_udp_over_tcp()` returns true.
    ///
    /// # Arguments
    /// * `client_stream` - The transport stream to the proxy server
    /// * `target` - The destination for UDP packets.
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// A message stream for sending/receiving UDP packets to the target.
    async fn setup_client_udp_bidirectional(
        &self,
        _client_stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP-over-TCP not supported by this protocol",
        ))
    }
}
