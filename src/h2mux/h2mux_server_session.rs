//! H2MUX Server Session
//!
//! Accepts incoming HTTP/2 streams and demultiplexes them into individual proxy streams.
//! Includes idle timeout support matching sing-mux behavior.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http::Response;
use log::{debug, info};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{AuthenticatedUser, TcpServerSetupResult};
use crate::tcp::tcp_server::handle_server_setup_result;
use crate::uot::SocksPacketAddrStream;
use crate::v2board::outbound::dispatcher::OutboundDispatcher;
use crate::vless::VlessMessageStream;

use super::MuxProtocol;
use super::activity_tracked_stream::ActivityTrackedStream;
use super::activity_tracker::{ActivityTracker, IDLE_TIMEOUT, SHUTDOWN_DRAIN_TIMEOUT};
use super::h2mux_padding::H2MuxPaddingStream;
use super::h2mux_protocol::{SessionRequest, StreamRequest};
use super::h2mux_server_stream::H2MuxServerStream;
use super::h2mux_stream::H2MuxStream;
use super::prepend_stream::PrependStream;

/// HTTP/2 window and frame size configuration
const STREAM_WINDOW_SIZE: u32 = 256 * 1024; // 256 KB per stream
const CONNECTION_WINDOW_SIZE: u32 = 1 << 20; // 1 MB (matches Go's http2 default)
const MAX_FRAME_SIZE: u32 = (1 << 24) - 1; // ~16 MB (max allowed by HTTP/2)

/// Channel buffer size for inbound streams
const INBOUND_BUFFER: usize = 128;

/// An incoming stream with its destination
pub struct InboundStream {
    /// The multiplexed stream (wrapped with deferred status response)
    pub stream: H2MuxServerStream,
    /// Stream request with destination info
    pub request: StreamRequest,
}

/// Server session that accepts multiplexed streams.
pub struct H2MuxServerSession {
    /// Receiver for incoming streams
    inbound_rx: mpsc::Receiver<InboundStream>,
    /// Session closed flag (shared with accept loop)
    #[allow(dead_code)]
    is_closed: Arc<AtomicBool>,
    /// Session protocol
    protocol: MuxProtocol,
    /// Padding enabled
    padding_enabled: bool,
}

impl H2MuxServerSession {
    /// Create a new server session from a raw connection.
    ///
    /// This performs:
    /// 1. Read session request header on RAW stream (unpadded)
    /// 2. Apply padding layer if client requested it
    /// 3. Perform HTTP/2 server handshake over (potentially padded) stream
    /// 4. Start accepting streams with idle timeout monitoring
    pub async fn new<IO>(conn: IO) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_inner(conn, None).await
    }

    /// Create a server session and require the client's padding negotiation to
    /// exactly match the listener configuration.
    pub async fn new_with_expected_padding<IO>(conn: IO, expected_padding: bool) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_inner(conn, Some(expected_padding)).await
    }

    async fn new_inner<IO>(mut conn: IO, expected_padding: Option<bool>) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Read session request header on RAW stream (before padding)
        let session_req = SessionRequest::decode(&mut conn).await?;

        if session_req.protocol != MuxProtocol::H2Mux {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported mux protocol: {:?}", session_req.protocol),
            ));
        }

        if let Some(expected_padding) = expected_padding
            && session_req.padding != expected_padding
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "mux padding configuration mismatch: server={expected_padding}, client={}",
                    session_req.padding
                ),
            ));
        }

        debug!(
            "H2MuxServerSession: received session request (version={}, protocol={:?}, padding={})",
            session_req.version, session_req.protocol, session_req.padding
        );

        // Apply padding layer and perform handshake
        if session_req.padding {
            let padded = H2MuxPaddingStream::new(conn);
            Self::handshake_and_spawn(padded, session_req.protocol, session_req.padding).await
        } else {
            Self::handshake_and_spawn(conn, session_req.protocol, session_req.padding).await
        }
    }

    /// Perform HTTP/2 handshake and spawn acceptor task.
    async fn handshake_and_spawn<IO>(
        conn: IO,
        protocol: MuxProtocol,
        padding_enabled: bool,
    ) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Create channel for inbound streams
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_BUFFER);
        let is_closed = Arc::new(AtomicBool::new(false));

        // Create activity tracker for idle timeout.
        // Wrap the connection with ActivityTrackedStream so that ALL HTTP/2 frames
        // (including PING, SETTINGS, WINDOW_UPDATE) count as activity,
        // matching Go's http2.Server.IdleTimeout behavior.
        let activity = ActivityTracker::new();
        let conn = ActivityTrackedStream::new(conn, activity.clone());

        // Perform H2 server handshake
        let connection = h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW_SIZE)
            .initial_connection_window_size(CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(1024)
            .handshake(conn)
            .await
            .map_err(|e| io::Error::other(format!("H2 server handshake failed: {}", e)))?;

        debug!("H2MuxServerSession: H2 handshake complete");

        // Spawn acceptor task with idle timeout monitoring
        let is_closed_clone = Arc::clone(&is_closed);
        tokio::spawn(async move {
            Self::accept_loop(connection, inbound_tx, is_closed_clone, activity).await;
        });

        Ok(Self {
            inbound_rx,
            is_closed,
            protocol,
            padding_enabled,
        })
    }

    /// Accept loop - handles incoming H2 streams with idle timeout.
    ///
    /// Activity tracking is handled at the IO level by ActivityTrackedStream,
    /// so we don't need to manually record activity on stream accept/read/write.
    async fn accept_loop(
        mut connection: h2::server::Connection<impl AsyncRead + AsyncWrite + Unpin, Bytes>,
        inbound_tx: mpsc::Sender<InboundStream>,
        is_closed: Arc<AtomicBool>,
        activity: ActivityTracker,
    ) {
        // Check idle timeout periodically (6 times per timeout period)
        let check_interval = IDLE_TIMEOUT / 6;
        let mut idle_timer = interval(check_interval);
        idle_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the first tick which returns immediately
        idle_timer.tick().await;

        loop {
            tokio::select! {
                // Accept new streams
                result = connection.accept() => {
                    match result {
                        Some(Ok((request, respond))) => {
                            let inbound_tx = inbound_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_stream(request, respond, inbound_tx).await {
                                    debug!("H2MuxServerSession: stream error: {}", e);
                                }
                            });
                        }
                        Some(Err(e)) => {
                            debug!("H2MuxServerSession: accept error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }

                // Check for idle timeout
                _ = idle_timer.tick() => {
                    if is_closed.load(Ordering::Relaxed) {
                        break;
                    }

                    if activity.is_idle(IDLE_TIMEOUT) {
                        debug!("H2MuxServerSession: idle timeout, initiating graceful shutdown");
                        // Send GOAWAY and allow existing streams to complete
                        connection.graceful_shutdown();

                        // Drain remaining accepts with a timeout to prevent indefinite hangs.
                        // Without this timeout, if the client keeps the TCP connection open
                        // (e.g., with keepalive PINGs), accept().await can block forever.
                        let drain_result = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
                            while let Some(result) = connection.accept().await {
                                match result {
                                    Ok((request, respond)) => {
                                        let inbound_tx = inbound_tx.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = Self::handle_stream(request, respond, inbound_tx).await {
                                                debug!("H2MuxServerSession: stream error during drain: {}", e);
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        debug!("H2MuxServerSession: error during drain, stopping: {}", e);
                                        break;
                                    }
                                }
                            }
                        }).await;

                        if drain_result.is_err() {
                            debug!("H2MuxServerSession: drain timeout, forcing close");
                        }
                        break;
                    }
                }
            }
        }

        is_closed.store(true, Ordering::Relaxed);
        debug!("H2MuxServerSession: accept loop ended");
    }

    /// Handle a single incoming H2 stream
    async fn handle_stream(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        inbound_tx: mpsc::Sender<InboundStream>,
    ) -> io::Result<()> {
        // Send 200 OK response
        let response = Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .map_err(|e| io::Error::other(format!("failed to build H2 response: {e}")))?;

        let send_stream = respond
            .send_response(response, false)
            .map_err(|e| io::Error::other(format!("failed to send H2 response: {e}")))?;

        let recv_stream = request.into_body();

        // Create H2MuxStream
        let mut stream = H2MuxStream::new(send_stream, recv_stream);

        // Read stream request (destination)
        let stream_request = StreamRequest::decode_async(&mut stream).await?;

        debug!(
            "H2MuxServerSession: new stream to {} ({})",
            stream_request.destination, stream_request.network
        );

        // Wrap with server stream that sends status on first write
        let server_stream = H2MuxServerStream::new(stream);

        // Send to inbound channel
        let inbound = InboundStream {
            stream: server_stream,
            request: stream_request,
        };

        inbound_tx
            .send(inbound)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "inbound channel closed"))?;

        Ok(())
    }

    /// Accept the next incoming stream.
    ///
    /// Returns None when the session is closed.
    pub async fn accept(&mut self) -> Option<InboundStream> {
        self.inbound_rx.recv().await
    }

    /// Check if the session is closed.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Close the session.
    #[allow(dead_code)]
    pub fn close(&self) {
        self.is_closed.store(true, Ordering::Relaxed);
    }

    /// Get the protocol being used
    pub fn protocol(&self) -> MuxProtocol {
        self.protocol
    }

    /// Check if padding is enabled
    pub fn padding_enabled(&self) -> bool {
        self.padding_enabled
    }
}

/// Run an H2MUX server session, forwarding each stream to a handler.
#[allow(dead_code)]
pub async fn run_h2mux_server<IO, F, Fut>(conn: IO, handler: F) -> io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(InboundStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    let mut session = H2MuxServerSession::new(conn).await?;

    while let Some(inbound) = session.accept().await {
        let fut = handler(inbound);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                debug!("H2MUX stream handler error: {}", e);
            }
        });
    }

    Ok(())
}

/// Handle an H2MUX session on a stream.
///
/// This function is called when a protocol handler detects the h2mux magic address.
/// It reads the session header, sets up HTTP/2, and handles each multiplexed stream.
pub async fn handle_h2mux_session<S>(
    stream: S,
    initial_data: Option<Box<[u8]>>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_h2mux_session_inner(
        stream,
        initial_data,
        udp_enabled,
        proxy_selector,
        resolver,
        outbound_dispatcher,
        None,
        None,
        None,
    )
    .await
}

/// Handle an H2MUX session with server-side negotiation and accounting
/// context. Each logical stream is passed through the same setup-result path
/// as a standalone inbound connection.
#[allow(clippy::too_many_arguments)]
pub async fn handle_h2mux_session_with_context<S>(
    stream: S,
    initial_data: Option<Box<[u8]>>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    expected_padding: bool,
    authenticated_user: Option<AuthenticatedUser>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_h2mux_session_inner(
        stream,
        initial_data,
        udp_enabled,
        proxy_selector,
        resolver,
        outbound_dispatcher,
        Some(expected_padding),
        authenticated_user,
        peer_addr,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_h2mux_session_inner<S>(
    stream: S,
    initial_data: Option<Box<[u8]>>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    expected_padding: Option<bool>,
    authenticated_user: Option<AuthenticatedUser>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("H2MUX: Starting server session");

    // Wrap with PrependStream if there's initial data from protocol parsing
    let stream = PrependStream::new(stream, initial_data);
    let mut session = match expected_padding {
        Some(expected_padding) => {
            H2MuxServerSession::new_with_expected_padding(stream, expected_padding).await?
        }
        None => H2MuxServerSession::new(stream).await?,
    };

    info!(
        "H2MUX: Session established (protocol={:?}, padding={})",
        session.protocol(),
        session.padding_enabled()
    );

    while let Some(inbound) = session.accept().await {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();
        let authenticated_user = authenticated_user.clone();
        let outbound_dispatcher = outbound_dispatcher.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_h2mux_stream(
                inbound,
                udp_enabled,
                proxy_selector,
                resolver,
                outbound_dispatcher,
                authenticated_user,
                peer_addr,
            )
            .await
            {
                debug!("H2MUX stream error: {}", e);
            }
        });
    }

    debug!("H2MUX: Session ended");
    Ok(())
}

/// Handle a single h2mux stream
async fn handle_h2mux_stream(
    inbound: InboundStream,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    authenticated_user: Option<AuthenticatedUser>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let InboundStream {
        mut stream,
        request,
    } = inbound;
    let is_udp = request.is_udp();
    let packet_addr = request.packet_addr;
    let destination = request.destination;

    info!(
        "H2MUX stream: {} -> {} (udp={}, packet_addr={})",
        if is_udp { "UDP" } else { "TCP" },
        destination,
        is_udp,
        packet_addr
    );

    if is_udp {
        if !udp_enabled {
            let _ = stream.write_error_response("UDP not enabled").await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP not enabled",
            ));
        }

        let setup_result = if packet_addr {
            // Per-packet addressing (like UoT V1)
            TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(SocksPacketAddrStream::new_socks(Box::new(stream))),
                need_initial_flush: false,
                proxy_selector,
                outbound_dispatcher,
                authenticated_user,
            }
        } else {
            // Fixed destination
            TcpServerSetupResult::BidirectionalUdp {
                remote_location: destination,
                stream: Box::new(VlessMessageStream::new(Box::new(stream))),
                need_initial_flush: false,
                proxy_selector,
                outbound_dispatcher,
                authenticated_user,
            }
        };
        handle_server_setup_result(setup_result, resolver, peer_addr).await
    } else {
        let setup_result = TcpServerSetupResult::TcpForward {
            remote_location: destination,
            stream: Box::new(stream),
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: None,
            proxy_selector,
            outbound_dispatcher,
            authenticated_user,
        };
        handle_server_setup_result(setup_result, resolver, peer_addr).await
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;
    use crate::h2mux::h2mux_protocol::VERSION_0;

    #[tokio::test]
    async fn test_server_session_creation() {
        // Verifies types compile correctly; full integration tests require a matching client
    }

    #[tokio::test]
    async fn rejects_padding_negotiation_mismatch_before_h2_handshake() {
        let (mut client, server) = duplex(64);
        client
            .write_all(&[VERSION_0, MuxProtocol::H2Mux as u8])
            .await
            .unwrap();

        let error = match H2MuxServerSession::new_with_expected_padding(server, true).await {
            Ok(_) => panic!("padding mismatch unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("mismatch"));
    }
}
