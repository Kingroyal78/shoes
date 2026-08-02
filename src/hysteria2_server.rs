use lru::LruCache;
use std::collections::{HashMap, hash_map::Entry};
use std::future::poll_fn;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::str;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};
use rustc_hash::FxHashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Maximum number of fragmented packets to track per connection.
/// Old entries are automatically evicted when this limit is reached.
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
const MAX_REASSEMBLED_UDP_PACKET_SIZE: usize = u16::MAX as usize;
const MAX_FRAGMENT_CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Keep unauthenticated HTTP/3 connections useful for camouflage without
/// allowing a peer to create an unbounded number of response streams.
const MAX_MASQUERADE_REQUESTS_PER_CONNECTION: usize = 32;
const MAX_MASQUERADE_BODY_BYTES: usize = 64 * 1024;
const MAX_MASQUERADE_CONTENT_TYPE_BYTES: usize = 256;

/// HTTP/3 error code for normal closure.
/// Per official hysteria reference: https://github.com/apernet/hysteria/blob/master/core/server/server.go#L20
const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError

const PROTOCOL_SNIFF_MAX_BYTES: usize = 2048;
const PROTOCOL_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);
const HYSTERIA_MIBPS_TO_BPS: u64 = 125_000;
const HYSTERIA2_OBFS_MAX_QUIC_UDP_PAYLOAD: u16 = 1444;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncReadMessage, AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, SniffedProtocol};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::hysteria2_obfs::Hysteria2Obfs;
use crate::protocol_sniff::{sniff_tcp_protocol, sniff_udp_protocol};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, ResolverCache};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::AuthenticatedUser;
use crate::tcp::tcp_server::{
    AuthenticatedConnectionScope, DirectionalSpeedLimiters, setup_client_tcp_stream,
};
use crate::util::allocate_vec;
use crate::v2board::outbound::dispatcher::OutboundDispatcher;

#[derive(Clone, Debug)]
pub struct Hysteria2ServerUser {
    pub password: String,
    pub authenticated_user: Option<AuthenticatedUser>,
}

impl Hysteria2ServerUser {
    pub fn new(password: String, authenticated_user: Option<AuthenticatedUser>) -> Self {
        Self {
            password,
            authenticated_user,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Hysteria2ServerUsers {
    users_by_password: Arc<HashMap<String, Hysteria2ServerUser>>,
}

impl Hysteria2ServerUsers {
    pub fn new(users: Vec<Hysteria2ServerUser>) -> std::io::Result<Self> {
        if users.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hysteria2 server requires at least one user",
            ));
        }

        let mut users_by_password = HashMap::with_capacity(users.len());
        for user in users {
            if user.password.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "hysteria2 user password must not be empty",
                ));
            }
            if users_by_password
                .insert(user.password.clone(), user)
                .is_some()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "duplicate hysteria2 user password",
                ));
            }
        }

        Ok(Self {
            users_by_password: Arc::new(users_by_password),
        })
    }

    fn get(&self, password: &str) -> Option<&Hysteria2ServerUser> {
        self.users_by_password.get(password)
    }
}

#[derive(Clone, Debug)]
pub struct Hysteria2Masquerade {
    status: http::StatusCode,
    content_type: http::HeaderValue,
    body: Bytes,
}

impl Hysteria2Masquerade {
    pub fn try_new(
        status_code: u16,
        content_type: impl AsRef<str>,
        body: impl Into<Bytes>,
    ) -> std::io::Result<Self> {
        let status = http::StatusCode::from_u16(status_code).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid hysteria2 masquerade status code {status_code}: {e}"),
            )
        })?;
        if status.is_informational() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hysteria2 masquerade status must be a final HTTP status",
            ));
        }
        if matches!(
            status,
            http::StatusCode::NO_CONTENT
                | http::StatusCode::RESET_CONTENT
                | http::StatusCode::NOT_MODIFIED
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hysteria2 masquerade status must permit a response body",
            ));
        }

        let content_type = content_type.as_ref();
        if content_type.is_empty() || content_type.len() > MAX_MASQUERADE_CONTENT_TYPE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "hysteria2 masquerade content type must contain 1..={MAX_MASQUERADE_CONTENT_TYPE_BYTES} bytes"
                ),
            ));
        }
        let content_type = content_type.parse::<http::HeaderValue>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid hysteria2 masquerade content type: {e}"),
            )
        })?;

        let body = body.into();
        if body.len() > MAX_MASQUERADE_BODY_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("hysteria2 masquerade body exceeds {MAX_MASQUERADE_BODY_BYTES} bytes"),
            ));
        }

        Ok(Self {
            status,
            content_type,
            body,
        })
    }
}

#[derive(Clone)]
pub struct Hysteria2StartConfig {
    pub bind_address: SocketAddr,
    pub quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    pub users: Hysteria2ServerUsers,
    pub client_proxy_selector: Arc<ClientProxySelector>,
    pub resolver: Arc<dyn Resolver>,
    pub outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    pub num_endpoints: usize,
    pub udp_enabled: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub ignore_client_bandwidth: bool,
    pub obfs: Option<Hysteria2Obfs>,
    pub masquerade: Option<Hysteria2Masquerade>,
}

#[derive(Clone)]
struct Hysteria2ConnectionContext {
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    users: Hysteria2ServerUsers,
    udp_enabled: bool,
    down_mbps: u64,
    node_speed_limiters: DirectionalSpeedLimiters,
    ignore_client_bandwidth: bool,
    masquerade: Option<Hysteria2Masquerade>,
}

async fn process_connection(
    conn: quinn::Incoming,
    context: Hysteria2ConnectionContext,
) -> std::io::Result<()> {
    let Hysteria2ConnectionContext {
        client_proxy_selector,
        resolver,
        outbound_dispatcher,
        users,
        udp_enabled,
        down_mbps,
        node_speed_limiters,
        ignore_client_bandwidth,
        masquerade,
    } = context;

    let connection = conn.await?;

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = CancellationToken::new();

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    //
    // we keep this function waiting for the tcp and udp tasks both to finish before dropping,
    // instead of passing the connection to one of the two loops, incase one finishes first.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("H3 connection setup failed: {e}")))?;

    // Without camouflage, preserve the reference three-second authentication
    // timeout and close behavior. With camouflage, the authentication window
    // still expires after three seconds, while ordinary HTTP/3 requests may
    // continue until the QUIC idle timeout or the per-connection request cap.
    let authenticated_user = if let Some(masquerade) = masquerade.as_ref() {
        auth_or_masquerade_connection(
            &mut h3_conn,
            &users,
            udp_enabled,
            down_mbps,
            ignore_client_bandwidth,
            masquerade,
        )
        .await?
    } else {
        match timeout(
            AUTH_TIMEOUT,
            auth_connection(
                &mut h3_conn,
                &users,
                udp_enabled,
                down_mbps,
                ignore_client_bandwidth,
            ),
        )
        .await
        {
            Ok(Ok(user)) => user,
            Ok(Err(e)) => {
                connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
                return Err(e);
            }
            Err(_elapsed) => {
                error!("Authentication timeout");
                connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "authentication timeout",
                ));
            }
        }
    };

    let connection_scope = Arc::new(
        AuthenticatedConnectionScope::start_with_directional_speed_limiters(
            &authenticated_user,
            Some(connection.remote_address()),
            node_speed_limiters,
        )?,
    );

    let udp_connection = connection.clone();
    let udp_client_proxy_selector = client_proxy_selector.clone();
    let udp_resolver = resolver.clone();
    let udp_cancel_token = cancel_token.clone();
    let udp_connection_scope = connection_scope.clone();

    let udp_dispatcher = outbound_dispatcher.clone();

    let uni_connection = connection.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let udp_loop = async {
        if udp_enabled {
            run_udp_local_to_remote_loop(
                udp_connection,
                udp_client_proxy_selector,
                udp_dispatcher,
                udp_resolver,
                udp_cancel_token,
                udp_connection_scope,
            )
            .await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        // Depending on the client, unidirectional streams could still be sent, accept and drop.
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(
        tcp_connection,
        client_proxy_selector,
        resolver,
        connection_scope,
    );

    let result = tokio::try_join!(udp_loop, uni_loop, tcp_loop);

    cancel_token.cancel();

    // Per sing-box reference (service.go:277-293), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

struct Hysteria2Auth {
    authenticated_user: Option<AuthenticatedUser>,
    client_rx_bps: u64,
}

fn validate_auth_request<T>(
    req: &http::Request<T>,
    users: &Hysteria2ServerUsers,
) -> std::io::Result<Hysteria2Auth> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;
    let Some(user) = users.get(auth_str) else {
        return Err(std::io::Error::other("incorrect auth password"));
    };

    let client_rx_bps = headers
        .get("hysteria-cc-rx")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(Hysteria2Auth {
        authenticated_user: user.authenticated_user.clone(),
        client_rx_bps,
    })
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    users: &Hysteria2ServerUsers,
    udp_enabled: bool,
    down_mbps: u64,
    ignore_client_bandwidth: bool,
) -> std::io::Result<Option<AuthenticatedUser>> {
    let receive_bps = down_mbps.saturating_mul(HYSTERIA_MIBPS_TO_BPS);
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(&req, users) {
                    Ok(auth) => {
                        if receive_bps > 0 && ignore_client_bandwidth && auth.client_rx_bps == 0 {
                            error!(
                                "Rejecting Hysteria2 auth because client did not advertise RX bandwidth while server bandwidth detection is disabled"
                            );
                            let resp = http::Response::builder()
                                .status(http::status::StatusCode::NOT_FOUND)
                                .body(())
                                .unwrap();
                            stream.send_response(resp).await.map_err(|e| {
                                std::io::Error::other(format!(
                                    "failed to send bandwidth reject response: {e}"
                                ))
                            })?;
                            stream.finish().await.map_err(|e| {
                                std::io::Error::other(format!(
                                    "failed to finish bandwidth reject stream: {e}"
                                ))
                            })?;
                            continue;
                        }

                        let cc_rx = if receive_bps == 0 && ignore_client_bandwidth {
                            "auto".to_string()
                        } else {
                            receive_bps.to_string()
                        };
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
                            .header("Hysteria-CC-RX", cc_rx)
                            .header("Hysteria-Padding", generate_ascii_string())
                            .body(())
                            .unwrap();

                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send auth response: {e}"))
                        })?;

                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish auth stream: {e}"))
                        })?;

                        return Ok(auth.authenticated_user);
                    }
                    Err(e) => {
                        error!("Received non-hysteria2 auth http3 request: {e}");
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send reject response: {e}"))
                        })?;
                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish reject stream: {e}"))
                        })?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

fn hysteria2_auth_window_open(elapsed: Duration) -> bool {
    elapsed < AUTH_TIMEOUT
}

fn hysteria2_masquerade_sends_body(method: &http::Method) -> bool {
    method != http::Method::HEAD
}

async fn auth_or_masquerade_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    users: &Hysteria2ServerUsers,
    udp_enabled: bool,
    down_mbps: u64,
    ignore_client_bandwidth: bool,
    masquerade: &Hysteria2Masquerade,
) -> std::io::Result<Option<AuthenticatedUser>> {
    let receive_bps = down_mbps.saturating_mul(HYSTERIA_MIBPS_TO_BPS);
    let auth_started = Instant::now();

    for _ in 0..MAX_MASQUERADE_REQUESTS_PER_CONNECTION {
        let Some(resolver) = h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "no streams",
            ));
        };
        let (req, mut stream) = resolver
            .resolve_request()
            .await
            .map_err(|err| std::io::Error::other(format!("Failed to resolve request: {err}")))?;

        let send_body = hysteria2_masquerade_sends_body(req.method());
        if hysteria2_auth_window_open(auth_started.elapsed()) {
            match validate_auth_request(&req, users) {
                Ok(auth)
                    if !(receive_bps > 0 && ignore_client_bandwidth && auth.client_rx_bps == 0) =>
                {
                    let cc_rx = if receive_bps == 0 && ignore_client_bandwidth {
                        "auto".to_string()
                    } else {
                        receive_bps.to_string()
                    };
                    let response = http::Response::builder()
                        .status(http::StatusCode::from_u16(233).unwrap())
                        .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
                        .header("Hysteria-CC-RX", cc_rx)
                        .header("Hysteria-Padding", generate_ascii_string())
                        .body(())
                        .unwrap();
                    stream.send_response(response).await.map_err(|e| {
                        std::io::Error::other(format!("failed to send auth response: {e}"))
                    })?;
                    stream.finish().await.map_err(|e| {
                        std::io::Error::other(format!("failed to finish auth stream: {e}"))
                    })?;
                    return Ok(auth.authenticated_user);
                }
                Ok(_) => {
                    debug!(
                        "Hysteria2 auth request did not satisfy server bandwidth requirements; serving masquerade"
                    );
                }
                Err(e) => {
                    debug!("Serving Hysteria2 masquerade for unauthenticated H3 request: {e}");
                }
            }
        } else {
            debug!("Serving Hysteria2 masquerade after authentication window expired");
        }

        send_hysteria2_masquerade_response(&mut stream, masquerade, send_body).await?;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "hysteria2 masquerade request limit exceeded ({MAX_MASQUERADE_REQUESTS_PER_CONNECTION})"
        ),
    ))
}

async fn send_hysteria2_masquerade_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    masquerade: &Hysteria2Masquerade,
    send_body: bool,
) -> std::io::Result<()> {
    // Do not spend connection-level flow-control budget reading an arbitrary
    // request body from an unauthenticated peer.
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);

    let response = http::Response::builder()
        .status(masquerade.status)
        .header(http::header::CONTENT_TYPE, masquerade.content_type.clone())
        .header(http::header::CONTENT_LENGTH, masquerade.body.len())
        .body(())
        .unwrap();
    stream.send_response(response).await.map_err(|e| {
        std::io::Error::other(format!("failed to send hysteria2 masquerade response: {e}"))
    })?;
    if send_body && !masquerade.body.is_empty() {
        stream
            .send_data(masquerade.body.clone())
            .await
            .map_err(|e| {
                std::io::Error::other(format!("failed to send hysteria2 masquerade body: {e}"))
            })?;
    }
    stream.finish().await.map_err(|e| {
        std::io::Error::other(format!("failed to finish hysteria2 masquerade stream: {e}"))
    })
}

struct UdpSession {
    packet_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    last_activity: std::time::Instant,
    cancel_token: CancellationToken,
}

struct FragmentedPacket {
    fragment_count: u8,
    fragment_received: u8,
    packet_len: usize,
    received: Vec<Option<Bytes>>,
    remote_location: Option<NetLocation>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFragmentKey {
    session_id: u32,
    packet_id: u16,
}

type UdpFragmentMap = LruCache<UdpFragmentKey, FragmentedPacket>;

struct PreparedHysteria2UdpPacket {
    remote_location: NetLocation,
    payload: Bytes,
}

impl UdpSession {
    #[allow(clippy::too_many_arguments)]
    fn start(
        client_stream: Box<dyn AsyncMessageStream>,
        session_id: u32,
        connection: quinn::Connection,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
        connection_scope: Arc<AuthenticatedConnectionScope>,
    ) -> Self {
        let session_cancel_token = parent_cancel_token.child_token();
        let (tx, rx) = mpsc::channel(64);

        let fallback_address_bytes: Bytes = initial_location.to_string().into_bytes().into();

        let session = UdpSession {
            packet_tx: tx,
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: std::time::Instant::now(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_session_loop(
                client_stream,
                rx,
                session_id,
                connection,
                override_local_write_location,
                fallback_address_bytes,
                session_cancel_token,
                connection_scope,
            )
            .await
            {
                error!("UDP session loop ended with error: {e}");
            }
        });

        session
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session_loop(
    mut client_stream: Box<dyn AsyncMessageStream>,
    mut rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    session_id: u32,
    connection: quinn::Connection,
    override_local_write_address: Option<NetLocation>,
    fallback_address_bytes: Bytes,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| std::io::Error::other("datagram not supported by remote endpoint"))?;

    let original_address_bytes: Option<(Bytes, Bytes)> = match override_local_write_address {
        Some(a) => {
            let address_bytes: Bytes = a.to_string().into_bytes().into();
            let address_len = address_bytes.len();
            let address_len_bytes = encode_varint(address_len as u64)?;
            Some((address_bytes, address_len_bytes.into()))
        }
        None => None,
    };

    let mut next_packet_id: u16 = 0;
    let mut read_buf = allocate_vec(65535);
    let mut loop_count: u8 = 0;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                return Ok(());
            }
            packet = rx.recv() => {
                match packet {
                    Some((payload, _socket_addr)) => {
                        poll_fn(|cx| Pin::new(&mut client_stream).poll_write_message(cx, &payload))
                            .await
                            .map_err(|e| std::io::Error::other(format!("UDP session write failed: {e}")))?;
                        poll_fn(|cx| Pin::new(&mut client_stream).poll_flush_message(cx))
                            .await
                            .map_err(|e| std::io::Error::other(format!("UDP session flush failed: {e}")))?;
                    }
                    None => return Ok(()),
                }
            }
            result = poll_fn(|cx| {
                let mut rb = ReadBuf::new(&mut read_buf);
                match Pin::new(&mut client_stream).poll_read_message(cx, &mut rb) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            }) => {
                let payload_len = result.map_err(|e| {
                    std::io::Error::other(format!("UDP session read failed: {e}"))
                })?;
                if payload_len == 0 {
                    // EOF on the upstream stream: exit the session loop instead
                    // of busy-spinning on streams that return Ready(Ok(0)) forever.
                    return Ok(());
                }

                loop_count = loop_count.wrapping_add(1);
                if loop_count == 0 {
                    tokio::task::yield_now().await;
                }

                let packet_id = next_packet_id;
                next_packet_id = next_packet_id.wrapping_add(1);

                let (address_bytes, address_len_bytes) = match original_address_bytes {
                    Some((ref a, ref b)) => (a.clone(), b.clone()),
                    None => {
                        let addr_len = fallback_address_bytes.len();
                        let addr_len_bytes = encode_varint(addr_len as u64)?.into();
                        (fallback_address_bytes.clone(), addr_len_bytes)
                    }
                };

                let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();

                if max_datagram_size <= header_overhead {
                    return Err(std::io::Error::other(format!(
                        "max datagram size ({max_datagram_size}) is smaller than header overhead ({header_overhead})"
                    )));
                }

                connection_scope.throttle_download_bytes(payload_len).await;
                if header_overhead + payload_len <= max_datagram_size {
                    let mut datagram = BytesMut::with_capacity(header_overhead + payload_len);
                    datagram.extend_from_slice(&session_id.to_be_bytes());
                    datagram.extend_from_slice(&packet_id.to_be_bytes());
                    datagram.extend_from_slice(&[0, 1]);
                    datagram.extend_from_slice(&address_len_bytes);
                    datagram.extend_from_slice(&address_bytes);
                    datagram.extend_from_slice(&read_buf[..payload_len]);

                    connection
                        .send_datagram(datagram.freeze())
                        .map_err(|e| std::io::Error::other(format!("Failed to send datagram: {e}")))?;
                    connection_scope.record_download_bytes(payload_len);
                } else {
                    let available_payload = max_datagram_size - header_overhead;
                    let fragment_count = payload_len.div_ceil(available_payload);
                    let fragment_count = u8::try_from(fragment_count).map_err(|_| {
                        std::io::Error::other(format!(
                            "UDP payload length {payload_len} requires too many fragments"
                        ))
                    })?;
                    for fragment_id in 0..fragment_count {
                        let start = (fragment_id as usize) * available_payload;
                        let end = std::cmp::min(start + available_payload, payload_len);
                        let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
                        datagram.extend_from_slice(&session_id.to_be_bytes());
                        datagram.extend_from_slice(&packet_id.to_be_bytes());
                        datagram.extend_from_slice(&[fragment_id, fragment_count]);
                        datagram.extend_from_slice(&address_len_bytes);
                        datagram.extend_from_slice(&address_bytes);
                        datagram.extend_from_slice(&read_buf[start..end]);

                        connection.send_datagram(datagram.freeze()).map_err(|e| {
                            std::io::Error::other(format!(
                                "Failed to send datagram fragment {fragment_id}: {e}"
                            ))
                        })?;
                    }
                    connection_scope.record_download_bytes(payload_len);
                }
            }
        }
    }
}

fn new_udp_fragment_map() -> UdpFragmentMap {
    LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap())
}

fn prepare_hysteria2_udp_packet(
    fragments: &mut UdpFragmentMap,
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    remote_location: NetLocation,
    payload_fragment: Bytes,
) -> std::io::Result<Option<PreparedHysteria2UdpPacket>> {
    if fragment_count == 0 {
        return Err(std::io::Error::other(format!(
            "Ignoring packet with empty fragment total for session {session_id}"
        )));
    }
    if fragment_id >= fragment_count {
        return Err(std::io::Error::other(format!(
            "Invalid fragment id {fragment_id} >= total {fragment_count} for session {session_id}"
        )));
    }
    if fragment_count == 1 {
        return Ok(Some(PreparedHysteria2UdpPacket {
            remote_location,
            payload: payload_fragment,
        }));
    }

    reassemble_hysteria2_udp_fragment(
        fragments,
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        remote_location,
        payload_fragment,
    )
}

fn reassemble_hysteria2_udp_fragment(
    fragments: &mut UdpFragmentMap,
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    remote_location: NetLocation,
    payload_fragment: Bytes,
) -> std::io::Result<Option<PreparedHysteria2UdpPacket>> {
    let key = UdpFragmentKey {
        session_id,
        packet_id,
    };
    let needs_new_entry = fragments
        .get(&key)
        .is_none_or(|packet| packet.fragment_count != fragment_count);

    if needs_new_entry {
        fragments.put(
            key,
            FragmentedPacket {
                fragment_count,
                fragment_received: 0,
                packet_len: 0,
                received: vec![None; fragment_count as usize],
                remote_location: None,
            },
        );
    }

    let fragment_error = {
        let packet = fragments
            .get(&key)
            .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;
        if packet.received[fragment_id as usize].is_some() {
            return Ok(None);
        }
        if packet
            .packet_len
            .checked_add(payload_fragment.len())
            .is_none_or(|len| len > MAX_REASSEMBLED_UDP_PACKET_SIZE)
        {
            Some(std::io::Error::other(format!(
                "Reassembled UDP packet exceeds {MAX_REASSEMBLED_UDP_PACKET_SIZE} bytes for session {session_id} packet {packet_id}"
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
            "Hysteria2 UDP fragment cache exceeds {MAX_FRAGMENT_CACHE_BYTES} bytes"
        )));
    }

    let is_complete = {
        let packet = fragments
            .get_mut(&key)
            .ok_or_else(|| std::io::Error::other("Fragment cache error"))?;

        if fragment_id == 0 {
            packet.remote_location = Some(remote_location);
        }
        packet.fragment_received += 1;
        packet.packet_len += payload_fragment.len();
        packet.received[fragment_id as usize] = Some(payload_fragment);
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
            "Missing first fragment address for session {session_id} packet {packet_id}"
        ))
    })?;

    let mut complete_payload = BytesMut::with_capacity(packet_len);
    for fragment in received {
        let fragment = fragment.ok_or_else(|| {
            std::io::Error::other(format!(
                "Missing fragment for session {session_id} packet {packet_id}"
            ))
        })?;
        complete_payload.extend_from_slice(&fragment);
    }

    Ok(Some(PreparedHysteria2UdpPacket {
        remote_location,
        payload: complete_payload.freeze(),
    }))
}

fn remove_hysteria2_fragments_for_session(fragments: &mut UdpFragmentMap, session_id: u32) {
    let keys: Vec<UdpFragmentKey> = fragments
        .iter()
        .filter_map(|(key, _)| (key.session_id == session_id).then_some(*key))
        .collect();
    for key in keys {
        fragments.pop(&key);
    }
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
    connection_scope: Arc<AuthenticatedConnectionScope>,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
    let mut fragments = new_udp_fragment_map();

    // Match reference implementation defaults for UDP session management
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);
    // Skip the first immediate tick (first cleanup at CLEANUP_INTERVAL).
    cleanup_interval.tick().await;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                let mut expired_session_ids = Vec::new();
                sessions.retain(|session_id, session| {
                    if session.last_activity.elapsed() > IDLE_TIMEOUT {
                        // Cancel the session's background task before removing
                        session.cancel_token.cancel();
                        debug!("Removing inactive UDP session {session_id}");
                        expired_session_ids.push(*session_id);
                        false
                    } else {
                        true
                    }
                });
                for session_id in expired_session_ids {
                    remove_hysteria2_fragments_for_session(&mut fragments, session_id);
                }
            }
            data = connection.read_datagram() => {
        let data = data
            .map_err(|err| std::io::Error::other(format!("failed to read datagram: {err}")))?;

        // Per official hysteria reference (server.go:332-353), parse errors are ignored
        // and we continue waiting for the next message. Only connection errors are fatal.
        if data.len() < 9 {
            debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, next_index) = {
            let first_byte = data[8];
            let length_indicator = first_byte >> 6;
            let mut value: u64 = (first_byte & 0b00111111) as u64;
            let num_bytes = match length_indicator {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => {
                    // impossible since we only have 2 bits
                    unreachable!();
                }
            };
            let mut next_index = 9;
            if num_bytes > 1 {
                if data.len() < 9 + (num_bytes - 1) {
                    debug!("Ignoring datagram with truncated address length varint");
                    continue;
                }
                let remaining = &data[9..9 + (num_bytes - 1)];
                for byte in remaining {
                    value <<= 8;
                    value |= *byte as u64;
                }
                next_index += num_bytes - 1;
            }
            (value as usize, next_index)
        };

        if address_len == 0 {
            debug!("Ignoring packet with empty address");
            continue;
        }

        if address_len > 2048 {
            debug!("Ignoring packet with address length {address_len}");
            continue;
        }

        if data.len() < next_index + address_len {
            debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        let PreparedHysteria2UdpPacket {
            remote_location,
            payload: complete_payload,
        } = match prepare_hysteria2_udp_packet(
            &mut fragments,
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            remote_location,
            payload_fragment,
        ) {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(e) => {
                debug!("{e}");
                continue;
            }
        };

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                if let Some(dispatcher) = &outbound_dispatcher {
                    let sniffed_protocol = if dispatcher.requires_protocol_sniff() {
                        sniff_udp_protocol(&complete_payload)
                    } else {
                        None
                    };

                    let resolved_address = match resolver_cache
                        .resolve_location(&remote_location)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve initial remote location {remote_location}: {e}"
                            );
                            continue;
                        }
                    };

                    let (override_remote_write_address, override_local_write_location) =
                        if resolved_address.to_string() != remote_location.to_string() {
                            (Some(resolved_address), Some(remote_location.clone()))
                        } else {
                            (None, None)
                        };

                    let resolved =
                        ResolvedLocation::with_resolved(remote_location.clone(), resolved_address);
                    let client_stream = match dispatcher
                        .connect_udp_bidirectional(&resolved, sniffed_protocol, &resolver)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Dispatcher failed to open UDP session to {remote_location}: {e}"
                            );
                            continue;
                        }
                    };

                    let session = UdpSession::start(
                        client_stream,
                        session_id,
                        connection.clone(),
                        remote_location.clone(),
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        &cancel_token,
                        connection_scope.clone(),
                    );
                    entry.insert(session)
                } else {
                    let sniffed_protocol = if client_proxy_selector.requires_protocol_sniff() {
                        sniff_udp_protocol(&complete_payload)
                    } else {
                        None
                    };
                    let action = client_proxy_selector
                        .judge_with_protocol(
                            remote_location.clone().into(),
                            &resolver,
                            sniffed_protocol,
                        )
                        .await;

                    let (chain_group, updated_location) = match action {
                        Ok(ConnectDecision::Allow {
                            chain_group,
                            remote_location,
                        }) => (chain_group, remote_location),
                        Ok(ConnectDecision::Block) => {
                            warn!("Blocked UDP forward to {remote_location}");
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to judge UDP forward to {remote_location}: {e}");
                            continue;
                        }
                    };

                    let resolved_address = match resolver_cache
                        .resolve_location(updated_location.location())
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve initial remote location {remote_location}: {e}"
                            );
                            continue;
                        }
                    };

                    let (override_remote_write_address, override_local_write_location) =
                        if resolved_address.to_string() != remote_location.to_string() {
                            (Some(resolved_address), Some(remote_location.clone()))
                        } else {
                            (None, None)
                        };

                    let client_stream = match chain_group
                        .connect_udp_bidirectional(&resolver, updated_location)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Chain group failed to open UDP session to {remote_location}: {e}"
                            );
                            continue;
                        }
                    };

                    let session = UdpSession::start(
                        client_stream,
                        session_id,
                        connection.clone(),
                        remote_location.clone(),
                        resolved_address,
                        override_local_write_location,
                        override_remote_write_address,
                        &cancel_token,
                        connection_scope.clone(),
                    );
                    entry.insert(session)
                }
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        let socket_addr = session.last_socket_addr;
        if remote_location != session.last_location {
            // The session's upstream stream is target-fixed at dial time; a
            // mid-session destination change from the client cannot be
            // honored (the client should open a new session for a new target).
            warn!(
                "Location changed during ongoing UDP session: {} (was {})",
                remote_location, session.last_location
            );
            session.last_location = remote_location.clone();
        }

        let payload_len = complete_payload.len();
        connection_scope.throttle_upload_bytes(payload_len).await;
        if let Err(e) = session
            .packet_tx
            .send((complete_payload, socket_addr))
            .await
        {
            error!("Failed to forward UDP payload for session {session_id}: {e}");
            sessions.remove(&session_id);
        } else {
            connection_scope.record_upload_bytes(payload_len);
            session.last_activity = std::time::Instant::now();
        }
            }
        }
    }
}

async fn run_tcp_loop(
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

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        let connection_scope = connection_scope.clone();
        tokio::spawn(async move {
            if let Err(e) = process_tcp_stream(
                client_proxy_selector,
                resolver,
                connection_scope,
                send_stream,
                recv_stream,
            )
            .await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

/// TCP request frame type constant from Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

async fn handle_tcp_header(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    // Read the TCP request frame type as a QUIC varint per protocol spec.
    // The value 0x401 can be encoded in multiple valid ways (e.g., [0x44, 0x01] as 2-byte form).
    let tcp_request_id = read_varint(recv, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    // max lengths from https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/internal/protocol/proxy.go#L19
    let address_len = read_varint(recv, &mut stream_reader).await?;
    if address_len > 2048 {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader.read_slice(recv, address_len as usize).await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(recv, &mut stream_reader).await?;
    if padding_len > 4096 {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader.read_slice(recv, padding_len as usize).await?;

    let response_bytes = {
        // [uint8] Status (0x00 = OK, 0x01 = Error)
        // [varint] Message length
        // [bytes] Message string
        // [varint] Padding length
        // [bytes] Random padding

        let mut rng = rand::rng();

        // only use the lower 6 bits so that the varint always fits in a single u8
        let padding_len = rng.random_range(0..=63);

        // first 3 bytes of status = 0x0, message length = 0, padding length
        let mut response_bytes = allocate_vec(3 + (padding_len as usize));
        response_bytes[0] = 0;
        response_bytes[1] = 0;
        response_bytes[2] = padding_len;
        rng.fill_bytes(&mut response_bytes[3..]);

        response_bytes
    };

    send.write_all(&response_bytes)
        .await
        .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;

    Ok((remote_location, stream_reader))
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

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    connection_scope: Arc<AuthenticatedConnectionScope>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let (remote_location, stream_reader) = match handle_tcp_header(&mut send, &mut recv).await {
        Ok(res) => res,
        Err(e) => {
            let _ = send.shutdown().await;
            return Err(e);
        }
    };

    let unparsed_before_wrap_len = stream_reader.unparsed_data().len();
    let mut initial_remote_data = stream_reader.unparsed_data_owned().map(Vec::from);
    let mut server_stream: Box<dyn AsyncStream> =
        connection_scope.wrap_stream(Box::new(QuicStream::from(send, recv)));

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

    if unparsed_before_wrap_len > 0 {
        connection_scope
            .throttle_upload_bytes(unparsed_before_wrap_len)
            .await;
    }
    let client_requires_flush = match initial_remote_data {
        Some(data) if !data.is_empty() => {
            client_stream
                .write_all(&data)
                .await
                .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
            if unparsed_before_wrap_len > 0 {
                connection_scope.record_upload_bytes(unparsed_before_wrap_len);
            }
            true
        }
        _ => false,
    };
    drop(stream_reader);

    // Use 32KB buffers to match hysteria2/sing-box reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

#[inline]
fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    if value <= 0b00111111 {
        Ok(Box::new([value as u8]))
    } else if value < (1 << 14) {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0b01000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 30) {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0b10000000;
        Ok(Box::new(bytes))
    } else if value < (1 << 62) {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0b11000000;
        Ok(Box::new(bytes))
    } else {
        Err(std::io::Error::other("value too large to encode as varint"))
    }
}

async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    let first_byte = stream_reader.read_u8(recv).await?;

    let length = first_byte >> 6;
    let mut value: u64 = (first_byte & 0b00111111) as u64;

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            // impossible since we only have 2 bits
            panic!("invalid num bytes value");
        }
    };

    if num_bytes > 1 {
        let remaining_bytes = stream_reader.read_slice(recv, num_bytes - 1).await?;
        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= *byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

pub async fn start_hysteria2_server(
    config: Hysteria2StartConfig,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let Hysteria2StartConfig {
        bind_address,
        quic_server_config,
        users,
        client_proxy_selector,
        resolver,
        outbound_dispatcher,
        num_endpoints,
        udp_enabled,
        up_mbps,
        down_mbps,
        ignore_client_bandwidth,
        obfs,
        masquerade,
    } = config;

    let mut endpoints = Vec::with_capacity(num_endpoints);
    let node_speed_limiters = hysteria2_node_speed_limiters(up_mbps, down_mbps);
    for _ in 0..num_endpoints {
        let obfs_enabled = obfs.is_some();
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());
        let mut mtu_discovery_config = quinn::MtuDiscoveryConfig::default();
        if obfs_enabled {
            mtu_discovery_config.upper_bound(HYSTERIA2_OBFS_MAX_QUIC_UDP_PAYLOAD);
        }

        let idle_timeout = Duration::from_secs(30)
            .try_into()
            .map_err(|e| std::io::Error::other(format!("invalid hysteria2 idle timeout: {e}")))?;
        let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
            std::io::Error::other("failed to get mutable hysteria2 QUIC transport config")
        })?;

        // Values estimated from the reference Hysteria2 server config.
        transport
            .max_concurrent_bidi_streams(4096_u32.into())
            // Required for HTTP/3 QPACK updates.
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(idle_timeout))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(Some(mtu_discovery_config))
            .enable_segmentation_offload(!obfs_enabled)
            .initial_rtt(Duration::from_millis(100));

        // Use 7.5MB socket buffers for high-throughput QUIC (8.625MB on BSD for 15% kernel overhead).
        let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            true,
            Some(8_625_000),
        )?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        if obfs_enabled {
            endpoint_config
                .max_udp_payload_size(HYSTERIA2_OBFS_MAX_QUIC_UDP_PAYLOAD)
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid hysteria2 obfs endpoint payload size: {e}"
                    ))
                })?;
        }

        let endpoint = if let Some(obfs) = &obfs {
            let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
            let socket = runtime.wrap_udp_socket(socket2_socket.into())?;
            let socket = obfs.wrap_socket(socket);
            quinn::Endpoint::new_with_abstract_socket(
                endpoint_config,
                Some(server_config),
                socket,
                runtime,
            )
        } else {
            quinn::Endpoint::new(
                endpoint_config,
                Some(server_config),
                socket2_socket.into(),
                Arc::new(quinn::TokioRuntime),
            )
        }
        .map_err(|e| std::io::Error::other(format!("failed to create hysteria2 endpoint: {e}")))?;
        endpoints.push(endpoint);
    }

    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let connection_context = Hysteria2ConnectionContext {
            client_proxy_selector: client_proxy_selector.clone(),
            resolver: resolver.clone(),
            outbound_dispatcher: outbound_dispatcher.clone(),
            users: users.clone(),
            udp_enabled,
            down_mbps,
            node_speed_limiters: node_speed_limiters.clone(),
            ignore_client_bandwidth,
            masquerade: masquerade.clone(),
        };
        let join_handle = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let context = connection_context.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(conn, context).await {
                        error!("Connection ended with error: {e}");
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

fn hysteria2_node_speed_limiters(up_mbps: u64, down_mbps: u64) -> DirectionalSpeedLimiters {
    DirectionalSpeedLimiters::from_mbps(Some(down_mbps), Some(up_mbps))
}

#[cfg(test)]
#[path = "hysteria2_masquerade_network_tests.rs"]
mod masquerade_network_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::net::Ipv4Addr;

    fn test_users() -> Hysteria2ServerUsers {
        Hysteria2ServerUsers::new(vec![Hysteria2ServerUser::new(
            "user-password".to_string(),
            None,
        )])
        .unwrap()
    }

    #[test]
    fn builds_bounded_hysteria2_static_masquerade() {
        let masquerade =
            Hysteria2Masquerade::try_new(200, "text/plain", Bytes::from_static(b"not a proxy"))
                .unwrap();

        assert_eq!(masquerade.status, http::StatusCode::OK);
        assert_eq!(masquerade.content_type, "text/plain");
        assert_eq!(masquerade.body, Bytes::from_static(b"not a proxy"));
        assert!(!hysteria2_masquerade_sends_body(&http::Method::HEAD));
        assert!(hysteria2_masquerade_sends_body(&http::Method::GET));
    }

    #[test]
    fn rejects_hysteria2_masquerade_statuses_that_forbid_a_body() {
        for status in [204, 205, 304] {
            let error = Hysteria2Masquerade::try_new(status, "text/plain", "body").unwrap_err();
            assert!(error.to_string().contains("must permit a response body"));
        }
    }

    #[test]
    fn rejects_oversized_hysteria2_static_masquerade() {
        let error = Hysteria2Masquerade::try_new(
            404,
            "text/plain",
            Bytes::from(vec![0; MAX_MASQUERADE_BODY_BYTES + 1]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("body exceeds"));
    }

    #[test]
    fn masquerade_keeps_h3_alive_but_does_not_extend_authentication_window() {
        assert!(hysteria2_auth_window_open(
            AUTH_TIMEOUT - Duration::from_nanos(1)
        ));
        assert!(!hysteria2_auth_window_open(AUTH_TIMEOUT));
        assert!(!hysteria2_auth_window_open(
            AUTH_TIMEOUT + Duration::from_secs(60)
        ));
    }

    #[test]
    fn validate_auth_request_reads_client_rx_bandwidth() {
        let users = test_users();
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", "user-password")
            .header("hysteria-cc-rx", "456000")
            .body(())
            .unwrap();

        let auth = validate_auth_request(&req, &users).unwrap();

        assert!(auth.authenticated_user.is_none());
        assert_eq!(auth.client_rx_bps, 456_000);
    }

    #[test]
    fn validate_auth_request_defaults_missing_client_rx_bandwidth_to_zero() {
        let users = test_users();
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", "user-password")
            .body(())
            .unwrap();

        let auth = validate_auth_request(&req, &users).unwrap();

        assert_eq!(auth.client_rx_bps, 0);
    }

    #[test]
    fn node_speed_limiters_share_v2board_hysteria2_bandwidth_across_connections() {
        let limiters = hysteria2_node_speed_limiters(10, 20);
        let cloned = limiters.clone();

        assert_eq!(limiters.upload_rate_bytes_per_sec(), Some(2_500_000));
        assert_eq!(limiters.download_rate_bytes_per_sec(), Some(1_250_000));
        assert!(limiters.shares_buckets_with(&cloned));
    }

    fn fragment_cache() -> UdpFragmentMap {
        new_udp_fragment_map()
    }

    fn test_location(last_octet: u8) -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, last_octet)), 443)
    }

    #[test]
    fn reassembles_hysteria2_fragments_independently_per_session_id() {
        let mut fragments = fragment_cache();
        let first_location = test_location(1);
        let second_location = test_location(2);

        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                10,
                7,
                0,
                2,
                first_location.clone(),
                Bytes::from_static(b"he"),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                11,
                7,
                0,
                2,
                second_location.clone(),
                Bytes::from_static(b"wo"),
            )
            .unwrap()
            .is_none()
        );

        let first = prepare_hysteria2_udp_packet(
            &mut fragments,
            10,
            7,
            1,
            2,
            first_location.clone(),
            Bytes::from_static(b"llo"),
        )
        .unwrap()
        .unwrap();
        let second = prepare_hysteria2_udp_packet(
            &mut fragments,
            11,
            7,
            1,
            2,
            second_location.clone(),
            Bytes::from_static(b"rld"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(first.remote_location, first_location);
        assert_eq!(first.payload.as_ref(), b"hello");
        assert_eq!(second.remote_location, second_location);
        assert_eq!(second.payload.as_ref(), b"world");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn reassembles_hysteria2_fragments_when_first_fragment_arrives_last() {
        let mut fragments = fragment_cache();
        let first_fragment_location = test_location(3);
        let later_fragment_location = test_location(4);

        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                20,
                9,
                1,
                2,
                later_fragment_location,
                Bytes::from_static(b"tail"),
            )
            .unwrap()
            .is_none()
        );
        let packet = prepare_hysteria2_udp_packet(
            &mut fragments,
            20,
            9,
            0,
            2,
            first_fragment_location.clone(),
            Bytes::from_static(b"head-"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(packet.remote_location, first_fragment_location);
        assert_eq!(packet.payload.as_ref(), b"head-tail");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn bounds_hysteria2_fragmented_udp_packet_and_connection_cache_bytes() {
        let mut fragments = fragment_cache();
        let location = test_location(4);
        let half = Bytes::from(vec![0u8; 32 * 1024]);
        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                40,
                1,
                0,
                2,
                location.clone(),
                half.clone(),
            )
            .unwrap()
            .is_none()
        );
        let error =
            match prepare_hysteria2_udp_packet(&mut fragments, 40, 1, 1, 2, location.clone(), half)
            {
                Err(error) => error,
                Ok(_) => panic!("oversized Hysteria2 UDP packet must be rejected"),
            };
        assert!(error.to_string().contains("exceeds 65535 bytes"));

        let mut fragments = fragment_cache();
        let maximum_fragment = Bytes::from(vec![0u8; MAX_REASSEMBLED_UDP_PACKET_SIZE]);
        for packet_id in 0..64 {
            assert!(
                prepare_hysteria2_udp_packet(
                    &mut fragments,
                    41,
                    packet_id,
                    0,
                    2,
                    location.clone(),
                    maximum_fragment.clone(),
                )
                .unwrap()
                .is_none()
            );
        }
        let error = match prepare_hysteria2_udp_packet(
            &mut fragments,
            41,
            64,
            0,
            2,
            location,
            maximum_fragment,
        ) {
            Err(error) => error,
            Ok(_) => panic!("over-budget Hysteria2 fragment cache must be rejected"),
        };
        assert!(error.to_string().contains("fragment cache exceeds"));
    }

    #[test]
    fn keeps_hysteria2_partial_packet_after_duplicate_fragment() {
        let mut fragments = fragment_cache();
        let location = test_location(5);

        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                30,
                5,
                0,
                2,
                location.clone(),
                Bytes::from_static(b"head-"),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                30,
                5,
                0,
                2,
                location.clone(),
                Bytes::from_static(b"duplicate-"),
            )
            .unwrap()
            .is_none()
        );
        let packet = prepare_hysteria2_udp_packet(
            &mut fragments,
            30,
            5,
            1,
            2,
            location.clone(),
            Bytes::from_static(b"tail"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(packet.remote_location, location);
        assert_eq!(packet.payload.as_ref(), b"head-tail");
        assert_eq!(fragments.len(), 0);
    }

    #[test]
    fn resets_hysteria2_partial_packet_when_fragment_count_changes() {
        let mut fragments = fragment_cache();
        let location = test_location(6);

        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                40,
                8,
                0,
                3,
                location.clone(),
                Bytes::from_static(b"stale-"),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            prepare_hysteria2_udp_packet(
                &mut fragments,
                40,
                8,
                0,
                2,
                location.clone(),
                Bytes::from_static(b"fresh-"),
            )
            .unwrap()
            .is_none()
        );
        let packet = prepare_hysteria2_udp_packet(
            &mut fragments,
            40,
            8,
            1,
            2,
            location.clone(),
            Bytes::from_static(b"packet"),
        )
        .unwrap()
        .unwrap();

        assert_eq!(packet.remote_location, location);
        assert_eq!(packet.payload.as_ref(), b"fresh-packet");
        assert_eq!(fragments.len(), 0);
    }
}
