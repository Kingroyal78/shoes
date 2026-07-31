//! Hyper-based NaiveProxy service
//!
//! This module provides a hyper-based HTTP/2 server for NaiveProxy connections.
//! It handles CONNECT requests with padding support and built-in static file fallback.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::debug;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::crypto::CryptoTlsStream;
use crate::h2mux::PrependStream;
use crate::protocol_sniff::sniff_tcp_protocol;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::tcp::tcp_handler::{AuthenticatedUser, TcpServerSetupResult};
use crate::tcp::tcp_server::{AuthenticatedConnectionScope, run_udp_copy};
use crate::tls_server_handler::NaiveConfig;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::v2board::outbound::dispatcher::OutboundDispatcher;

use tokio::io::AsyncReadExt;

use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, PaddingTypeRequest,
    add_server_padding_response_headers, negotiate_server_padding,
};
use super::user_lookup::UserLookup;

/// Wrapper for hyper's upgraded stream that implements AsyncStream.
///
/// This is needed because `TokioIo<Upgraded>` doesn't implement `AsyncStream`
/// (which requires `Sync`), but we need `AsyncStream` for UoT stream wrappers.
struct HyperUpgradedStream(TokioIo<hyper::upgrade::Upgraded>);

impl tokio::io::AsyncRead for HyperUpgradedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HyperUpgradedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl crate::async_stream::AsyncPing for HyperUpgradedStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}

// SAFETY: The underlying hyper Upgraded stream is used only from async contexts
// in a single-threaded manner per connection. The Sync bound is required by
// AsyncStream but the stream is never actually shared across threads.
unsafe impl Sync for HyperUpgradedStream {}

impl AsyncStream for HyperUpgradedStream {}

/// Service configuration for hyper NaiveProxy handler
pub(super) struct NaiveServiceConfig {
    pub(super) users: Arc<UserLookup>,
    pub(super) fallback_path: Option<PathBuf>,
    pub(super) resolver: Arc<dyn Resolver>,
    pub(super) proxy_selector: Arc<ClientProxySelector>,
    pub(super) outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) udp_enabled: bool,
    pub(super) padding_enabled: bool,
}

const PROTOCOL_SNIFF_MAX_BYTES: usize = 2048;
const PROTOCOL_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);

fn empty_body() -> BoxBody<Bytes, io::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(data: Bytes) -> BoxBody<Bytes, io::Error> {
    Full::new(data).map_err(|never| match never {}).boxed()
}

/// Run the hyper-based NaiveProxy service
///
/// This is an internal function called by `setup_naive_server_stream` after
/// determining the HTTP version to use.
pub(super) async fn run_naive_hyper_service<IO: AsyncStream + 'static>(
    tls_stream: CryptoTlsStream<IO>,
    naive_cfg: &NaiveConfig,
    effective_selector: Arc<ClientProxySelector>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    resolver: Arc<dyn Resolver>,
    use_h2: bool,
    peer_addr: Option<SocketAddr>,
) -> io::Result<TcpServerSetupResult> {
    let io = TokioIo::new(tls_stream);

    let service_config = Arc::new(NaiveServiceConfig {
        users: naive_cfg.users.clone(),
        fallback_path: naive_cfg.fallback_path.clone(),
        resolver,
        proxy_selector: effective_selector,
        outbound_dispatcher,
        peer_addr,
        udp_enabled: naive_cfg.udp_enabled,
        padding_enabled: naive_cfg.padding_enabled,
    });

    if use_h2 {
        // HTTP/2 for NaiveProxy clients
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let config = service_config.clone();
                async move { naive_service(req, config).await }
            });

            // H2 settings tuned for reasonable throughput without excessive memory
            // Reference naiveproxy uses ~64KB default, we use 256 KB for better throughput
            const WINDOW_SIZE: u32 = 256 * 1024; // 256 KB (was 16 MB)
            const MAX_FRAME_SIZE: u32 = (1 << 24) - 1; // ~16 MB (max allowed by HTTP/2)

            let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .auto_date_header(false)
                .initial_stream_window_size(WINDOW_SIZE)
                .initial_connection_window_size(WINDOW_SIZE)
                .max_frame_size(MAX_FRAME_SIZE)
                .max_concurrent_streams(1024)
                .serve_connection(io, service)
                .await;

            if let Err(e) = result {
                debug!("Naive HTTP/2 connection error: {}", e);
            }
        });
    } else {
        // HTTP/1.1 for browsers and censors - serve static files only, no proxy
        let fallback_path = naive_cfg.fallback_path.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let path = fallback_path.clone();
                async move { http1_fallback_service(req, path).await }
            });

            let result = hyper::server::conn::http1::Builder::new()
                .auto_date_header(false)
                .serve_connection(io, service)
                .await;

            if let Err(e) = result {
                debug!("Naive HTTP/1.1 fallback error: {}", e);
            }
        });
    }

    Ok(TcpServerSetupResult::AlreadyHandled)
}

/// HTTP/1.1 fallback service - only serves static files, no proxy functionality
async fn http1_fallback_service(
    req: Request<Incoming>,
    fallback_path: Option<PathBuf>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            let path = req.uri().path();
            let is_head = req.method() == Method::HEAD;
            debug!("NaiveProxy HTTP/1.1: serving fallback for {}", path);
            serve_fallback(path, &fallback_path, is_head).await
        }
        Method::OPTIONS => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("allow", "GET, HEAD, OPTIONS")
            .body(empty_body())
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap()),
    }
}

/// Main NaiveProxy service handler for HTTP/2 (hyper)
async fn naive_service(
    mut req: Request<Incoming>,
    config: Arc<NaiveServiceConfig>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::CONNECT => {}
        Method::GET | Method::HEAD => {
            let is_head = req.method() == Method::HEAD;
            debug!(
                "NaiveProxy HTTP/2: serving fallback for {}",
                req.uri().path()
            );
            return serve_fallback(req.uri().path(), &config.fallback_path, is_head).await;
        }
        Method::OPTIONS => {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("allow", "GET, HEAD, OPTIONS")
                .body(empty_body())
                .unwrap());
        }
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    }

    let has_padding = req.headers().get("padding").is_some();

    let validated_user = match req.headers().get("proxy-authorization") {
        Some(auth) => match auth.to_str().ok().and_then(|s| config.users.validate(s)) {
            Some(user) => user,
            None => {
                debug!("NaiveProxy: invalid credentials, returning 400");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(empty_body())
                    .unwrap());
            }
        },
        None => {
            debug!("NaiveProxy: missing auth header, returning 400");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };
    let username = validated_user.name.to_string();
    let authenticated_user = validated_user.authenticated_user.cloned();

    let destination = match parse_connect_destination(&req) {
        Some(dest) => dest,
        None => {
            log::warn!("NaiveProxy: invalid CONNECT destination");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    debug!("[{}] NaiveProxy CONNECT to {}", username, destination);

    let padding_type_request = match req.headers().get("padding-type-request") {
        Some(types) => match types.to_str() {
            Ok(types) => PaddingTypeRequest::Value(types),
            Err(_) => PaddingTypeRequest::Malformed,
        },
        None => PaddingTypeRequest::Absent,
    };
    let padding_type =
        negotiate_server_padding(config.padding_enabled, has_padding, padding_type_request);

    // Get upgrade future before moving the request
    let on_upgrade = hyper::upgrade::on(&mut req);
    let resolver = config.resolver.clone();
    let proxy_selector = config.proxy_selector.clone();
    let outbound_dispatcher = config.outbound_dispatcher.clone();
    let peer_addr = config.peer_addr;
    let udp_enabled = config.udp_enabled;

    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = HyperUpgradedStream(TokioIo::new(upgraded));

                let stream_context = NaiveStreamContext {
                    resolver,
                    proxy_selector,
                    outbound_dispatcher,
                    udp_enabled,
                    user_name: username,
                    authenticated_user,
                    peer_addr,
                };

                let result = if padding_type != PaddingType::None {
                    let stream =
                        NaivePaddingStream::new(io, PaddingDirection::Server, padding_type);
                    handle_naive_stream(stream, destination, stream_context).await
                } else {
                    handle_naive_stream(io, destination, stream_context).await
                };

                if let Err(e) = result {
                    debug!("NaiveProxy tunnel error: {}", e);
                }
            }
            Err(e) => {
                debug!("NaiveProxy upgrade failed: {}", e);
            }
        }
    });

    let response = add_server_padding_response_headers(
        Response::builder().status(StatusCode::OK),
        padding_type,
    );
    Ok(response.body(empty_body()).unwrap())
}

fn parse_connect_destination(req: &Request<Incoming>) -> Option<NetLocation> {
    let authority = req.uri().authority()?;
    parse_authority(authority.as_str()).ok()
}

/// Parse authority string (host:port) into NetLocation
pub(super) fn parse_authority(authority: &str) -> io::Result<NetLocation> {
    // Handle IPv6: [::1]:443
    if authority.starts_with('[') {
        let end_bracket = authority
            .find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid IPv6 address"))?;

        let host = &authority[1..end_bracket];

        let port =
            if authority.len() > end_bracket + 1 && authority.as_bytes()[end_bracket + 1] == b':' {
                authority[end_bracket + 2..].parse::<u16>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {}", e))
                })?
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Missing port"));
            };

        let addr = host.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IPv6: {}", e))
        })?;

        return Ok(NetLocation::new(Address::Ipv6(addr), port));
    }

    // Handle host:port
    let colon = authority
        .rfind(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port"))?;

    let host = &authority[..colon];
    let port = authority[colon + 1..]
        .parse::<u16>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {}", e)))?;

    let address = Address::from(host)?;
    Ok(NetLocation::new(address, port))
}

/// Serve static files or return 401 Unauthorized
async fn serve_fallback(
    uri_path: &str,
    fallback_path: &Option<PathBuf>,
    is_head: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    let Some(base_path) = fallback_path else {
        // Return 401 instead of 407 to avoid revealing proxy
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(empty_body())
            .unwrap());
    };

    // Sanitize path to prevent directory traversal
    let request_path = uri_path.trim_start_matches('/');
    let mut file_path = base_path.clone();

    for component in std::path::Path::new(request_path).components() {
        match component {
            std::path::Component::Normal(c) => file_path.push(c),
            std::path::Component::ParentDir => {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty_body())
                    .unwrap());
            }
            _ => {}
        }
    }

    if file_path.is_dir() {
        file_path.push("index.html");
    }

    match tokio::fs::read(&file_path).await {
        Ok(contents) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();

            let body = if is_head {
                empty_body()
            } else {
                full_body(Bytes::from(contents.clone()))
            };

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", mime)
                .header("content-length", contents.len())
                .body(body)
                .unwrap())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(empty_body())
            .unwrap()),
    }
}

/// Handle a single NaiveProxy stream after setup
///
/// This handles both TCP and UDP-over-TCP (UoT) connections.
pub(super) struct NaiveStreamContext {
    pub resolver: Arc<dyn Resolver>,
    pub proxy_selector: Arc<ClientProxySelector>,
    pub outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
    pub udp_enabled: bool,
    pub user_name: String,
    pub authenticated_user: Option<AuthenticatedUser>,
    pub peer_addr: Option<SocketAddr>,
}

pub(super) async fn handle_naive_stream<S: AsyncStream + 'static>(
    mut stream: S,
    remote_location: NetLocation,
    context: NaiveStreamContext,
) -> io::Result<()> {
    use crate::client_proxy_selector::ConnectDecision;

    let NaiveStreamContext {
        resolver,
        proxy_selector,
        outbound_dispatcher,
        udp_enabled,
        user_name,
        authenticated_user,
        peer_addr,
    } = context;

    if let Address::Hostname(host) = remote_location.address() {
        if host == UOT_V1_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            debug!("NaiveProxy stream (user: {}): UoT V1 mode", user_name);
            let scope = AuthenticatedConnectionScope::start(&authenticated_user, peer_addr)?;
            let uot_stream = UotV1ServerStream::new_uot(stream);
            let server_stream = scope.wrap_targeted_message_stream(Box::new(uot_stream));

            return run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                outbound_dispatcher.clone(),
                resolver,
                false,
            )
            .await;
        } else if host == UOT_V2_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            let scope = AuthenticatedConnectionScope::start(&authenticated_user, peer_addr)?;
            // UoT V2 header: destination uses SOCKS5 address format
            let is_connect = stream.read_u8().await?;
            let destination = read_location_direct(&mut stream).await?;

            debug!(
                "NaiveProxy stream (user: {}): UoT V2 connect={} -> {}",
                user_name, is_connect, destination
            );

            if is_connect == 1 {
                let uot_v2_stream = UotV2Stream::new(stream);
                let server_stream = scope.wrap_message_stream(Box::new(uot_v2_stream));

                let action = proxy_selector
                    .judge(destination.clone().into(), &resolver)
                    .await?;

                match action {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        let client_stream = match &outbound_dispatcher {
                            Some(dispatcher) => {
                                dispatcher
                                    .connect_udp_bidirectional(&remote_location, &resolver)
                                    .await?
                            }
                            None => {
                                chain_group
                                    .connect_udp_bidirectional(&resolver, remote_location)
                                    .await?
                            }
                        };

                        return run_udp_copy(server_stream, client_stream, false, false).await;
                    }
                    ConnectDecision::Block => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "UDP blocked by rules",
                        ));
                    }
                }
            } else {
                // V2 non-connect mode (same as V1)
                let uot_stream = UotV1ServerStream::new_uot(stream);
                let server_stream = scope.wrap_targeted_message_stream(Box::new(uot_stream));

                return run_udp_routing(
                    ServerStream::Targeted(server_stream),
                    proxy_selector,
                    outbound_dispatcher.clone(),
                    resolver,
                    false,
                )
                .await;
            }
        }
    }

    let scope = AuthenticatedConnectionScope::start(&authenticated_user, peer_addr)?;
    let mut stream = scope.wrap_stream_upload_metered_only(Box::new(stream));

    debug!(
        "NaiveProxy stream (user: {}): TCP -> {}",
        user_name, remote_location
    );

    let (sniffed_protocol, sniffed_stream) =
        sniff_naive_tcp_protocol(stream, &proxy_selector).await?;
    stream = sniffed_stream;

    let action = proxy_selector
        .judge_with_protocol(remote_location.clone().into(), &resolver, sniffed_protocol)
        .await?;

    let mut client_stream: Box<dyn AsyncStream> = match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => match &outbound_dispatcher {
            Some(dispatcher) => dispatcher
                .dial_tcp(remote_location.location(), None, &resolver)
                .await
                .map_err(|e| e.to_io_error())?,
            None => {
                chain_group
                    .connect_tcp(remote_location, &resolver)
                    .await?
                    .client_stream
            }
        },
        ConnectDecision::Block => {
            debug!("NaiveProxy: connection blocked by rules");
            return Ok(());
        }
    };
    client_stream = scope.wrap_download_read_metered_stream(client_stream);

    // Use larger buffers for better throughput (default 8KB is too small)
    const COPY_BUF_SIZE: usize = 256 * 1024;
    let result = copy_bidirectional_with_sizes(
        &mut stream,
        &mut client_stream,
        false,
        false,
        COPY_BUF_SIZE,
        COPY_BUF_SIZE,
    )
    .await;

    let _ = stream.shutdown().await;
    let _ = client_stream.shutdown().await;

    match result {
        Ok(()) => {
            debug!("NaiveProxy stream (user: {}): done", user_name);
            Ok(())
        }
        Err(e) => {
            debug!("NaiveProxy stream (user: {}): error: {}", user_name, e);
            Err(e)
        }
    }
}

async fn sniff_naive_tcp_protocol(
    mut stream: Box<dyn AsyncStream>,
    proxy_selector: &ClientProxySelector,
) -> io::Result<(
    Option<crate::client_proxy_selector::SniffedProtocol>,
    Box<dyn AsyncStream>,
)> {
    if !proxy_selector.requires_protocol_sniff() {
        return Ok((None, stream));
    }

    let started_at = Instant::now();
    let mut initial = Vec::new();
    while initial.len() < PROTOCOL_SNIFF_MAX_BYTES {
        if let Some(protocol) = sniff_tcp_protocol(&initial) {
            return Ok((Some(protocol), prepend_initial_data(stream, initial)));
        }

        let remaining_timeout = PROTOCOL_SNIFF_TIMEOUT
            .checked_sub(started_at.elapsed())
            .unwrap_or_default();
        if remaining_timeout.is_zero() {
            break;
        }

        let read_capacity = PROTOCOL_SNIFF_MAX_BYTES
            .saturating_sub(initial.len())
            .min(512);
        let mut buf = vec![0; read_capacity];
        match tokio::time::timeout(remaining_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                initial.extend_from_slice(&buf[..n]);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }

    let protocol = sniff_tcp_protocol(&initial);
    Ok((protocol, prepend_initial_data(stream, initial)))
}

fn prepend_initial_data(stream: Box<dyn AsyncStream>, initial: Vec<u8>) -> Box<dyn AsyncStream> {
    if initial.is_empty() {
        stream
    } else {
        Box::new(PrependStream::new(stream, Some(initial.into_boxed_slice())))
    }
}
