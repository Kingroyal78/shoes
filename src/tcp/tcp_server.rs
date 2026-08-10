use std::future::{Future, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use log::{debug, error};
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{Sleep, timeout};

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use super::tcp_server_handler_factory::create_tcp_server_handler;

use crate::address::NetLocation;
use crate::async_stream::AsyncPing;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncReadTargetedMessage, AsyncSessionMessageStream, AsyncShutdownMessage,
    AsyncTargetedMessageStream, AsyncWriteMessage, AsyncWriteSessionMessage,
    AsyncWriteSourcedMessage,
};
use crate::async_stream::{AsyncShutdownMessageExt, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, SniffedProtocol};
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::protocol_sniff::sniff_tcp_protocol;
use crate::protocol_sniff::sniff_udp_protocol;
use crate::quic_server::start_quic_servers;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socket_util::{accept_loop_count, new_tcp_listeners, set_tcp_keepalive};
use crate::tcp::tcp_handler::{
    AuthenticatedUser, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
    TrafficRecorder,
};
#[cfg(unix)]
use crate::tun::start_tun_server;
use crate::util::write_all;
use crate::v2board::outbound::dispatcher::{DialError, OutboundDispatcher};

const TCP_STREAM_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn stream_shutdown_timeout() -> Duration {
    if cfg!(test) {
        Duration::from_millis(20)
    } else {
        TCP_STREAM_SHUTDOWN_TIMEOUT
    }
}

async fn shutdown_tcp_stream_pair(
    server_stream: &mut dyn AsyncStream,
    client_stream: &mut dyn AsyncStream,
    shutdown_timeout: Duration,
) {
    if timeout(shutdown_timeout, async {
        let _ = futures::join!(server_stream.shutdown(), client_stream.shutdown());
    })
    .await
    .is_err()
    {
        debug!("timed out shutting down completed TCP proxy streams");
    }
}

async fn shutdown_message_stream_pair(
    server_stream: &mut dyn AsyncMessageStream,
    client_stream: &mut dyn AsyncMessageStream,
    shutdown_timeout: Duration,
) {
    if timeout(shutdown_timeout, async {
        let _ = futures::join!(
            server_stream.shutdown_message(),
            client_stream.shutdown_message()
        );
    })
    .await
    .is_err()
    {
        debug!("timed out shutting down completed message proxy streams");
    }
}

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e}");
                // Back off briefly so a persistent failure (e.g. EMFILE from
                // fd exhaustion) does not hot-spin the accept loop at 100% CPU
                // while logging a continuous error storm.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive: {e}");
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {e}");
        }

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            match process_stream(stream, cloned_handler, cloned_resolver, Some(addr)).await {
                Ok(()) => debug!("{}:{} finished successfully", addr.ip(), addr.port()),
                Err(StreamFailure::Handshake(e)) => {
                    debug!("{}:{} handshake rejected: {}", addr.ip(), addr.port(), e)
                }
                Err(StreamFailure::Proxy(e)) => {
                    error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e)
                }
            }
        });
    }
}

#[cfg(target_family = "unix")]
async fn run_unix_server(
    listener: tokio::net::UnixListener,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {e:?}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            match process_stream(stream, cloned_handler, cloned_resolver, None).await {
                Ok(()) => debug!("{addr:?} finished successfully"),
                Err(StreamFailure::Handshake(e)) => debug!("{addr:?} handshake rejected: {e}"),
                Err(StreamFailure::Proxy(e)) => error!("{addr:?} finished with error: {e:?}"),
            }
        });
    }
}

#[cfg(target_family = "unix")]
async fn bind_unix_listener(path_buf: &PathBuf) -> std::io::Result<tokio::net::UnixListener> {
    if tokio::fs::symlink_metadata(path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(path_buf).await;
    }

    crate::socket_util::new_unix_listener(path_buf, 4096)
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    peer_addr: Option<SocketAddr>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler
        .setup_server_stream_with_peer_addr(server_stream, peer_addr)
        .await
}

/// Why a connection ended, so the caller can pick a log level.
///
/// A public proxy port collects a constant stream of peers that never complete
/// our inbound handshake: clients configured without the plugin, port scans,
/// truncated headers, resets. That is the peer's problem, and logging each one
/// as an error drowns out the failures that are actually ours.
#[derive(Debug)]
pub enum StreamFailure {
    /// The peer never got through the inbound handshake.
    Handshake(std::io::Error),
    /// Failed after the handshake: outbound setup, routing, or the proxying
    /// itself. These deserve an operator's attention.
    Proxy(std::io::Error),
}

impl StreamFailure {
    pub fn into_io_error(self) -> std::io::Error {
        match self {
            StreamFailure::Handshake(error) | StreamFailure::Proxy(error) => error,
        }
    }
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamFailure::Handshake(error) | StreamFailure::Proxy(error) => error.fmt(f),
        }
    }
}

/// Streams currently being served, physical connections and multiplexed logical
/// streams alike.
///
/// Per-connection memory scales with this rather than with the socket count: one
/// physical connection can carry many logical streams, and it is the logical
/// stream that holds the copy buffers. Reported next to the allocator counters
/// so a capacity measurement can control for load directly instead of inferring
/// it from a proxy like the UDP router count.
pub static LIVE_STREAMS: AtomicUsize = AtomicUsize::new(0);

/// Streams refused because [`max_concurrent_streams`] was already reached.
pub static STREAMS_REFUSED: AtomicUsize = AtomicUsize::new(0);

/// Upper bound on concurrently served streams, or `None` for no bound.
///
/// Every change so far has lowered what a stream costs, but a lower cost is
/// still a cost: past some number the node stops being able to serve anyone
/// well. A cap turns that into a predictable refusal of *new* work instead of
/// degrading every connection already being served.
///
/// Read from `SHOES_MAX_CONCURRENT_STREAMS`, and unset means unlimited -- the
/// right number depends on the machine, and guessing one here would be a
/// behaviour change nobody asked for.
/// Whether a stream arriving now would exceed the cap.
///
/// Split out so the boundary is pinned by a test: the limit counts streams
/// already being served, so admitting at `live == limit` would serve one more
/// than configured.
fn at_stream_limit(live: usize, limit: usize) -> bool {
    live >= limit
}

fn max_concurrent_streams() -> Option<usize> {
    static LIMIT: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("SHOES_MAX_CONCURRENT_STREAMS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|limit| *limit > 0)
    })
}

struct LiveStreamGuard;

impl LiveStreamGuard {
    fn new() -> Self {
        LIVE_STREAMS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for LiveStreamGuard {
    fn drop(&mut self) {
        LIVE_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) -> Result<(), StreamFailure>
where
    AS: AsyncStream + 'static,
{
    if let Some(limit) = max_concurrent_streams()
        && at_stream_limit(LIVE_STREAMS.load(Ordering::Relaxed), limit)
    {
        STREAMS_REFUSED.fetch_add(1, Ordering::Relaxed);
        return Err(StreamFailure::Handshake(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!("refused: already serving the configured maximum of {limit} streams"),
        )));
    }
    let _live = LiveStreamGuard::new();
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler, peer_addr),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(StreamFailure::Handshake(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            )));
        }
        Err(elapsed) => {
            return Err(StreamFailure::Handshake(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            )));
        }
    };

    handle_server_setup_result(setup_result, resolver, peer_addr)
        .await
        .map_err(StreamFailure::Proxy)
}

pub async fn handle_server_setup_result(
    mut setup_result: TcpServerSetupResult,
    resolver: Arc<dyn Resolver>,
    mut peer_addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    loop {
        return match setup_result {
            TcpServerSetupResult::PeerAddressOverride {
                peer_addr: override_peer_addr,
                result,
            } => {
                peer_addr = override_peer_addr.or(peer_addr);
                setup_result = *result;
                continue;
            }
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream: mut server_stream,
                need_initial_flush: server_need_initial_flush,
                proxy_selector,
                outbound_dispatcher,
                connection_success_response,
                initial_remote_data,
                authenticated_user,
            } => {
                let _alive_guard = match check_device_limit(&authenticated_user, peer_addr) {
                    Ok(guard) => guard,
                    Err(e) => {
                        let _ = server_stream.shutdown().await;
                        return Err(e);
                    }
                };

                let upload_counter = Arc::new(AtomicU64::new(0));
                let download_counter = Arc::new(AtomicU64::new(0));
                let _traffic_flush = TrafficFlushTask::start(
                    &authenticated_user,
                    upload_counter.clone(),
                    download_counter.clone(),
                );
                if authenticated_user.is_some() {
                    server_stream = Box::new(MeteredStream::new(
                        server_stream,
                        upload_counter.clone(),
                        download_counter.clone(),
                    ));
                }
                let speed_limiter = speed_limiter_for(&authenticated_user);
                if let Some(speed_limiter) = &speed_limiter {
                    server_stream = Box::new(SpeedLimitedStream::new(
                        server_stream,
                        speed_limiter.clone(),
                    ));
                }

                let mut initial_remote_data = initial_remote_data.map(Vec::from);
                let pre_metered_initial_upload_len =
                    initial_remote_data.as_ref().map_or(0, Vec::len);
                let sniffed_protocol = if proxy_selector.requires_protocol_sniff()
                    || outbound_dispatcher
                        .as_ref()
                        .is_some_and(|dispatcher| dispatcher.requires_protocol_sniff())
                {
                    sniff_tcp_forward_protocol(&mut server_stream, &mut initial_remote_data).await?
                } else {
                    None
                };

                let setup_client_stream_future = timeout(
                    Duration::from_secs(60),
                    setup_client_tcp_stream(
                        &mut server_stream,
                        proxy_selector,
                        resolver,
                        remote_location.clone(),
                        sniffed_protocol,
                        outbound_dispatcher.as_deref(),
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

                if let Some(data) = connection_success_response {
                    write_all(&mut server_stream, &data).await?;
                    // server_need_initial_flush should be set to true by the handler if
                    // it's needed.
                }

                let client_need_initial_flush = match initial_remote_data {
                    Some(data) => {
                        let pre_metered_len = pre_metered_initial_upload_len.min(data.len());
                        if pre_metered_len > 0 {
                            if let Some(speed_limiter) = &speed_limiter
                                && let Some(delay) = speed_limiter.reserve_delay(pre_metered_len)
                            {
                                tokio::time::sleep(delay).await;
                            }
                            if authenticated_user.is_some() {
                                upload_counter.fetch_add(pre_metered_len as u64, Ordering::Relaxed);
                            }
                        }
                        write_all(&mut client_stream, &data).await?;
                        true
                    }
                    None => false,
                };

                let copy_result = copy_bidirectional(
                    &mut server_stream,
                    &mut client_stream,
                    server_need_initial_flush,
                    client_need_initial_flush,
                )
                .await;

                shutdown_tcp_stream_pair(
                    &mut *server_stream,
                    &mut *client_stream,
                    stream_shutdown_timeout(),
                )
                .await;

                copy_result?;
                Ok(())
            }
            TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: mut server_stream,
                need_initial_flush: server_need_initial_flush,
                proxy_selector,
                outbound_dispatcher,
                authenticated_user,
            } => {
                let _alive_guard = check_device_limit(&authenticated_user, peer_addr)?;
                let upload_counter = Arc::new(AtomicU64::new(0));
                let download_counter = Arc::new(AtomicU64::new(0));
                let _traffic_flush = TrafficFlushTask::start(
                    &authenticated_user,
                    upload_counter.clone(),
                    download_counter.clone(),
                );
                if authenticated_user.is_some() {
                    server_stream = Box::new(MeteredMessageStream::new(
                        server_stream,
                        upload_counter.clone(),
                        download_counter.clone(),
                    ));
                }
                if let Some(speed_limiter) = speed_limiter_for(&authenticated_user) {
                    server_stream =
                        Box::new(SpeedLimitedMessageStream::new(server_stream, speed_limiter));
                }
                let (sniffed_protocol, initial_udp_data) = if proxy_selector
                    .requires_protocol_sniff()
                    || outbound_dispatcher
                        .as_ref()
                        .is_some_and(|d| d.requires_protocol_sniff())
                {
                    sniff_bidirectional_udp_protocol(&mut server_stream).await?
                } else {
                    (None, None)
                };
                let action = proxy_selector
                    .judge_with_protocol(remote_location.into(), &resolver, sniffed_protocol)
                    .await?;
                match action {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        let mut client_stream = match &outbound_dispatcher {
                            Some(dispatcher) => {
                                let dial = dispatcher.connect_udp_bidirectional(
                                    &remote_location,
                                    sniffed_protocol,
                                    &resolver,
                                );
                                tokio::time::timeout(Duration::from_secs(60), dial)
                                    .await
                                    .map_err(|_| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::TimedOut,
                                            format!(
                                                "timed out dispatching UDP to {remote_location}"
                                            ),
                                        )
                                    })??
                            }
                            None => {
                                let target_desc = remote_location.to_string();
                                let dial = chain_group
                                    .connect_udp_bidirectional(&resolver, remote_location);
                                tokio::time::timeout(Duration::from_secs(60), dial)
                                    .await
                                    .map_err(|_| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::TimedOut,
                                            format!("timed out dialing UDP chain to {target_desc}"),
                                        )
                                    })??
                            }
                        };
                        let client_need_initial_flush = match initial_udp_data {
                            Some(data) => {
                                write_udp_message(&mut client_stream, &data).await?;
                                true
                            }
                            None => false,
                        };

                        run_udp_copy(
                            server_stream,
                            client_stream,
                            server_need_initial_flush,
                            client_need_initial_flush,
                        )
                        .await
                    }
                    ConnectDecision::Block => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "Blocked bidirectional udp forward",
                    )),
                }
            }
            TcpServerSetupResult::MultiDirectionalUdp {
                stream: mut server_stream,
                need_initial_flush,
                proxy_selector,
                outbound_dispatcher,
                authenticated_user,
            } => {
                let _alive_guard = check_device_limit(&authenticated_user, peer_addr)?;
                let upload_counter = Arc::new(AtomicU64::new(0));
                let download_counter = Arc::new(AtomicU64::new(0));
                let _traffic_flush = TrafficFlushTask::start(
                    &authenticated_user,
                    upload_counter.clone(),
                    download_counter.clone(),
                );
                if authenticated_user.is_some() {
                    server_stream = Box::new(MeteredTargetedMessageStream::new(
                        server_stream,
                        upload_counter.clone(),
                        download_counter.clone(),
                    ));
                }
                if let Some(speed_limiter) = speed_limiter_for(&authenticated_user) {
                    server_stream = Box::new(SpeedLimitedTargetedMessageStream::new(
                        server_stream,
                        speed_limiter,
                    ));
                }
                run_udp_routing(
                    ServerStream::Targeted(server_stream),
                    proxy_selector,
                    outbound_dispatcher,
                    resolver,
                    need_initial_flush,
                )
                .await
            }
            TcpServerSetupResult::SessionBasedUdp {
                stream: mut server_stream,
                need_initial_flush,
                proxy_selector,
                outbound_dispatcher,
                authenticated_user,
            } => {
                let _alive_guard = check_device_limit(&authenticated_user, peer_addr)?;
                let upload_counter = Arc::new(AtomicU64::new(0));
                let download_counter = Arc::new(AtomicU64::new(0));
                let _traffic_flush = TrafficFlushTask::start(
                    &authenticated_user,
                    upload_counter.clone(),
                    download_counter.clone(),
                );
                if authenticated_user.is_some() {
                    server_stream = Box::new(MeteredSessionMessageStream::new(
                        server_stream,
                        upload_counter.clone(),
                        download_counter.clone(),
                    ));
                }
                if let Some(speed_limiter) = speed_limiter_for(&authenticated_user) {
                    server_stream = Box::new(SpeedLimitedSessionMessageStream::new(
                        server_stream,
                        speed_limiter,
                    ));
                }
                run_udp_routing(
                    ServerStream::Session(server_stream),
                    proxy_selector,
                    outbound_dispatcher,
                    resolver,
                    need_initial_flush,
                )
                .await
            }
            TcpServerSetupResult::AlreadyHandled => {
                // Connection is being handled by a spawned task (e.g., Reality fallback).
                // Nothing more to do here.
                Ok(())
            }
        };
    }
}

fn check_device_limit(
    authenticated_user: &Option<AuthenticatedUser>,
    peer_addr: Option<SocketAddr>,
) -> std::io::Result<Option<AliveIpGuard>> {
    if let (Some(user), Some(addr)) = (authenticated_user, peer_addr)
        && let Some(recorder) = &user.recorder
    {
        if !recorder.add_alive_ip_and_check_limit(
            &user.node_tag,
            user.uid,
            addr.ip(),
            user.device_limit,
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("device limit exceeded for user {}", user.uid),
            ));
        }
        return Ok(Some(AliveIpGuard {
            recorder: recorder.clone(),
            node_tag: user.node_tag.clone(),
            uid: user.uid,
            ip: addr.ip(),
        }));
    }
    Ok(None)
}

pub(crate) struct AuthenticatedConnectionScope {
    _alive_guard: Option<AliveIpGuard>,
    _traffic_flush: TrafficFlushTask,
    authenticated: bool,
    upload_counter: Arc<AtomicU64>,
    download_counter: Arc<AtomicU64>,
    speed_limiter: Option<Arc<RateLimiter>>,
    upload_speed_limiter: Option<Arc<RateLimiter>>,
    download_speed_limiter: Option<Arc<RateLimiter>>,
}

#[derive(Clone, Default)]
pub(crate) struct DirectionalSpeedLimiters {
    upload: Option<Arc<RateLimiter>>,
    download: Option<Arc<RateLimiter>>,
}

impl DirectionalSpeedLimiters {
    pub(crate) fn from_mbps(
        upload_limit_mbps: Option<u64>,
        download_limit_mbps: Option<u64>,
    ) -> Self {
        Self {
            upload: speed_limiter_for_mbps(upload_limit_mbps),
            download: speed_limiter_for_mbps(download_limit_mbps),
        }
    }

    #[cfg(test)]
    pub(crate) fn upload_rate_bytes_per_sec(&self) -> Option<u64> {
        self.upload
            .as_ref()
            .map(|limiter| limiter.rate_bytes_per_sec())
    }

    #[cfg(test)]
    pub(crate) fn download_rate_bytes_per_sec(&self) -> Option<u64> {
        self.download
            .as_ref()
            .map(|limiter| limiter.rate_bytes_per_sec())
    }

    #[cfg(test)]
    pub(crate) fn shares_buckets_with(&self, other: &Self) -> bool {
        option_arc_ptr_eq(&self.upload, &other.upload)
            && option_arc_ptr_eq(&self.download, &other.download)
    }
}

impl AuthenticatedConnectionScope {
    pub(crate) fn start(
        authenticated_user: &Option<AuthenticatedUser>,
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        Self::start_with_directional_speed_limits(authenticated_user, peer_addr, None, None)
    }

    pub(crate) fn start_with_directional_speed_limits(
        authenticated_user: &Option<AuthenticatedUser>,
        peer_addr: Option<SocketAddr>,
        upload_limit_mbps: Option<u64>,
        download_limit_mbps: Option<u64>,
    ) -> std::io::Result<Self> {
        Self::start_with_directional_speed_limiters(
            authenticated_user,
            peer_addr,
            DirectionalSpeedLimiters::from_mbps(upload_limit_mbps, download_limit_mbps),
        )
    }

    pub(crate) fn start_with_directional_speed_limiters(
        authenticated_user: &Option<AuthenticatedUser>,
        peer_addr: Option<SocketAddr>,
        directional_limiters: DirectionalSpeedLimiters,
    ) -> std::io::Result<Self> {
        let alive_guard = check_device_limit(authenticated_user, peer_addr)?;
        let upload_counter = Arc::new(AtomicU64::new(0));
        let download_counter = Arc::new(AtomicU64::new(0));
        let traffic_flush = TrafficFlushTask::start(
            authenticated_user,
            upload_counter.clone(),
            download_counter.clone(),
        );
        let speed_limiter = speed_limiter_for(authenticated_user);
        Ok(Self {
            _alive_guard: alive_guard,
            _traffic_flush: traffic_flush,
            authenticated: authenticated_user.is_some(),
            upload_counter,
            download_counter,
            speed_limiter,
            upload_speed_limiter: directional_limiters.upload,
            download_speed_limiter: directional_limiters.download,
        })
    }

    pub(crate) fn wrap_stream(&self, mut stream: Box<dyn AsyncStream>) -> Box<dyn AsyncStream> {
        if self.authenticated {
            stream = Box::new(MeteredStream::new(
                stream,
                self.upload_counter.clone(),
                self.download_counter.clone(),
            ));
        }
        if let Some(speed_limiter) = &self.speed_limiter {
            stream = Box::new(SpeedLimitedStream::new(stream, speed_limiter.clone()));
        }
        if self.upload_speed_limiter.is_some() || self.download_speed_limiter.is_some() {
            stream = Box::new(DirectionalSpeedLimitedStream::new(
                stream,
                self.upload_speed_limiter.clone(),
                self.download_speed_limiter.clone(),
            ));
        }
        stream
    }

    pub(crate) fn wrap_stream_upload_metered_only(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> Box<dyn AsyncStream> {
        if self.authenticated {
            stream = Box::new(MeteredStream::new_with_counters(
                stream,
                Some(self.upload_counter.clone()),
                None,
            ));
        }
        if let Some(speed_limiter) = &self.speed_limiter {
            stream = Box::new(SpeedLimitedStream::new(stream, speed_limiter.clone()));
        }
        if self.upload_speed_limiter.is_some() || self.download_speed_limiter.is_some() {
            stream = Box::new(DirectionalSpeedLimitedStream::new(
                stream,
                self.upload_speed_limiter.clone(),
                self.download_speed_limiter.clone(),
            ));
        }
        stream
    }

    pub(crate) fn wrap_download_read_metered_stream(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> Box<dyn AsyncStream> {
        if self.authenticated {
            stream = Box::new(MeteredStream::new_with_counters(
                stream,
                Some(self.download_counter.clone()),
                None,
            ));
        }
        stream
    }

    pub(crate) fn wrap_message_stream(
        &self,
        mut stream: Box<dyn AsyncMessageStream>,
    ) -> Box<dyn AsyncMessageStream> {
        if self.authenticated {
            stream = Box::new(MeteredMessageStream::new(
                stream,
                self.upload_counter.clone(),
                self.download_counter.clone(),
            ));
        }
        if let Some(speed_limiter) = &self.speed_limiter {
            stream = Box::new(SpeedLimitedMessageStream::new(
                stream,
                speed_limiter.clone(),
            ));
        }
        stream
    }

    pub(crate) fn wrap_targeted_message_stream(
        &self,
        mut stream: Box<dyn AsyncTargetedMessageStream>,
    ) -> Box<dyn AsyncTargetedMessageStream> {
        if self.authenticated {
            stream = Box::new(MeteredTargetedMessageStream::new(
                stream,
                self.upload_counter.clone(),
                self.download_counter.clone(),
            ));
        }
        if let Some(speed_limiter) = &self.speed_limiter {
            stream = Box::new(SpeedLimitedTargetedMessageStream::new(
                stream,
                speed_limiter.clone(),
            ));
        }
        stream
    }

    pub(crate) async fn throttle_upload_bytes(&self, bytes: usize) {
        self.throttle_bytes(bytes).await;
        Self::throttle_directional_bytes(&self.upload_speed_limiter, bytes).await;
    }

    pub(crate) async fn throttle_download_bytes(&self, bytes: usize) {
        self.throttle_bytes(bytes).await;
        Self::throttle_directional_bytes(&self.download_speed_limiter, bytes).await;
    }

    pub(crate) fn record_upload_bytes(&self, bytes: usize) {
        if self.authenticated && bytes > 0 {
            self.upload_counter
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_download_bytes(&self, bytes: usize) {
        if self.authenticated && bytes > 0 {
            self.download_counter
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    async fn throttle_bytes(&self, bytes: usize) {
        let Some(speed_limiter) = &self.speed_limiter else {
            return;
        };
        if let Some(delay) = speed_limiter.reserve_delay(bytes) {
            tokio::time::sleep(delay).await;
        }
    }

    async fn throttle_directional_bytes(speed_limiter: &Option<Arc<RateLimiter>>, bytes: usize) {
        let Some(speed_limiter) = speed_limiter else {
            return;
        };
        if let Some(delay) = speed_limiter.reserve_delay(bytes) {
            tokio::time::sleep(delay).await;
        }
    }
}

struct AliveIpGuard {
    recorder: Arc<dyn TrafficRecorder>,
    node_tag: Arc<str>,
    uid: u64,
    ip: IpAddr,
}

impl Drop for AliveIpGuard {
    fn drop(&mut self) {
        self.recorder
            .remove_alive_ip(&self.node_tag, self.uid, self.ip);
    }
}

/// A connection's byte counters, as seen by the periodic reporter.
struct ActiveTraffic {
    user: AuthenticatedUser,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

/// Every authenticated connection currently reporting traffic.
///
/// This used to be a task and a timer per connection. Both are per-connection
/// costs that buy nothing: the work is two atomic swaps every ten seconds, and
/// a million connections meant a million timer entries and a hundred thousand
/// wakeups a second purely to perform them. One sweeper walking this map does
/// the same work in a single task.
static ACTIVE_TRAFFIC: LazyLock<DashMap<u64, ActiveTraffic>> = LazyLock::new(DashMap::new);
static NEXT_ACTIVE_TRAFFIC_ID: AtomicU64 = AtomicU64::new(0);

/// Start the sweeper on first use, so a process with no authenticated traffic
/// (and every unit test) never spawns it.
fn ensure_traffic_sweeper() {
    static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    STARTED.get_or_init(|| {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ACTIVE_TRAFFIC_FLUSH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                for entry in ACTIVE_TRAFFIC.iter() {
                    let active = entry.value();
                    record_traffic_for(&active.user, &active.upload, &active.download);
                }
            }
        });
    });
}

pub(crate) struct TrafficFlushTask {
    /// Key into [`ACTIVE_TRAFFIC`], absent when this connection has no recorder.
    id: Option<u64>,
    authenticated_user: Option<AuthenticatedUser>,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl TrafficFlushTask {
    fn start(
        authenticated_user: &Option<AuthenticatedUser>,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
    ) -> Self {
        let authenticated_user = authenticated_user.clone();
        let id = authenticated_user
            .as_ref()
            .filter(|user| user.recorder.is_some())
            .map(|user| {
                ensure_traffic_sweeper();
                let id = NEXT_ACTIVE_TRAFFIC_ID.fetch_add(1, Ordering::Relaxed);
                ACTIVE_TRAFFIC.insert(
                    id,
                    ActiveTraffic {
                        user: user.clone(),
                        upload: upload.clone(),
                        download: download.clone(),
                    },
                );
                id
            });
        Self {
            id,
            authenticated_user,
            upload,
            download,
        }
    }
}

impl Drop for TrafficFlushTask {
    fn drop(&mut self) {
        // Deregister before reporting. The sweeper holds a shard of this map
        // while it reports, so taking the recorder's lock first here would
        // invert the order the two paths acquire them in.
        if let Some(id) = self.id.take() {
            ACTIVE_TRAFFIC.remove(&id);
        }
        if record_user_traffic(&self.authenticated_user, &self.upload, &self.download) {
            flush_pending_traffic(&self.authenticated_user);
        }
    }
}

fn record_user_traffic(
    authenticated_user: &Option<AuthenticatedUser>,
    upload: &AtomicU64,
    download: &AtomicU64,
) -> bool {
    match authenticated_user {
        Some(user) => record_traffic_for(user, upload, download),
        None => false,
    }
}

fn record_traffic_for(user: &AuthenticatedUser, upload: &AtomicU64, download: &AtomicU64) -> bool {
    let upload = upload.swap(0, Ordering::Relaxed);
    let download = download.swap(0, Ordering::Relaxed);
    if upload == 0 && download == 0 {
        return false;
    }
    if let Some(recorder) = &user.recorder {
        recorder.add_traffic(&user.node_tag, user.uid, upload, download);
        return true;
    }
    false
}

#[cfg(test)]
fn active_traffic_len() -> usize {
    ACTIVE_TRAFFIC.len()
}

fn flush_pending_traffic(authenticated_user: &Option<AuthenticatedUser>) {
    if let Some(user) = authenticated_user
        && let Some(recorder) = &user.recorder
    {
        recorder.flush_pending_traffic();
    }
}

fn speed_limiter_for(authenticated_user: &Option<AuthenticatedUser>) -> Option<Arc<RateLimiter>> {
    let user = authenticated_user.as_ref()?;
    let key = UserSpeedLimitKey {
        node_tag: user.node_tag.clone(),
        uid: user.uid,
    };
    let Some(speed_limit) = user.speed_limit else {
        // Only take the shard write lock when an entry actually exists (the
        // common case for a never-limited user is a cheap read). The per-sync
        // reconcile also removes entries for users whose limits were cleared.
        if USER_SPEED_LIMITERS.contains_key(&key) {
            USER_SPEED_LIMITERS.remove(&key);
        }
        return None;
    };
    let Some(bytes_per_sec) = panel_speed_limit_to_bytes_per_sec(speed_limit) else {
        if USER_SPEED_LIMITERS.contains_key(&key) {
            USER_SPEED_LIMITERS.remove(&key);
        }
        return None;
    };

    match USER_SPEED_LIMITERS.entry(key) {
        Entry::Occupied(entry) => {
            let limiter = entry.get().clone();
            limiter.update_rate(bytes_per_sec);
            Some(limiter)
        }
        Entry::Vacant(entry) => {
            let limiter = Arc::new(RateLimiter::new(bytes_per_sec));
            entry.insert(limiter.clone());
            Some(limiter)
        }
    }
}

fn speed_limiter_for_mbps(limit_mbps: Option<u64>) -> Option<Arc<RateLimiter>> {
    panel_speed_limit_to_bytes_per_sec(limit_mbps.unwrap_or(0))
        .map(RateLimiter::new)
        .map(Arc::new)
}

#[cfg(test)]
fn option_arc_ptr_eq<T>(left: &Option<Arc<T>>, right: &Option<Arc<T>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn panel_speed_limit_to_bytes_per_sec(speed_limit_mbps: u64) -> Option<u64> {
    if speed_limit_mbps == 0 {
        return None;
    }
    Some(speed_limit_mbps.saturating_mul(125_000).max(1))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UserSpeedLimitKey {
    node_tag: Arc<str>,
    uid: u64,
}

static USER_SPEED_LIMITERS: LazyLock<DashMap<UserSpeedLimitKey, Arc<RateLimiter>>> =
    LazyLock::new(DashMap::new);

/// Drop speed-limit entries for `node_tag` whose user is no longer in
/// `active_uids`. Called after each successful user-list sync so the global
/// map cannot grow with users deleted from the panel. Active connections keep
/// their cloned `Arc<RateLimiter>` until they close; new connections simply
/// create a fresh limiter.
pub(crate) fn reconcile_speed_limiters(
    node_tag: &str,
    active_uids: &std::collections::HashSet<u64>,
) {
    USER_SPEED_LIMITERS
        .retain(|key, _| &*key.node_tag != node_tag || active_uids.contains(&key.uid));
}

#[cfg(test)]
fn speed_limiter_map_len() -> usize {
    USER_SPEED_LIMITERS.len()
}

#[cfg(test)]
fn speed_limiter_map_len_for(node_tag: &str) -> usize {
    USER_SPEED_LIMITERS
        .iter()
        .filter(|entry| &*entry.key().node_tag == node_tag)
        .count()
}

#[cfg(test)]
fn speed_limiter_map_contains(node_tag: &str, uid: u64) -> bool {
    USER_SPEED_LIMITERS.contains_key(&UserSpeedLimitKey {
        node_tag: node_tag.into(),
        uid,
    })
}

#[derive(Debug)]
struct RateLimiter {
    state: Mutex<RateLimiterState>,
}

#[derive(Debug)]
struct RateLimiterState {
    rate_bytes_per_sec: f64,
    burst_bytes: f64,
    tokens: f64,
    last_refill: Instant,
}

const SPEED_LIMIT_BURST_SECONDS: f64 = 2.0;

/// Smallest slice a rate-limited stream will read or write at once, so a
/// nearly-empty token bucket cannot degrade a transfer into byte-at-a-time IO.
const MIN_LIMITED_CHUNK_BYTES: usize = 4096;
const ACTIVE_TRAFFIC_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

impl RateLimiter {
    fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec.max(1) as f64;
        let burst = (rate * SPEED_LIMIT_BURST_SECONDS).max(1.0);
        Self {
            state: Mutex::new(RateLimiterState {
                rate_bytes_per_sec: rate,
                burst_bytes: burst,
                tokens: burst,
                last_refill: Instant::now(),
            }),
        }
    }

    fn update_rate(&self, rate_bytes_per_sec: u64) {
        let rate = rate_bytes_per_sec.max(1) as f64;
        let burst = (rate * SPEED_LIMIT_BURST_SECONDS).max(1.0);
        let mut state = self.state.lock();
        state.refill(Instant::now());
        state.rate_bytes_per_sec = rate;
        state.burst_bytes = burst;
        state.tokens = state.tokens.min(burst);
    }

    #[cfg(test)]
    fn rate_bytes_per_sec(&self) -> u64 {
        self.state.lock().rate_bytes_per_sec as u64
    }

    fn available_or_delay(&self, requested: usize) -> Result<usize, Duration> {
        let requested = requested.max(1);
        let mut state = self.state.lock();
        state.refill(Instant::now());
        // Never hand out a tiny slice just because a byte or two has trickled
        // in. Doing so drives the transfer one poll (and one timer-wheel
        // insertion) per handful of bytes, which costs far more CPU than the
        // limit itself; waiting for a worthwhile chunk delivers the same
        // throughput at a fraction of the wakeups. The floor is clamped by both
        // the bucket capacity and the request, so it can never wait for tokens
        // the bucket cannot hold or that the caller does not want.
        let min_chunk = (MIN_LIMITED_CHUNK_BYTES as f64)
            .min(state.burst_bytes)
            .min(requested as f64);
        if state.tokens >= min_chunk {
            return Ok(requested.min(state.tokens.floor() as usize).max(1));
        }
        let wait_secs = (min_chunk - state.tokens) / state.rate_bytes_per_sec;
        Err(Duration::from_secs_f64(wait_secs.max(0.001)))
    }

    fn can_send_or_delay(&self, bytes: usize) -> Result<(), Duration> {
        if bytes == 0 {
            return Ok(());
        }
        let mut state = self.state.lock();
        state.refill(Instant::now());
        if state.tokens >= bytes as f64 {
            return Ok(());
        }
        let wait_secs = (bytes as f64 - state.tokens) / state.rate_bytes_per_sec;
        Err(Duration::from_secs_f64(wait_secs.max(0.001)))
    }

    fn consume(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut state = self.state.lock();
        state.refill(Instant::now());
        state.tokens -= bytes as f64;
    }

    fn reserve_delay(&self, bytes: usize) -> Option<Duration> {
        if bytes == 0 {
            return None;
        }
        let mut state = self.state.lock();
        state.refill(Instant::now());
        state.tokens -= bytes as f64;
        if state.tokens >= 0.0 {
            None
        } else {
            Some(Duration::from_secs_f64(
                (-state.tokens / state.rate_bytes_per_sec).max(0.001),
            ))
        }
    }
}

impl RateLimiterState {
    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        self.tokens = (self.tokens + elapsed * self.rate_bytes_per_sec).min(self.burst_bytes);
        self.last_refill = now;
    }
}

fn poll_limiter_sleep(
    sleep: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
    delay: Duration,
) -> Poll<()> {
    let deadline = tokio::time::Instant::now() + delay;
    match sleep {
        Some(existing) => existing.as_mut().reset(deadline),
        None => *sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
    }
    if sleep.as_mut().unwrap().as_mut().poll(cx).is_ready() {
        *sleep = None;
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

struct MeteredStream {
    inner: Box<dyn AsyncStream>,
    read_counter: Option<Arc<AtomicU64>>,
    write_counter: Option<Arc<AtomicU64>>,
}

impl MeteredStream {
    fn new(inner: Box<dyn AsyncStream>, upload: Arc<AtomicU64>, download: Arc<AtomicU64>) -> Self {
        Self::new_with_counters(inner, Some(upload), Some(download))
    }

    fn new_with_counters(
        inner: Box<dyn AsyncStream>,
        read_counter: Option<Arc<AtomicU64>>,
        write_counter: Option<Arc<AtomicU64>>,
    ) -> Self {
        Self {
            inner,
            read_counter,
            write_counter,
        }
    }
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if let Some(counter) = &self.read_counter {
                counter.fetch_add(after.saturating_sub(before) as u64, Ordering::Relaxed);
            }
        }
        result
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if let Some(counter) = &self.write_counter {
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Poll::Ready(Ok(n))
        } else {
            result
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for MeteredStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for MeteredStream {}

struct SpeedLimitedStream {
    inner: Box<dyn AsyncStream>,
    limiter: Arc<RateLimiter>,
    read_sleep: Option<Pin<Box<Sleep>>>,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl SpeedLimitedStream {
    fn new(inner: Box<dyn AsyncStream>, limiter: Arc<RateLimiter>) -> Self {
        Self {
            inner,
            limiter,
            read_sleep: None,
            write_sleep: None,
        }
    }
}

impl AsyncRead for SpeedLimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let allowed = match self.limiter.available_or_delay(buf.remaining()) {
            Ok(allowed) => allowed,
            Err(delay) => {
                if poll_limiter_sleep(&mut self.read_sleep, cx, delay).is_pending() {
                    return Poll::Pending;
                }
                return self.poll_read(cx, buf);
            }
        };
        let read = {
            let mut limited = buf.take(allowed);
            let before = limited.filled().len();
            match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => limited.filled().len().saturating_sub(before),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        if read > 0 {
            // `ReadBuf::take` writes into the caller's unfilled memory but does not
            // advance the caller's filled cursor.
            unsafe { buf.assume_init(read) };
            buf.advance(read);
            self.limiter.consume(read);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SpeedLimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let allowed = match self.limiter.available_or_delay(buf.len()) {
            Ok(allowed) => allowed,
            Err(delay) => {
                if poll_limiter_sleep(&mut self.write_sleep, cx, delay).is_pending() {
                    return Poll::Pending;
                }
                return self.poll_write(cx, buf);
            }
        };
        match Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]) {
            Poll::Ready(Ok(n)) => {
                self.limiter.consume(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for SpeedLimitedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for SpeedLimitedStream {}

struct DirectionalSpeedLimitedStream {
    inner: Box<dyn AsyncStream>,
    read_limiter: Option<Arc<RateLimiter>>,
    write_limiter: Option<Arc<RateLimiter>>,
    read_sleep: Option<Pin<Box<Sleep>>>,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl DirectionalSpeedLimitedStream {
    fn new(
        inner: Box<dyn AsyncStream>,
        read_limiter: Option<Arc<RateLimiter>>,
        write_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self {
            inner,
            read_limiter,
            write_limiter,
            read_sleep: None,
            write_sleep: None,
        }
    }
}

impl AsyncRead for DirectionalSpeedLimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let allowed = match self.read_limiter.clone() {
            Some(limiter) => match limiter.available_or_delay(buf.remaining()) {
                Ok(allowed) => allowed,
                Err(delay) => {
                    if poll_limiter_sleep(&mut self.read_sleep, cx, delay).is_pending() {
                        return Poll::Pending;
                    }
                    return self.poll_read(cx, buf);
                }
            },
            None => buf.remaining(),
        };

        let read = {
            let mut limited = buf.take(allowed);
            let before = limited.filled().len();
            match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                Poll::Ready(Ok(())) => limited.filled().len().saturating_sub(before),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        if read > 0 {
            unsafe { buf.assume_init(read) };
            buf.advance(read);
            if let Some(limiter) = &self.read_limiter {
                limiter.consume(read);
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DirectionalSpeedLimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let allowed = match self.write_limiter.clone() {
            Some(limiter) => match limiter.available_or_delay(buf.len()) {
                Ok(allowed) => allowed,
                Err(delay) => {
                    if poll_limiter_sleep(&mut self.write_sleep, cx, delay).is_pending() {
                        return Poll::Pending;
                    }
                    return self.poll_write(cx, buf);
                }
            },
            None => buf.len(),
        };

        match Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]) {
            Poll::Ready(Ok(n)) => {
                if let Some(limiter) = &self.write_limiter {
                    limiter.consume(n);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for DirectionalSpeedLimitedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for DirectionalSpeedLimitedStream {}

macro_rules! impl_message_common {
    ($type:ty, $stream_trait:ident) => {
        impl AsyncFlushMessage for $type {
            fn poll_flush_message(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush_message(cx)
            }
        }

        impl AsyncShutdownMessage for $type {
            fn poll_shutdown_message(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown_message(cx)
            }
        }

        impl AsyncPing for $type {
            fn supports_ping(&self) -> bool {
                self.inner.supports_ping()
            }

            fn poll_write_ping(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<bool>> {
                Pin::new(&mut self.inner).poll_write_ping(cx)
            }
        }

        impl $stream_trait for $type {}
    };
}

struct MeteredMessageStream {
    inner: Box<dyn AsyncMessageStream>,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl MeteredMessageStream {
    fn new(
        inner: Box<dyn AsyncMessageStream>,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            upload,
            download,
        }
    }
}

impl AsyncReadMessage for MeteredMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.upload.fetch_add(
                buf.filled().len().saturating_sub(before) as u64,
                Ordering::Relaxed,
            );
        }
        result
    }
}

impl AsyncWriteMessage for MeteredMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_write_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.download.fetch_add(buf.len() as u64, Ordering::Relaxed);
        }
        result
    }
}

impl_message_common!(MeteredMessageStream, AsyncMessageStream);

struct SpeedLimitedMessageStream {
    inner: Box<dyn AsyncMessageStream>,
    limiter: Arc<RateLimiter>,
    read_sleep: Option<Pin<Box<Sleep>>>,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl SpeedLimitedMessageStream {
    fn new(inner: Box<dyn AsyncMessageStream>, limiter: Arc<RateLimiter>) -> Self {
        Self {
            inner,
            limiter,
            read_sleep: None,
            write_sleep: None,
        }
    }
}

impl AsyncReadMessage for SpeedLimitedMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let requested = buf.remaining().max(1);
        if let Err(delay) = self.limiter.can_send_or_delay(requested) {
            if poll_limiter_sleep(&mut self.read_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_read_message(cx, buf);
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.limiter
                .consume(buf.filled().len().saturating_sub(before));
        }
        result
    }
}

impl AsyncWriteMessage for SpeedLimitedMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        if let Err(delay) = self.limiter.can_send_or_delay(buf.len()) {
            if poll_limiter_sleep(&mut self.write_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_write_message(cx, buf);
        }
        let result = Pin::new(&mut self.inner).poll_write_message(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.limiter.consume(buf.len());
        }
        result
    }
}

impl_message_common!(SpeedLimitedMessageStream, AsyncMessageStream);

struct MeteredTargetedMessageStream {
    inner: Box<dyn AsyncTargetedMessageStream>,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl MeteredTargetedMessageStream {
    fn new(
        inner: Box<dyn AsyncTargetedMessageStream>,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            upload,
            download,
        }
    }
}

impl AsyncReadTargetedMessage for MeteredTargetedMessageStream {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_targeted_message(cx, buf);
        if let Poll::Ready(Ok(_)) = &result {
            self.upload.fetch_add(
                buf.filled().len().saturating_sub(before) as u64,
                Ordering::Relaxed,
            );
        }
        result
    }
}

impl AsyncWriteSourcedMessage for MeteredTargetedMessageStream {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_write_sourced_message(cx, buf, source);
        if let Poll::Ready(Ok(())) = &result {
            self.download.fetch_add(buf.len() as u64, Ordering::Relaxed);
        }
        result
    }
}

impl_message_common!(MeteredTargetedMessageStream, AsyncTargetedMessageStream);

struct SpeedLimitedTargetedMessageStream {
    inner: Box<dyn AsyncTargetedMessageStream>,
    limiter: Arc<RateLimiter>,
    read_sleep: Option<Pin<Box<Sleep>>>,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl SpeedLimitedTargetedMessageStream {
    fn new(inner: Box<dyn AsyncTargetedMessageStream>, limiter: Arc<RateLimiter>) -> Self {
        Self {
            inner,
            limiter,
            read_sleep: None,
            write_sleep: None,
        }
    }
}

impl AsyncReadTargetedMessage for SpeedLimitedTargetedMessageStream {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let requested = buf.remaining().max(1);
        if let Err(delay) = self.limiter.can_send_or_delay(requested) {
            if poll_limiter_sleep(&mut self.read_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_read_targeted_message(cx, buf);
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_targeted_message(cx, buf);
        if let Poll::Ready(Ok(_)) = &result {
            self.limiter
                .consume(buf.filled().len().saturating_sub(before));
        }
        result
    }
}

impl AsyncWriteSourcedMessage for SpeedLimitedTargetedMessageStream {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        if let Err(delay) = self.limiter.can_send_or_delay(buf.len()) {
            if poll_limiter_sleep(&mut self.write_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_write_sourced_message(cx, buf, source);
        }
        let result = Pin::new(&mut self.inner).poll_write_sourced_message(cx, buf, source);
        if let Poll::Ready(Ok(())) = &result {
            self.limiter.consume(buf.len());
        }
        result
    }
}

impl_message_common!(
    SpeedLimitedTargetedMessageStream,
    AsyncTargetedMessageStream
);

struct MeteredSessionMessageStream {
    inner: Box<dyn AsyncSessionMessageStream>,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl MeteredSessionMessageStream {
    fn new(
        inner: Box<dyn AsyncSessionMessageStream>,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            upload,
            download,
        }
    }
}

impl AsyncReadSessionMessage for MeteredSessionMessageStream {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_session_message(cx, buf);
        if let Poll::Ready(Ok(_)) = &result {
            self.upload.fetch_add(
                buf.filled().len().saturating_sub(before) as u64,
                Ordering::Relaxed,
            );
        }
        result
    }
}

impl AsyncWriteSessionMessage for MeteredSessionMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let result =
            Pin::new(&mut self.inner).poll_write_session_message(cx, session_id, buf, target);
        if let Poll::Ready(Ok(())) = &result {
            self.download.fetch_add(buf.len() as u64, Ordering::Relaxed);
        }
        result
    }
}

impl_message_common!(MeteredSessionMessageStream, AsyncSessionMessageStream);

struct SpeedLimitedSessionMessageStream {
    inner: Box<dyn AsyncSessionMessageStream>,
    limiter: Arc<RateLimiter>,
    read_sleep: Option<Pin<Box<Sleep>>>,
    write_sleep: Option<Pin<Box<Sleep>>>,
}

impl SpeedLimitedSessionMessageStream {
    fn new(inner: Box<dyn AsyncSessionMessageStream>, limiter: Arc<RateLimiter>) -> Self {
        Self {
            inner,
            limiter,
            read_sleep: None,
            write_sleep: None,
        }
    }
}

impl AsyncReadSessionMessage for SpeedLimitedSessionMessageStream {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        let requested = buf.remaining().max(1);
        if let Err(delay) = self.limiter.can_send_or_delay(requested) {
            if poll_limiter_sleep(&mut self.read_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_read_session_message(cx, buf);
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read_session_message(cx, buf);
        if let Poll::Ready(Ok(_)) = &result {
            self.limiter
                .consume(buf.filled().len().saturating_sub(before));
        }
        result
    }
}

impl AsyncWriteSessionMessage for SpeedLimitedSessionMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        if let Err(delay) = self.limiter.can_send_or_delay(buf.len()) {
            if poll_limiter_sleep(&mut self.write_sleep, cx, delay).is_pending() {
                return Poll::Pending;
            }
            return self.poll_write_session_message(cx, session_id, buf, target);
        }
        let result =
            Pin::new(&mut self.inner).poll_write_session_message(cx, session_id, buf, target);
        if let Poll::Ready(Ok(())) = &result {
            self.limiter.consume(buf.len());
        }
        result
    }
}

impl_message_common!(SpeedLimitedSessionMessageStream, AsyncSessionMessageStream);

pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    sniffed_protocol: Option<SniffedProtocol>,
    outbound_dispatcher: Option<&OutboundDispatcher>,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector
        .judge_with_protocol(remote_location.clone().into(), &resolver, sniffed_protocol)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            // Node-side local routing: when an outbound dispatcher is
            // configured it takes over the dial (its chain groups include
            // direct), keeping the v2board selector as the block gate.
            if let Some(dispatcher) = outbound_dispatcher {
                let client_stream = dispatcher
                    .dial_tcp(remote_location.location(), sniffed_protocol, &resolver)
                    .await
                    .map_err(|e| {
                        let kind = match &e {
                            DialError::Blocked(_) => std::io::ErrorKind::ConnectionRefused,
                            DialError::MissingOutbound(_) => std::io::ErrorKind::NotFound,
                            DialError::Io(io) => io.kind(),
                        };
                        std::io::Error::new(
                            kind,
                            format!("failed to dispatch outbound to {remote_location}: {e}"),
                        )
                    })?;
                return Ok(Some(client_stream));
            }

            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                server_stream.write_all(&data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}

const PROTOCOL_SNIFF_MAX_BYTES: usize = 2048;
const PROTOCOL_SNIFF_TIMEOUT: Duration = Duration::from_millis(500);
const UDP_PROTOCOL_SNIFF_MAX_BYTES: usize = 65535;

async fn sniff_tcp_forward_protocol(
    server_stream: &mut Box<dyn AsyncStream>,
    initial_remote_data: &mut Option<Vec<u8>>,
) -> std::io::Result<Option<SniffedProtocol>> {
    if let Some(protocol) = sniff_tcp_protocol(initial_remote_data.as_deref().unwrap_or_default()) {
        return Ok(Some(protocol));
    }

    let started_at = Instant::now();
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

async fn sniff_bidirectional_udp_protocol(
    server_stream: &mut Box<dyn AsyncMessageStream>,
) -> std::io::Result<(Option<SniffedProtocol>, Option<Box<[u8]>>)> {
    let mut buf = vec![0; UDP_PROTOCOL_SNIFF_MAX_BYTES];
    let mut read_buf = ReadBuf::new(&mut buf);
    let result = timeout(
        PROTOCOL_SNIFF_TIMEOUT,
        poll_fn(|cx| Pin::new(&mut **server_stream).poll_read_message(cx, &mut read_buf)),
    )
    .await;

    match result {
        Ok(Ok(())) => {
            let len = read_buf.filled().len();
            if len == 0 {
                return Ok((None, None));
            }
            buf.truncate(len);
            let protocol = sniff_udp_protocol(&buf);
            Ok((protocol, Some(buf.into_boxed_slice())))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok((None, None)),
    }
}

async fn write_udp_message(
    stream: &mut Box<dyn AsyncMessageStream>,
    data: &[u8],
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut **stream).poll_write_message(cx, data)).await
}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    shutdown_message_stream_pair(
        &mut *server_stream,
        &mut *client_stream,
        stream_shutdown_timeout(),
    )
    .await;

    copy_result
}

pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config {
        #[cfg(unix)]
        Config::TunServer(tun_config) => start_tun_server(tun_config, resolver)
            .await
            .map(|t| vec![t]),
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => start_tcp_or_quic_servers(server_config, resolver).await,
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

pub async fn start_tcp_handler_servers(
    bind_location: BindLocation,
    tcp_config: TcpConfig,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = vec![];
    match bind_location {
        BindLocation::Address(a) => {
            let socket_addrs = a.to_socket_addrs()?;
            for socket_addr in socket_addrs {
                let listeners =
                    match new_tcp_listeners(socket_addr, 4096, None, accept_loop_count()) {
                        Ok(listeners) => listeners,
                        Err(e) => {
                            abort_join_handles(handles);
                            return Err(e);
                        }
                    };
                for listener in listeners {
                    let tcp_config = tcp_config.clone();
                    let server_handler = server_handler.clone();
                    let resolver = resolver.clone();
                    handles.push(tokio::spawn(async move {
                        if let Err(e) =
                            run_tcp_server(listener, tcp_config, resolver, server_handler).await
                        {
                            log::error!("TCP server at {socket_addr} stopped with error: {e}");
                        }
                    }));
                }
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let listener = match bind_unix_listener(&path_buf).await {
                    Ok(listener) => listener,
                    Err(e) => {
                        abort_join_handles(handles);
                        return Err(e);
                    }
                };
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_unix_server(listener, resolver, server_handler).await {
                        log::error!(
                            "Unix server at {} stopped with error: {e}",
                            path_buf.display()
                        );
                    }
                }));
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    if handles.is_empty() {
        return Err(std::io::Error::other(
            "failed to start TCP handler server: no bind addresses",
        ));
    }

    Ok(handles)
}

fn abort_join_handles(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        handle.abort();
    }
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => match start_tcp_servers(config.clone(), resolver).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_servers(config.clone(), resolver).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Udp => todo!(),
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            &config.bind_location
        )));
    }

    Ok(join_handles)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", &protocol, &bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let client_proxy_selector = Arc::new(create_tcp_client_proxy_selector(
        rules.clone(),
        resolver.clone(),
    ));

    // Extract bind_ip from bind_location for handlers that need it (e.g., SOCKS5 UDP ASSOCIATE)
    let bind_ip = match &bind_location {
        BindLocation::Address(a) => {
            // Use to_socket_addrs() and extract IP from first result
            a.to_socket_addrs()
                .ok()
                .and_then(|addrs| addrs.first().map(|addr| addr.ip()))
        }
        BindLocation::Path(_) => None, // Unix socket, no IP needed
    };

    let tcp_handler: Arc<dyn TcpServerHandler> =
        create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, bind_ip).into();
    debug!("TCP handler: {tcp_handler:?}");

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(a) => {
            let socket_addrs = a.to_socket_addrs()?;
            for socket_addr in socket_addrs {
                let listeners =
                    match new_tcp_listeners(socket_addr, 4096, None, accept_loop_count()) {
                        Ok(listeners) => listeners,
                        Err(e) => {
                            abort_join_handles(handles);
                            return Err(e);
                        }
                    };
                for listener in listeners {
                    let tcp_config = tcp_config.clone();
                    let tcp_handler = tcp_handler.clone();
                    let resolver = resolver.clone();
                    handles.push(tokio::spawn(async move {
                        run_tcp_server(listener, tcp_config, resolver, tcp_handler)
                            .await
                            .unwrap();
                    }));
                }
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let listener = match bind_unix_listener(&path_buf).await {
                    Ok(listener) => listener,
                    Err(e) => {
                        abort_join_handles(handles);
                        return Err(e);
                    }
                };
                let tcp_handler = tcp_handler.clone();
                let handle = tokio::spawn(async move {
                    run_unix_server(listener, resolver, tcp_handler)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    Ok(handles)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::address::{Address, NetLocationMask};
    use crate::client_proxy_selector::{ConnectAction, ConnectMatcher, ConnectRule};
    use crate::tcp::chain_builder::build_direct_chain_group;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestStream {
        read: Vec<u8>,
        read_offset: usize,
        written: Vec<u8>,
    }

    impl TestStream {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read,
                read_offset: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining = self.read.len().saturating_sub(self.read_offset);
            if remaining == 0 || buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = remaining.min(buf.remaining());
            let start = self.read_offset;
            let end = start + n;
            buf.put_slice(&self.read[start..end]);
            self.read_offset = end;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
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
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    struct PendingShutdownTestStream;

    impl AsyncRead for PendingShutdownTestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingShutdownTestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncPing for PendingShutdownTestStream {
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

    impl AsyncStream for PendingShutdownTestStream {}

    #[tokio::test]
    async fn tcp_stream_cleanup_is_bounded_when_shutdown_remains_pending() {
        let mut server = PendingShutdownTestStream;
        let mut client = PendingShutdownTestStream;

        tokio::time::timeout(
            Duration::from_millis(100),
            shutdown_tcp_stream_pair(&mut server, &mut client, Duration::from_millis(10)),
        )
        .await
        .expect("TCP stream cleanup exceeded its shutdown deadline");
    }

    struct PendingShutdownMessageTestStream;

    impl AsyncReadMessage for PendingShutdownMessageTestStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for PendingShutdownMessageTestStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for PendingShutdownMessageTestStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for PendingShutdownMessageTestStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncPing for PendingShutdownMessageTestStream {
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

    impl AsyncMessageStream for PendingShutdownMessageTestStream {}

    struct TestMessageStream {
        read: Option<Vec<u8>>,
        written: Vec<Vec<u8>>,
    }

    impl TestMessageStream {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read: Some(read),
                written: Vec::new(),
            }
        }
    }

    impl AsyncReadMessage for TestMessageStream {
        fn poll_read_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(data) = self.read.take() else {
                return Poll::Ready(Ok(()));
            };
            buf.put_slice(&data[..data.len().min(buf.remaining())]);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWriteMessage for TestMessageStream {
        fn poll_write_message(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<()>> {
            self.written.push(buf.to_vec());
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for TestMessageStream {
        fn poll_flush_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for TestMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TestMessageStream {
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

    impl AsyncMessageStream for TestMessageStream {}

    #[tokio::test]
    async fn udp_copy_cleanup_is_bounded_when_message_shutdown_remains_pending() {
        let server: Box<dyn AsyncMessageStream> = Box::new(PendingShutdownMessageTestStream);
        let client: Box<dyn AsyncMessageStream> = Box::new(TestMessageStream::new(Vec::new()));

        tokio::time::timeout(
            Duration::from_millis(100),
            run_udp_copy(server, client, false, false),
        )
        .await
        .expect("UDP copy cleanup exceeded its shutdown deadline")
        .unwrap();
    }

    #[derive(Default, Debug)]
    struct TestRecorder {
        traffic: Mutex<(u64, u64)>,
        alive_ips: Mutex<Vec<IpAddr>>,
        removed_ips: Mutex<Vec<IpAddr>>,
        pending_flushes: Mutex<usize>,
    }

    impl TrafficRecorder for TestRecorder {
        fn add_traffic(&self, _node_tag: &str, _uid: u64, upload: u64, download: u64) {
            let mut traffic = self.traffic.lock();
            traffic.0 += upload;
            traffic.1 += download;
        }

        fn flush_pending_traffic(&self) {
            *self.pending_flushes.lock() += 1;
        }

        fn add_alive_ip_and_check_limit(
            &self,
            _node_tag: &str,
            _uid: u64,
            ip: IpAddr,
            _device_limit: Option<u64>,
        ) -> bool {
            self.alive_ips.lock().push(ip);
            true
        }

        fn remove_alive_ip(&self, _node_tag: &str, _uid: u64, ip: IpAddr) {
            self.removed_ips.lock().push(ip);
        }
    }

    #[derive(Debug)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn authenticated_user(uid: u64, speed_limit: Option<u64>) -> Option<AuthenticatedUser> {
        Some(AuthenticatedUser {
            node_tag: "node-a".into(),
            uid,
            user_key: format!("user-{uid}"),
            speed_limit,
            device_limit: None,
            recorder: None,
        })
    }

    #[test]
    fn the_stream_limit_counts_streams_already_being_served() {
        assert!(!at_stream_limit(0, 1));
        assert!(!at_stream_limit(98, 99));
        // At the limit the node is already serving as many as it was told to.
        assert!(at_stream_limit(99, 99));
        assert!(at_stream_limit(100, 99));
    }

    #[tokio::test]
    async fn active_connections_register_with_the_sweeper_and_deregister_on_close() {
        let recorder = Arc::new(TestRecorder::default());
        let user = authenticated_user_with_recorder(9001, recorder.clone());
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));

        let before = active_traffic_len();
        let task = TrafficFlushTask::start(&user, upload.clone(), download.clone());
        assert_eq!(
            active_traffic_len(),
            before + 1,
            "an authenticated connection must be visible to the sweeper"
        );

        // Closing must take it back out, or the sweeper would keep reporting
        // for a connection that no longer exists -- the leak the per-connection
        // task could not have.
        upload.store(11, Ordering::Relaxed);
        download.store(22, Ordering::Relaxed);
        drop(task);
        assert_eq!(active_traffic_len(), before);
        assert_eq!(*recorder.traffic.lock(), (11, 22));

        // A connection with no recorder is not registered at all.
        let anonymous = TrafficFlushTask::start(
            &None,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        assert_eq!(active_traffic_len(), before);
        drop(anonymous);
    }

    fn authenticated_user_with_tag(
        node_tag: &str,
        uid: u64,
        speed_limit: Option<u64>,
    ) -> Option<AuthenticatedUser> {
        Some(AuthenticatedUser {
            node_tag: node_tag.into(),
            uid,
            user_key: format!("user-{uid}"),
            speed_limit,
            device_limit: None,
            recorder: None,
        })
    }

    fn authenticated_user_with_recorder(
        uid: u64,
        recorder: Arc<dyn TrafficRecorder>,
    ) -> Option<AuthenticatedUser> {
        Some(AuthenticatedUser {
            node_tag: "node-a".into(),
            uid,
            user_key: format!("user-{uid}"),
            speed_limit: None,
            device_limit: None,
            recorder: Some(recorder),
        })
    }

    fn direct_allow_selector(
        resolver: Arc<dyn Resolver>,
        require_http_sniff: bool,
    ) -> Arc<ClientProxySelector> {
        let matcher = if require_http_sniff {
            ConnectMatcher::protocol(SniffedProtocol::Http)
        } else {
            ConnectMatcher::Location(NetLocationMask::from("0.0.0.0/0").unwrap())
        };
        Arc::new(ClientProxySelector::new(vec![ConnectRule::new_matchers(
            vec![matcher],
            ConnectAction::new_allow(None, build_direct_chain_group(resolver)),
        )]))
    }

    async fn start_tcp_sink() -> (NetLocation, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let remote_location = NetLocation::new(
            match addr.ip() {
                IpAddr::V4(ip) => Address::Ipv4(ip),
                IpAddr::V6(ip) => Address::Ipv6(ip),
            },
            addr.port(),
        );
        (remote_location, handle)
    }

    #[test]
    fn panel_speed_limit_to_bytes_per_sec_handles_v2board_mbps() {
        assert_eq!(panel_speed_limit_to_bytes_per_sec(0), None);
        assert_eq!(panel_speed_limit_to_bytes_per_sec(1), Some(125_000));
        assert_eq!(panel_speed_limit_to_bytes_per_sec(100), Some(12_500_000));
    }

    #[test]
    fn available_or_delay_waits_for_a_chunk_instead_of_dribbling_bytes() {
        // 1 Mbps is the common panel limit; the bucket starts full.
        let limiter = RateLimiter::new(125_000);
        limiter.consume(250_000);

        // A bucket holding a few bytes must ask the caller to wait rather than
        // authorise a tiny read, which would spin one poll per handful of bytes.
        limiter.state.lock().tokens = 64.0;
        let delay = limiter
            .available_or_delay(65_536)
            .expect_err("a nearly-empty bucket must delay");
        // Waiting for the 4 KiB floor at 125 kB/s is ~32ms, not the 1ms minimum.
        assert!(delay >= Duration::from_millis(30), "delay was {delay:?}");

        // Once a full chunk has accumulated the read is authorised.
        limiter.state.lock().tokens = MIN_LIMITED_CHUNK_BYTES as f64;
        assert_eq!(
            limiter.available_or_delay(65_536).unwrap(),
            MIN_LIMITED_CHUNK_BYTES
        );
    }

    #[test]
    fn available_or_delay_never_waits_past_the_request_or_bucket() {
        // A request smaller than the chunk floor must not block on tokens the
        // caller never asked for.
        let limiter = RateLimiter::new(125_000);
        limiter.state.lock().tokens = 16.0;
        assert_eq!(limiter.available_or_delay(8).unwrap(), 8);

        // A bucket whose capacity is below the floor must still make progress
        // rather than wait forever for tokens it can never hold.
        let tiny = RateLimiter::new(1);
        assert!(tiny.state.lock().burst_bytes < MIN_LIMITED_CHUNK_BYTES as f64);
        assert!(tiny.available_or_delay(65_536).is_ok());
    }

    #[test]
    fn speed_limiter_for_mbps_ignores_zero_and_maps_v2board_units() {
        assert!(speed_limiter_for_mbps(None).is_none());
        assert!(speed_limiter_for_mbps(Some(0)).is_none());
        assert_eq!(
            speed_limiter_for_mbps(Some(3))
                .unwrap()
                .rate_bytes_per_sec(),
            375_000
        );
    }

    #[test]
    fn authenticated_connection_scope_keeps_directional_limits_separate() {
        let scope = AuthenticatedConnectionScope::start_with_directional_speed_limits(
            &None,
            None,
            Some(2),
            Some(5),
        )
        .unwrap();

        assert_eq!(
            scope
                .upload_speed_limiter
                .as_ref()
                .unwrap()
                .rate_bytes_per_sec(),
            250_000
        );
        assert_eq!(
            scope
                .download_speed_limiter
                .as_ref()
                .unwrap()
                .rate_bytes_per_sec(),
            625_000
        );
    }

    #[test]
    fn user_speed_limiter_is_shared_by_node_and_uid() {
        let user = authenticated_user(1001, Some(2));
        let first = speed_limiter_for(&user).unwrap();
        let second = speed_limiter_for(&user).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.rate_bytes_per_sec(), 250_000);
    }

    #[test]
    fn user_speed_limiter_updates_and_clears_runtime_config() {
        let user = authenticated_user(1002, Some(1));
        let first = speed_limiter_for(&user).unwrap();
        assert_eq!(first.rate_bytes_per_sec(), 125_000);

        let updated = authenticated_user(1002, Some(4));
        let second = speed_limiter_for(&updated).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.rate_bytes_per_sec(), 500_000);

        assert!(speed_limiter_for(&authenticated_user(1002, Some(0))).is_none());
        let recreated = speed_limiter_for(&authenticated_user(1002, Some(2))).unwrap();
        assert!(!Arc::ptr_eq(&first, &recreated));
        assert_eq!(recreated.rate_bytes_per_sec(), 250_000);
    }

    #[test]
    fn directional_speed_limiters_clone_shared_node_buckets() {
        let limiters = DirectionalSpeedLimiters::from_mbps(Some(3), Some(5));
        let cloned = limiters.clone();

        assert_eq!(limiters.upload_rate_bytes_per_sec(), Some(375_000));
        assert_eq!(limiters.download_rate_bytes_per_sec(), Some(625_000));
        assert!(limiters.shares_buckets_with(&cloned));
    }

    #[test]
    fn reconcile_speed_limiters_drops_users_absent_from_panel_list() {
        let node_tag = "reconcile-test-node";
        let users = vec![
            authenticated_user_with_tag(node_tag, 7001, Some(2)),
            authenticated_user_with_tag(node_tag, 7002, Some(3)),
        ];
        for user in &users {
            assert!(speed_limiter_for(user).is_some());
        }
        assert_eq!(speed_limiter_map_len_for(node_tag), 2);

        // A user removed from the panel leaves; the survivor stays.
        let active: std::collections::HashSet<u64> = [7001u64].into_iter().collect();
        reconcile_speed_limiters(node_tag, &active);
        assert!(speed_limiter_map_contains(node_tag, 7001));
        assert!(!speed_limiter_map_contains(node_tag, 7002));

        // Reconciling with an empty list drains the node entirely.
        reconcile_speed_limiters(node_tag, &std::collections::HashSet::new());
        assert_eq!(speed_limiter_map_len_for(node_tag), 0);
    }

    #[tokio::test]
    async fn speed_limited_stream_read_advances_caller_buffer() {
        let payload = b"GET /fast.bin HTTP/1.1\r\n\r\n".to_vec();
        let inner: Box<dyn AsyncStream> = Box::new(TestStream::new(payload.clone()));
        let limiter = Arc::new(RateLimiter::new(125_000));
        let mut stream = SpeedLimitedStream::new(inner, limiter);
        let mut received = vec![0; payload.len() + 8];

        let n = stream.read(&mut received).await.unwrap();

        assert_eq!(n, payload.len());
        assert_eq!(&received[..n], payload.as_slice());
    }

    #[tokio::test]
    async fn tcp_protocol_sniff_preserves_bytes_read_from_stream() {
        let payload = b"GET /payload.bin HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream::new(payload.clone()));
        let mut initial_remote_data = None;

        let protocol = sniff_tcp_forward_protocol(&mut stream, &mut initial_remote_data)
            .await
            .unwrap();

        assert_eq!(protocol, Some(SniffedProtocol::Http));
        assert_eq!(initial_remote_data.unwrap(), payload);

        let mut rest = [0; 1];
        assert_eq!(stream.read(&mut rest).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn tcp_protocol_sniff_appends_to_existing_initial_data() {
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream::new(
            b"BitTorrent protocol\x00\x00\x00\x00".to_vec(),
        ));
        let mut initial_remote_data = Some(vec![0x13]);

        let protocol = sniff_tcp_forward_protocol(&mut stream, &mut initial_remote_data)
            .await
            .unwrap();

        assert_eq!(protocol, Some(SniffedProtocol::Bittorrent));
        assert_eq!(
            initial_remote_data.unwrap(),
            b"\x13BitTorrent protocol\x00\x00\x00\x00".to_vec()
        );
    }

    #[tokio::test]
    async fn udp_protocol_sniff_preserves_quic_datagram() {
        let payload = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xde, 0xad];
        let mut stream: Box<dyn AsyncMessageStream> =
            Box::new(TestMessageStream::new(payload.clone()));

        let (protocol, initial_data) = sniff_bidirectional_udp_protocol(&mut stream).await.unwrap();

        assert_eq!(protocol, Some(SniffedProtocol::Quic));
        assert_eq!(initial_data.unwrap().as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn traffic_flush_task_flushes_pending_deltas_on_drop() {
        let recorder = Arc::new(TestRecorder::default());
        let upload = Arc::new(AtomicU64::new(11));
        let download = Arc::new(AtomicU64::new(22));
        let user = Some(AuthenticatedUser {
            node_tag: "node-a".into(),
            uid: 1003,
            user_key: "user-1003".to_string(),
            speed_limit: None,
            device_limit: None,
            recorder: Some(recorder.clone()),
        });

        {
            let _task = TrafficFlushTask::start(&user, upload.clone(), download.clone());
        }

        assert_eq!(*recorder.traffic.lock(), (11, 22));
        assert_eq!(*recorder.pending_flushes.lock(), 1);
        assert_eq!(upload.load(Ordering::Relaxed), 0);
        assert_eq!(download.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn traffic_flush_task_skips_pending_flush_without_deltas_on_drop() {
        let recorder = Arc::new(TestRecorder::default());
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        let user = Some(AuthenticatedUser {
            node_tag: "node-a".into(),
            uid: 1004,
            user_key: "user-1004".to_string(),
            speed_limit: None,
            device_limit: None,
            recorder: Some(recorder.clone()),
        });

        {
            let _task = TrafficFlushTask::start(&user, upload, download);
        }

        assert_eq!(*recorder.traffic.lock(), (0, 0));
        assert_eq!(*recorder.pending_flushes.lock(), 0);
    }

    #[tokio::test]
    async fn tcp_forward_counts_initial_remote_data_as_upload() {
        let recorder = Arc::new(TestRecorder::default());
        let authenticated_user = authenticated_user_with_recorder(1006, recorder.clone());
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);
        let (remote_location, target) = start_tcp_sink().await;
        let initial_remote_data =
            b"GET /payload.bin HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();

        handle_server_setup_result(
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(TestStream::new(Vec::new())),
                need_initial_flush: false,
                connection_success_response: None,
                initial_remote_data: Some(initial_remote_data.clone().into_boxed_slice()),
                proxy_selector: direct_allow_selector(resolver.clone(), false),
                outbound_dispatcher: None,
                authenticated_user,
            },
            resolver,
            Some("127.0.0.1:50000".parse().unwrap()),
        )
        .await
        .unwrap();

        assert_eq!(target.await.unwrap(), initial_remote_data);
        assert_eq!(
            *recorder.traffic.lock(),
            (initial_remote_data.len() as u64, 0)
        );
        assert_eq!(*recorder.pending_flushes.lock(), 1);
    }

    #[tokio::test]
    async fn tcp_forward_counts_premetered_initial_data_without_double_counting_sniffed_bytes() {
        let recorder = Arc::new(TestRecorder::default());
        let authenticated_user = authenticated_user_with_recorder(1007, recorder.clone());
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);
        let (remote_location, target) = start_tcp_sink().await;
        let prefix = b"GE".to_vec();
        let suffix = b"T /sniffed.bin HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
        let mut expected = prefix.clone();
        expected.extend_from_slice(&suffix);

        handle_server_setup_result(
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(TestStream::new(suffix)),
                need_initial_flush: false,
                connection_success_response: None,
                initial_remote_data: Some(prefix.into_boxed_slice()),
                proxy_selector: direct_allow_selector(resolver.clone(), true),
                outbound_dispatcher: None,
                authenticated_user,
            },
            resolver,
            Some("127.0.0.1:50001".parse().unwrap()),
        )
        .await
        .unwrap();

        assert_eq!(target.await.unwrap(), expected);
        assert_eq!(*recorder.traffic.lock(), (expected.len() as u64, 0));
        assert_eq!(*recorder.pending_flushes.lock(), 1);
    }

    #[tokio::test]
    async fn authenticated_scope_supports_naiveproxy_split_metering() {
        let user = authenticated_user(1005, None);
        let scope = AuthenticatedConnectionScope::start(&user, None).unwrap();

        let mut client_side =
            scope.wrap_stream_upload_metered_only(Box::new(TestStream::new(b"up".to_vec())));
        let mut upload = [0; 2];
        client_side.read_exact(&mut upload).await.unwrap();
        client_side.write_all(b"down-through-h2").await.unwrap();

        assert_eq!(scope.upload_counter.load(Ordering::Relaxed), 2);
        assert_eq!(scope.download_counter.load(Ordering::Relaxed), 0);

        let mut remote_side = scope
            .wrap_download_read_metered_stream(Box::new(TestStream::new(b"download".to_vec())));
        let mut download = [0; 8];
        remote_side.read_exact(&mut download).await.unwrap();
        remote_side.write_all(b"request").await.unwrap();

        assert_eq!(scope.upload_counter.load(Ordering::Relaxed), 2);
        assert_eq!(scope.download_counter.load(Ordering::Relaxed), 8);
    }

    #[tokio::test]
    async fn peer_address_override_drives_device_limit_alive_ip() {
        let recorder = Arc::new(TestRecorder::default());
        let proxied_peer = "198.18.0.41:42441".parse::<SocketAddr>().unwrap();
        let kernel_peer = "127.0.0.1:50000".parse::<SocketAddr>().unwrap();
        let authenticated_user = Some(AuthenticatedUser {
            node_tag: "node-a".into(),
            uid: 1004,
            user_key: "user-1004".to_string(),
            speed_limit: None,
            device_limit: Some(1),
            recorder: Some(recorder.clone()),
        });
        let setup_result = TcpServerSetupResult::PeerAddressOverride {
            peer_addr: Some(proxied_peer),
            result: Box::new(TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::UNSPECIFIED,
                stream: Box::new(TestStream::new(Vec::new())),
                need_initial_flush: false,
                connection_success_response: None,
                initial_remote_data: None,
                proxy_selector: Arc::new(ClientProxySelector::new(Vec::new())),
                outbound_dispatcher: None,
                authenticated_user,
            }),
        };

        handle_server_setup_result(setup_result, Arc::new(NoopResolver), Some(kernel_peer))
            .await
            .unwrap();

        assert_eq!(*recorder.alive_ips.lock(), vec![proxied_peer.ip()]);
        assert_eq!(*recorder.removed_ips.lock(), vec![proxied_peer.ip()]);
    }
}
