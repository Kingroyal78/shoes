use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ::http::{HeaderMap, Request, Response, StatusCode};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Bytes, BytesMut};
use futures::future::poll_fn;
use h2::RecvStream;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use url::form_urlencoded;

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::handle_server_setup_result;
use crate::util::write_all;

const MAX_H2_WRITE_PAYLOAD_LEN: usize = 16 * 1024;
const DEFAULT_MAX_EACH_POST_BYTES: usize = 1_000_000;
const DEFAULT_MAX_BUFFERED_POSTS: usize = 30;
const SESSION_REAP_SECS: u64 = 30;
/// Connected sessions idle longer than this are reaped so the client-controlled
/// session registry cannot pin entries (and their buffers) forever.
const SESSION_IDLE_REAP_SECS: u64 = 120;
/// Interval of the session reaper loop.
const SESSION_REAP_INTERVAL_SECS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XHttpConfig {
    pub host: Option<String>,
    pub path: String,
    pub mode: XHttpMode,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub max_each_post_bytes: usize,
    pub max_buffered_posts: usize,
    pub session_id_placement: XHttpPlacement,
    pub session_id_key: String,
    pub seq_placement: XHttpPlacement,
    pub seq_key: String,
    pub uplink_data_placement: XHttpDataPlacement,
    pub uplink_data_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XHttpConfigParts {
    pub host: Option<String>,
    pub path: String,
    pub mode: XHttpMode,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub max_each_post_bytes: Option<usize>,
    pub max_buffered_posts: Option<usize>,
    pub session_id_placement: XHttpPlacement,
    pub session_id_key: Option<String>,
    pub seq_placement: XHttpPlacement,
    pub seq_key: Option<String>,
    pub uplink_data_placement: XHttpDataPlacement,
    pub uplink_data_key: Option<String>,
}

impl XHttpConfig {
    pub fn new(parts: XHttpConfigParts) -> Self {
        let XHttpConfigParts {
            host,
            path,
            mode,
            no_grpc_header,
            no_sse_header,
            max_each_post_bytes,
            max_buffered_posts,
            session_id_placement,
            session_id_key,
            seq_placement,
            seq_key,
            uplink_data_placement,
            uplink_data_key,
        } = parts;

        let session_id_key = session_id_key
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| match session_id_placement {
                XHttpPlacement::Header => "X-Session".to_string(),
                XHttpPlacement::Cookie | XHttpPlacement::Query => "x_session".to_string(),
                XHttpPlacement::Path => String::new(),
            });
        let seq_key = seq_key
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| match seq_placement {
                XHttpPlacement::Header => "X-Seq".to_string(),
                XHttpPlacement::Cookie | XHttpPlacement::Query => "x_seq".to_string(),
                XHttpPlacement::Path => String::new(),
            });
        let uplink_data_key = uplink_data_key
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| match uplink_data_placement {
                XHttpDataPlacement::Cookie => "x_data".to_string(),
                XHttpDataPlacement::Header | XHttpDataPlacement::Auto => "X-Data".to_string(),
                XHttpDataPlacement::Body => String::new(),
            });
        let path = normalize_path(path, session_id_placement, seq_placement);
        Self {
            host: host
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty()),
            path,
            mode,
            no_grpc_header,
            no_sse_header,
            max_each_post_bytes: max_each_post_bytes
                .unwrap_or(DEFAULT_MAX_EACH_POST_BYTES)
                .max(1),
            max_buffered_posts: max_buffered_posts
                .unwrap_or(DEFAULT_MAX_BUFFERED_POSTS)
                .max(1),
            session_id_placement,
            session_id_key,
            seq_placement,
            seq_key,
            uplink_data_placement,
            uplink_data_key,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XHttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XHttpPlacement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XHttpDataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Debug)]
pub struct XHttpServerHandler {
    config: XHttpConfig,
    sessions: SessionMap,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    http2: bool,
}

type SessionMap = Arc<Mutex<HashMap<String, Arc<XHttpSession>>>>;

#[derive(Debug)]
struct XHttpSession {
    tx: mpsc::Sender<XHttpPacket>,
    rx: Mutex<Option<mpsc::Receiver<XHttpPacket>>>,
    connected: AtomicBool,
    /// Milliseconds since a process-global reference point of the last upload
    /// or download activity. Uses tokio's monotonic clock so the idle-reap
    /// logic is deterministic under `tokio::time::pause()` in tests.
    last_activity: AtomicU64,
}

static ACTIVITY_EPOCH: LazyLock<tokio::time::Instant> = LazyLock::new(tokio::time::Instant::now);

fn activity_millis() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_millis() as u64
}

#[derive(Debug)]
struct XHttpPacket {
    seq: u64,
    payload: Bytes,
}

impl XHttpServerHandler {
    pub fn new(
        config: XHttpConfig,
        handler: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
        http2: bool,
    ) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            handler,
            resolver,
            http2,
        }
    }

    async fn run_h2(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let connection = h2::server::handshake(server_stream)
            .await
            .map_err(h2_error)?;
        spawn_h2_accept_loop(
            connection,
            self.config.clone(),
            self.sessions.clone(),
            self.handler.clone(),
            self.resolver.clone(),
            peer_addr,
        );
        Ok(TcpServerSetupResult::AlreadyHandled)
    }

    async fn run_http1(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let request = ParsedHttp1Request::parse(&mut server_stream).await?;
        validate_host(&self.config, request.host.as_deref())?;
        validate_path(&self.config, &request.path)?;
        if request.method.eq_ignore_ascii_case("OPTIONS") {
            write_http1_status(
                &mut server_stream,
                StatusCode::OK,
                &self.config,
                &request.method,
                &request.headers,
                true,
            )
            .await?;
            return Ok(TcpServerSetupResult::AlreadyHandled);
        }
        let meta = extract_meta(
            &self.config,
            &request.path,
            request.query.as_deref(),
            &request.headers,
        );
        let kind = classify_request(&self.config, &request.method, meta)?;

        match kind {
            XHttpRequestKind::PacketUp { session_id, seq } => {
                let body = read_http1_body(
                    &mut server_stream,
                    &request.reader,
                    request.content_length,
                    self.config.max_each_post_bytes,
                )
                .await?;
                let payload = packet_payload(&self.config, &request.headers, body)?;
                let session = get_or_create_session(
                    &self.sessions,
                    &session_id,
                    self.config.max_buffered_posts,
                );
                push_packet(&session, seq, payload).await?;
                write_http1_status(
                    &mut server_stream,
                    StatusCode::OK,
                    &self.config,
                    &request.method,
                    &request.headers,
                    true,
                )
                .await?;
                Ok(TcpServerSetupResult::AlreadyHandled)
            }
            XHttpRequestKind::StreamUp { session_id } => {
                let body = read_http1_body(
                    &mut server_stream,
                    &request.reader,
                    request.content_length,
                    self.config.max_each_post_bytes,
                )
                .await?;
                let session = get_or_create_session(
                    &self.sessions,
                    &session_id,
                    self.config.max_buffered_posts,
                );
                push_packet(&session, 0, body).await?;
                write_http1_status(
                    &mut server_stream,
                    StatusCode::OK,
                    &self.config,
                    &request.method,
                    &request.headers,
                    true,
                )
                .await?;
                Ok(TcpServerSetupResult::AlreadyHandled)
            }
            XHttpRequestKind::StreamDown { session_id } => {
                let reader = take_session_reader(
                    &self.sessions,
                    &session_id,
                    self.config.max_buffered_posts,
                )?;
                write_http1_status(
                    &mut server_stream,
                    StatusCode::OK,
                    &self.config,
                    &request.method,
                    &request.headers,
                    false,
                )
                .await?;
                let stream = Box::new(XHttpStream::new(
                    XHttpReadHalf::Upload(reader),
                    XHttpWriteHalf::Http1(server_stream),
                ));
                self.handler
                    .setup_server_stream_with_peer_addr(stream, peer_addr)
                    .await
            }
            XHttpRequestKind::StreamOne => {
                let body = read_http1_body(
                    &mut server_stream,
                    &request.reader,
                    request.content_length,
                    self.config.max_each_post_bytes,
                )
                .await?;
                write_http1_status(
                    &mut server_stream,
                    StatusCode::OK,
                    &self.config,
                    &request.method,
                    &request.headers,
                    false,
                )
                .await?;
                let stream = Box::new(XHttpStream::new(
                    XHttpReadHalf::Bytes(BytesReadHalf::new(body)),
                    XHttpWriteHalf::Http1(server_stream),
                ));
                self.handler
                    .setup_server_stream_with_peer_addr(stream, peer_addr)
                    .await
            }
        }
    }
}

#[async_trait]
impl TcpServerHandler for XHttpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(server_stream, None)
            .await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        if self.http2 {
            self.run_h2(server_stream, peer_addr).await
        } else {
            self.run_http1(server_stream, peer_addr).await
        }
    }
}

fn spawn_h2_accept_loop<T>(
    mut connection: h2::server::Connection<T, Bytes>,
    config: XHttpConfig,
    sessions: SessionMap,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            let (request, respond) = match result {
                Ok(parts) => parts,
                Err(e) => {
                    log::debug!("xhttp h2 connection stopped: {e}");
                    break;
                }
            };
            tokio::spawn(handle_h2_request(
                request,
                respond,
                config.clone(),
                sessions.clone(),
                handler.clone(),
                resolver.clone(),
                peer_addr,
            ));
        }
    });
}

async fn handle_h2_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: XHttpConfig,
    sessions: SessionMap,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) {
    if let Err(e) = handle_h2_request_result(
        request,
        &mut respond,
        config,
        sessions,
        handler,
        resolver,
        peer_addr,
    )
    .await
    {
        log::debug!("xhttp h2 request failed: {e}");
    }
}

async fn handle_h2_request_result(
    request: Request<RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    config: XHttpConfig,
    sessions: SessionMap,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()> {
    validate_host(&config, request_authority(&request).as_deref())?;
    validate_path(&config, request.uri().path())?;
    let headers = header_map_to_strings(request.headers());
    let method = request.method().as_str().to_string();
    if method.eq_ignore_ascii_case("OPTIONS") {
        let (_parts, _recv) = request.into_parts();
        respond
            .send_response(
                h2_response(StatusCode::OK, &config, &method, &headers, true)?,
                true,
            )
            .map_err(h2_error)?;
        return Ok(());
    }
    let meta = extract_meta(
        &config,
        request.uri().path(),
        request.uri().query(),
        &headers,
    );
    let kind = classify_request(&config, &method, meta)?;
    let (_parts, recv) = request.into_parts();

    match kind {
        XHttpRequestKind::PacketUp { session_id, seq } => {
            let body = read_h2_body(recv, config.max_each_post_bytes).await?;
            let payload = packet_payload(&config, &headers, body)?;
            let session = get_or_create_session(&sessions, &session_id, config.max_buffered_posts);
            push_packet(&session, seq, payload).await?;
            respond
                .send_response(
                    h2_response(StatusCode::OK, &config, &method, &headers, true)?,
                    true,
                )
                .map_err(h2_error)?;
        }
        XHttpRequestKind::StreamUp { session_id } => {
            let response = h2_response(StatusCode::OK, &config, &method, &headers, false)?;
            let mut send = respond.send_response(response, false).map_err(h2_error)?;
            let session = get_or_create_session(&sessions, &session_id, config.max_buffered_posts);
            stream_h2_body_to_session(recv, session, config.max_each_post_bytes).await?;
            send.send_data(Bytes::new(), true).map_err(h2_error)?;
        }
        XHttpRequestKind::StreamDown { session_id } => {
            let reader = take_session_reader(&sessions, &session_id, config.max_buffered_posts)?;
            let response = h2_response(StatusCode::OK, &config, &method, &headers, false)?;
            let send = respond.send_response(response, false).map_err(h2_error)?;
            let stream = Box::new(XHttpStream::new(
                XHttpReadHalf::Upload(reader),
                XHttpWriteHalf::Http2 {
                    send,
                    shutdown_sent: false,
                },
            ));
            let mut setup_result = handler
                .setup_server_stream_with_peer_addr(stream, peer_addr)
                .await?;
            if !matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                setup_result.set_need_initial_flush(true);
            }
            handle_server_setup_result(setup_result, resolver, peer_addr).await?;
        }
        XHttpRequestKind::StreamOne => {
            let response = h2_response(StatusCode::OK, &config, &method, &headers, false)?;
            let send = respond.send_response(response, false).map_err(h2_error)?;
            let stream = Box::new(XHttpStream::new(
                XHttpReadHalf::Http2 {
                    recv,
                    recv_buf: Bytes::new(),
                },
                XHttpWriteHalf::Http2 {
                    send,
                    shutdown_sent: false,
                },
            ));
            let mut setup_result = handler
                .setup_server_stream_with_peer_addr(stream, peer_addr)
                .await?;
            if !matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                setup_result.set_need_initial_flush(true);
            }
            handle_server_setup_result(setup_result, resolver, peer_addr).await?;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum XHttpRequestKind {
    PacketUp { session_id: String, seq: u64 },
    StreamUp { session_id: String },
    StreamDown { session_id: String },
    StreamOne,
}

#[derive(Debug)]
struct XHttpMeta {
    session_id: Option<String>,
    seq: Option<String>,
}

fn classify_request(
    config: &XHttpConfig,
    method: &str,
    meta: XHttpMeta,
) -> io::Result<XHttpRequestKind> {
    let method = method.to_ascii_uppercase();
    let XHttpMeta { session_id, seq } = meta;
    let is_uplink = if method == "GET" { seq.is_some() } else { true };

    match (is_uplink, method.as_str(), session_id, seq) {
        (true, _, Some(session_id), Some(seq)) => {
            if !matches!(config.mode, XHttpMode::Auto | XHttpMode::PacketUp) {
                return invalid("xhttp packet-up request is not allowed by configured mode");
            }
            let seq = seq.parse::<u64>().map_err(|e| {
                invalid_error(format!("xhttp packet-up seq `{seq}` is invalid: {e}"))
            })?;
            Ok(XHttpRequestKind::PacketUp { session_id, seq })
        }
        (true, _, Some(session_id), None) => {
            if !matches!(config.mode, XHttpMode::Auto | XHttpMode::StreamUp) {
                return invalid("xhttp stream-up request is not allowed by configured mode");
            }
            Ok(XHttpRequestKind::StreamUp { session_id })
        }
        (_, "GET", Some(session_id), _) => {
            if matches!(config.mode, XHttpMode::StreamOne) {
                return invalid("xhttp stream-down request is not allowed by stream-one mode");
            }
            Ok(XHttpRequestKind::StreamDown { session_id })
        }
        (true, _, None, Some(_)) => invalid("xhttp packet-up request is missing session id"),
        (_, "GET", None, _) => invalid("xhttp stream-down request is missing session id"),
        (_, _, None, _) => {
            if !matches!(
                config.mode,
                XHttpMode::Auto | XHttpMode::StreamOne | XHttpMode::StreamUp
            ) {
                return invalid("xhttp stream-one request is not allowed by configured mode");
            }
            Ok(XHttpRequestKind::StreamOne)
        }
        _ => invalid(format!("xhttp unsupported method `{method}`")),
    }
}

fn get_or_create_session(
    sessions: &SessionMap,
    session_id: &str,
    max_buffered_posts: usize,
) -> Arc<XHttpSession> {
    let mut guard = sessions.lock();
    if let Some(session) = guard.get(session_id).cloned() {
        return session;
    }

    let session = new_session(max_buffered_posts);
    guard.insert(session_id.to_string(), session.clone());
    drop(guard);

    spawn_session_reaper(sessions.clone(), session_id.to_string(), session.clone());
    session
}

fn take_session_reader(
    sessions: &SessionMap,
    session_id: &str,
    max_buffered_posts: usize,
) -> io::Result<XHttpUploadReader> {
    let mut created = None;
    let (session, receiver) = {
        let mut guard = sessions.lock();
        let session = match guard.get(session_id).cloned() {
            Some(session) => session,
            None => {
                let session = new_session(max_buffered_posts);
                guard.insert(session_id.to_string(), session.clone());
                created = Some(session.clone());
                session
            }
        };

        if session.connected.swap(true, Ordering::SeqCst) {
            return invalid(format!(
                "xhttp session `{session_id}` already has a download stream"
            ));
        }

        let receiver = session.rx.lock().take().ok_or_else(|| {
            invalid_error(format!("xhttp session `{session_id}` receiver is missing"))
        })?;
        (session, receiver)
    };

    if let Some(session) = created {
        spawn_session_reaper(sessions.clone(), session_id.to_string(), session);
    }

    Ok(XHttpUploadReader {
        receiver: Mutex::new(receiver),
        pending: BTreeMap::new(),
        next_seq: 0,
        current: Bytes::new(),
        max_buffered_posts,
        session_id: session_id.to_string(),
        session,
        sessions: sessions.clone(),
    })
}

fn new_session(max_buffered_posts: usize) -> Arc<XHttpSession> {
    let (tx, rx) = mpsc::channel(max_buffered_posts);
    Arc::new(XHttpSession {
        tx,
        rx: Mutex::new(Some(rx)),
        connected: AtomicBool::new(false),
        last_activity: AtomicU64::new(activity_millis()),
    })
}

fn touch_session(session: &XHttpSession) {
    session
        .last_activity
        .store(activity_millis(), Ordering::Relaxed);
}

fn spawn_session_reaper(sessions: SessionMap, session_id: String, session: Arc<XHttpSession>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SESSION_REAP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let idle_millis =
                activity_millis().saturating_sub(session.last_activity.load(Ordering::Relaxed));
            let stale = if session.connected.load(Ordering::SeqCst) {
                idle_millis > SESSION_IDLE_REAP_SECS * 1000
            } else {
                idle_millis > SESSION_REAP_SECS * 1000
            };
            if stale {
                remove_session_if_current(&sessions, &session_id, &session);
                break;
            }
            // Stop when the session was removed some other way (e.g. the
            // upload reader dropped) so the reaper task does not linger.
            let current = sessions.lock().get(&session_id).cloned();
            if current.is_none_or(|current| !Arc::ptr_eq(&current, &session)) {
                break;
            }
        }
    });
}

fn remove_session_if_current(sessions: &SessionMap, session_id: &str, session: &Arc<XHttpSession>) {
    let mut guard = sessions.lock();
    if guard
        .get(session_id)
        .is_some_and(|current| Arc::ptr_eq(current, session))
    {
        guard.remove(session_id);
    }
}

async fn push_packet(session: &XHttpSession, seq: u64, payload: Bytes) -> io::Result<()> {
    touch_session(session);
    session
        .tx
        .send(XHttpPacket { seq, payload })
        .await
        .map_err(|_| invalid_error("xhttp upload session is closed"))
}

async fn stream_h2_body_to_session(
    mut recv: RecvStream,
    session: Arc<XHttpSession>,
    limit: usize,
) -> io::Result<()> {
    let mut total = 0usize;
    let mut seq = 0u64;
    loop {
        let Some(data) = poll_fn(|cx| Pin::new(&mut recv).poll_data(cx)).await else {
            break;
        };
        let data = data.map_err(h2_error)?;
        let len = data.len();
        total = total
            .checked_add(len)
            .ok_or_else(|| invalid_error("xhttp stream-up body length overflow"))?;
        if total > limit {
            return invalid("xhttp stream-up body exceeds configured post size");
        }
        recv.flow_control()
            .release_capacity(len)
            .map_err(h2_error)?;
        push_packet(&session, seq, data).await?;
        seq += 1;
    }
    Ok(())
}

struct XHttpUploadReader {
    receiver: Mutex<mpsc::Receiver<XHttpPacket>>,
    pending: BTreeMap<u64, Bytes>,
    next_seq: u64,
    current: Bytes,
    max_buffered_posts: usize,
    session_id: String,
    session: Arc<XHttpSession>,
    sessions: SessionMap,
}

impl AsyncRead for XHttpUploadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        touch_session(&self.session);

        loop {
            if !self.current.is_empty() {
                let to_copy = self.current.len().min(buf.remaining());
                buf.put_slice(&self.current[..to_copy]);
                self.current = self.current.slice(to_copy..);
                return Poll::Ready(Ok(()));
            }

            let next_seq = self.next_seq;
            if let Some(payload) = self.pending.remove(&next_seq) {
                self.next_seq += 1;
                self.current = payload;
                continue;
            }

            let packet = {
                let mut receiver = self.receiver.lock();
                match Pin::new(&mut *receiver).poll_recv(cx) {
                    Poll::Ready(Some(packet)) => packet,
                    Poll::Ready(None) => {
                        if !self.pending.is_empty() {
                            return Poll::Ready(Err(invalid_error(format!(
                                "xhttp upload session closed before seq {}",
                                self.next_seq
                            ))));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            };

            if packet.seq == self.next_seq {
                self.next_seq += 1;
                self.current = packet.payload;
                continue;
            }

            if packet.seq < self.next_seq || self.pending.contains_key(&packet.seq) {
                continue;
            }
            if self.pending.len() >= self.max_buffered_posts {
                return Poll::Ready(Err(invalid_error("xhttp upload queue is too large")));
            }
            self.pending.insert(packet.seq, packet.payload);
        }
    }
}

impl Drop for XHttpUploadReader {
    fn drop(&mut self) {
        remove_session_if_current(&self.sessions, &self.session_id, &self.session);
    }
}

struct BytesReadHalf {
    bytes: Bytes,
}

impl BytesReadHalf {
    fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }
}

impl AsyncRead for BytesReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.bytes.is_empty() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let to_copy = self.bytes.len().min(buf.remaining());
        buf.put_slice(&self.bytes[..to_copy]);
        self.bytes = self.bytes.slice(to_copy..);
        Poll::Ready(Ok(()))
    }
}

enum XHttpReadHalf {
    Upload(XHttpUploadReader),
    Http2 { recv: RecvStream, recv_buf: Bytes },
    Bytes(BytesReadHalf),
}

enum XHttpWriteHalf {
    Http1(Box<dyn AsyncStream>),
    Http2 {
        send: h2::SendStream<Bytes>,
        shutdown_sent: bool,
    },
}

struct XHttpStream {
    read: XHttpReadHalf,
    write: XHttpWriteHalf,
}

impl XHttpStream {
    fn new(read: XHttpReadHalf, write: XHttpWriteHalf) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for XHttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.read {
            XHttpReadHalf::Upload(reader) => Pin::new(reader).poll_read(cx, buf),
            XHttpReadHalf::Bytes(reader) => Pin::new(reader).poll_read(cx, buf),
            XHttpReadHalf::Http2 { recv, recv_buf } => {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                if !recv_buf.is_empty() {
                    let to_copy = recv_buf.len().min(buf.remaining());
                    buf.put_slice(&recv_buf[..to_copy]);
                    *recv_buf = recv_buf.slice(to_copy..);
                    return Poll::Ready(Ok(()));
                }
                loop {
                    match Pin::new(&mut *recv).poll_data(cx) {
                        Poll::Ready(Some(Ok(data))) => {
                            let len = data.len();
                            recv.flow_control()
                                .release_capacity(len)
                                .map_err(h2_error)?;
                            if data.is_empty() {
                                continue;
                            }
                            let to_copy = data.len().min(buf.remaining());
                            buf.put_slice(&data[..to_copy]);
                            if to_copy < data.len() {
                                *recv_buf = data.slice(to_copy..);
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
                        Poll::Ready(None) => return Poll::Ready(Ok(())),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for XHttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.write {
            XHttpWriteHalf::Http1(stream) => Pin::new(stream).poll_write(cx, buf),
            XHttpWriteHalf::Http2 {
                send,
                shutdown_sent,
            } => poll_h2_write(send, *shutdown_sent, cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.write {
            XHttpWriteHalf::Http1(stream) => Pin::new(stream).poll_flush(cx),
            XHttpWriteHalf::Http2 { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.write {
            XHttpWriteHalf::Http1(stream) => Pin::new(stream).poll_shutdown(cx),
            XHttpWriteHalf::Http2 {
                send,
                shutdown_sent,
            } => {
                if !*shutdown_sent {
                    send.send_data(Bytes::new(), true).map_err(h2_error)?;
                    *shutdown_sent = true;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncPing for XHttpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for XHttpStream {}
impl AsyncStream for XHttpStream {}

impl fmt::Debug for XHttpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XHttpStream").finish_non_exhaustive()
    }
}

fn poll_h2_write(
    send: &mut h2::SendStream<Bytes>,
    shutdown_sent: bool,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if shutdown_sent {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "xhttp h2 stream is shut down",
        )));
    }
    let available = if send.capacity() > 0 {
        send.capacity()
    } else {
        send.reserve_capacity(buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN));
        match send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => capacity,
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "xhttp h2 send stream closed",
                )));
            }
            Poll::Pending => return Poll::Pending,
        }
    };
    if available == 0 {
        send.reserve_capacity(buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN));
        return Poll::Pending;
    }
    let payload_len = buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN).min(available);
    send.send_data(Bytes::copy_from_slice(&buf[..payload_len]), false)
        .map_err(h2_error)?;
    Poll::Ready(Ok(payload_len))
}

struct ParsedHttp1Request {
    method: String,
    path: String,
    query: Option<String>,
    host: Option<String>,
    headers: HashMap<String, String>,
    content_length: usize,
    reader: StreamReader,
}

impl ParsedHttp1Request {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> io::Result<Self> {
        let mut reader = StreamReader::new();
        let first_line = reader.read_line(stream).await?.to_string();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("");
        if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return invalid(format!("invalid xhttp request line `{first_line}`"));
        }
        let (path, query) = split_http_target(target);

        let mut headers = HashMap::new();
        let mut line_count = 0usize;
        loop {
            let line = reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }
            if line.len() >= 4096 {
                return invalid("xhttp request header line is too long");
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| invalid_error(format!("invalid xhttp header `{line}`")))?;
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            line_count += 1;
            if line_count >= 128 {
                return invalid("xhttp request has too many headers");
            }
        }
        let host = headers.get("host").cloned();
        let content_length = headers
            .get("content-length")
            .map(|value| {
                value.parse::<usize>().map_err(|e| {
                    invalid_error(format!("xhttp content-length `{value}` is invalid: {e}"))
                })
            })
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            method,
            path,
            query,
            host,
            headers,
            content_length,
            reader,
        })
    }
}

async fn read_http1_body(
    stream: &mut Box<dyn AsyncStream>,
    reader: &StreamReader,
    content_length: usize,
    limit: usize,
) -> io::Result<Bytes> {
    if content_length > limit {
        return invalid("xhttp request body exceeds configured post size");
    }
    let mut body = Vec::with_capacity(content_length);
    if let Some(unparsed) = reader.unparsed_data_owned() {
        let take = unparsed.len().min(content_length);
        body.extend_from_slice(&unparsed[..take]);
    }
    if body.len() < content_length {
        let mut remaining = vec![0u8; content_length - body.len()];
        stream.read_exact(&mut remaining).await?;
        body.extend_from_slice(&remaining);
    }
    Ok(Bytes::from(body))
}

fn split_http_target(target: &str) -> (String, Option<String>) {
    let path_with_query = if let Some(rest) = target.strip_prefix("http://") {
        match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        }
    } else if let Some(rest) = target.strip_prefix("https://") {
        match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        }
    } else {
        target
    };
    let (path, query) = path_with_query
        .split_once('?')
        .map(|(path, query)| (path, Some(query.to_string())))
        .unwrap_or((path_with_query, None));
    (path.to_string(), query)
}

fn validate_host(config: &XHttpConfig, actual: Option<&str>) -> io::Result<()> {
    let Some(expected) = &config.host else {
        return Ok(());
    };
    let actual = actual
        .ok_or_else(|| invalid_error("xhttp request is missing Host/:authority"))?
        .trim()
        .to_ascii_lowercase();
    if actual == *expected || actual.starts_with(&format!("{expected}:")) {
        Ok(())
    } else {
        invalid(format!("xhttp bad host `{actual}` expected `{expected}`"))
    }
}

fn validate_path(config: &XHttpConfig, path: &str) -> io::Result<()> {
    if path.starts_with(&config.path) {
        Ok(())
    } else {
        invalid(format!(
            "xhttp bad path `{path}` expected prefix `{}`",
            config.path
        ))
    }
}

fn extract_meta(
    config: &XHttpConfig,
    path: &str,
    query: Option<&str>,
    headers: &HashMap<String, String>,
) -> XHttpMeta {
    let cookies = headers
        .get("cookie")
        .map(|value| parse_cookies(value))
        .unwrap_or_default();
    let mut path_parts = Vec::new();
    let mut path_part = 0usize;
    if matches!(config.session_id_placement, XHttpPlacement::Path)
        || matches!(config.seq_placement, XHttpPlacement::Path)
    {
        let suffix = path.strip_prefix(&config.path).unwrap_or("");
        path_parts = suffix
            .split('/')
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }

    let session_id = match config.session_id_placement {
        XHttpPlacement::Path => {
            let value = path_parts.get(path_part).cloned();
            if value.is_some() {
                path_part += 1;
            }
            value
        }
        XHttpPlacement::Query => query_value(query, &config.session_id_key),
        XHttpPlacement::Header => headers
            .get(&config.session_id_key.to_ascii_lowercase())
            .cloned(),
        XHttpPlacement::Cookie => cookies.get(&config.session_id_key).cloned(),
    };

    let seq = match config.seq_placement {
        XHttpPlacement::Path => path_parts.get(path_part).cloned(),
        XHttpPlacement::Query => query_value(query, &config.seq_key),
        XHttpPlacement::Header => headers.get(&config.seq_key.to_ascii_lowercase()).cloned(),
        XHttpPlacement::Cookie => cookies.get(&config.seq_key).cloned(),
    };

    XHttpMeta { session_id, seq }
}

fn packet_payload(
    config: &XHttpConfig,
    headers: &HashMap<String, String>,
    body: Bytes,
) -> io::Result<Bytes> {
    match config.uplink_data_placement {
        XHttpDataPlacement::Body => Ok(body),
        XHttpDataPlacement::Header => header_payload(headers, &config.uplink_data_key),
        XHttpDataPlacement::Cookie => cookie_payload(headers, &config.uplink_data_key),
        XHttpDataPlacement::Auto => {
            let mut payload = BytesMut::new();
            payload.extend_from_slice(&header_payload(headers, &config.uplink_data_key)?);
            payload.extend_from_slice(&cookie_payload(headers, &config.uplink_data_key)?);
            payload.extend_from_slice(&body);
            Ok(payload.freeze())
        }
    }
}

fn header_payload(headers: &HashMap<String, String>, key: &str) -> io::Result<Bytes> {
    if key.is_empty() {
        return Ok(Bytes::new());
    }
    let key = key.to_ascii_lowercase();
    let mut encoded = String::new();
    for i in 0.. {
        let header_key = format!("{key}-{i}");
        let Some(chunk) = headers.get(&header_key) else {
            break;
        };
        encoded.push_str(chunk);
    }
    decode_payload(&encoded, "header")
}

fn cookie_payload(headers: &HashMap<String, String>, key: &str) -> io::Result<Bytes> {
    if key.is_empty() {
        return Ok(Bytes::new());
    }
    let Some(cookie_header) = headers.get("cookie") else {
        return Ok(Bytes::new());
    };
    let cookies = parse_cookies(cookie_header);
    let mut encoded = String::new();
    for i in 0.. {
        let cookie_key = format!("{key}_{i}");
        let Some(chunk) = cookies.get(&cookie_key) else {
            break;
        };
        encoded.push_str(chunk);
    }
    decode_payload(&encoded, "cookie")
}

fn decode_payload(encoded: &str, placement: &str) -> io::Result<Bytes> {
    if encoded.is_empty() {
        return Ok(Bytes::new());
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map(Bytes::from)
        .map_err(|e| invalid_error(format!("xhttp invalid base64 {placement} payload: {e}")))
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.into_owned())
}

fn parse_cookies(value: &str) -> HashMap<String, String> {
    value
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn request_authority<B>(request: &Request<B>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        })
}

fn header_map_to_strings(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect()
}

async fn read_h2_body(mut recv: RecvStream, limit: usize) -> io::Result<Bytes> {
    let mut body = BytesMut::new();
    while let Some(data) = poll_fn(|cx| Pin::new(&mut recv).poll_data(cx)).await {
        let data = data.map_err(h2_error)?;
        let len = data.len();
        if body.len() + len > limit {
            return invalid("xhttp h2 request body exceeds configured post size");
        }
        recv.flow_control()
            .release_capacity(len)
            .map_err(h2_error)?;
        body.extend_from_slice(&data);
    }
    Ok(body.freeze())
}

async fn write_http1_status(
    stream: &mut Box<dyn AsyncStream>,
    status: StatusCode,
    config: &XHttpConfig,
    request_method: &str,
    request_headers: &HashMap<String, String>,
    end_stream: bool,
) -> io::Result<()> {
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut response = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);
    for (key, value) in xhttp_response_headers(config, request_method, request_headers, end_stream)
    {
        response.push_str(key);
        response.push_str(": ");
        response.push_str(&value);
        response.push_str("\r\n");
    }
    if !config.no_sse_header && !end_stream {
        response.push_str("Content-Type: text/event-stream\r\n");
    }
    response.push_str("\r\n");
    write_all(stream, response.as_bytes()).await?;
    stream.flush().await
}

fn h2_response(
    status: StatusCode,
    config: &XHttpConfig,
    request_method: &str,
    request_headers: &HashMap<String, String>,
    end_stream: bool,
) -> io::Result<Response<()>> {
    let mut builder = Response::builder().status(status);
    for (key, value) in xhttp_response_headers(config, request_method, request_headers, end_stream)
    {
        builder = builder.header(key, value);
    }
    if !config.no_sse_header && !end_stream {
        builder = builder.header("content-type", "text/event-stream");
    }
    builder.body(()).map_err(|e| invalid_error(e.to_string()))
}

fn xhttp_response_headers(
    config: &XHttpConfig,
    request_method: &str,
    request_headers: &HashMap<String, String>,
    end_stream: bool,
) -> Vec<(&'static str, String)> {
    let mut headers = Vec::new();
    headers.push((
        "access-control-allow-origin",
        request_headers
            .get("origin")
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| "*".to_string()),
    ));
    if xhttp_uses_cookie_credentials(config) {
        headers.push(("access-control-allow-credentials", "true".to_string()));
    }
    if request_method.eq_ignore_ascii_case("OPTIONS") {
        headers.push((
            "access-control-allow-methods",
            request_headers
                .get("access-control-request-method")
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
        ));
        headers.push((
            "access-control-allow-headers",
            request_headers
                .get("access-control-request-headers")
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
        ));
    }
    headers.push(("x-accel-buffering", "no".to_string()));
    headers.push(("cache-control", "no-store".to_string()));
    if end_stream {
        headers.push(("content-length", "0".to_string()));
    }
    headers
}

fn xhttp_uses_cookie_credentials(config: &XHttpConfig) -> bool {
    matches!(config.session_id_placement, XHttpPlacement::Cookie)
        || matches!(config.seq_placement, XHttpPlacement::Cookie)
        || matches!(config.uplink_data_placement, XHttpDataPlacement::Cookie)
}

fn normalize_path(
    path: String,
    session_id_placement: XHttpPlacement,
    seq_placement: XHttpPlacement,
) -> String {
    let mut path = path
        .split_once('?')
        .map(|(path, _)| path.to_string())
        .unwrap_or(path);
    if path.trim().is_empty() {
        path = "/".to_string();
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if (matches!(session_id_placement, XHttpPlacement::Path)
        || matches!(seq_placement, XHttpPlacement::Path))
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

fn invalid<T>(msg: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn h2_error(e: h2::Error) -> io::Error {
    io::Error::other(format!("xhttp h2 error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> XHttpConfig {
        XHttpConfig::new(XHttpConfigParts {
            host: Some("example.com".to_string()),
            path: "/x".to_string(),
            mode: XHttpMode::Auto,
            no_grpc_header: false,
            no_sse_header: false,
            max_each_post_bytes: None,
            max_buffered_posts: None,
            session_id_placement: XHttpPlacement::Path,
            session_id_key: None,
            seq_placement: XHttpPlacement::Path,
            seq_key: None,
            uplink_data_placement: XHttpDataPlacement::Auto,
            uplink_data_key: None,
        })
    }

    #[test]
    fn normalizes_path_for_default_path_meta() {
        let config = default_config();
        assert_eq!(config.path, "/x/");
    }

    #[test]
    fn extracts_default_path_session_and_seq() {
        let config = default_config();
        let meta = extract_meta(&config, "/x/session-id/12", None, &HashMap::new());
        assert_eq!(meta.session_id.as_deref(), Some("session-id"));
        assert_eq!(meta.seq.as_deref(), Some("12"));
    }

    #[test]
    fn classifies_packet_up_and_stream_down() {
        let config = default_config();
        let packet = classify_request(
            &config,
            "POST",
            XHttpMeta {
                session_id: Some("s".to_string()),
                seq: Some("1".to_string()),
            },
        )
        .unwrap();
        assert!(matches!(packet, XHttpRequestKind::PacketUp { seq: 1, .. }));

        let down = classify_request(
            &config,
            "GET",
            XHttpMeta {
                session_id: Some("s".to_string()),
                seq: None,
            },
        )
        .unwrap();
        assert!(matches!(down, XHttpRequestKind::StreamDown { .. }));
    }

    #[test]
    fn rejects_xhttp_seq_without_session_id() {
        let config = default_config();
        let err = classify_request(
            &config,
            "POST",
            XHttpMeta {
                session_id: None,
                seq: Some("7".to_string()),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing session id"));
    }

    #[test]
    fn response_headers_echo_origin_for_cors() {
        let config = default_config();
        let mut request_headers = HashMap::new();
        request_headers.insert("origin".to_string(), "https://client.example".to_string());

        let headers = xhttp_response_headers(&config, "GET", &request_headers, false);

        assert!(headers.contains(&(
            "access-control-allow-origin",
            "https://client.example".to_string()
        )));
        assert!(
            !headers
                .iter()
                .any(|(key, _)| *key == "access-control-allow-credentials")
        );
    }

    #[test]
    fn response_headers_allow_credentials_for_cookie_placement() {
        let config = XHttpConfig::new(XHttpConfigParts {
            host: Some("example.com".to_string()),
            path: "/x".to_string(),
            mode: XHttpMode::Auto,
            no_grpc_header: false,
            no_sse_header: false,
            max_each_post_bytes: None,
            max_buffered_posts: None,
            session_id_placement: XHttpPlacement::Cookie,
            session_id_key: None,
            seq_placement: XHttpPlacement::Path,
            seq_key: None,
            uplink_data_placement: XHttpDataPlacement::Cookie,
            uplink_data_key: None,
        });
        let mut request_headers = HashMap::new();
        request_headers.insert("origin".to_string(), "https://client.example".to_string());

        let headers = xhttp_response_headers(&config, "GET", &request_headers, false);

        assert!(headers.contains(&(
            "access-control-allow-origin",
            "https://client.example".to_string()
        )));
        assert!(headers.contains(&("access-control-allow-credentials", "true".to_string())));
    }

    #[test]
    fn options_response_headers_reflect_requested_method_and_headers() {
        let config = default_config();
        let mut request_headers = HashMap::new();
        request_headers.insert("origin".to_string(), "https://client.example".to_string());
        request_headers.insert(
            "access-control-request-method".to_string(),
            "POST".to_string(),
        );
        request_headers.insert(
            "access-control-request-headers".to_string(),
            "X-Session, X-Data-0".to_string(),
        );

        let headers = xhttp_response_headers(&config, "OPTIONS", &request_headers, true);

        assert!(headers.contains(&("access-control-allow-methods", "POST".to_string())));
        assert!(headers.contains(&(
            "access-control-allow-headers",
            "X-Session, X-Data-0".to_string()
        )));
        assert!(headers.contains(&("content-length", "0".to_string())));
    }

    #[tokio::test]
    async fn upload_reader_reorders_packets() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session = get_or_create_session(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS);
        push_packet(&session, 1, Bytes::from_static(b"two"))
            .await
            .unwrap();
        push_packet(&session, 0, Bytes::from_static(b"one"))
            .await
            .unwrap();
        let mut reader = take_session_reader(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS).unwrap();
        let mut out = [0u8; 6];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"onetwo");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_create_session_is_atomic_under_concurrency() {
        for _ in 0..100 {
            let sessions = Arc::new(Mutex::new(HashMap::new()));
            let barrier = Arc::new(tokio::sync::Barrier::new(2));

            let task_sessions = sessions.clone();
            let task_barrier = barrier.clone();
            let handle = tokio::spawn(async move {
                task_barrier.wait().await;
                get_or_create_session(&task_sessions, "s", DEFAULT_MAX_BUFFERED_POSTS)
            });

            barrier.wait().await;
            let local = get_or_create_session(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS);
            let remote = handle.await.unwrap();

            assert!(Arc::ptr_eq(&local, &remote));
            assert_eq!(sessions.lock().len(), 1);
        }
    }

    #[test]
    fn decodes_header_payload() {
        let mut headers = HashMap::new();
        headers.insert("x-data-0".to_string(), "aGVs".to_string());
        headers.insert("x-data-1".to_string(), "bG8".to_string());
        let payload = header_payload(&headers, "X-Data").unwrap();
        assert_eq!(payload.as_ref(), b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_removes_never_connected_session() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session = get_or_create_session(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS);
        assert_eq!(sessions.lock().len(), 1);

        // Step time so the reaper task gets polled between advances. The
        // session never gets activity, so it becomes stale after 30s.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(20)).await;
            tokio::task::yield_now().await;
        }

        assert_eq!(sessions.lock().len(), 0);
        assert!(!session.connected.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_removes_idle_connected_session() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session = get_or_create_session(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS);
        session.connected.store(true, Ordering::SeqCst);
        assert_eq!(sessions.lock().len(), 1);

        // Jump past the idle threshold, then mark the session idle since the
        // paused-clock epoch: the next reaper tick sees idle > 120s.
        tokio::time::advance(Duration::from_secs(SESSION_IDLE_REAP_SECS + 60)).await;
        session.last_activity.store(0, Ordering::Relaxed);
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(SESSION_REAP_INTERVAL_SECS)).await;
            tokio::task::yield_now().await;
        }

        assert_eq!(sessions.lock().len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_keeps_active_connected_session() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let session = get_or_create_session(&sessions, "s", DEFAULT_MAX_BUFFERED_POSTS);
        session.connected.store(true, Ordering::SeqCst);
        // Touch activity so the session looks live.
        touch_session(&session);
        assert_eq!(sessions.lock().len(), 1);

        // Several reap intervals pass while the session stays active.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(SESSION_REAP_INTERVAL_SECS)).await;
            touch_session(&session);
            tokio::task::yield_now().await;
            assert_eq!(sessions.lock().len(), 1);
        }
    }
}
