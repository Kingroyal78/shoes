use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use super::virtual_stream::{
    InboundChannels, InboundEvent, InboundTerminal, OutboundCommand, ReceiveBudget,
    SmuxV2FlowControl, VirtualStream, WindowUpdate,
};
use crate::async_stream::AsyncStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::process_stream;
use crate::util::allocate_vec;

const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const HEADER_SIZE: usize = 8;
const UPDATE_PAYLOAD_SIZE: usize = 8;

/// Logical streams killed because their inbound queue overran.
///
/// smux v1 has no per-stream window, so a stream that cannot keep up has to be
/// dropped rather than backpressured. Whether that is rare enough to live with
/// or worth trading memory for is a question about the rate, and the rate was
/// previously only visible at debug level -- which is off in production.
pub static STREAMS_DROPPED_BY_BACKPRESSURE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Default ceiling on queued inbound bytes for one logical stream.
///
/// The queue holds what arrives while the stream's own destination is not
/// taking it, so it has to cover roughly a high-latency path's worth of data
/// in flight. Four frames -- the previous limit, and expressed in frames
/// rather than bytes -- is a small fraction of that on a 200ms path, which is
/// why ordinary congestion rather than a wedged peer was costing streams.
const DEFAULT_STREAM_RECEIVE_BUFFER: usize = 256 * 1024;

/// Default ceiling on queued inbound bytes across a listener's sessions.
/// Far above what healthy traffic queues -- data sits here only while a logical
/// stream is slower than its peer -- but low enough to bound a listener that
/// would otherwise scale with the connection count.
const DEFAULT_LISTENER_RECEIVE_BUFFER: usize = 256 * 1024 * 1024;

/// How long a finished session waits for its logical streams to wind down
/// before cancelling them.
///
/// Their tasks own the drop-close permits and the outbound sender clones that
/// the close forwarder and the writer block on, so waiting for those two is
/// really waiting on a proxied peer that may never answer. That wait used to
/// expire on a third of all sessions, and expiring aborted the writer with
/// flushes still queued, failing every stream that had one in flight.
/// Cancelling the streams directly ends the session in bounded time and lets
/// the shared machinery close on its own terms instead.
///
/// A second rather than something tighter because this also covers the
/// teardowns where the physical connection is still writable -- the reader
/// breaking on a protocol violation, say -- and a stream mid-download there can
/// still use the time. When the peer is simply gone, which is the common case,
/// the streams fail fast and the grace never elapses at all.
const STREAM_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// How often the server sends a NOP on an otherwise quiet v1 session.
///
/// Deliberately paired with no read timeout. A read timeout cannot tell an
/// abandoned session from a merely idle one -- an idle client sends no smux
/// frames either -- so it would drop live connections that happen to be quiet.
/// The cases it would catch are already covered: a peer that has gone away
/// fails these writes once TCP gives up, which tears the session down, and TCP
/// keepalive (300s idle + probes) reaps an unreachable peer on its own. The
/// NOPs also keep middleboxes from dropping the flow underneath a quiet
/// session.
const SMUX_V1_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

fn listener_budget(config: &SmuxServerConfig) -> Option<Arc<ReceiveBudget>> {
    config
        .max_listener_receive_buffer
        .map(|max| Arc::new(ReceiveBudget::new(max)))
}

#[derive(Clone, Copy, Debug)]
pub struct SmuxLimits {
    pub max_concurrent_streams: usize,
    pub inbound_frames_per_stream: usize,
    pub outbound_frame_queue: usize,
    pub max_frame_payload: usize,
}

impl Default for SmuxLimits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 256,
            inbound_frames_per_stream: 256,
            outbound_frame_queue: 128,
            max_frame_payload: u16::MAX as usize,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SmuxServerConfig {
    pub version: u8,
    pub limits: SmuxLimits,
    pub max_receive_buffer: usize,
    pub max_stream_buffer: usize,
    pub keepalive_interval: Option<std::time::Duration>,
    pub keepalive_timeout: Option<std::time::Duration>,
    /// Ceiling on queued inbound bytes across every session this handler
    /// serves. `max_receive_buffer` is per session, so without this the
    /// listener's exposure is that figure times the number of connections.
    pub max_listener_receive_buffer: Option<usize>,
    /// Ceiling on queued inbound bytes for one logical stream. Bounds what a
    /// single stream may take of the session's budget, and decides whether
    /// congestion costs a stream or only a wedged peer does.
    pub max_stream_receive_buffer: usize,
}

impl Default for SmuxServerConfig {
    fn default() -> Self {
        Self {
            version: VERSION_V1,
            limits: SmuxLimits::default(),
            max_receive_buffer: 4 * 1024 * 1024,
            max_stream_buffer: 2 * 1024 * 1024,
            keepalive_interval: None,
            keepalive_timeout: None,
            max_listener_receive_buffer: Some(DEFAULT_LISTENER_RECEIVE_BUFFER),
            max_stream_receive_buffer: DEFAULT_STREAM_RECEIVE_BUFFER,
        }
    }
}

pub struct SmuxServerHandler {
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    config: SmuxServerConfig,
    listener_budget: Option<Arc<ReceiveBudget>>,
}

impl fmt::Debug for SmuxServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmuxServerHandler")
            .field("inner", &self.inner)
            .field("resolver", &self.resolver)
            .field("config", &self.config)
            .finish()
    }
}

impl SmuxServerHandler {
    pub fn new(
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
        config: SmuxServerConfig,
    ) -> Self {
        Self {
            inner,
            resolver,
            config,
            listener_budget: listener_budget(&config),
        }
    }
}

#[async_trait]
impl TcpServerHandler for SmuxServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        validate_config(self.config)?;
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        let config = self.config;
        let budget = self.listener_budget.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_smux(stream, inner, resolver, peer_addr, config, budget).await
            {
                log::debug!(
                    "smux v{} session finished with error: {error}",
                    config.version
                );
            }
        });
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

pub struct SmuxV1ServerHandler {
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    config: SmuxServerConfig,
    listener_budget: Option<Arc<ReceiveBudget>>,
}

impl fmt::Debug for SmuxV1ServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmuxV1ServerHandler")
            .field("inner", &self.inner)
            .field("resolver", &self.resolver)
            .field("config", &self.config)
            .finish()
    }
}

impl SmuxV1ServerHandler {
    pub fn new(
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
        limits: SmuxLimits,
    ) -> Self {
        let config = SmuxServerConfig {
            version: VERSION_V1,
            limits,
            keepalive_interval: Some(SMUX_V1_KEEPALIVE_INTERVAL),
            keepalive_timeout: None,
            ..SmuxServerConfig::default()
        };
        Self {
            inner,
            resolver,
            config,
            listener_budget: listener_budget(&config),
        }
    }
}

#[async_trait]
impl TcpServerHandler for SmuxV1ServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let config = self.config;
        validate_config(config)?;
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        let budget = self.listener_budget.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_smux(stream, inner, resolver, peer_addr, config, budget).await
            {
                log::debug!("smux v1 session finished with error: {error}");
            }
        });
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Frame {
    command: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn parse_header(
    header: [u8; HEADER_SIZE],
    version: u8,
    max_payload: usize,
) -> io::Result<(u8, u32, usize)> {
    if header[0] != version {
        return invalid(format!("unsupported smux protocol version {}", header[0]));
    }
    let command = header[1];
    if !(matches!(command, CMD_SYN | CMD_FIN | CMD_PSH | CMD_NOP)
        || version == VERSION_V2 && command == CMD_UPD)
    {
        return invalid(format!("unknown smux v{version} command"));
    }
    let length = u16::from_le_bytes([header[2], header[3]]) as usize;
    if length > max_payload {
        return invalid(format!("smux v{version} payload exceeds configured limit"));
    }
    if matches!(command, CMD_SYN | CMD_FIN | CMD_NOP) && length != 0 {
        return invalid(format!("smux v{version} control frame contains a payload"));
    }
    if command == CMD_UPD && length != UPDATE_PAYLOAD_SIZE {
        return invalid("smux v2 window update must contain exactly 8 bytes");
    }
    let stream_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if command != CMD_NOP && stream_id == 0 {
        return invalid(format!("smux v{version} stream ID zero is reserved"));
    }
    if command == CMD_NOP && stream_id != 0 {
        return invalid(format!("smux v{version} NOP must use stream ID zero"));
    }
    Ok((command, stream_id, length))
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    version: u8,
    max_payload: usize,
) -> io::Result<Option<Frame>> {
    let mut header = [0u8; HEADER_SIZE];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let (command, stream_id, length) = parse_header(header, version, max_payload)?;
    // Not `vec![0u8; length]`: `read_exact` overwrites every byte before anyone
    // can observe one, so zeroing first is a memset per frame on the busiest
    // path in the process.
    let mut payload = allocate_vec(length);
    reader.read_exact(&mut payload).await?;
    Ok(Some(Frame {
        command,
        stream_id,
        payload,
    }))
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    version: u8,
    command: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let length = u16::try_from(payload.len())
        .map_err(|_| invalid_error("smux payload exceeds 65535 bytes"))?;
    let mut header = [0u8; HEADER_SIZE];
    header[0] = version;
    header[1] = command;
    header[2..4].copy_from_slice(&length.to_le_bytes());
    header[4..8].copy_from_slice(&stream_id.to_le_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

struct StreamState {
    inbound: Option<mpsc::Sender<InboundEvent>>,
    terminal: Option<oneshot::Sender<InboundTerminal>>,
    flow: Option<Arc<SmuxV2FlowControl>>,
    /// Charges this stream's queued bytes, and through its parent the
    /// session's and the listener's.
    budget: Arc<ReceiveBudget>,
}

async fn serve_smux(
    stream: Box<dyn AsyncStream>,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<std::net::SocketAddr>,
    config: SmuxServerConfig,
    listener_budget: Option<Arc<ReceiveBudget>>,
) -> io::Result<()> {
    let version = config.version;
    let limits = config.limits;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) =
        mpsc::channel::<OutboundCommand>(limits.outbound_frame_queue);
    let (drop_close_tx, mut drop_close_rx) = mpsc::channel::<u32>(limits.max_concurrent_streams);
    let close_outbound = outbound_tx.clone();
    let mut close_forwarder = tokio::spawn(async move {
        while let Some(stream_id) = drop_close_rx.recv().await {
            close_outbound
                .send(OutboundCommand::Finished { stream_id })
                .await
                .map_err(|_| invalid_error("smux session writer closed"))?;
        }
        Ok::<(), io::Error>(())
    });
    let (updates_tx, mut updates_rx) = mpsc::channel::<WindowUpdate>(limits.outbound_frame_queue);
    let receive_budget = Arc::new(ReceiveBudget::with_parent(
        config.max_receive_buffer,
        listener_budget,
    ));
    // A v2 stream tells its peer it may keep `max_stream_buffer` in flight, so
    // budgeting less than that would drop a stream for doing exactly what it
    // was granted. v1 advertises no window, so its own ceiling stands.
    let stream_receive_buffer = if version == VERSION_V2 {
        config
            .max_stream_receive_buffer
            .max(config.max_stream_buffer)
    } else {
        config.max_stream_receive_buffer
    };
    // The writer cannot be ended by dropping senders alone: an inner handler
    // that takes a logical stream, spawns it and returns `AlreadyHandled`
    // keeps an outbound clone in a task this session cannot reach, so the
    // channel never closes however much of its own work the session cancels.
    // A signal ends it regardless of who else is still holding a sender.
    let writer_shutdown = Arc::new(tokio::sync::Notify::new());
    let writer_shutdown_signal = writer_shutdown.clone();
    let mut writer_task = tokio::spawn(async move {
        let mut updates_open = true;
        let mut closing = false;
        let ping_period = config
            .keepalive_interval
            .unwrap_or_else(|| std::time::Duration::from_secs(365 * 24 * 60 * 60));
        let mut ping = tokio::time::interval(ping_period);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // `interval` ticks immediately; consume that tick so NOP is sent after
        // one complete keepalive period.
        ping.tick().await;
        loop {
            tokio::select! {
                update = updates_rx.recv(), if updates_open => {
                    match update {
                        Some(update) => {
                            let mut payload = [0_u8; UPDATE_PAYLOAD_SIZE];
                            payload[..4].copy_from_slice(&update.consumed.to_le_bytes());
                            payload[4..].copy_from_slice(&update.window.to_le_bytes());
                            write_frame(
                                &mut writer,
                                version,
                                CMD_UPD,
                                update.stream_id,
                                &payload,
                            ).await?;
                        }
                        None => updates_open = false,
                    }
                }
                command = outbound_rx.recv() => {
                    let Some(command) = command else { break };
                    match command {
                        OutboundCommand::Data { stream_id, data } => {
                            write_frame(&mut writer, version, CMD_PSH, stream_id, &data).await?;
                        }
                        OutboundCommand::Finished { stream_id } => {
                            write_frame(&mut writer, version, CMD_FIN, stream_id, &[]).await?;
                        }
                        OutboundCommand::Barrier { complete } => {
                            // Bound the flush: a half-open physical stream can
                            // stall flush forever, which would hold the
                            // barrier's oneshot open, wedge the logical
                            // stream's shutdown, and leak the outbound
                            // connection in CLOSE_WAIT. On timeout report the
                            // error so the logical stream closes anyway.
                            let result = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                writer.flush(),
                            )
                            .await
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "smux barrier flush timed out",
                                )
                            })?;
                            let reported = result
                                .as_ref()
                                .map(|_| ())
                                .map_err(|error| io::Error::new(error.kind(), error.to_string()));
                            let _ = complete.send(reported);
                            result?;
                        }
                    }
                }
                _ = ping.tick(), if config.keepalive_interval.is_some() => {
                    write_frame(&mut writer, version, CMD_NOP, 0, &[]).await?;
                }
                _ = writer_shutdown_signal.notified(), if !closing => {
                    // Closing the receiver rather than breaking: it refuses new
                    // sends but still yields what is already queued, so the
                    // barriers in flight are completed instead of dropped --
                    // dropping them is the failure this whole teardown path was
                    // rewritten to stop causing. The drain then ends the loop
                    // through the ordinary `None` arm below.
                    outbound_rx.close();
                    closing = true;
                }
            }
        }
        writer.shutdown().await
    });

    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    // Held rather than detached so the session can cancel what it started.
    // Dropping this set aborts anything still running, which is the right end
    // for a logical stream whose physical session is gone: it has no transport
    // left to carry anything to the client.
    let mut stream_tasks = tokio::task::JoinSet::new();
    let read_result = loop {
        let read = read_frame(&mut reader, version, limits.max_frame_payload);
        let frame_result = if let Some(timeout) = config.keepalive_timeout {
            match tokio::time::timeout(timeout, read).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("smux v{version} keepalive timeout"),
                )),
            }
        } else {
            read.await
        };
        let frame = match frame_result {
            Ok(Some(frame)) => frame,
            Ok(None) => break Ok(()),
            Err(error) => break Err(error),
        };
        match frame.command {
            CMD_SYN => {
                // Reclaim slots whose logical stream is gone. A server-initiated
                // close sends FIN but leaves the entry behind, and only a FIN
                // *from the peer* removes one, so without this a peer that never
                // reciprocates walks the map up to the concurrency limit and
                // trips it -- which tears down the physical session and every
                // live logical stream sharing it. The inbound receiver lives
                // exactly as long as its `VirtualStream`, so a closed sender is
                // precisely the "this stream is finished" signal.
                streams.retain(|_, state| {
                    state
                        .inbound
                        .as_ref()
                        .is_some_and(|inbound| !inbound.is_closed())
                });
                // Same reclaim, one layer down: a finished task left in the set
                // would otherwise accumulate for the life of the session.
                while stream_tasks.try_join_next().is_some() {}
                if streams.contains_key(&frame.stream_id) {
                    break invalid("smux v1 SYN reused an active stream ID");
                }
                if streams.len() >= limits.max_concurrent_streams {
                    break invalid(format!("smux v{version} concurrent stream limit exceeded"));
                }
                let close_permit = match drop_close_tx.clone().reserve_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break invalid(format!("smux v{version} close forwarder closed")),
                };
                let (inbound_tx, inbound_rx) = mpsc::channel(limits.inbound_frames_per_stream);
                let (terminal_tx, terminal_rx) = oneshot::channel();
                let flow = (version == VERSION_V2).then(|| Arc::new(SmuxV2FlowControl::new()));
                streams.insert(
                    frame.stream_id,
                    StreamState {
                        inbound: Some(inbound_tx),
                        terminal: Some(terminal_tx),
                        flow: flow.clone(),
                        budget: Arc::new(ReceiveBudget::with_parent(
                            stream_receive_buffer,
                            Some(receive_budget.clone()),
                        )),
                    },
                );
                let mut logical = if let Some(flow) = flow {
                    VirtualStream::new_smux_v2(
                        frame.stream_id,
                        InboundChannels::new(inbound_rx, terminal_rx),
                        outbound_tx.clone(),
                        limits.max_frame_payload,
                        flow,
                        updates_tx.clone(),
                        config.max_stream_buffer as u32,
                    )
                } else {
                    VirtualStream::new(
                        frame.stream_id,
                        InboundChannels::new(inbound_rx, terminal_rx),
                        outbound_tx.clone(),
                        limits.max_frame_payload,
                    )
                };
                logical.set_drop_close_permit(close_permit);
                let inner = inner.clone();
                let resolver = resolver.clone();
                stream_tasks.spawn(async move {
                    if let Err(error) = process_stream(logical, inner, resolver, peer_addr).await {
                        log::debug!(
                            "smux v{version} logical stream {} finished with error: {error}",
                            frame.stream_id
                        );
                    }
                });
            }
            CMD_PSH => {
                // An unknown stream id is an ordinary race, not an error: the
                // server closed the logical stream and sent FIN while this frame
                // was already on the wire. Discard the payload -- failing the
                // session here would punish every other stream sharing it.
                let mut overran_queue = false;
                if let Some(inbound) = streams.get_mut(&frame.stream_id)
                    && !frame.payload.is_empty()
                    && let Some(sender) = &inbound.inbound
                {
                    // Charged to this stream first, so a stream that will not
                    // drain exhausts its own budget rather than the session's,
                    // and the streams beside it keep their room. Exhausting it
                    // costs this stream only: the reader never waits, because
                    // waiting freezes every other stream the same client has
                    // open, and never fails the session, because that takes
                    // those streams down outright.
                    match inbound.budget.track(frame.payload) {
                        Ok(data) => match sender.try_send(InboundEvent::Data(data)) {
                            Ok(()) => {}
                            Err(TrySendError::Closed(_)) => inbound.inbound = None,
                            Err(TrySendError::Full(_)) => overran_queue = true,
                        },
                        Err(_) => overran_queue = true,
                    }
                }
                if overran_queue {
                    STREAMS_DROPPED_BY_BACKPRESSURE
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // This stream is not draining as fast as its peer is
                    // sending, and smux v1 has no per-stream window to push
                    // back with. Dropping the frame would leave a hole in the
                    // stream's byte sequence, so the stream itself cannot
                    // survive -- but only this one. Failing the session here
                    // tore down every other logical stream multiplexed onto the
                    // same connection over a condition caused by one of them,
                    // and the collateral was invisible because those streams
                    // report their failures at debug level.
                    if let Some(state) = streams.remove(&frame.stream_id)
                        && let Some(terminal) = state.terminal
                    {
                        let _ = terminal.send(InboundTerminal::Failed(format!(
                            "smux v{version} logical inbound queue is full"
                        )));
                    }
                    // Deliberately no close from here. The stream's own drop
                    // sends one through a permit reserved at SYN time, which
                    // cannot block. Enqueuing another would duplicate it and --
                    // because the outbound queue is bounded -- park the
                    // *physical reader* whenever the writer is backed up,
                    // stalling every stream on the connection over one
                    // stream's overflow. A congested path is exactly where the
                    // overflow and the backed-up writer happen together.
                }
            }
            CMD_FIN => {
                // With slots reclaimed on close, the peer FINning a stream the
                // server already finished is the common case, not a violation.
                if let Some(inbound) = streams.remove(&frame.stream_id)
                    && let Some(terminal) = inbound.terminal
                {
                    let _ = terminal.send(InboundTerminal::Finished);
                }
            }
            CMD_NOP => {}
            CMD_UPD => {
                // Same race as PSH; a window update for a finished stream is
                // simply nothing to apply.
                let Some(stream) = streams.get(&frame.stream_id) else {
                    continue;
                };
                // A v1 session receiving a v2 frame is a real protocol error,
                // not a race, so it still fails the session.
                let Some(flow) = &stream.flow else {
                    break invalid("smux v1 received a v2 window update");
                };
                let consumed = u32::from_le_bytes(
                    frame.payload[..4]
                        .try_into()
                        .expect("validated UPD payload"),
                );
                let window = u32::from_le_bytes(
                    frame.payload[4..]
                        .try_into()
                        .expect("validated UPD payload"),
                );
                if let Err(error) = flow.update(consumed, window) {
                    break Err(error);
                }
            }
            _ => unreachable!("command validated by parser"),
        }
    };

    let failure = read_result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("smux v{version} physical stream closed"));
    for (_, stream) in streams {
        if let Some(terminal) = stream.terminal {
            let _ = terminal.send(InboundTerminal::Failed(failure.clone()));
        }
    }
    drop(drop_close_tx);
    drop(updates_tx);
    drop(outbound_tx);
    // Wind the logical streams down before waiting on the forwarder and the
    // writer, because those two cannot finish until every stream has released
    // its permit and its sender. The terminal events delivered above only
    // unblock a stream's inbound half; one parked on its proxied peer needs
    // cancelling. The grace lets a stream that is already finishing report its
    // own outcome first.
    if tokio::time::timeout(STREAM_SHUTDOWN_GRACE, async {
        while stream_tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        stream_tasks.shutdown().await;
    }
    // Whatever is left holding a drop-close permit at this point is not
    // reachable from here -- an inner handler that detached the stream it was
    // given, most concretely -- so waiting on the forwarder is waiting on
    // something this session can no longer influence. Bounded by the same
    // grace rather than by five seconds for that reason. Aborting it cannot
    // orphan copy tasks: it only forwards close notifications, and the session
    // is over.
    let close_result = match tokio::time::timeout(STREAM_SHUTDOWN_GRACE, &mut close_forwarder).await
    {
        Ok(joined) => {
            joined.map_err(|error| io::Error::other(format!("smux close task failed: {error}")))
        }
        Err(_) => {
            // Not a failure of this session. Having cancelled every stream
            // it owns, a forwarder still waiting means a permit is held
            // where it cannot reach, and reporting that as the session's
            // outcome buried the real one -- the read result -- under a
            // timeout the session could do nothing about.
            close_forwarder.abort();
            log::debug!(
                "smux v{version} close forwarder outlived the streams this session owns; \
                     an inner handler kept one"
            );
            Ok(Ok(()))
        }
    };
    // Tell the writer to drain and stop. Signalled after the streams were
    // cancelled so the FINs their drops emit are already queued, and issued
    // whether or not the forwarder finished, because the writer is held open by
    // the same unreachable senders.
    writer_shutdown.notify_one();
    let close_result = close_result?;
    // Bound only the writer drain: the writer may be stuck behind a leaked
    // outbound sender, and aborting it only releases the write half of the
    // physical stream (the fd is owned by the reader side, which has already
    // finished and delivered per-stream shutdown events above).
    let writer_result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut writer_task)
        .await
        .map_err(|_| {
            writer_task.abort();
            io::Error::other("smux writer task timed out")
        })?
        .map_err(|error| io::Error::other(format!("smux writer task failed: {error}")))?;
    read_result.and(close_result).and(writer_result)
}

fn validate_config(config: SmuxServerConfig) -> io::Result<()> {
    let limits = config.limits;
    if !matches!(config.version, VERSION_V1 | VERSION_V2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "smux version must be 1 or 2",
        ));
    }
    if limits.max_concurrent_streams == 0
        || limits.max_concurrent_streams > tokio::sync::Semaphore::MAX_PERMITS
        || limits.inbound_frames_per_stream == 0
        || limits.inbound_frames_per_stream > tokio::sync::Semaphore::MAX_PERMITS
        || limits.outbound_frame_queue == 0
        || limits.outbound_frame_queue > tokio::sync::Semaphore::MAX_PERMITS
        || limits.max_frame_payload == 0
        || limits.max_frame_payload > u16::MAX as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid smux v1 resource limits",
        ));
    }
    // No relation to `max_receive_buffer` is required: a listener ceiling below
    // one session's is simply the constraint that binds first.
    if config
        .max_listener_receive_buffer
        .is_some_and(|max| max == 0 || max > i32::MAX as usize)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid smux listener receive buffer limit",
        ));
    }
    if config.max_receive_buffer == 0
        || config.max_receive_buffer > i32::MAX as usize
        || config.max_stream_buffer == 0
        || config.max_stream_buffer > i32::MAX as usize
        || config.max_stream_buffer > config.max_receive_buffer
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid smux receive/stream buffer limits",
        ));
    }
    if config
        .keepalive_interval
        .is_some_and(|duration| duration.is_zero())
        || config
            .keepalive_timeout
            .is_some_and(|duration| duration.is_zero())
        || matches!(
            (config.keepalive_interval, config.keepalive_timeout),
            (Some(interval), Some(timeout)) if timeout <= interval
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid smux keepalive interval/timeout",
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio::sync::Notify;

    use super::*;
    use crate::async_stream::AsyncPing;
    use crate::resolver::NativeResolver;
    use crate::ss_plugins::transport::virtual_stream::InboundData;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct UnusedHandler;

    #[async_trait]
    impl TcpServerHandler for UnusedHandler {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            unreachable!("the clean-close test does not create a logical stream")
        }
    }

    #[derive(Default)]
    struct HoldingHandler {
        held: Mutex<Vec<Box<dyn AsyncStream>>>,
        ready: Notify,
    }

    impl fmt::Debug for HoldingHandler {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("HoldingHandler")
        }
    }

    #[async_trait]
    impl TcpServerHandler for HoldingHandler {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            self.held
                .lock()
                .expect("holding handler mutex poisoned")
                .push(stream);
            self.ready.notify_one();
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[test]
    fn parses_v1_little_endian_header_at_payload_boundary() {
        let mut header = [0u8; HEADER_SIZE];
        header[0] = VERSION_V1;
        header[1] = CMD_PSH;
        header[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        header[4..8].copy_from_slice(&0x7856_3412u32.to_le_bytes());
        assert_eq!(
            parse_header(header, VERSION_V1, u16::MAX as usize).unwrap(),
            (CMD_PSH, 0x7856_3412, u16::MAX as usize)
        );
    }

    #[test]
    fn rejects_bad_version_commands_control_payload_and_zero_id() {
        assert!(parse_header([2, CMD_SYN, 0, 0, 1, 0, 0, 0], VERSION_V1, 65535).is_err());
        assert!(parse_header([1, 9, 0, 0, 1, 0, 0, 0], VERSION_V1, 65535).is_err());
        assert!(parse_header([1, CMD_SYN, 1, 0, 1, 0, 0, 0], VERSION_V1, 65535).is_err());
        assert!(parse_header([1, CMD_PSH, 0, 0, 0, 0, 0, 0], VERSION_V1, 65535).is_err());
        assert!(parse_header([1, CMD_PSH, 9, 0, 1, 0, 0, 0], VERSION_V1, 8).is_err());
        assert!(parse_header([1, CMD_UPD, 8, 0, 1, 0, 0, 0], VERSION_V1, 65535).is_err());
        assert!(parse_header([2, CMD_UPD, 7, 0, 1, 0, 0, 0], VERSION_V2, 65535).is_err());
    }

    #[test]
    fn parses_v2_window_update_and_enforces_consumed_boundary() {
        assert_eq!(
            parse_header([VERSION_V2, CMD_UPD, 8, 0, 9, 0, 0, 0], VERSION_V2, 65535,).unwrap(),
            (CMD_UPD, 9, UPDATE_PAYLOAD_SIZE)
        );

        let flow = SmuxV2FlowControl::new();
        assert_eq!(flow.available().unwrap(), 262_144);
        flow.record_write(262_144);
        assert_eq!(flow.available().unwrap(), 0);
        flow.update(1024, 262_144).unwrap();
        assert_eq!(flow.available().unwrap(), 1024);
        assert!(flow.update(262_145, 262_144).is_err());
    }

    #[test]
    fn rejects_channel_capacities_above_tokio_semaphore_limit() {
        for limits in [
            SmuxLimits {
                max_concurrent_streams: tokio::sync::Semaphore::MAX_PERMITS + 1,
                ..SmuxLimits::default()
            },
            SmuxLimits {
                inbound_frames_per_stream: tokio::sync::Semaphore::MAX_PERMITS + 1,
                ..SmuxLimits::default()
            },
            SmuxLimits {
                outbound_frame_queue: tokio::sync::Semaphore::MAX_PERMITS + 1,
                ..SmuxLimits::default()
            },
        ] {
            let error = validate_config(SmuxServerConfig {
                limits,
                ..SmuxServerConfig::default()
            })
            .expect_err("oversized channel must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn v1_handler_sends_keepalives_without_imposing_a_read_timeout() {
        let handler = SmuxV1ServerHandler::new(
            Arc::new(UnusedHandler),
            Arc::new(NativeResolver::new()),
            SmuxLimits::default(),
        );
        assert_eq!(
            handler.config.keepalive_interval,
            Some(SMUX_V1_KEEPALIVE_INTERVAL)
        );
        // A read timeout would close idle-but-live sessions, which are
        // indistinguishable from abandoned ones at this layer.
        assert_eq!(handler.config.keepalive_timeout, None);
        validate_config(handler.config).expect("the shipped v1 config must be valid");
    }

    #[test]
    fn default_smux_config_does_not_enable_idle_read_timeout() {
        let config = SmuxServerConfig::default();
        assert!(config.keepalive_interval.is_none());
        assert!(config.keepalive_timeout.is_none());
    }

    #[tokio::test]
    async fn frame_reader_handles_one_byte_fragmentation() {
        let wire = [1, CMD_PSH, 3, 0, 7, 0, 0, 0, b'a', b'b', b'c'];
        let reader = tokio::io::BufReader::with_capacity(1, wire.as_slice());
        tokio::pin!(reader);
        let frame = read_frame(&mut reader, VERSION_V1, 1024)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            frame,
            Frame {
                command: CMD_PSH,
                stream_id: 7,
                payload: b"abc".to_vec()
            }
        );
    }

    #[tokio::test]
    async fn distinguishes_clean_eof_from_truncated_header_and_body() {
        let empty: &[u8] = &[];
        assert!(
            read_frame(&mut std::io::Cursor::new(empty), VERSION_V1, 1024)
                .await
                .unwrap()
                .is_none()
        );
        let error = read_frame(
            &mut std::io::Cursor::new(&[VERSION_V1, CMD_SYN][..]),
            VERSION_V1,
            1024,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        let error = read_frame(
            &mut std::io::Cursor::new(&[VERSION_V1, CMD_PSH, 2, 0, 1, 0, 0, 0, b'x'][..]),
            VERSION_V1,
            1024,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn v2_stream_reports_initial_and_half_window_consumption() {
        let (inbound_tx, inbound_rx) = mpsc::channel(4);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(4);
        let (updates_tx, mut updates_rx) = mpsc::channel(4);
        let flow = Arc::new(SmuxV2FlowControl::new());
        let mut stream = VirtualStream::new_smux_v2(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
            flow,
            updates_tx,
            8,
        );
        inbound_tx
            .send(InboundEvent::Data(InboundData::untracked(
                b"abcdefgh".to_vec(),
            )))
            .await
            .unwrap();

        let mut first = [0_u8; 1];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [b'a']);
        assert_eq!(
            updates_rx.recv().await.unwrap(),
            WindowUpdate {
                stream_id: 7,
                consumed: 1,
                window: 8,
            }
        );

        let mut next = [0_u8; 4];
        stream.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"bcde");
        assert_eq!(
            updates_rx.recv().await.unwrap(),
            WindowUpdate {
                stream_id: 7,
                consumed: 5,
                window: 8,
            }
        );
    }

    #[tokio::test]
    async fn v2_reads_backpressure_when_the_bounded_update_queue_is_full() {
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let (updates_tx, mut updates_rx) = mpsc::channel(1);
        updates_tx
            .send(WindowUpdate {
                stream_id: 99,
                consumed: 1,
                window: 1,
            })
            .await
            .unwrap();
        let flow = Arc::new(SmuxV2FlowControl::new());
        let mut stream = VirtualStream::new_smux_v2(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
            flow,
            updates_tx,
            8,
        );
        inbound_tx
            .send(InboundEvent::Data(InboundData::untracked(b"x".to_vec())))
            .await
            .unwrap();

        let mut byte = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                stream.read_exact(&mut byte)
            )
            .await
            .is_err(),
            "read must wait rather than dropping a required window update"
        );

        assert_eq!(updates_rx.recv().await.unwrap().stream_id, 99);
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);
        assert_eq!(
            updates_rx.recv().await.unwrap(),
            WindowUpdate {
                stream_id: 7,
                consumed: 1,
                window: 8,
            }
        );
    }

    /// Running out of queue space is one stream's problem. Failing the session
    /// takes down every stream the same client has open, which is the
    /// collateral this budget exists to bound rather than to cause.
    #[tokio::test]
    async fn a_session_out_of_receive_budget_drops_a_stream_not_itself() {
        let (mut client, server) = tokio::io::duplex(256);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    inbound_frames_per_stream: 4,
                    max_frame_payload: 4,
                    ..SmuxLimits::default()
                },
                max_receive_buffer: 4,
                max_stream_buffer: 4,
                ..SmuxServerConfig::default()
            },
            None,
        ));

        for stream_id in [1, 2] {
            write_frame(&mut client, VERSION_V1, CMD_SYN, stream_id, &[])
                .await
                .unwrap();
            handler.ready.notified().await;
        }
        // The session budget is four bytes, so the second of these has nowhere
        // to go even though its own stream has barely used anything.
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"abc")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_PSH, 2, b"def")
            .await
            .unwrap();

        // Still serving: a session that gave up here would never get this far.
        write_frame(&mut client, VERSION_V1, CMD_SYN, 3, &[])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handler.ready.notified())
            .await
            .expect("a session out of budget must keep serving its other streams");

        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();
        client.shutdown().await.unwrap();
        session
            .await
            .unwrap()
            .expect("the session outlives running out of queue space");
    }

    /// One stream's congestion must not eat the room its neighbours need, so
    /// the charge lands on the stream before the session.
    #[tokio::test]
    async fn a_stream_exhausts_its_own_budget_before_the_sessions() {
        let (mut client, server) = tokio::io::duplex(512);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    inbound_frames_per_stream: 64,
                    max_frame_payload: 4,
                    ..SmuxLimits::default()
                },
                // Room for many streams, but very little for any one of them.
                max_receive_buffer: 4096,
                max_stream_buffer: 8,
                max_stream_receive_buffer: 4,
                ..SmuxServerConfig::default()
            },
            None,
        ));

        for stream_id in [1, 2] {
            write_frame(&mut client, VERSION_V1, CMD_SYN, stream_id, &[])
                .await
                .unwrap();
            handler.ready.notified().await;
        }
        // Nobody reads stream 1, so it fills its four bytes and then loses the
        // rest -- while stream 2 still has its own four to itself.
        for _ in 0..8 {
            write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"aa")
                .await
                .unwrap();
        }
        write_frame(&mut client, VERSION_V1, CMD_PSH, 2, b"bb")
            .await
            .unwrap();

        write_frame(&mut client, VERSION_V1, CMD_SYN, 4, &[])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handler.ready.notified())
            .await
            .expect("a stream over its own budget must not stall or fail the session");

        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();
        client.shutdown().await.unwrap();
        session
            .await
            .unwrap()
            .expect("the session outlives one stream exhausting its budget");
    }

    #[tokio::test]
    async fn fin_does_not_block_the_physical_reader_when_inbound_queue_is_full() {
        let (mut client, server) = tokio::io::duplex(512);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    inbound_frames_per_stream: 1,
                    max_frame_payload: 4,
                    ..SmuxLimits::default()
                },
                max_receive_buffer: 8,
                max_stream_buffer: 4,
                ..SmuxServerConfig::default()
            },
            None,
        ));

        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"x")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_FIN, 1, &[])
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_SYN, 2, &[])
            .await
            .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            handler.ready.notified(),
        )
        .await
        .expect("smux reader must continue after FIN even when the logical queue is full");

        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();
        client.shutdown().await.unwrap();
        session.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn server_closed_streams_release_their_concurrency_slot() {
        let (mut client, server) = tokio::io::duplex(512);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    max_concurrent_streams: 2,
                    ..SmuxLimits::default()
                },
                ..SmuxServerConfig::default()
            },
            None,
        ));

        // Open more streams over the session's life than it may hold at once,
        // closing each from the server side and never sending a FIN back. Every
        // one of those slots used to be held until the peer reciprocated, so the
        // third SYN tripped the concurrency limit and killed the session --
        // taking any other logical stream on it down as well.
        for stream_id in 1..=5_u32 {
            write_frame(&mut client, VERSION_V1, CMD_SYN, stream_id, &[])
                .await
                .unwrap();
            // Bounded: when a slot is not reclaimed the session dies at the
            // limit check and this stream is never handed to the handler, so
            // waiting unconditionally would hang the suite instead of failing.
            tokio::time::timeout(std::time::Duration::from_secs(5), handler.ready.notified())
                .await
                .unwrap_or_else(|_| {
                    panic!("stream {stream_id} was refused: a closed stream did not free its slot")
                });
            handler
                .held
                .lock()
                .expect("holding handler mutex poisoned")
                .clear();
            tokio::task::yield_now().await;
        }

        // Reclaiming slots makes a frame for an already-finished stream a normal
        // race rather than a protocol error, so late frames must be discarded
        // instead of failing the session.
        write_frame(&mut client, VERSION_V1, CMD_PSH, 5, b"late")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_FIN, 5, &[])
            .await
            .unwrap();

        client.shutdown().await.unwrap();
        session
            .await
            .unwrap()
            .expect("a server-closed stream must free its slot and tolerate late frames");
    }

    #[tokio::test]
    async fn a_stream_overrunning_its_queue_does_not_take_the_session_with_it() {
        let (mut client, server) = tokio::io::duplex(512);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    inbound_frames_per_stream: 1,
                    max_frame_payload: 4,
                    ..SmuxLimits::default()
                },
                max_receive_buffer: 64,
                max_stream_buffer: 8,
                ..SmuxServerConfig::default()
            },
            None,
        ));

        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;

        // The handler holds stream 1 without ever reading it, so its one-slot
        // queue fills and the next frame has nowhere to go.
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"aa")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"bb")
            .await
            .unwrap();

        // The session must still serve everyone else on it.
        write_frame(&mut client, VERSION_V1, CMD_SYN, 2, &[])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handler.ready.notified())
            .await
            .expect("one stream overrunning its queue must not tear down the session");

        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();
        client.shutdown().await.unwrap();
        session
            .await
            .unwrap()
            .expect("the session outlives a single stream's overflow");
    }

    #[tokio::test]
    async fn an_overflow_leaves_the_close_to_the_stream_itself() {
        // A finished logical stream announces itself on drop, through a permit
        // it reserved when it was opened -- that send cannot block. Anything
        // the physical reader enqueues on top of it is both a duplicate FIN and
        // a chance for the reader to park on a full outbound queue, stalling
        // every other stream on the connection. Exactly one close must reach
        // the peer, and it must not come from the reader.
        let (client, server) = tokio::io::duplex(4096);
        let handler = Arc::new(HoldingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig {
                limits: SmuxLimits {
                    inbound_frames_per_stream: 1,
                    max_frame_payload: 4,
                    ..SmuxLimits::default()
                },
                max_receive_buffer: 256,
                max_stream_buffer: 4,
                ..SmuxServerConfig::default()
            },
            None,
        ));

        let mut client = client;
        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        // One frame fills the single inbound slot; the next overruns it.
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"aa")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"bb")
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // Let the overrun stream drop, which is what should emit the close.
        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();
        client.shutdown().await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), session).await;

        let mut closes = 0;
        while let Ok(Some(frame)) = read_frame(&mut client, VERSION_V1, 1024).await {
            if frame.command == CMD_FIN && frame.stream_id == 1 {
                closes += 1;
            }
        }
        assert_eq!(
            closes, 1,
            "the reader must leave the close to the stream's own drop"
        );
    }

    #[derive(Debug, Default)]
    struct ParkingHandler {
        ready: Notify,
    }

    #[async_trait]
    impl TcpServerHandler for ParkingHandler {
        async fn setup_server_stream(
            &self,
            _: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            self.ready.notify_one();
            // Stands in for a logical stream parked on a peer that never
            // answers, which is the state a third of production sessions were
            // in when their physical connection went away.
            std::future::pending::<()>().await;
            unreachable!("the parked handler never resolves")
        }
    }

    #[derive(Debug, Default)]
    struct DetachingHandler {
        ready: Notify,
    }

    #[async_trait]
    impl TcpServerHandler for DetachingHandler {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            // What the h2mux magic-destination branch does: carry the logical
            // stream off into a task of its own and report the work as handled.
            // The session's own bookkeeping then sees that stream finish, while
            // its drop-close permit and outbound sender stay alive somewhere
            // the session cannot reach -- so nothing it cancels will close the
            // channels its forwarder and writer are waiting on.
            tokio::spawn(async move {
                let _held = stream;
                std::future::pending::<()>().await;
            });
            self.ready.notify_one();
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[tokio::test]
    async fn a_detached_inner_session_does_not_hold_the_sessions_teardown_open() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = Arc::new(DetachingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig::default(),
            None,
        ));

        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        drop(client);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("a detached inner session must not hold the session's teardown open")
            .expect("the session task must not panic");

        if let Err(error) = outcome {
            assert!(
                !error.to_string().contains("close task timed out"),
                "teardown fell back to the close-forwarder timeout: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_parked_stream_does_not_hold_the_sessions_teardown_open() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = Arc::new(ParkingHandler::default());
        let session = tokio::spawn(serve_smux(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig::default(),
            None,
        ));

        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        // The peer goes away while that stream is still parked, so nothing will
        // release its drop-close permit or its outbound sender on its own.
        drop(client);

        // The close forwarder and the writer bound their own waits at five
        // seconds each, and a session in this state used to sit out both.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("a parked stream must not hold the session's teardown open")
            .expect("the session task must not panic");

        // Whatever the session reports, it must not be the close forwarder
        // giving up: that timeout is what used to abort the writer with flushes
        // still queued. A write-half error is fair game here -- the peer is
        // already gone -- so only the timeout itself is disqualifying.
        if let Err(error) = outcome {
            assert!(
                !error.to_string().contains("close task timed out"),
                "teardown fell back to the close-forwarder timeout: {error}"
            );
        }
    }

    #[tokio::test]
    async fn clean_physical_close_does_not_spin_after_update_channel_closes() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let session = serve_smux(
            Box::new(TestStream(server)),
            Arc::new(UnusedHandler),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig::default(),
            None,
        );
        tokio::time::timeout(std::time::Duration::from_millis(100), session)
            .await
            .expect("closed smux session must not leave the writer in a hot loop")
            .unwrap();
    }
}
