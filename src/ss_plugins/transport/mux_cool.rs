use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use super::smux::{BackpressureCause, record_backpressure_drop};
use super::virtual_stream::{
    BudgetEviction, InboundChannels, InboundEvent, InboundFailure, InboundTerminal,
    OutboundCommand, ReceiveBudget, VirtualStream,
};
use crate::async_stream::AsyncStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::process_stream;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 0x01;
const MUX_COOL_STREAM_RECEIVE_BUFFER: usize = 256 * 1024;
const MUX_COOL_SESSION_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;
const MUX_COOL_LISTENER_RECEIVE_BUFFER: usize = 256 * 1024 * 1024;

/// How long a finished session waits for its logical streams to wind down
/// before cancelling them.
///
/// Their tasks own the drop-close permits and the outbound sender clones that
/// the close forwarder and the writer block on, so waiting for those two is
/// really waiting on a proxied peer that may never answer. Nothing bounded
/// that wait before, so a single parked stream kept the session task -- and
/// the physical connection's fd -- alive for good. Cancelling the streams
/// directly ends the session in bounded time and lets the shared machinery
/// close on its own terms instead.
///
/// A second rather than something tighter because this also covers the
/// teardowns where the physical connection is still writable -- the reader
/// breaking on a protocol violation, say -- and a stream mid-download there can
/// still use the time. When the peer is simply gone, which is the common case,
/// the streams fail fast and the grace never elapses at all.
const STREAM_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub struct MuxCoolLimits {
    pub max_concurrent_streams: usize,
    pub inbound_frames_per_stream: usize,
    pub outbound_frame_queue: usize,
    pub max_metadata_bytes: usize,
}

impl Default for MuxCoolLimits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 256,
            inbound_frames_per_stream: 4,
            outbound_frame_queue: 128,
            max_metadata_bytes: 1024,
        }
    }
}

pub struct MuxCoolServerHandler {
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    limits: MuxCoolLimits,
    listener_budget: Arc<ReceiveBudget>,
}

impl fmt::Debug for MuxCoolServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxCoolServerHandler")
            .field("inner", &self.inner)
            .field("resolver", &self.resolver)
            .field("limits", &self.limits)
            .finish()
    }
}

impl MuxCoolServerHandler {
    pub fn new(
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
        limits: MuxCoolLimits,
    ) -> Self {
        Self {
            inner,
            resolver,
            limits,
            listener_budget: Arc::new(ReceiveBudget::new(MUX_COOL_LISTENER_RECEIVE_BUFFER)),
        }
    }
}

#[async_trait]
impl TcpServerHandler for MuxCoolServerHandler {
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
        validate_limits(self.limits)?;
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        let limits = self.limits;
        let listener_budget = self.listener_budget.clone();
        Ok(TcpServerSetupResult::connection_task(async move {
            if let Err(error) =
                serve_mux_cool(stream, inner, resolver, peer_addr, limits, listener_budget).await
            {
                log::debug!("Mux.Cool session finished with error: {error}");
            }
            Ok(())
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct ParsedMetadata {
    stream_id: u16,
    status: u8,
    has_data: bool,
    has_error: bool,
}

fn parse_metadata(metadata: &[u8]) -> io::Result<ParsedMetadata> {
    if metadata.len() < 4 {
        return invalid("Mux.Cool metadata is shorter than 4 bytes");
    }
    let stream_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let options = metadata[3];
    if options & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return invalid("Mux.Cool frame has unknown option bits");
    }
    match status {
        STATUS_NEW => parse_new_metadata(&metadata[4..])?,
        STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE if metadata.len() == 4 => {}
        STATUS_KEEP | STATUS_END | STATUS_KEEP_ALIVE => {
            return invalid("Mux.Cool control metadata has trailing bytes");
        }
        _ => return invalid("Mux.Cool frame has unknown status"),
    }
    Ok(ParsedMetadata {
        stream_id,
        status,
        has_data: options & OPTION_DATA != 0,
        has_error: options & OPTION_ERROR != 0,
    })
}

fn parse_new_metadata(metadata: &[u8]) -> io::Result<()> {
    if metadata.len() < 4 {
        return invalid("Mux.Cool New metadata is truncated");
    }
    if metadata[0] != NETWORK_TCP {
        return invalid("Mux.Cool plugin transport supports TCP logical streams only");
    }
    // Port is bytes 1..3 and may legally be zero in V2Ray's dokodemo/plugin
    // topology.  The address is validated but deliberately not used for routing:
    // every logical stream must enter the configured Shadowsocks server handler.
    let address = &metadata[3..];
    let consumed = match address.first().copied() {
        Some(0x01) => 1 + 4,
        Some(0x02) => {
            let length = *address
                .get(1)
                .ok_or_else(|| invalid_error("Mux.Cool domain length is missing"))?
                as usize;
            if length == 0 {
                return invalid("Mux.Cool domain is empty");
            }
            let domain = address
                .get(2..2 + length)
                .ok_or_else(|| invalid_error("Mux.Cool domain is truncated"))?;
            if !domain.is_ascii() {
                return invalid("Mux.Cool domain is not ASCII");
            }
            2 + length
        }
        Some(0x03) => 1 + 16,
        Some(_) => return invalid("Mux.Cool address type is unknown"),
        None => return invalid("Mux.Cool address type is missing"),
    };
    if address.len() != consumed {
        return invalid("Mux.Cool New metadata has trailing address bytes");
    }
    Ok(())
}

/// Frame decoding state that outlives the future reading into it.
///
/// The session loop has to service budget evictions while a read is in
/// flight, and `tokio::select!` drops whichever branch loses. A decoder that
/// kept its partial metadata or payload on the future's own stack would take
/// those bytes with it, leaving the next read to parse the middle of a frame
/// and killing a session that did nothing wrong. Holding the state here makes
/// the read resumable, so cancelling it costs nothing.
#[derive(Default)]
struct FrameReader {
    length_bytes: [u8; 2],
    length_read: usize,
    metadata: Vec<u8>,
    metadata_read: usize,
    parsed: Option<ParsedMetadata>,
    data_length_bytes: [u8; 2],
    data_length_read: usize,
    data: Vec<u8>,
    data_read: usize,
}

impl FrameReader {
    async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        max_metadata: usize,
    ) -> io::Result<Option<(ParsedMetadata, Vec<u8>)>> {
        while self.length_read < 2 {
            let read = reader
                .read(&mut self.length_bytes[self.length_read..])
                .await?;
            if read == 0 {
                return if self.length_read == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Mux.Cool metadata length truncated",
                    ))
                };
            }
            self.length_read += read;
        }
        if self.parsed.is_none() {
            let metadata_len = u16::from_be_bytes(self.length_bytes) as usize;
            if metadata_len > max_metadata {
                return invalid("Mux.Cool metadata exceeds configured limit");
            }
            if self.metadata.len() != metadata_len {
                self.metadata = vec![0u8; metadata_len];
            }
            while self.metadata_read < metadata_len {
                let read = reader
                    .read(&mut self.metadata[self.metadata_read..])
                    .await?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Mux.Cool metadata truncated",
                    ));
                }
                self.metadata_read += read;
            }
            self.parsed = Some(parse_metadata(&self.metadata)?);
        }
        let parsed = self.parsed.expect("metadata was just parsed");
        if parsed.has_data {
            while self.data_length_read < 2 {
                let read = reader
                    .read(&mut self.data_length_bytes[self.data_length_read..])
                    .await?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Mux.Cool payload length truncated",
                    ));
                }
                self.data_length_read += read;
            }
            let length = u16::from_be_bytes(self.data_length_bytes) as usize;
            if self.data.len() != length {
                self.data = vec![0u8; length];
            }
            while self.data_read < length {
                let read = reader.read(&mut self.data[self.data_read..]).await?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Mux.Cool payload truncated",
                    ));
                }
                self.data_read += read;
            }
        }
        let data = std::mem::take(&mut self.data);
        *self = Self::default();
        Ok(Some((parsed, data)))
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_metadata: usize,
) -> io::Result<Option<(ParsedMetadata, Vec<u8>)>> {
    FrameReader::default().read(reader, max_metadata).await
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    stream_id: u16,
    status: u8,
    data: &[u8],
) -> io::Result<()> {
    let has_data = !data.is_empty();
    let mut frame = Vec::with_capacity(8 + data.len());
    frame.extend_from_slice(&4u16.to_be_bytes());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(status);
    frame.push(if has_data { OPTION_DATA } else { 0 });
    if has_data {
        let length = u16::try_from(data.len())
            .map_err(|_| invalid_error("Mux.Cool payload exceeds 65535 bytes"))?;
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(data);
    }
    // Mihomo's Mux.Read reads the status and option with one net.Conn.Read
    // instead of io.ReadFull.  A WebSocket transport preserves write
    // boundaries, so emitting the fields through separate writes can expose a
    // one-byte status frame and desynchronize that client.  The reference
    // V2Ray writer also emits one complete mux frame at a time.
    writer.write_all(&frame).await
}

struct LogicalStreamState {
    inbound: Option<mpsc::Sender<InboundEvent>>,
    terminal: Option<oneshot::Sender<InboundTerminal>>,
    budget: Arc<ReceiveBudget>,
    task: Option<tokio::task::AbortHandle>,
}

async fn serve_mux_cool(
    stream: Box<dyn AsyncStream>,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<std::net::SocketAddr>,
    limits: MuxCoolLimits,
    listener_budget: Arc<ReceiveBudget>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (outbound_tx, mut outbound_rx) =
        mpsc::channel::<OutboundCommand>(limits.outbound_frame_queue);
    let (drop_close_tx, mut drop_close_rx) = mpsc::channel::<u32>(limits.max_concurrent_streams);
    let (eviction_tx, mut eviction_rx) = mpsc::unbounded_channel::<BudgetEviction>();
    let receive_budget = Arc::new(ReceiveBudget::with_parent(
        MUX_COOL_SESSION_RECEIVE_BUFFER,
        Some(listener_budget),
    ));
    let close_outbound = outbound_tx.clone();
    let mut close_forwarder = tokio::spawn(async move {
        while let Some(stream_id) = drop_close_rx.recv().await {
            close_outbound
                .send(OutboundCommand::Finished { stream_id })
                .await
                .map_err(|_| invalid_error("Mux.Cool session writer closed"))?;
        }
        Ok::<(), io::Error>(())
    });
    // The writer has an explicit shutdown signal so its lifetime does not
    // depend on every nested sender clone disappearing in a particular order.
    let writer_shutdown = Arc::new(tokio::sync::Notify::new());
    let writer_shutdown_signal = writer_shutdown.clone();
    let mut writer_task = tokio::spawn(async move {
        let mut closing = false;
        loop {
            tokio::select! {
                command = outbound_rx.recv() => {
                    let Some(command) = command else { break };
                    match command {
                        OutboundCommand::Data { stream_id, data } => {
                            let stream_id = u16::try_from(stream_id)
                                .map_err(|_| invalid_error("Mux.Cool stream ID exceeds u16"))?;
                            write_frame(&mut writer, stream_id, STATUS_KEEP, &data).await?;
                        }
                        OutboundCommand::Finished { stream_id } => {
                            let stream_id = u16::try_from(stream_id)
                                .map_err(|_| invalid_error("Mux.Cool stream ID exceeds u16"))?;
                            write_frame(&mut writer, stream_id, STATUS_END, &[]).await?;
                        }
                        OutboundCommand::Barrier { complete } => {
                            let result = writer.flush().await;
                            let reported = result
                                .as_ref()
                                .map(|_| ())
                                .map_err(|error| io::Error::new(error.kind(), error.to_string()));
                            let _ = complete.send(reported);
                            result?;
                        }
                    }
                }
                _ = writer_shutdown_signal.notified(), if !closing => {
                    // Closing the receiver rather than breaking: it refuses new
                    // sends but still yields what is already queued, so the
                    // flush barriers in flight are completed instead of
                    // dropped, and the End frames a cancelled stream's drop
                    // emitted still reach the peer. The drain then ends the
                    // loop through the ordinary `None` arm above.
                    outbound_rx.close();
                    closing = true;
                }
            }
        }
        writer.shutdown().await
    });

    let mut streams: HashMap<u16, LogicalStreamState> = HashMap::new();
    // Held rather than detached so the session can cancel what it started.
    // Dropping this set aborts anything still running, which is the right end
    // for a logical stream whose physical session is gone: it has no transport
    // left to carry anything to the client.
    let mut stream_tasks = tokio::task::JoinSet::new();
    let mut frame_reader = FrameReader::default();
    let read_result = loop {
        let frame = tokio::select! {
            biased;
            Some(eviction) = eviction_rx.recv() => {
                let stream_id = eviction.stream_id as u16;
                if let Some(state) = streams.remove(&stream_id) {
                    record_backpressure_drop(BackpressureCause::Bytes(eviction.scope));
                    if let Some(task) = state.task {
                        task.abort();
                    }
                    if let Some(terminal) = state.terminal {
                        let _ = terminal.send(InboundTerminal::Failed(InboundFailure::new(
                        io::ErrorKind::OutOfMemory,
                        format!("Mux.Cool {} receive budget evicted the largest buffered stream", eviction.scope),
                        )));
                    }
                }
                continue;
            }
            frame = frame_reader.read(&mut reader, limits.max_metadata_bytes) => frame,
        };
        let (metadata, data) = match frame {
            Ok(Some(frame)) => frame,
            Ok(None) => break Ok(()),
            Err(error) => break Err(error),
        };
        match metadata.status {
            STATUS_NEW => {
                // Mux.Cool reclaims a map slot when the peer sends End, so
                // this is the one point where the session's stream count is
                // allowed to grow; reap here too, or a finished task would sit
                // in the set for the life of the session.
                while stream_tasks.try_join_next().is_some() {}
                if streams.contains_key(&metadata.stream_id) {
                    break invalid("Mux.Cool New reused an active stream ID");
                }
                if streams.len() >= limits.max_concurrent_streams {
                    break invalid("Mux.Cool concurrent stream limit exceeded");
                }
                let close_permit = match drop_close_tx.clone().reserve_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break invalid("Mux.Cool close forwarder closed"),
                };
                let (inbound_tx, inbound_rx) = mpsc::channel(limits.inbound_frames_per_stream);
                let (terminal_tx, terminal_rx) = oneshot::channel();
                let budget = Arc::new(ReceiveBudget::stream(
                    MUX_COOL_STREAM_RECEIVE_BUFFER,
                    receive_budget.clone(),
                    u32::from(metadata.stream_id),
                    eviction_tx.clone(),
                ));
                if !data.is_empty() {
                    let tracked = match budget.track(data) {
                        Ok(data) => data,
                        Err(error) => {
                            record_backpressure_drop(BackpressureCause::Bytes(error.scope));
                            let _ = outbound_tx.try_send(OutboundCommand::Finished {
                                stream_id: u32::from(metadata.stream_id),
                            });
                            continue;
                        }
                    };
                    if inbound_tx.try_send(InboundEvent::Data(tracked)).is_err() {
                        record_backpressure_drop(BackpressureCause::FrameQueue);
                        let _ = outbound_tx.try_send(OutboundCommand::Finished {
                            stream_id: u32::from(metadata.stream_id),
                        });
                        continue;
                    }
                }
                streams.insert(
                    metadata.stream_id,
                    LogicalStreamState {
                        inbound: Some(inbound_tx),
                        terminal: Some(terminal_tx),
                        budget,
                        task: None,
                    },
                );
                let mut logical = VirtualStream::new(
                    u32::from(metadata.stream_id),
                    InboundChannels::new(inbound_rx, terminal_rx),
                    outbound_tx.clone(),
                    u16::MAX as usize,
                );
                logical.set_drop_close_permit(close_permit);
                let inner = inner.clone();
                let resolver = resolver.clone();
                let task = stream_tasks.spawn(async move {
                    if let Err(error) = process_stream(logical, inner, resolver, peer_addr).await {
                        log::debug!(
                            "Mux.Cool logical stream {} finished with error: {error}",
                            metadata.stream_id
                        );
                    }
                });
                streams
                    .get_mut(&metadata.stream_id)
                    .expect("stream state was just inserted")
                    .task = Some(task);
            }
            STATUS_KEEP => {
                match streams.get_mut(&metadata.stream_id) {
                    Some(state) => {
                        if !data.is_empty()
                            && let Some(sender) = &state.inbound
                        {
                            let tracked = match state.budget.track(data) {
                                Ok(data) => data,
                                Err(error) => {
                                    record_backpressure_drop(BackpressureCause::Bytes(error.scope));
                                    let removed = streams.remove(&metadata.stream_id);
                                    if let Some(task) =
                                        removed.as_ref().and_then(|state| state.task.as_ref())
                                    {
                                        task.abort();
                                    }
                                    if let Some(terminal) = removed.and_then(|state| state.terminal)
                                    {
                                        let _ = terminal.send(InboundTerminal::Failed(
                                            InboundFailure::new(
                                                io::ErrorKind::OutOfMemory,
                                                error.to_string(),
                                            ),
                                        ));
                                    }
                                    continue;
                                }
                            };
                            match sender.try_send(InboundEvent::Data(tracked)) {
                                Ok(()) => {}
                                Err(TrySendError::Closed(_)) => state.inbound = None,
                                Err(TrySendError::Full(_)) => {
                                    record_backpressure_drop(BackpressureCause::FrameQueue);
                                    let removed = streams.remove(&metadata.stream_id);
                                    if let Some(task) =
                                        removed.as_ref().and_then(|state| state.task.as_ref())
                                    {
                                        task.abort();
                                    }
                                    if let Some(terminal) = removed.and_then(|state| state.terminal)
                                    {
                                        let _ = terminal.send(InboundTerminal::Failed(
                                            InboundFailure::new(
                                                io::ErrorKind::OutOfMemory,
                                                "Mux.Cool logical inbound frame queue is full",
                                            ),
                                        ));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    None => {
                        // V2Ray's reference server treats a late Keep as a
                        // per-stream condition: discard its payload and tell
                        // the peer to close that stream.  It must not tear
                        // down every logical stream on the physical session.
                        if outbound_tx
                            .send(OutboundCommand::Finished {
                                stream_id: u32::from(metadata.stream_id),
                            })
                            .await
                            .is_err()
                        {
                            break invalid("Mux.Cool session writer closed");
                        }
                    }
                }
            }
            STATUS_END => {
                // Close is idempotent in the reference implementation.  In
                // particular, Mihomo may emit End more than once while
                // unwinding layered net.Conn wrappers.
                if let Some(mut state) = streams.remove(&metadata.stream_id) {
                    let mut local_failure = None;
                    if !data.is_empty()
                        && let Some(inbound) = state.inbound.take()
                    {
                        match state.budget.track(data) {
                            Ok(tracked) => {
                                if matches!(
                                    inbound.try_send(InboundEvent::Data(tracked)),
                                    Err(TrySendError::Full(_))
                                ) {
                                    record_backpressure_drop(BackpressureCause::FrameQueue);
                                    local_failure = Some(
                                        "Mux.Cool logical inbound frame queue is full".to_string(),
                                    );
                                }
                            }
                            Err(error) => {
                                record_backpressure_drop(BackpressureCause::Bytes(error.scope));
                                local_failure = Some(error.to_string());
                            }
                        }
                    }
                    if let Some(message) = local_failure {
                        if let Some(task) = state.task {
                            task.abort();
                        }
                        if let Some(terminal_tx) = state.terminal {
                            let _ = terminal_tx.send(InboundTerminal::Failed(InboundFailure::new(
                                io::ErrorKind::OutOfMemory,
                                message,
                            )));
                        }
                    } else if let Some(terminal_tx) = state.terminal {
                        let terminal = if metadata.has_error {
                            InboundTerminal::Failed(InboundFailure::new(
                                io::ErrorKind::ConnectionReset,
                                "Mux.Cool peer closed the logical stream",
                            ))
                        } else {
                            InboundTerminal::Finished
                        };
                        let _ = terminal_tx.send(terminal);
                    }
                }
            }
            STATUS_KEEP_ALIVE => {}
            _ => unreachable!("status validated by parser"),
        }
    };

    let failure = read_result.as_ref().err().map_or_else(
        || {
            InboundFailure::new(
                io::ErrorKind::ConnectionAborted,
                "Mux.Cool physical stream closed",
            )
        },
        InboundFailure::from_error,
    );
    for (_, stream) in streams {
        if let Some(terminal) = stream.terminal {
            let _ = terminal.send(InboundTerminal::Failed(failure.clone()));
        }
    }
    drop(drop_close_tx);
    drop(outbound_tx);
    // Wind the logical streams down before waiting on the forwarder and the
    // writer, because those two cannot finish until every stream has released
    // its drop-close permit and its outbound sender. The End events delivered
    // above only unblock a stream's inbound half; one parked on its proxied
    // peer needs cancelling. The grace lets a stream that is already finishing
    // report its own outcome first.
    if tokio::time::timeout(STREAM_SHUTDOWN_GRACE, async {
        while stream_tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        stream_tasks.shutdown().await;
    }
    // Every production handler now returns an owned connection future, so all
    // permits should have been released above. Keep a bound here as an
    // invariant guard: if a future implementation leaks ownership, teardown
    // still cannot retain the physical connection forever.
    let close_result =
        match tokio::time::timeout(STREAM_SHUTDOWN_GRACE, &mut close_forwarder).await {
            Ok(joined) => joined
                .map_err(|error| io::Error::other(format!("Mux.Cool close task failed: {error}"))),
            Err(_) => {
                // Not a failure of this session. Having cancelled every stream it
                // owns, a forwarder still waiting means a permit is held where the
                // session cannot reach it, and reporting that as the outcome would
                // bury the result that actually describes the session -- the read
                // result -- under something it could do nothing about.
                close_forwarder.abort();
                log::debug!("Mux.Cool close-forwarder ownership invariant violated");
                Ok(Ok(()))
            }
        };
    // Tell the writer to drain and stop. Signalled after the streams were
    // cancelled so the End frames their drops emit are already queued, and
    // issued whether or not the forwarder finished, because an invariant
    // violation may still have left a sender alive.
    writer_shutdown.notify_one();
    let close_result = close_result?;
    // Bound only the writer drain: it may still be blocked on a physical
    // stream that never completes a write, and aborting it only releases the
    // write half (the fd is owned by the reader side, which has already
    // finished and delivered per-stream End events above).
    let writer_result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut writer_task)
        .await
        .map_err(|_| {
            writer_task.abort();
            io::Error::other("Mux.Cool writer task timed out")
        })?
        .map_err(|error| io::Error::other(format!("Mux.Cool writer task failed: {error}")))?;
    read_result.and(close_result).and(writer_result)
}

fn validate_limits(limits: MuxCoolLimits) -> io::Result<()> {
    if limits.max_concurrent_streams == 0
        || limits.max_concurrent_streams > tokio::sync::Semaphore::MAX_PERMITS
        || limits.inbound_frames_per_stream == 0
        || limits.inbound_frames_per_stream > tokio::sync::Semaphore::MAX_PERMITS
        || limits.outbound_frame_queue == 0
        || limits.outbound_frame_queue > tokio::sync::Semaphore::MAX_PERMITS
        || limits.max_metadata_bytes < 4
        || limits.max_metadata_bytes > u16::MAX as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Mux.Cool resource limits",
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
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncReadExt, DuplexStream, ReadBuf};
    use tokio::sync::Notify;

    use super::*;
    use crate::address::NetLocation;
    use crate::async_stream::AsyncPing;

    #[derive(Default)]
    struct WriteBoundaryRecorder {
        writes: Vec<Vec<u8>>,
    }

    impl AsyncWrite for WriteBoundaryRecorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push(data.to_vec());
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

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

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
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
            _stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            unreachable!("control-frame test does not create logical streams")
        }
    }

    #[derive(Debug)]
    struct UnusedResolver;

    impl Resolver for UnusedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            unreachable!("control-frame test does not resolve destinations")
        }
    }

    fn control_frame(stream_id: u16, status: u8) -> [u8; 6] {
        let [id_hi, id_lo] = stream_id.to_be_bytes();
        [0, 4, id_hi, id_lo, status, 0]
    }

    /// A minimal New frame: TCP to 127.0.0.1:80, which the handler never sees
    /// because Mux.Cool logical streams are not routed on their metadata.
    fn new_frame(stream_id: u16) -> [u8; 14] {
        let [id_hi, id_lo] = stream_id.to_be_bytes();
        [
            0,
            12,
            id_hi,
            id_lo,
            STATUS_NEW,
            0,
            NETWORK_TCP,
            0,
            80,
            0x01,
            127,
            0,
            0,
            1,
        ]
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
            // Stands in for a logical stream parked on a proxied peer that
            // never answers: nothing releases its drop-close permit or its
            // outbound sender on its own.
            std::future::pending::<()>().await;
            unreachable!("the parked handler never resolves")
        }
    }

    #[tokio::test]
    async fn a_parked_stream_does_not_hold_the_sessions_teardown_open() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = Arc::new(ParkingHandler::default());
        let session = tokio::spawn(serve_mux_cool(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(UnusedResolver),
            None,
            MuxCoolLimits::default(),
            Arc::new(ReceiveBudget::new(MUX_COOL_LISTENER_RECEIVE_BUFFER)),
        ));

        client.write_all(&new_frame(1)).await.unwrap();
        handler.ready.notified().await;
        // The peer goes away while that stream is still parked, so nothing will
        // release its drop-close permit or its outbound sender on its own.
        drop(client);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("a parked stream must not hold the session's teardown open")
            .expect("the session task must not panic");

        // A write-half error is fair game -- the peer is already gone -- but
        // teardown must not fall back on one of its own bounds, which would
        // mean it gave up on the shared machinery instead of releasing it.
        if let Err(error) = outcome {
            let message = error.to_string();
            assert!(
                !message.contains("timed out"),
                "teardown fell back to one of its own bounds: {message}"
            );
        }
    }

    #[tokio::test]
    async fn a_full_logical_queue_does_not_fail_the_mux_cool_session() {
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = Arc::new(ParkingHandler::default());
        let session = tokio::spawn(serve_mux_cool(
            Box::new(TestStream(server)),
            handler.clone(),
            Arc::new(UnusedResolver),
            None,
            MuxCoolLimits {
                inbound_frames_per_stream: 1,
                ..MuxCoolLimits::default()
            },
            Arc::new(ReceiveBudget::new(MUX_COOL_LISTENER_RECEIVE_BUFFER)),
        ));

        client.write_all(&new_frame(1)).await.unwrap();
        handler.ready.notified().await;
        write_frame(&mut client, 1, STATUS_KEEP, b"a")
            .await
            .unwrap();
        write_frame(&mut client, 1, STATUS_KEEP, b"b")
            .await
            .unwrap();
        client.write_all(&new_frame(2)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), handler.ready.notified())
            .await
            .expect("one full logical queue must not terminate the physical session");

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("Mux.Cool session must tear down after the peer closes");
    }

    /// A listener-scope eviction is delivered to the read loop of whichever
    /// session owns the debtor, which is normally *not* the session that ran
    /// out of budget. That loop may be parked halfway through a frame at the
    /// time, so handling the eviction must not discard the bytes it already
    /// consumed: losing them desynchronises the framing and kills the whole
    /// session, which is the collateral the eviction exists to avoid.
    #[tokio::test]
    async fn a_listener_eviction_does_not_desynchronise_the_victims_frame_reader() {
        let listener = Arc::new(ReceiveBudget::new(8));

        let (mut victim_client, victim_server) = tokio::io::duplex(4096);
        let victim_handler = Arc::new(ParkingHandler::default());
        let victim = tokio::spawn(serve_mux_cool(
            Box::new(TestStream(victim_server)),
            victim_handler.clone(),
            Arc::new(UnusedResolver),
            None,
            MuxCoolLimits::default(),
            listener.clone(),
        ));

        let (mut greedy_client, greedy_server) = tokio::io::duplex(4096);
        let greedy_handler = Arc::new(ParkingHandler::default());
        let greedy = tokio::spawn(serve_mux_cool(
            Box::new(TestStream(greedy_server)),
            greedy_handler.clone(),
            Arc::new(UnusedResolver),
            None,
            MuxCoolLimits::default(),
            listener,
        ));

        // The victim parks six of the listener's eight bytes, making it the
        // debtor any listener-scope eviction will pick. Opening a second
        // stream proves that payload was consumed and charged.
        victim_client.write_all(&new_frame(1)).await.unwrap();
        victim_handler.ready.notified().await;
        write_frame(&mut victim_client, 1, STATUS_KEEP, b"abcdef")
            .await
            .unwrap();
        victim_client.write_all(&new_frame(2)).await.unwrap();
        victim_handler.ready.notified().await;

        // Park the victim's reader inside a frame: announce four payload bytes
        // and deliver two.
        victim_client
            .write_all(&[0, 4, 0, 1, STATUS_KEEP, OPTION_DATA, 0, 4, b'g', b'h'])
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // A different session now runs the listener budget out. It is not the
        // debtor, so the eviction lands on the victim's parked stream.
        greedy_client.write_all(&new_frame(1)).await.unwrap();
        greedy_handler.ready.notified().await;
        write_frame(&mut greedy_client, 1, STATUS_KEEP, b"ijk")
            .await
            .unwrap();

        // Complete the interrupted frame and open another stream. The trailing
        // payload belongs to an evicted stream and is discarded, but the frame
        // after it must still be understood.
        victim_client.write_all(b"ij").await.unwrap();
        victim_client.write_all(&new_frame(3)).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            victim_handler.ready.notified(),
        )
        .await
        .expect("evicting a stream must not cost the session its framing");

        drop(victim_client);
        drop(greedy_client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), victim).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), greedy).await;
    }

    #[test]
    fn parses_new_metadata_for_every_address_type() {
        let ipv4 = [0, 7, STATUS_NEW, 0, NETWORK_TCP, 0, 80, 1, 127, 0, 0, 1];
        let domain = [
            0,
            8,
            STATUS_NEW,
            OPTION_DATA,
            NETWORK_TCP,
            1,
            187,
            2,
            3,
            b'a',
            b'.',
            b'b',
        ];
        let mut ipv6 = vec![0, 9, STATUS_NEW, 0, NETWORK_TCP, 0, 53, 3];
        ipv6.extend_from_slice(&[0; 16]);
        assert_eq!(parse_metadata(&ipv4).unwrap().stream_id, 7);
        assert!(parse_metadata(&domain).unwrap().has_data);
        assert_eq!(parse_metadata(&ipv6).unwrap().status, STATUS_NEW);
    }

    #[test]
    fn rejects_truncated_unknown_and_trailing_metadata() {
        assert!(parse_metadata(&[0, 1, STATUS_NEW]).is_err());
        assert!(parse_metadata(&[0, 1, 0xff, 0]).is_err());
        assert!(parse_metadata(&[0, 1, STATUS_KEEP, 0, 0]).is_err());
        assert!(parse_metadata(&[0, 1, STATUS_NEW, 0, NETWORK_TCP, 0, 80, 2, 4, b'a']).is_err());
        assert!(
            parse_metadata(&[0, 1, STATUS_NEW, 0x80, NETWORK_TCP, 0, 80, 1, 1, 2, 3, 4]).is_err()
        );
    }

    #[test]
    fn accepts_the_reference_error_option_on_end_frames() {
        let parsed = parse_metadata(&[0, 7, STATUS_END, OPTION_ERROR]).unwrap();
        assert_eq!(parsed.stream_id, 7);
        assert!(parsed.has_error);
        assert!(!parsed.has_data);
    }

    #[test]
    fn rejects_channel_capacities_above_tokio_semaphore_limit() {
        for limits in [
            MuxCoolLimits {
                inbound_frames_per_stream: tokio::sync::Semaphore::MAX_PERMITS + 1,
                ..MuxCoolLimits::default()
            },
            MuxCoolLimits {
                outbound_frame_queue: tokio::sync::Semaphore::MAX_PERMITS + 1,
                ..MuxCoolLimits::default()
            },
        ] {
            let error = validate_limits(limits).expect_err("oversized channel must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[tokio::test]
    async fn frame_reader_handles_fragmentation_and_max_payload_boundary() {
        let metadata = [0, 42, STATUS_KEEP, OPTION_DATA];
        let payload = vec![0x5a; u16::MAX as usize];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        wire.extend_from_slice(&metadata);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&payload);
        let fragmented = tokio::io::BufReader::with_capacity(1, wire.as_slice());
        tokio::pin!(fragmented);
        let (parsed, read_payload) = read_frame(&mut fragmented, 1024).await.unwrap().unwrap();
        assert_eq!(parsed.stream_id, 42);
        assert_eq!(read_payload, payload);
    }

    #[tokio::test]
    async fn distinguishes_clean_eof_from_truncated_frame() {
        let empty: &[u8] = &[];
        assert!(
            read_frame(&mut std::io::Cursor::new(empty), 1024)
                .await
                .unwrap()
                .is_none()
        );
        let one_byte: &[u8] = &[0];
        let error = read_frame(&mut std::io::Cursor::new(one_byte), 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn writes_each_mux_frame_with_one_transport_write() {
        let mut writer = WriteBoundaryRecorder::default();
        write_frame(&mut writer, 7, STATUS_KEEP, b"abc")
            .await
            .unwrap();
        assert_eq!(writer.writes.len(), 1);
        assert_eq!(
            writer.writes[0],
            [0, 4, 0, 7, STATUS_KEEP, OPTION_DATA, 0, 3, b'a', b'b', b'c']
        );
    }

    #[tokio::test]
    async fn duplicate_unknown_end_is_ignored_and_late_keep_gets_end() {
        let (mut client, server) = tokio::io::duplex(1024);
        let session = tokio::spawn(serve_mux_cool(
            Box::new(TestStream(server)),
            Arc::new(UnusedHandler),
            Arc::new(UnusedResolver),
            None,
            MuxCoolLimits::default(),
            Arc::new(ReceiveBudget::new(MUX_COOL_LISTENER_RECEIVE_BUFFER)),
        ));

        client
            .write_all(&control_frame(7, STATUS_END))
            .await
            .unwrap();
        client
            .write_all(&control_frame(7, STATUS_END))
            .await
            .unwrap();
        client
            .write_all(&control_frame(9, STATUS_KEEP))
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, control_frame(9, STATUS_END));
        session.await.unwrap().unwrap();
    }
}
