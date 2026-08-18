use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use super::virtual_stream::{
    InboundChannels, InboundData, InboundEvent, InboundTerminal, OutboundCommand, VirtualStream,
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
        tokio::spawn(async move {
            if let Err(error) = serve_mux_cool(stream, inner, resolver, peer_addr, limits).await {
                log::debug!("Mux.Cool session finished with error: {error}");
            }
        });
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[derive(Debug)]
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

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_metadata: usize,
) -> io::Result<Option<(ParsedMetadata, Vec<u8>)>> {
    let mut length_bytes = [0u8; 2];
    let first = reader.read(&mut length_bytes[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut length_bytes[1..]).await?;
    let metadata_len = u16::from_be_bytes(length_bytes) as usize;
    if metadata_len > max_metadata {
        return invalid("Mux.Cool metadata exceeds configured limit");
    }
    let mut metadata = vec![0u8; metadata_len];
    reader.read_exact(&mut metadata).await?;
    let parsed = parse_metadata(&metadata)?;
    let data = if parsed.has_data {
        let length = reader.read_u16().await? as usize;
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data).await?;
        data
    } else {
        Vec::new()
    };
    Ok(Some((parsed, data)))
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
}

async fn serve_mux_cool(
    stream: Box<dyn AsyncStream>,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<std::net::SocketAddr>,
    limits: MuxCoolLimits,
) -> io::Result<()> {
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
                .map_err(|_| invalid_error("Mux.Cool session writer closed"))?;
        }
        Ok::<(), io::Error>(())
    });
    // The writer cannot be ended by dropping senders alone: an inner handler
    // that takes a logical stream, spawns it and returns `AlreadyHandled`
    // keeps an outbound clone in a task this session cannot reach, so the
    // channel never closes however much of its own work the session cancels.
    // A signal ends it regardless of who else is still holding a sender.
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
    let read_result = loop {
        let (metadata, data) = match read_frame(&mut reader, limits.max_metadata_bytes).await {
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
                if !data.is_empty()
                    && inbound_tx
                        .try_send(InboundEvent::Data(InboundData::untracked(data)))
                        .is_err()
                {
                    break invalid("Mux.Cool logical inbound queue rejected initial data");
                }
                streams.insert(
                    metadata.stream_id,
                    LogicalStreamState {
                        inbound: Some(inbound_tx),
                        terminal: Some(terminal_tx),
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
                stream_tasks.spawn(async move {
                    if let Err(error) = process_stream(logical, inner, resolver, peer_addr).await {
                        log::debug!(
                            "Mux.Cool logical stream {} finished with error: {error}",
                            metadata.stream_id
                        );
                    }
                });
            }
            STATUS_KEEP => {
                match streams.get_mut(&metadata.stream_id) {
                    Some(state) => {
                        if !data.is_empty()
                            && let Some(sender) = &state.inbound
                        {
                            match sender.try_send(InboundEvent::Data(InboundData::untracked(data)))
                            {
                                Ok(()) => {}
                                Err(TrySendError::Closed(_)) => state.inbound = None,
                                Err(TrySendError::Full(_)) => {
                                    break invalid("Mux.Cool logical inbound queue is full");
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
                if let Some(state) = streams.remove(&metadata.stream_id) {
                    if !data.is_empty()
                        && let Some(inbound) = state.inbound
                    {
                        match inbound.try_send(InboundEvent::Data(InboundData::untracked(data))) {
                            Ok(()) => {}
                            Err(TrySendError::Closed(_)) => {}
                            Err(TrySendError::Full(_)) => {
                                break invalid("Mux.Cool logical inbound queue is full");
                            }
                        }
                    }
                    if let Some(terminal_tx) = state.terminal {
                        let terminal = if metadata.has_error {
                            InboundTerminal::Failed(
                                "Mux.Cool peer closed the logical stream".to_string(),
                            )
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

    let failure = read_result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_else(|| "Mux.Cool physical stream closed".to_string());
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
    // Whatever still holds a drop-close permit here is out of this session's
    // reach -- an inner handler that detached the logical stream it was given,
    // most concretely -- so waiting on the forwarder is waiting on something
    // the session can no longer influence. Bounded by the same grace for that
    // reason. Aborting it cannot orphan anything: it only turns drop
    // notifications into End frames, and the session is over.
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
                log::debug!(
                    "Mux.Cool close forwarder outlived the streams this session owns; \
                 an inner handler kept one"
                );
                Ok(Ok(()))
            }
        };
    // Tell the writer to drain and stop. Signalled after the streams were
    // cancelled so the End frames their drops emit are already queued, and
    // issued whether or not the forwarder finished, because the writer is held
    // open by the same unreachable senders.
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
