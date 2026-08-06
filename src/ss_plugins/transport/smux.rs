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

const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const HEADER_SIZE: usize = 8;
const UPDATE_PAYLOAD_SIZE: usize = 8;

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
            inbound_frames_per_stream: 4,
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
        }
    }
}

pub struct SmuxServerHandler {
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    config: SmuxServerConfig,
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
        tokio::spawn(async move {
            if let Err(error) = serve_smux(stream, inner, resolver, peer_addr, config).await {
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
    limits: SmuxLimits,
}

impl fmt::Debug for SmuxV1ServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmuxV1ServerHandler")
            .field("inner", &self.inner)
            .field("resolver", &self.resolver)
            .field("limits", &self.limits)
            .finish()
    }
}

impl SmuxV1ServerHandler {
    pub fn new(
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
        limits: SmuxLimits,
    ) -> Self {
        Self {
            inner,
            resolver,
            limits,
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
        let config = SmuxServerConfig {
            version: VERSION_V1,
            limits: self.limits,
            ..SmuxServerConfig::default()
        };
        validate_config(config)?;
        let inner = self.inner.clone();
        let resolver = self.resolver.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_smux(stream, inner, resolver, peer_addr, config).await {
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
    let mut payload = vec![0u8; length];
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
}

async fn serve_smux(
    stream: Box<dyn AsyncStream>,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<std::net::SocketAddr>,
    config: SmuxServerConfig,
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
    let receive_budget = Arc::new(ReceiveBudget::new(config.max_receive_buffer));
    let mut writer_task = tokio::spawn(async move {
        let mut updates_open = true;
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
            }
        }
        writer.shutdown().await
    });

    let mut streams: HashMap<u32, StreamState> = HashMap::new();
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
                tokio::spawn(async move {
                    if let Err(error) = process_stream(logical, inner, resolver, peer_addr).await {
                        log::debug!(
                            "smux v{version} logical stream {} finished with error: {error}",
                            frame.stream_id
                        );
                    }
                });
            }
            CMD_PSH => {
                let Some(inbound) = streams.get_mut(&frame.stream_id) else {
                    break invalid(format!("smux v{version} PSH references an unknown stream"));
                };
                if !frame.payload.is_empty()
                    && let Some(sender) = &inbound.inbound
                {
                    let data = match receive_budget.track(frame.payload) {
                        Ok(data) => data,
                        Err(error) => break Err(error),
                    };
                    match sender.try_send(InboundEvent::Data(data)) {
                        Ok(()) => {}
                        Err(TrySendError::Closed(_)) => inbound.inbound = None,
                        Err(TrySendError::Full(_)) => {
                            break invalid(format!(
                                "smux v{version} logical inbound queue is full"
                            ));
                        }
                    }
                }
            }
            CMD_FIN => {
                let Some(inbound) = streams.remove(&frame.stream_id) else {
                    break invalid(format!("smux v{version} FIN references an unknown stream"));
                };
                if let Some(terminal) = inbound.terminal {
                    let _ = terminal.send(InboundTerminal::Finished);
                }
            }
            CMD_NOP => {}
            CMD_UPD => {
                let Some(stream) = streams.get(&frame.stream_id) else {
                    break invalid("smux v2 UPD references an unknown stream");
                };
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
    // Bound the close forwarder wait. All logical-stream shutdown events were
    // delivered above, so aborting the forwarder here cannot orphan copy
    // tasks; it only releases the drop-close channel and its outbound sender
    // clone so the writer drain below can complete.
    let close_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut close_forwarder)
            .await
            .map_err(|_| {
                close_forwarder.abort();
                io::Error::other("smux close task timed out")
            })
            .and_then(|res| {
                res.map_err(|error| io::Error::other(format!("smux close task failed: {error}")))
            });
    // If the close forwarder failed, still drain/abort the writer so no
    // background task is orphaned (a leaked writer holds the write half of
    // the physical stream and its fd).
    if close_result.is_err() {
        writer_task.abort();
    }
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

    #[tokio::test]
    async fn enforces_receive_buffer_across_the_physical_session() {
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
        ));

        write_frame(&mut client, VERSION_V1, CMD_SYN, 1, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        write_frame(&mut client, VERSION_V1, CMD_SYN, 2, &[])
            .await
            .unwrap();
        handler.ready.notified().await;
        write_frame(&mut client, VERSION_V1, CMD_PSH, 1, b"abc")
            .await
            .unwrap();
        write_frame(&mut client, VERSION_V1, CMD_PSH, 2, b"def")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        handler
            .held
            .lock()
            .expect("holding handler mutex poisoned")
            .clear();

        let error = session
            .await
            .unwrap()
            .expect_err("physical receive budget must reject excess queued bytes");
        assert!(error.to_string().contains("receive buffer"));
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
    async fn clean_physical_close_does_not_spin_after_update_channel_closes() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let session = serve_smux(
            Box::new(TestStream(server)),
            Arc::new(UnusedHandler),
            Arc::new(NativeResolver::new()),
            None,
            SmuxServerConfig::default(),
        );
        tokio::time::timeout(std::time::Duration::from_millis(100), session)
            .await
            .expect("closed smux session must not leave the writer in a hot loop")
            .unwrap();
    }
}
