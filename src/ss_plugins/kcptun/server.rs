//! Bounded, in-process Kcptun UDP server.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use kcp::{Error as KcpError, KCP_OVERHEAD, Kcp, get_conv, get_sn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use super::config::KcptunConfig;
use super::crypto::PacketCrypt;
use super::fec::{
    FEC_DATA_HEADER_SIZE, FEC_HEADER_SIZE, FEC_TYPE_DATA, FEC_TYPE_OOB, FEC_TYPE_PARITY,
    FecDecoder, FecEncoder,
};
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::resolver::Resolver;
use crate::ss_plugins::transport::{SmuxLimits, SmuxServerConfig, SmuxServerHandler};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const UDP_RECEIVE_BUFFER: usize = u16::MAX as usize + 1;
const SNAPPY_STREAM_IDENTIFIER: &[u8; 10] = b"\xff\x06\x00\x00sNaPpY";

#[derive(Clone, Debug)]
pub struct KcptunServerLimits {
    pub max_sessions: usize,
    pub inbound_packets_per_session: usize,
    pub outbound_packets_per_session: usize,
    pub max_stream_buffer: usize,
    pub max_socket_buffer: usize,
    pub idle_timeout: Duration,
}

impl Default for KcptunServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: 4096,
            inbound_packets_per_session: 256,
            outbound_packets_per_session: 256,
            max_stream_buffer: 16 * 1024 * 1024,
            max_socket_buffer: 64 * 1024 * 1024,
            idle_timeout: Duration::ZERO,
        }
    }
}

impl KcptunServerLimits {
    fn validate(&self) -> io::Result<()> {
        if self.max_sessions == 0
            || self.inbound_packets_per_session == 0
            || self.outbound_packets_per_session == 0
            || self.max_stream_buffer == 0
            || self.max_socket_buffer == 0
        {
            return Err(invalid("Kcptun server resource limits must be positive"));
        }
        Ok(())
    }

    fn effective_idle_timeout(&self, keepalive_secs: u32) -> Duration {
        if self.idle_timeout.is_zero() {
            Duration::from_secs(u64::from(keepalive_secs).saturating_mul(4).max(30))
        } else {
            self.idle_timeout
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KcptunSmuxSettings {
    pub version: u8,
    pub max_receive_buffer: usize,
    pub max_stream_buffer: usize,
    pub max_frame_size: usize,
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
}

impl KcptunSmuxSettings {
    fn from_config(config: &KcptunConfig) -> Self {
        let interval = Duration::from_secs(u64::from(config.keepalive_secs));
        Self {
            version: config.smux_version,
            max_receive_buffer: config.smux_buffer as usize,
            max_stream_buffer: config.stream_buffer as usize,
            max_frame_size: config.frame_size as usize,
            keepalive_interval: interval,
            keepalive_timeout: interval.saturating_mul(3),
        }
    }
}

pub struct KcptunStream {
    inner: DuplexStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    conversation: u32,
}

impl KcptunStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn conversation(&self) -> u32 {
        self.conversation
    }
}

impl fmt::Debug for KcptunStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KcptunStream")
            .field("peer_addr", &self.peer_addr)
            .field("local_addr", &self.local_addr)
            .field("conversation", &self.conversation)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for KcptunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for KcptunStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl AsyncPing for KcptunStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for KcptunStream {}

#[async_trait]
pub trait KcptunSessionHandler: Send + Sync + fmt::Debug {
    async fn handle_session(
        &self,
        stream: KcptunStream,
        smux: KcptunSmuxSettings,
    ) -> io::Result<()>;
}

#[derive(Debug)]
struct TcpPipelineSessionHandler {
    pipeline: Arc<dyn TcpServerHandler>,
}

#[async_trait]
impl KcptunSessionHandler for TcpPipelineSessionHandler {
    async fn handle_session(
        &self,
        stream: KcptunStream,
        _smux: KcptunSmuxSettings,
    ) -> io::Result<()> {
        let peer = stream.peer_addr();
        match self
            .pipeline
            .setup_server_stream_with_peer_addr(Box::new(stream), Some(peer))
            .await?
        {
            TcpServerSetupResult::AlreadyHandled => Ok(()),
            _ => Err(io::Error::other(
                "Kcptun physical-session handler did not consume the stream",
            )),
        }
    }
}

/// Builds the standard Kcptun `Snappy -> smux v1/v2 -> TcpServerHandler`
/// pipeline.
pub fn smux_session_handler(
    config: &KcptunConfig,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<Arc<dyn KcptunSessionHandler>> {
    let frame_size = config.frame_size as usize;
    let stream_buffer = config.stream_buffer as usize;
    let smux_buffer = config.smux_buffer as usize;
    let limits = SmuxLimits {
        max_concurrent_streams: (smux_buffer / stream_buffer.max(1)).clamp(1, 4096),
        inbound_frames_per_stream: (stream_buffer / frame_size.max(1)).clamp(1, 256),
        outbound_frame_queue: (smux_buffer / frame_size.max(1)).clamp(1, 4096),
        max_frame_payload: frame_size,
    };
    let keepalive_interval = Duration::from_secs(u64::from(config.keepalive_secs));
    Ok(Arc::new(TcpPipelineSessionHandler {
        pipeline: Arc::new(SmuxServerHandler::new(
            raw_handler,
            resolver,
            SmuxServerConfig {
                version: config.smux_version,
                limits,
                max_receive_buffer: config.smux_buffer as usize,
                max_stream_buffer: config.stream_buffer as usize,
                keepalive_interval: Some(keepalive_interval),
                keepalive_timeout: Some(keepalive_interval.saturating_mul(3)),
                ..SmuxServerConfig::default()
            },
        )),
    }))
}

#[deprecated(note = "use smux_session_handler; it supports both smux v1 and v2")]
pub fn smux_v1_session_handler(
    config: &KcptunConfig,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<Arc<dyn KcptunSessionHandler>> {
    smux_session_handler(config, raw_handler, resolver)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KcptunServerStats {
    pub active_sessions: usize,
    pub rejected_sessions: u64,
    pub dropped_packets: u64,
    pub invalid_packets: u64,
}

#[derive(Default)]
struct SharedStats {
    active_sessions: AtomicUsize,
    rejected_sessions: AtomicU64,
    dropped_packets: AtomicU64,
    invalid_packets: AtomicU64,
}

impl SharedStats {
    fn snapshot(&self) -> KcptunServerStats {
        KcptunServerStats {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            rejected_sessions: self.rejected_sessions.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            invalid_packets: self.invalid_packets.load(Ordering::Relaxed),
        }
    }
}

pub struct KcptunServerHandle {
    local_addr: SocketAddr,
    cancellation: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
    stats: Arc<SharedStats>,
}

impl KcptunServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> KcptunServerStats {
        self.stats.snapshot()
    }

    pub fn shutdown(&self) {
        self.cancellation.cancel();
    }

    pub async fn wait(mut self) -> io::Result<()> {
        let task = self
            .task
            .take()
            .ok_or_else(|| io::Error::other("Kcptun server task was already taken"))?;
        task.await
            .map_err(|error| io::Error::other(format!("Kcptun server task failed: {error}")))?
    }
}

impl Drop for KcptunServerHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

pub struct KcptunServer;

impl KcptunServer {
    pub async fn bind(
        bind_addr: SocketAddr,
        config: KcptunConfig,
        limits: KcptunServerLimits,
        handler: Arc<dyn KcptunSessionHandler>,
    ) -> io::Result<KcptunServerHandle> {
        validate_runtime(&config, &limits)?;
        let socket = bind_udp_socket(bind_addr, &config, &limits)?;
        Self::from_socket(socket, config, limits, handler)
    }

    pub async fn bind_with_tcp_handler(
        bind_addr: SocketAddr,
        config: KcptunConfig,
        limits: KcptunServerLimits,
        raw_handler: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<KcptunServerHandle> {
        let handler = smux_session_handler(&config, raw_handler, resolver)?;
        Self::bind(bind_addr, config, limits, handler).await
    }

    pub fn from_socket(
        socket: UdpSocket,
        mut config: KcptunConfig,
        limits: KcptunServerLimits,
        handler: Arc<dyn KcptunSessionHandler>,
    ) -> io::Result<KcptunServerHandle> {
        config.apply_mode();
        validate_runtime(&config, &limits)?;
        let local_addr = socket.local_addr()?;
        let crypt = Arc::new(PacketCrypt::new(config.crypt, &config.key)?);
        let socket = Arc::new(socket);
        let cancellation = CancellationToken::new();
        let stats = Arc::new(SharedStats::default());
        let task = tokio::spawn(run_server(
            socket,
            Arc::new(config),
            limits,
            crypt,
            handler,
            cancellation.clone(),
            stats.clone(),
        ));
        Ok(KcptunServerHandle {
            local_addr,
            cancellation,
            task: Some(task),
            stats,
        })
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct SessionKey {
    peer: SocketAddr,
    conversation: u32,
}

struct SessionEntry {
    generation: u64,
    inbound: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy)]
struct SessionClosed {
    key: SessionKey,
    generation: u64,
}

async fn run_server(
    socket: Arc<UdpSocket>,
    config: Arc<KcptunConfig>,
    limits: KcptunServerLimits,
    crypt: Arc<PacketCrypt>,
    handler: Arc<dyn KcptunSessionHandler>,
    cancellation: CancellationToken,
    stats: Arc<SharedStats>,
) -> io::Result<()> {
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
    let mut sessions: HashMap<SessionKey, SessionEntry> = HashMap::new();
    let mut active_peer: HashMap<SocketAddr, u32> = HashMap::new();
    let mut generation = 0_u64;
    let mut receive_buffer = vec![0_u8; UDP_RECEIVE_BUFFER];

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            Some(closed) = closed_rx.recv() => {
                remove_if_generation(
                    &mut sessions,
                    &mut active_peer,
                    closed,
                    &stats,
                );
            }
            received = socket.recv_from(&mut receive_buffer) => {
                let (length, peer) = received?;
                let plaintext = match crypt.open(&receive_buffer[..length]) {
                    Ok(packet) => packet,
                    Err(_) => {
                        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let route = match route_packet(&plaintext, peer, &active_peer) {
                    Ok(Some(route)) => route,
                    Ok(None) => {
                        stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(_) => {
                        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let route_key = route.key;
                let route_sequence_number = route.sequence_number;

                if let Some(current_conv) = active_peer.get(&peer).copied()
                    && current_conv != route_key.conversation
                {
                    if route_sequence_number != Some(0) {
                        stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let old_key = SessionKey { peer, conversation: current_conv };
                    if let Some(old) = sessions.remove(&old_key) {
                        old.cancellation.cancel();
                        stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
                    }
                    active_peer.remove(&peer);
                }

                if let Some(entry) = sessions.get(&route_key) {
                    if entry.inbound.try_send(plaintext).is_err() {
                        stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
                if sessions.len() >= limits.max_sessions {
                    stats.rejected_sessions.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(kcp_packet) = route.kcp_packet else {
                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if validate_kcp_packet(kcp_packet, route_key.conversation).is_err() {
                    stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                generation = generation.wrapping_add(1);
                let (inbound_tx, inbound_rx) =
                    mpsc::channel(limits.inbound_packets_per_session);
                if inbound_tx.try_send(plaintext).is_err() {
                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let session_cancel = cancellation.child_token();
                sessions.insert(
                    route_key,
                    SessionEntry {
                        generation,
                        inbound: inbound_tx,
                        cancellation: session_cancel.clone(),
                    },
                );
                active_peer.insert(peer, route_key.conversation);
                stats.active_sessions.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(run_session(
                    route_key,
                    generation,
                    socket.clone(),
                    config.clone(),
                    limits.clone(),
                    crypt.clone(),
                    handler.clone(),
                    inbound_rx,
                    session_cancel,
                    closed_tx.clone(),
                    stats.clone(),
                ));
            }
        }
    }

    for (_, session) in sessions.drain() {
        session.cancellation.cancel();
    }
    stats.active_sessions.store(0, Ordering::Relaxed);
    Ok(())
}

fn remove_if_generation(
    sessions: &mut HashMap<SessionKey, SessionEntry>,
    active_peer: &mut HashMap<SocketAddr, u32>,
    closed: SessionClosed,
    stats: &SharedStats,
) {
    if sessions
        .get(&closed.key)
        .is_some_and(|entry| entry.generation == closed.generation)
    {
        sessions.remove(&closed.key);
        if active_peer.get(&closed.key.peer) == Some(&closed.key.conversation) {
            active_peer.remove(&closed.key.peer);
        }
        stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

struct PacketRoute<'a> {
    key: SessionKey,
    sequence_number: Option<u32>,
    kcp_packet: Option<&'a [u8]>,
}

fn route_packet<'a>(
    packet: &'a [u8],
    peer: SocketAddr,
    active_peer: &HashMap<SocketAddr, u32>,
) -> io::Result<Option<PacketRoute<'a>>> {
    if packet.len() < FEC_HEADER_SIZE {
        return Err(invalid_data("truncated Kcptun packet"));
    }
    let fec_type = u16::from_le_bytes(packet[4..6].try_into().expect("fixed type slice"));
    match fec_type {
        FEC_TYPE_DATA => {
            if packet.len() < FEC_DATA_HEADER_SIZE + KCP_OVERHEAD {
                return Err(invalid_data("truncated Kcptun FEC data packet"));
            }
            let kcp_packet = &packet[FEC_DATA_HEADER_SIZE..];
            let conversation = get_conv(kcp_packet);
            Ok(Some(PacketRoute {
                key: SessionKey { peer, conversation },
                sequence_number: Some(get_sn(kcp_packet)),
                kcp_packet: Some(kcp_packet),
            }))
        }
        FEC_TYPE_PARITY => Ok(active_peer
            .get(&peer)
            .copied()
            .map(|conversation| PacketRoute {
                key: SessionKey { peer, conversation },
                sequence_number: None,
                kcp_packet: None,
            })),
        FEC_TYPE_OOB => Ok(None),
        _ => {
            if packet.len() < KCP_OVERHEAD {
                return Err(invalid_data("truncated Kcptun KCP packet"));
            }
            let conversation = get_conv(packet);
            Ok(Some(PacketRoute {
                key: SessionKey { peer, conversation },
                sequence_number: Some(get_sn(packet)),
                kcp_packet: Some(packet),
            }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    key: SessionKey,
    generation: u64,
    socket: Arc<UdpSocket>,
    config: Arc<KcptunConfig>,
    limits: KcptunServerLimits,
    crypt: Arc<PacketCrypt>,
    handler: Arc<dyn KcptunSessionHandler>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    cancellation: CancellationToken,
    closed_tx: mpsc::UnboundedSender<SessionClosed>,
    stats: Arc<SharedStats>,
) {
    let result = run_session_inner(
        key,
        socket,
        config,
        limits,
        crypt,
        handler,
        inbound_rx,
        cancellation.clone(),
        stats,
    )
    .await;
    if let Err(error) = result {
        log::debug!(
            "Kcptun session {} conv={} finished with error: {error}",
            key.peer,
            key.conversation
        );
    }
    cancellation.cancel();
    let _ = closed_tx.send(SessionClosed { key, generation });
}

#[allow(clippy::too_many_arguments)]
async fn run_session_inner(
    key: SessionKey,
    socket: Arc<UdpSocket>,
    config: Arc<KcptunConfig>,
    limits: KcptunServerLimits,
    crypt: Arc<PacketCrypt>,
    handler: Arc<dyn KcptunSessionHandler>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    cancellation: CancellationToken,
    stats: Arc<SharedStats>,
) -> io::Result<()> {
    let plaintext_mtu = config.mtu as usize - crypt.overhead();
    let kcp_mtu = plaintext_mtu - FEC_DATA_HEADER_SIZE;
    let (outbound_tx, outbound_rx) = mpsc::channel(limits.outbound_packets_per_session);
    let output = KcpOutput {
        outbound: outbound_tx,
        max_packet_size: kcp_mtu,
    };
    let mut kcp = Kcp::new_stream(key.conversation, output);
    kcp.set_mtu(kcp_mtu).map_err(kcp_error)?;
    kcp.set_nodelay(
        config.no_delay,
        config.interval_ms as i32,
        config.resend as i32,
        config.no_congestion,
    );
    kcp.set_wndsize(config.send_window as u16, config.receive_window as u16);

    let local_addr = socket.local_addr()?;
    let sender_cancel = cancellation.child_token();
    let sender_task = tokio::spawn(send_outbound(
        socket,
        key.peer,
        config.clone(),
        crypt,
        outbound_rx,
        sender_cancel,
    ));

    let stream_capacity = config.stream_buffer as usize;
    let (application_stream, pump_stream) = tokio::io::duplex(stream_capacity);
    let stream = KcptunStream {
        inner: application_stream,
        peer_addr: key.peer,
        local_addr,
        conversation: key.conversation,
    };
    let smux = KcptunSmuxSettings::from_config(&config);
    let handler_task = tokio::spawn(async move { handler.handle_session(stream, smux).await });
    let (mut application_reader, mut application_writer) = tokio::io::split(pump_stream);

    let session_result = pump_kcp_session(
        &mut kcp,
        &config,
        &limits,
        &mut inbound_rx,
        &mut application_reader,
        &mut application_writer,
        &cancellation,
        &stats,
        plaintext_mtu,
    )
    .await;
    cancellation.cancel();
    drop(kcp);

    let sender_result = sender_task
        .await
        .map_err(|error| io::Error::other(format!("Kcptun sender task failed: {error}")))?;
    if !handler_task.is_finished() {
        handler_task.abort();
    }
    session_result.and(sender_result)
}

#[allow(clippy::too_many_arguments)]
async fn pump_kcp_session(
    kcp: &mut Kcp<KcpOutput>,
    config: &KcptunConfig,
    limits: &KcptunServerLimits,
    inbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    application_reader: &mut ReadHalf<DuplexStream>,
    application_writer: &mut WriteHalf<DuplexStream>,
    cancellation: &CancellationToken,
    stats: &SharedStats,
    plaintext_mtu: usize,
) -> io::Result<()> {
    let mut fec = FecDecoder::new(
        config.data_shards as usize,
        config.parity_shards as usize,
        plaintext_mtu,
    )?;
    let mut decoder =
        (!config.no_compression).then(|| SnappyFramedDecoder::new(config.stream_buffer as usize));
    let mut encoder = (!config.no_compression).then(SnappyFramedEncoder::new);
    let mut pending_to_application = BytesMut::new();
    let mut application_buffer = vec![0_u8; config.frame_size as usize];
    let mut kcp_receive_buffer = vec![0_u8; config.stream_buffer.min(64 * 1024) as usize];
    let started = Instant::now();
    let mut last_peer_activity = Instant::now();
    let idle_timeout = limits.effective_idle_timeout(config.keepalive_secs);
    let mut ticker = tokio::time::interval(Duration::from_millis(
        u64::from(config.interval_ms).clamp(10, 5000),
    ));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = ticker.tick() => {
                update_kcp(kcp, monotonic_millis(started))?;
                drain_kcp(
                    kcp,
                    &mut kcp_receive_buffer,
                    decoder.as_mut(),
                    &mut pending_to_application,
                    config.stream_buffer as usize,
                )?;
                if last_peer_activity.elapsed() >= idle_timeout {
                    break;
                }
            }
            packet = inbound_rx.recv() => {
                let Some(packet) = packet else { break };
                let kcp_packets = decode_transport_packet(&mut fec, packet)?;
                let mut accepted = false;
                for packet in kcp_packets {
                    if validate_kcp_packet(&packet, kcp.conv()).is_err() {
                        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if kcp.input(&packet).is_ok() {
                        accepted = true;
                    } else {
                        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if accepted {
                    last_peer_activity = Instant::now();
                    if config.ack_no_delay {
                        update_kcp(kcp, monotonic_millis(started))?;
                    }
                    drain_kcp(
                        kcp,
                        &mut kcp_receive_buffer,
                        decoder.as_mut(),
                        &mut pending_to_application,
                        config.stream_buffer as usize,
                    )?;
                }
            }
            read = application_reader.read(&mut application_buffer),
                if kcp.wait_snd() < config.send_window as usize =>
            {
                let count = read?;
                if count == 0 {
                    break;
                }
                let wire = if let Some(encoder) = encoder.as_mut() {
                    encoder.encode(&application_buffer[..count])?
                } else {
                    application_buffer[..count].to_vec()
                };
                let maximum_send = (kcp_mss(kcp) * 127).max(1);
                for chunk in wire.chunks(maximum_send) {
                    kcp.send(chunk).map_err(kcp_error)?;
                }
                update_kcp(kcp, monotonic_millis(started))?;
            }
            written = application_writer.write(&pending_to_application),
                if !pending_to_application.is_empty() =>
            {
                let count = written?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Kcptun application stream stopped accepting data",
                    ));
                }
                pending_to_application.advance(count);
                drain_kcp(
                    kcp,
                    &mut kcp_receive_buffer,
                    decoder.as_mut(),
                    &mut pending_to_application,
                    config.stream_buffer as usize,
                )?;
            }
        }
    }
    application_writer.shutdown().await
}

fn decode_transport_packet(fec: &mut FecDecoder, packet: Vec<u8>) -> io::Result<Vec<Vec<u8>>> {
    if packet.len() < FEC_HEADER_SIZE {
        return Err(invalid_data("truncated Kcptun transport packet"));
    }
    let packet_type = u16::from_le_bytes(packet[4..6].try_into().expect("fixed type slice"));
    if matches!(packet_type, FEC_TYPE_DATA | FEC_TYPE_PARITY) {
        Ok(fec.decode(&packet)?.kcp_packets)
    } else if packet_type == FEC_TYPE_OOB {
        Ok(Vec::new())
    } else {
        Ok(vec![packet])
    }
}

fn drain_kcp(
    kcp: &mut Kcp<KcpOutput>,
    receive_buffer: &mut Vec<u8>,
    mut decoder: Option<&mut SnappyFramedDecoder>,
    pending: &mut BytesMut,
    pending_limit: usize,
) -> io::Result<()> {
    while pending.len() < pending_limit {
        let size = match kcp.peeksize() {
            Ok(size) if size > 0 => size,
            Ok(_) | Err(KcpError::RecvQueueEmpty | KcpError::ExpectingFragment) => break,
            Err(error) => return Err(kcp_error(error)),
        };
        if size > pending_limit {
            return Err(invalid_data(
                "Kcptun receive record exceeds the stream buffer",
            ));
        }
        receive_buffer.resize(size, 0);
        let count = kcp.recv(receive_buffer).map_err(kcp_error)?;
        if let Some(decoder) = decoder.as_deref_mut() {
            let decoded = decoder.push(&receive_buffer[..count])?;
            if pending.len().saturating_add(decoded.len()) > pending_limit {
                return Err(invalid_data(
                    "Kcptun decompressed data exceeds the stream buffer",
                ));
            }
            pending.extend_from_slice(&decoded);
        } else {
            if pending.len().saturating_add(count) > pending_limit {
                break;
            }
            pending.extend_from_slice(&receive_buffer[..count]);
        }
    }
    Ok(())
}

fn update_kcp(kcp: &mut Kcp<KcpOutput>, now: u32) -> io::Result<()> {
    match kcp.update(now) {
        Ok(()) => Ok(()),
        Err(KcpError::IoError(error)) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(kcp_error(error)),
    }
}

fn kcp_mss(kcp: &Kcp<KcpOutput>) -> usize {
    kcp.mtu().saturating_sub(KCP_OVERHEAD)
}

fn monotonic_millis(started: Instant) -> u32 {
    started.elapsed().as_millis() as u32
}

#[derive(Clone)]
struct KcpOutput {
    outbound: mpsc::Sender<Vec<u8>>,
    max_packet_size: usize,
}

impl Write for KcpOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.max_packet_size {
            return Err(invalid_data("KCP emitted an oversized datagram"));
        }
        self.outbound
            .try_send(buffer.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "Kcptun outbound queue is full")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "Kcptun outbound queue is closed")
                }
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn send_outbound(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    config: Arc<KcptunConfig>,
    crypt: Arc<PacketCrypt>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let maximum_kcp_packet = config.mtu as usize - crypt.overhead() - FEC_DATA_HEADER_SIZE;
    let mut fec = FecEncoder::new(
        config.data_shards as usize,
        config.parity_shards as usize,
        maximum_kcp_packet,
    )?;
    let mut limiter = ByteRateLimiter::new(config.rate_limit, config.mtu as usize);
    loop {
        let packet = tokio::select! {
            _ = cancellation.cancelled() => break,
            packet = outbound.recv() => {
                let Some(packet) = packet else { break };
                packet
            }
        };
        for packet in fec.encode(&packet)?.packets {
            let packet = crypt.seal(&packet)?;
            if packet.len() > config.mtu as usize {
                return Err(invalid_data(
                    "encrypted Kcptun datagram exceeds configured MTU",
                ));
            }
            if !limiter.acquire(packet.len(), &cancellation).await {
                return Ok(());
            }
            let written = socket.send_to(&packet, peer).await?;
            if written != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial Kcptun UDP datagram write",
                ));
            }
        }
    }
    Ok(())
}

struct ByteRateLimiter {
    bytes_per_second: u32,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl ByteRateLimiter {
    fn new(bytes_per_second: u32, mtu: usize) -> Self {
        let capacity = if bytes_per_second == 0 {
            f64::INFINITY
        } else {
            f64::from(bytes_per_second).max((mtu.saturating_mul(64)) as f64)
        };
        Self {
            bytes_per_second,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        }
    }

    async fn acquire(&mut self, bytes: usize, cancellation: &CancellationToken) -> bool {
        if self.bytes_per_second == 0 {
            return true;
        }
        loop {
            let now = Instant::now();
            self.tokens = (self.tokens
                + now.duration_since(self.updated).as_secs_f64()
                    * f64::from(self.bytes_per_second))
            .min(self.capacity);
            self.updated = now;
            if self.tokens >= bytes as f64 {
                self.tokens -= bytes as f64;
                return true;
            }
            let wait = Duration::from_secs_f64(
                (bytes as f64 - self.tokens) / f64::from(self.bytes_per_second),
            );
            tokio::select! {
                _ = cancellation.cancelled() => return false,
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

struct SnappyFramedEncoder {
    encoder: snap::write::FrameEncoder<Vec<u8>>,
}

impl SnappyFramedEncoder {
    fn new() -> Self {
        Self {
            encoder: snap::write::FrameEncoder::new(Vec::new()),
        }
    }

    fn encode(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        self.encoder.write_all(input)?;
        self.encoder.flush()?;
        Ok(std::mem::take(self.encoder.get_mut()))
    }
}

struct SnappyFramedDecoder {
    input: BytesMut,
    saw_identifier: bool,
    max_buffer: usize,
}

impl SnappyFramedDecoder {
    fn new(max_buffer: usize) -> Self {
        Self {
            input: BytesMut::new(),
            saw_identifier: false,
            max_buffer,
        }
    }

    fn push(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        if self.input.len().saturating_add(input.len()) > self.max_buffer {
            return Err(invalid_data("Kcptun Snappy input buffer limit exceeded"));
        }
        self.input.extend_from_slice(input);
        if !self.saw_identifier {
            if self.input.len() < SNAPPY_STREAM_IDENTIFIER.len() {
                return Ok(Vec::new());
            }
            if &self.input[..SNAPPY_STREAM_IDENTIFIER.len()] != SNAPPY_STREAM_IDENTIFIER {
                return Err(invalid_data("invalid Kcptun Snappy stream identifier"));
            }
            self.input.advance(SNAPPY_STREAM_IDENTIFIER.len());
            self.saw_identifier = true;
        }

        let mut output = Vec::new();
        loop {
            if self.input.len() < 4 {
                break;
            }
            let payload_len = usize::from(self.input[1])
                | (usize::from(self.input[2]) << 8)
                | (usize::from(self.input[3]) << 16);
            let frame_len = 4_usize
                .checked_add(payload_len)
                .ok_or_else(|| invalid_data("Kcptun Snappy frame length overflow"))?;
            if frame_len > self.max_buffer {
                return Err(invalid_data("Kcptun Snappy frame exceeds configured limit"));
            }
            if self.input.len() < frame_len {
                break;
            }
            let frame = self.input.split_to(frame_len);
            let mut encoded = Vec::with_capacity(SNAPPY_STREAM_IDENTIFIER.len() + frame.len());
            encoded.extend_from_slice(SNAPPY_STREAM_IDENTIFIER);
            encoded.extend_from_slice(&frame);
            let mut decoder = snap::read::FrameDecoder::new(Cursor::new(encoded));
            let before = output.len();
            decoder.read_to_end(&mut output)?;
            if output.len() > self.max_buffer || output.len() < before {
                return Err(invalid_data("Kcptun Snappy output buffer limit exceeded"));
            }
        }
        Ok(output)
    }
}

fn validate_kcp_packet(packet: &[u8], conversation: u32) -> io::Result<()> {
    let mut remaining = packet;
    let mut segments = 0_usize;
    while !remaining.is_empty() {
        if remaining.len() < KCP_OVERHEAD {
            return Err(invalid_data("truncated KCP segment"));
        }
        if u32::from_le_bytes(remaining[..4].try_into().expect("fixed conv slice")) != conversation
        {
            return Err(invalid_data("KCP conversation mismatch"));
        }
        if !matches!(remaining[4], 81..=84) {
            return Err(invalid_data("unsupported KCP command"));
        }
        let payload_len =
            u32::from_le_bytes(remaining[20..24].try_into().expect("fixed length slice")) as usize;
        let segment_len = KCP_OVERHEAD
            .checked_add(payload_len)
            .ok_or_else(|| invalid_data("KCP segment length overflow"))?;
        if remaining.len() < segment_len {
            return Err(invalid_data("truncated KCP segment payload"));
        }
        remaining = &remaining[segment_len..];
        segments += 1;
        if segments > 256 {
            return Err(invalid_data("too many KCP segments in one datagram"));
        }
    }
    Ok(())
}

fn validate_runtime(config: &KcptunConfig, limits: &KcptunServerLimits) -> io::Result<()> {
    config.validate()?;
    limits.validate()?;
    if config.send_window > u16::MAX as u32 || config.receive_window > u16::MAX as u32 {
        return Err(invalid(
            "the Rust KCP engine supports send/receive windows up to 65535",
        ));
    }
    if config.resend > i32::MAX as u32 {
        return Err(invalid("Kcptun resend exceeds the KCP engine limit"));
    }
    if config.stream_buffer as usize > limits.max_stream_buffer {
        return Err(invalid("Kcptun stream buffer exceeds the server limit"));
    }
    if config.socket_buffer as usize > limits.max_socket_buffer {
        return Err(invalid("Kcptun socket buffer exceeds the server limit"));
    }
    let crypt = PacketCrypt::new(config.crypt, &config.key)?;
    let kcp_mtu = config
        .mtu
        .checked_sub(crypt.overhead() as u16)
        .and_then(|mtu| mtu.checked_sub(FEC_DATA_HEADER_SIZE as u16))
        .ok_or_else(|| invalid("Kcptun MTU is smaller than its wire overhead"))?;
    if kcp_mtu < 50 {
        return Err(invalid("Kcptun KCP payload MTU must be at least 50"));
    }
    Ok(())
}

fn bind_udp_socket(
    bind_addr: SocketAddr,
    config: &KcptunConfig,
    limits: &KcptunServerLimits,
) -> io::Result<UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if bind_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    let socket_buffer = (config.socket_buffer as usize).min(limits.max_socket_buffer);
    socket.set_recv_buffer_size(socket_buffer)?;
    socket.set_send_buffer_size(socket_buffer)?;
    if bind_addr.is_ipv4() && config.dscp != 0 {
        socket.set_tos_v4(u32::from(config.dscp) << 2)?;
    }
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn kcp_error(error: KcpError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::NativeResolver;
    use crate::ss_plugins::kcptun::config::{KcptunCrypt, KcptunMode};

    #[derive(Debug)]
    struct HoldingHandler;

    #[async_trait]
    impl KcptunSessionHandler for HoldingHandler {
        async fn handle_session(
            &self,
            mut stream: KcptunStream,
            _smux: KcptunSmuxSettings,
        ) -> io::Result<()> {
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.map(|_| ())
        }
    }

    #[derive(Debug)]
    struct EchoTcpHandler;

    #[async_trait]
    impl TcpServerHandler for EchoTcpHandler {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 16 * 1024];
                loop {
                    let count = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => count,
                    };
                    if stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[test]
    fn snappy_framing_survives_arbitrary_kcp_boundaries() {
        let mut encoder = SnappyFramedEncoder::new();
        let encoded = encoder
            .encode(b"the quick brown fox jumps over the lazy dog")
            .unwrap();
        let mut decoder = SnappyFramedDecoder::new(4096);
        let mut decoded = Vec::new();
        for chunk in encoded.chunks(3) {
            decoded.extend(decoder.push(chunk).unwrap());
        }
        assert_eq!(decoded, b"the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn rejects_bad_snappy_and_kcp_packets() {
        let mut decoder = SnappyFramedDecoder::new(64);
        assert!(decoder.push(b"not-snappy").is_err());
        assert!(validate_kcp_packet(&[0; 23], 1).is_err());

        let mut segment = vec![0_u8; KCP_OVERHEAD];
        segment[..4].copy_from_slice(&1_u32.to_le_bytes());
        segment[4] = 0xff;
        assert!(validate_kcp_packet(&segment, 1).is_err());
    }

    #[tokio::test]
    async fn expires_idle_peer_conversation_and_rejects_bad_packets() {
        let config = KcptunConfig {
            crypt: KcptunCrypt::Null,
            mode: KcptunMode::Manual,
            no_compression: true,
            interval_ms: 10,
            data_shards: 2,
            parity_shards: 1,
            ..KcptunConfig::default()
        };
        let limits = KcptunServerLimits {
            idle_timeout: Duration::from_millis(80),
            max_sessions: 8,
            ..KcptunServerLimits::default()
        };
        let server = KcptunServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            config,
            limits,
            Arc::new(HoldingHandler),
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client
            .send_to(&[1, 2, 3, 4, 5], server.local_addr())
            .await
            .unwrap();

        let conversation = 0x1234_5678_u32;
        let mut kcp_packet = vec![0_u8; KCP_OVERHEAD];
        kcp_packet[..4].copy_from_slice(&conversation.to_le_bytes());
        kcp_packet[4] = 81; // IKCP_CMD_PUSH
        kcp_packet[6..8].copy_from_slice(&128_u16.to_le_bytes());
        let mut fec = FecEncoder::new(2, 1, 256).unwrap();
        let packet = fec.encode(&kcp_packet).unwrap().packets.remove(0);
        client.send_to(&packet, server.local_addr()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let stats = server.stats();
                if stats.active_sessions == 1 && stats.invalid_packets >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if server.stats().active_sessions == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("idle Kcptun session was not scavenged");

        server.shutdown();
        server.wait().await.unwrap();
    }

    /// Black-box compatibility check against the official Go kcp-go, Snappy,
    /// and xtaci/smux implementations. It is ignored in the default Rust suite
    /// because it requires a Go toolchain and its module cache.
    #[tokio::test]
    #[ignore = "requires the Go toolchain"]
    async fn official_go_kcp_fec_snappy_smux_v1_v2_echo() {
        for version in [1_u8, 2] {
            let config = KcptunConfig {
                key: "shoes-kcptun-interop".to_string(),
                crypt: KcptunCrypt::Aes128,
                mode: KcptunMode::Manual,
                mtu: 1350,
                send_window: 256,
                receive_window: 512,
                data_shards: 4,
                parity_shards: 2,
                no_compression: false,
                ack_no_delay: true,
                no_delay: true,
                interval_ms: 10,
                resend: 2,
                no_congestion: true,
                smux_version: version,
                smux_buffer: 4 * 1024 * 1024,
                stream_buffer: 1024 * 1024,
                frame_size: 8192,
                keepalive_secs: 1,
                ..KcptunConfig::default()
            };
            let server = KcptunServer::bind_with_tcp_handler(
                "127.0.0.1:0".parse().unwrap(),
                config,
                KcptunServerLimits {
                    idle_timeout: Duration::from_secs(10),
                    ..KcptunServerLimits::default()
                },
                Arc::new(EchoTcpHandler),
                Arc::new(NativeResolver),
            )
            .await
            .unwrap();
            let address = server.local_addr().to_string();
            let testdata = format!(
                "{}/src/ss_plugins/kcptun/testdata",
                env!("CARGO_MANIFEST_DIR")
            );
            let output = tokio::time::timeout(
                Duration::from_secs(90),
                tokio::task::spawn_blocking(move || {
                    std::process::Command::new("go")
                        .args(["run", ".", &address, &version.to_string()])
                        .current_dir(testdata)
                        .env("GOTOOLCHAIN", "local")
                        .output()
                }),
            )
            .await
            .expect("Go Kcptun interop client timed out")
            .expect("Go Kcptun interop task panicked")
            .expect("failed to execute Go Kcptun interop client");
            server.shutdown();
            server.wait().await.unwrap();
            assert!(
                output.status.success(),
                "Go smux-v{version} client failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
}
