use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::{Rng, RngExt};

const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_MAX_ON_WIRE_SIZE: usize = 2048;
const GECKO_DEFAULT_MIN_PACKET_SIZE: usize = 512;
const GECKO_DEFAULT_MAX_PACKET_SIZE: usize = 1200;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;
const MIN_RECEIVE_SEGMENTS_WITH_OBFS: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Hysteria2Obfs {
    Salamander {
        password: String,
    },
    Gecko {
        password: String,
        min_packet_size: usize,
        max_packet_size: usize,
    },
}

impl Hysteria2Obfs {
    pub fn salamander(password: String) -> io::Result<Self> {
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 salamander obfs password must not be empty",
            ));
        }
        Ok(Self::Salamander { password })
    }

    pub fn gecko(
        password: String,
        min_packet_size: Option<usize>,
        max_packet_size: Option<usize>,
    ) -> io::Result<Self> {
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 gecko obfs password must not be empty",
            ));
        }
        let min_packet_size = min_packet_size.unwrap_or(GECKO_DEFAULT_MIN_PACKET_SIZE);
        let max_packet_size = max_packet_size.unwrap_or(GECKO_DEFAULT_MAX_PACKET_SIZE);
        if min_packet_size == 0
            || min_packet_size > max_packet_size
            || max_packet_size > GECKO_MAX_ON_WIRE_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 gecko obfs packet size range is invalid",
            ));
        }
        Ok(Self::Gecko {
            password,
            min_packet_size,
            max_packet_size,
        })
    }

    pub fn wrap_socket(&self, inner: Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(Hysteria2ObfsSocket::new(inner, self.clone()))
    }

    fn encode_packet(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::Salamander { password } => {
                let mut salt = [0u8; SALAMANDER_SALT_LEN];
                rand::rng().fill_bytes(&mut salt);
                encode_salamander_packet_with_salt(password.as_bytes(), &salt, payload)
            }
            Self::Gecko { password, .. } => {
                let mut salt = [0u8; SALAMANDER_SALT_LEN];
                rand::rng().fill_bytes(&mut salt);
                encode_salamander_packet_with_salt(password.as_bytes(), &salt, payload)
            }
        }
    }

    fn decode_packet_in_place(&self, packet: &mut [u8]) -> Option<usize> {
        match self {
            Self::Salamander { password } => {
                decode_salamander_packet_in_place(password.as_bytes(), packet)
            }
            Self::Gecko { password, .. } => {
                decode_salamander_packet_in_place(password.as_bytes(), packet)
            }
        }
    }
}

#[derive(Debug)]
struct Hysteria2ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Hysteria2Obfs,
    gecko_state: Option<Mutex<GeckoState>>,
    gecko_msg_id_counter: AtomicU32,
}

impl Hysteria2ObfsSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: Hysteria2Obfs) -> Self {
        let gecko_state =
            matches!(obfs, Hysteria2Obfs::Gecko { .. }).then(|| Mutex::new(GeckoState::new()));
        Self {
            inner,
            obfs,
            gecko_state,
            gecko_msg_id_counter: AtomicU32::new(0),
        }
    }
}

impl AsyncUdpSocket for Hysteria2ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 obfs socket received segmented QUIC transmit despite max_transmit_segments=1",
            ));
        }

        let encoded_packets = self.encode_transmit_packets(transmit.contents)?;
        for encoded in &encoded_packets {
            let encoded_transmit = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: encoded,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&encoded_transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.obfs, Hysteria2Obfs::Gecko { .. }) {
            return self.poll_recv_gecko(cx, bufs, meta);
        }

        let received = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(received)) => received,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };

        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(received) {
            decode_received_meta(&self.obfs, buf, meta);
        }

        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner
            .max_receive_segments()
            .saturating_add(1)
            .max(MIN_RECEIVE_SEGMENTS_WITH_OBFS)
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

impl Hysteria2ObfsSocket {
    fn encode_transmit_packets(&self, payload: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let Hysteria2Obfs::Gecko {
            password,
            min_packet_size,
            max_packet_size,
        } = &self.obfs
        else {
            return Ok(vec![self.obfs.encode_packet(payload)]);
        };

        if payload.is_empty() || payload[0] & GECKO_FRAGMENT_FLAG == 0 {
            return Ok(vec![self.obfs.encode_packet(payload)]);
        }

        let chunks = rand::rng().random_range(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS);
        let chunk_size = payload.len() / chunks;
        let msg_id = self
            .gecko_msg_id_counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1) as u8;

        let mut packets = Vec::with_capacity(chunks);
        for index in 0..chunks {
            let start = index * chunk_size;
            let end = if index < chunks - 1 {
                start + chunk_size
            } else {
                payload.len()
            };
            let chunk = &payload[start..end];
            let pad_len = random_gecko_pad_len(chunk.len(), *min_packet_size, *max_packet_size);
            let mut frame = vec![0u8; GECKO_HEADER_LEN + pad_len + chunk.len()];
            frame[0] = GECKO_FRAGMENT_FLAG;
            frame[1] = msg_id;
            frame[2] = ((index as u8) << 4) | (chunks as u8 & 0x0f);
            frame[3..5].copy_from_slice(&(pad_len as u16).to_be_bytes());
            if pad_len > 0 {
                rand::rng().fill_bytes(&mut frame[GECKO_HEADER_LEN..GECKO_HEADER_LEN + pad_len]);
            }
            frame[GECKO_HEADER_LEN + pad_len..].copy_from_slice(chunk);

            let mut salt = [0u8; SALAMANDER_SALT_LEN];
            rand::rng().fill_bytes(&mut salt);
            packets.push(encode_salamander_packet_with_salt(
                password.as_bytes(),
                &salt,
                &frame,
            ));
        }
        Ok(packets)
    }

    fn poll_recv_gecko(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let received = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(received)) => received,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if received == 0 {
                return Poll::Ready(Ok(0));
            }

            for index in 0..received {
                let raw_meta = meta[index];
                let raw_stride = if raw_meta.stride == 0 {
                    raw_meta.len
                } else {
                    raw_meta.stride
                };
                let mut read_offset = 0usize;
                while read_offset < raw_meta.len {
                    let raw_len = raw_stride.min(raw_meta.len - read_offset);
                    let completed = {
                        let raw_packet = &mut bufs[index][read_offset..read_offset + raw_len];
                        self.decode_gecko_segment(raw_packet, raw_meta.addr)
                    };

                    if let Some(packet) = completed {
                        if packet.len() > bufs[0].len() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "decoded hysteria2 gecko packet exceeds receive buffer",
                            )));
                        }
                        bufs[0][..packet.len()].copy_from_slice(&packet);
                        meta[0] = raw_meta;
                        meta[0].len = packet.len();
                        meta[0].stride = packet.len();
                        return Poll::Ready(Ok(1));
                    }

                    read_offset += raw_len;
                }
            }
        }
    }

    fn decode_gecko_segment(&self, raw_packet: &mut [u8], addr: SocketAddr) -> Option<Vec<u8>> {
        let decoded_len = self.obfs.decode_packet_in_place(raw_packet)?;
        let decoded = &raw_packet[..decoded_len];
        if decoded.is_empty() {
            return None;
        }
        if decoded[0] & GECKO_FRAGMENT_FLAG == 0 {
            return Some(decoded.to_vec());
        }
        let chunk = parse_gecko_chunk(decoded)?;
        let state = self.gecko_state.as_ref()?;
        state.lock().ok()?.accept_chunk(addr, chunk)
    }
}

fn encode_salamander_packet_with_salt(
    password: &[u8],
    salt: &[u8; SALAMANDER_SALT_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let key = salamander_key(password, salt);
    let mut packet = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
    packet.extend_from_slice(salt);
    for (index, byte) in payload.iter().enumerate() {
        packet.push(*byte ^ key[index % SALAMANDER_KEY_LEN]);
    }
    packet
}

fn decode_salamander_packet_in_place(password: &[u8], packet: &mut [u8]) -> Option<usize> {
    if packet.len() <= SALAMANDER_SALT_LEN {
        return None;
    }

    let mut salt = [0u8; SALAMANDER_SALT_LEN];
    salt.copy_from_slice(&packet[..SALAMANDER_SALT_LEN]);
    let key = salamander_key(password, &salt);
    let payload_len = packet.len() - SALAMANDER_SALT_LEN;
    for index in 0..payload_len {
        packet[index] = packet[SALAMANDER_SALT_LEN + index] ^ key[index % SALAMANDER_KEY_LEN];
    }
    Some(payload_len)
}

fn random_gecko_pad_len(chunk_len: usize, min_packet_size: usize, max_packet_size: usize) -> usize {
    let base = SALAMANDER_SALT_LEN + GECKO_HEADER_LEN + chunk_len;
    let low = min_packet_size.max(base);
    if low > max_packet_size {
        return 0;
    }
    low - base + rand::rng().random_range(0..=max_packet_size - low)
}

#[derive(Debug)]
struct GeckoChunk<'a> {
    msg_id: u8,
    chunk_index: usize,
    total_chunks: usize,
    payload: &'a [u8],
}

fn parse_gecko_chunk(packet: &[u8]) -> Option<GeckoChunk<'_>> {
    if packet.len() < GECKO_HEADER_LEN {
        return None;
    }
    let msg_id = packet[1];
    let chunk_index = (packet[2] >> 4) as usize;
    let total_chunks = (packet[2] & 0x0f) as usize;
    if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total_chunks) {
        return None;
    }
    if chunk_index >= total_chunks {
        return None;
    }
    let pad_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    let payload_start = GECKO_HEADER_LEN.checked_add(pad_len)?;
    if payload_start > packet.len() {
        return None;
    }
    Some(GeckoChunk {
        msg_id,
        chunk_index,
        total_chunks,
        payload: &packet[payload_start..],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct GeckoReassemblyKey {
    addr: SocketAddr,
    msg_id: u8,
}

#[derive(Debug)]
struct GeckoReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: usize,
    deadline: Instant,
}

#[derive(Debug)]
struct GeckoState {
    entries: HashMap<GeckoReassemblyKey, GeckoReassemblyEntry>,
    per_source: HashMap<SocketAddr, usize>,
    last_sweep: Instant,
}

impl GeckoState {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            per_source: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    fn accept_chunk(&mut self, addr: SocketAddr, chunk: GeckoChunk<'_>) -> Option<Vec<u8>> {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= GECKO_REASSEMBLY_TTL / 2 {
            self.sweep_expired(now);
        }

        let key = GeckoReassemblyKey {
            addr,
            msg_id: chunk.msg_id,
        };
        if !self.entries.contains_key(&key) {
            if self.per_source.get(&addr).copied().unwrap_or(0) >= GECKO_MAX_PER_SOURCE {
                return None;
            }
            if self.entries.len() >= GECKO_MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.entries.insert(
                key,
                GeckoReassemblyEntry {
                    chunks: vec![None; chunk.total_chunks],
                    received: 0,
                    total: chunk.total_chunks,
                    deadline: now + GECKO_REASSEMBLY_TTL,
                },
            );
            *self.per_source.entry(addr).or_insert(0) += 1;
        }

        let entry = self.entries.get_mut(&key)?;
        if entry.total != chunk.total_chunks
            || chunk.chunk_index >= entry.chunks.len()
            || entry.chunks[chunk.chunk_index].is_some()
        {
            return None;
        }
        entry.chunks[chunk.chunk_index] = Some(chunk.payload.to_vec());
        entry.received += 1;
        if entry.received < entry.total {
            return None;
        }

        let mut out = Vec::new();
        for chunk in &entry.chunks {
            out.extend_from_slice(chunk.as_deref()?);
        }
        self.drop_entry(key);
        Some(out)
    }

    fn drop_entry(&mut self, key: GeckoReassemblyKey) {
        if self.entries.remove(&key).is_none() {
            return;
        }
        match self.per_source.entry(key.addr) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let count = entry.get_mut();
                *count = count.saturating_sub(1);
                if *count == 0 {
                    entry.remove();
                }
            }
            std::collections::hash_map::Entry::Vacant(_) => {}
        }
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_key, entry)| entry.deadline)
            .map(|(key, _entry)| *key)
        else {
            return;
        };
        self.drop_entry(key);
    }

    fn sweep_expired(&mut self, now: Instant) {
        let expired = self
            .entries
            .iter()
            .filter_map(|(key, entry)| (now > entry.deadline).then_some(*key))
            .collect::<Vec<_>>();
        for key in expired {
            self.drop_entry(key);
        }
        self.last_sweep = now;
    }
}

fn decode_received_meta(obfs: &Hysteria2Obfs, buf: &mut IoSliceMut<'_>, meta: &mut RecvMeta) {
    if meta.len == 0 {
        return;
    }

    let raw_stride = if meta.stride == 0 {
        meta.len
    } else {
        meta.stride
    };
    let mut read_offset = 0usize;
    let mut write_offset = 0usize;
    let mut first_payload_len = None;

    while read_offset < meta.len {
        let raw_len = raw_stride.min(meta.len - read_offset);
        let decoded_len = {
            let raw_packet = &mut buf[read_offset..read_offset + raw_len];
            obfs.decode_packet_in_place(raw_packet)
        };

        let Some(decoded_len) = decoded_len else {
            read_offset += raw_len;
            continue;
        };

        if write_offset != read_offset {
            buf.copy_within(read_offset..read_offset + decoded_len, write_offset);
        }
        first_payload_len.get_or_insert(decoded_len);
        write_offset += decoded_len;
        read_offset += raw_len;
    }

    match first_payload_len {
        Some(stride) => {
            meta.len = write_offset;
            meta.stride = stride;
        }
        None => {
            meta.len = 0;
            meta.stride = 0;
        }
    }
}

fn salamander_key(password: &[u8], salt: &[u8; SALAMANDER_SALT_LEN]) -> [u8; SALAMANDER_KEY_LEN] {
    let mut hasher = Blake2bVar::new(SALAMANDER_KEY_LEN).expect("valid blake2b output length");
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0u8; SALAMANDER_KEY_LEN];
    hasher
        .finalize_variable(&mut key)
        .expect("valid blake2b output buffer");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct FakeUdpSocket {
        sent: Mutex<Vec<FakeSent>>,
        send_error: Mutex<Option<io::ErrorKind>>,
        max_receive_segments: usize,
    }

    #[derive(Debug)]
    struct FakeSent {
        destination: SocketAddr,
        ecn: Option<quinn::udp::EcnCodepoint>,
        contents: Vec<u8>,
        segment_size: Option<usize>,
        src_ip: Option<IpAddr>,
    }

    #[derive(Debug)]
    struct FakeUdpPoller;

    impl FakeUdpSocket {
        fn new(max_receive_segments: usize) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                send_error: Mutex::new(None),
                max_receive_segments,
            }
        }

        fn fail_next_send(&self, kind: io::ErrorKind) {
            *self.send_error.lock().unwrap() = Some(kind);
        }
    }

    impl AsyncUdpSocket for FakeUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(FakeUdpPoller)
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            if let Some(kind) = self.send_error.lock().unwrap().take() {
                return Err(io::Error::new(kind, "fake send error"));
            }

            self.sent.lock().unwrap().push(FakeSent {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            });
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn max_receive_segments(&self) -> usize {
            self.max_receive_segments
        }
    }

    impl UdpPoller for FakeUdpPoller {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn encode_salamander_packet_with_salt_matches_reference_vector() {
        let packet =
            encode_salamander_packet_with_salt(b"secret", &[1, 2, 3, 4, 5, 6, 7, 8], b"hello");

        assert_eq!(hex_string(&packet), "01020304050607086a673faae8");
    }

    #[test]
    fn decode_salamander_packet_in_place_recovers_payload() {
        let mut packet =
            encode_salamander_packet_with_salt(b"secret", &[1, 2, 3, 4, 5, 6, 7, 8], b"hello");

        let payload_len = decode_salamander_packet_in_place(b"secret", &mut packet).unwrap();

        assert_eq!(payload_len, 5);
        assert_eq!(&packet[..payload_len], b"hello");
    }

    #[test]
    fn decode_salamander_packet_rejects_salt_only_datagram() {
        let mut packet = [0u8; SALAMANDER_SALT_LEN];

        assert_eq!(
            decode_salamander_packet_in_place(b"secret", &mut packet),
            None
        );
    }

    #[test]
    fn gecko_short_header_packet_uses_single_salamander_datagram() {
        let inner = Arc::new(FakeUdpSocket::new(1));
        let socket = Hysteria2ObfsSocket::new(
            inner.clone(),
            Hysteria2Obfs::gecko("secret".to_string(), Some(64), Some(160)).unwrap(),
        );
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 443)),
            ecn: None,
            contents: b"\x40short-header",
            segment_size: None,
            src_ip: None,
        };

        socket.try_send(&transmit).unwrap();

        let sent = inner.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let mut packet = sent[0].contents.clone();
        let payload_len =
            decode_salamander_packet_in_place(b"secret", &mut packet).expect("valid packet");
        assert_eq!(&packet[..payload_len], transmit.contents);
    }

    #[test]
    fn gecko_fragments_long_header_packet_and_reassembles() {
        let inner = Arc::new(FakeUdpSocket::new(1));
        let socket = Hysteria2ObfsSocket::new(
            inner.clone(),
            Hysteria2Obfs::gecko("secret".to_string(), Some(64), Some(160)).unwrap(),
        );
        let payload = [0x80u8]
            .into_iter()
            .chain((1u8..=95).map(|byte| byte & 0x7f))
            .collect::<Vec<_>>();
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 443)),
            ecn: None,
            contents: &payload,
            segment_size: None,
            src_ip: None,
        };

        socket.try_send(&transmit).unwrap();

        let sent = inner.sent.lock().unwrap();
        assert!((GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&sent.len()));
        let mut state = GeckoState::new();
        let addr = SocketAddr::from(([127, 0, 0, 1], 443));
        let mut reassembled = None;
        for sent in sent.iter().rev() {
            assert!((64..=160).contains(&sent.contents.len()));
            let mut packet = sent.contents.clone();
            let decoded_len =
                decode_salamander_packet_in_place(b"secret", &mut packet).expect("valid packet");
            let chunk = parse_gecko_chunk(&packet[..decoded_len]).expect("valid gecko chunk");
            if let Some(out) = state.accept_chunk(addr, chunk) {
                reassembled = Some(out);
            }
        }

        assert_eq!(reassembled.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn decode_received_meta_compacts_gro_segments() {
        let obfs = Hysteria2Obfs::salamander("secret".to_string()).unwrap();
        let first =
            encode_salamander_packet_with_salt(b"secret", &[1, 2, 3, 4, 5, 6, 7, 8], b"one");
        let second =
            encode_salamander_packet_with_salt(b"secret", &[8, 7, 6, 5, 4, 3, 2, 1], b"two");
        assert_eq!(first.len(), second.len());

        let mut storage = [0u8; 64];
        storage[..first.len()].copy_from_slice(&first);
        storage[first.len()..first.len() + second.len()].copy_from_slice(&second);
        let mut buf = IoSliceMut::new(&mut storage);
        let mut meta = RecvMeta {
            len: first.len() + second.len(),
            stride: first.len(),
            ..RecvMeta::default()
        };

        decode_received_meta(&obfs, &mut buf, &mut meta);

        assert_eq!(meta.len, 6);
        assert_eq!(meta.stride, 3);
        assert_eq!(&buf[..6], b"onetwo");
    }

    #[test]
    fn decode_received_meta_handles_many_gro_segments_with_short_final_segment() {
        let obfs = Hysteria2Obfs::salamander("secret".to_string()).unwrap();
        let mut encoded = Vec::new();
        let mut expected = Vec::new();
        let mut stride = 0usize;

        for index in 0u8..63 {
            let payload = [index; 4];
            let packet = encode_salamander_packet_with_salt(
                b"secret",
                &[index; SALAMANDER_SALT_LEN],
                &payload,
            );
            stride = packet.len();
            encoded.extend_from_slice(&packet);
            expected.extend_from_slice(&payload);
        }

        let last = encode_salamander_packet_with_salt(b"secret", &[63; SALAMANDER_SALT_LEN], b"z");
        encoded.extend_from_slice(&last);
        expected.extend_from_slice(b"z");

        let mut storage = encoded;
        let mut buf = IoSliceMut::new(&mut storage);
        let mut meta = RecvMeta {
            len: stride * 63 + last.len(),
            stride,
            ..RecvMeta::default()
        };

        decode_received_meta(&obfs, &mut buf, &mut meta);

        assert_eq!(meta.len, expected.len());
        assert_eq!(meta.stride, 4);
        assert_eq!(&buf[..expected.len()], expected.as_slice());
    }

    #[test]
    fn obfs_socket_encrypts_single_transmit_and_preserves_metadata() {
        let inner = Arc::new(FakeUdpSocket::new(1));
        let socket = Hysteria2ObfsSocket::new(
            inner.clone(),
            Hysteria2Obfs::salamander("secret".to_string()).unwrap(),
        );
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 443)),
            ecn: Some(quinn::udp::EcnCodepoint::Ect0),
            contents: b"payload",
            segment_size: None,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        };

        socket.try_send(&transmit).unwrap();

        let sent = inner.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].destination, transmit.destination);
        assert_eq!(sent[0].ecn, transmit.ecn);
        assert_eq!(sent[0].segment_size, None);
        assert_eq!(sent[0].src_ip, transmit.src_ip);
        assert_eq!(
            sent[0].contents.len(),
            SALAMANDER_SALT_LEN + transmit.contents.len()
        );

        let mut packet = sent[0].contents.clone();
        let payload_len =
            decode_salamander_packet_in_place(b"secret", &mut packet).expect("valid packet");
        assert_eq!(&packet[..payload_len], transmit.contents);
    }

    #[test]
    fn obfs_socket_propagates_would_block() {
        let inner = Arc::new(FakeUdpSocket::new(1));
        inner.fail_next_send(io::ErrorKind::WouldBlock);
        let socket = Hysteria2ObfsSocket::new(
            inner.clone(),
            Hysteria2Obfs::salamander("secret".to_string()).unwrap(),
        );
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 443)),
            ecn: None,
            contents: b"payload",
            segment_size: None,
            src_ip: None,
        };

        let err = socket.try_send(&transmit).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(inner.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn obfs_socket_rejects_segmented_transmit() {
        let inner = Arc::new(FakeUdpSocket::new(1));
        let socket = Hysteria2ObfsSocket::new(
            inner.clone(),
            Hysteria2Obfs::salamander("secret".to_string()).unwrap(),
        );
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 443)),
            ecn: None,
            contents: b"payload",
            segment_size: Some(4),
            src_ip: None,
        };

        let err = socket.try_send(&transmit).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(inner.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn obfs_socket_expands_receive_segment_capacity_for_salt_overhead() {
        let socket = Hysteria2ObfsSocket::new(
            Arc::new(FakeUdpSocket::new(1)),
            Hysteria2Obfs::salamander("secret".to_string()).unwrap(),
        );
        assert_eq!(socket.max_receive_segments(), 2);

        let socket = Hysteria2ObfsSocket::new(
            Arc::new(FakeUdpSocket::new(64)),
            Hysteria2Obfs::salamander("secret".to_string()).unwrap(),
        );
        assert_eq!(socket.max_receive_segments(), 65);
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
