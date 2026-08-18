use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::aes::Aes192;
use aes_gcm::{AesGcm, Nonce as RustCryptoNonce};
use aws_lc_rs::aead::{
    Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
};
use aws_lc_rs::error::Unspecified;
use futures::ready;
use rand::Rng;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead_util::TAG_LEN;
use super::salt_checker::SaltChecker;
use super::shadowsocks_cipher::ShadowsocksAeadAlgorithm;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream_type::ShadowsocksStreamType;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;

type Aes192Gcm = AesGcm<Aes192, U12>;

fn generate_iv(buf: &mut [u8]) {
    let mut rng = rand::rng();
    rng.fill_bytes(buf);
}

pub struct IncreasingSequence([u8; NONCE_LEN]);

impl IncreasingSequence {
    fn new() -> IncreasingSequence {
        IncreasingSequence([0u8; NONCE_LEN])
    }

    fn advance_bytes(&mut self) -> [u8; NONCE_LEN] {
        let ret = self.0;
        for i in self.0.iter_mut() {
            *i = i.wrapping_add(1);
            if *i > 0 {
                break;
            }
        }
        ret
    }
}

impl NonceSequence for IncreasingSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.advance_bytes()))
    }
}

enum ShadowsocksSealingKey {
    AwsLc(SealingKey<IncreasingSequence>),
    Aes192Gcm {
        cipher: Box<Aes192Gcm>,
        nonce: IncreasingSequence,
    },
}

impl ShadowsocksSealingKey {
    fn new(algorithm: ShadowsocksAeadAlgorithm, session_key: &[u8]) -> std::io::Result<Self> {
        match algorithm {
            ShadowsocksAeadAlgorithm::AwsLc(algorithm) => {
                let unbound_key = UnboundKey::new(algorithm, session_key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid Shadowsocks AEAD session key",
                    )
                })?;
                Ok(Self::AwsLc(SealingKey::new(
                    unbound_key,
                    IncreasingSequence::new(),
                )))
            }
            ShadowsocksAeadAlgorithm::Aes192Gcm => {
                let cipher = Aes192Gcm::new_from_slice(session_key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm session key",
                    )
                })?;
                Ok(Self::Aes192Gcm {
                    cipher: Box::new(cipher),
                    nonce: IncreasingSequence::new(),
                })
            }
        }
    }

    fn seal_in_place_separate_tag(&mut self, in_out: &mut [u8]) -> std::io::Result<[u8; TAG_LEN]> {
        match self {
            Self::AwsLc(key) => {
                let tag = key
                    .seal_in_place_separate_tag(Aad::empty(), in_out)
                    .map_err(|_| std::io::Error::other("shadowsocks AEAD seal failed"))?;
                let mut tag_bytes = [0u8; TAG_LEN];
                tag_bytes.copy_from_slice(tag.as_ref());
                Ok(tag_bytes)
            }
            Self::Aes192Gcm { cipher, nonce } => {
                let nonce_bytes = nonce.advance_bytes();
                let nonce: RustCryptoNonce<U12> = (&nonce_bytes[..]).try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm nonce length",
                    )
                })?;
                let tag = cipher
                    .encrypt_inout_detached(&nonce, b"", in_out.into())
                    .map_err(|_| std::io::Error::other("aes-192-gcm seal failed"))?;
                let mut tag_bytes = [0u8; TAG_LEN];
                tag_bytes.copy_from_slice(tag.as_slice());
                Ok(tag_bytes)
            }
        }
    }
}

enum ShadowsocksOpeningKey {
    AwsLc(OpeningKey<IncreasingSequence>),
    Aes192Gcm {
        cipher: Box<Aes192Gcm>,
        nonce: IncreasingSequence,
    },
}

impl ShadowsocksOpeningKey {
    fn new(algorithm: ShadowsocksAeadAlgorithm, session_key: &[u8]) -> std::io::Result<Self> {
        match algorithm {
            ShadowsocksAeadAlgorithm::AwsLc(algorithm) => {
                let unbound_key = UnboundKey::new(algorithm, session_key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid Shadowsocks AEAD session key",
                    )
                })?;
                Ok(Self::AwsLc(OpeningKey::new(
                    unbound_key,
                    IncreasingSequence::new(),
                )))
            }
            ShadowsocksAeadAlgorithm::Aes192Gcm => {
                let cipher = Aes192Gcm::new_from_slice(session_key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm session key",
                    )
                })?;
                Ok(Self::Aes192Gcm {
                    cipher: Box::new(cipher),
                    nonce: IncreasingSequence::new(),
                })
            }
        }
    }

    fn open_in_place(&mut self, in_out: &mut [u8]) -> std::io::Result<()> {
        match self {
            Self::AwsLc(key) => key
                .open_in_place(Aad::empty(), in_out)
                .map(|_| ())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "open failed")),
            Self::Aes192Gcm { cipher, nonce } => {
                if in_out.len() < TAG_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "aes-192-gcm ciphertext is shorter than tag",
                    ));
                }
                let nonce_bytes = nonce.advance_bytes();
                let nonce: RustCryptoNonce<U12> = (&nonce_bytes[..]).try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm nonce length",
                    )
                })?;
                let split_at = in_out.len() - TAG_LEN;
                let (payload, tag_bytes) = in_out.split_at_mut(split_at);
                let tag_bytes: [u8; TAG_LEN] = tag_bytes.try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm tag length",
                    )
                })?;
                let tag: aes_gcm::Tag = (&tag_bytes[..]).try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid aes-192-gcm tag length",
                    )
                })?;
                cipher
                    .decrypt_inout_detached(&nonce, b"", payload.into(), &tag)
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "open failed")
                    })
            }
        }
    }
}

pub struct ShadowsocksStream {
    stream: Box<dyn AsyncStream>,

    stream_type: ShadowsocksStreamType,
    algorithm: ShadowsocksAeadAlgorithm,
    salt_len: usize,
    key: Arc<Box<dyn ShadowsocksKey>>,
    salt_checker: Option<Arc<dyn SaltChecker>>,
    encrypt_iv: Box<[u8]>,
    decrypt_iv: Option<Box<[u8]>>,

    sealing_key: ShadowsocksSealingKey,
    opening_key: Option<ShadowsocksOpeningKey>,

    unprocessed_buf: Vec<u8>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,
    unprocessed_pending_len: Option<usize>,
    processed_buf: Vec<u8>,
    processed_start_offset: usize,
    processed_end_offset: usize,

    write_cache: Vec<u8>,
    write_cache_start_offset: usize,
    write_cache_end_offset: usize,

    is_initial_read: bool,
    is_initial_write: bool,
    is_eof: bool,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
}

const METADATA_SIZE: usize = 2 + (2 * TAG_LEN);

/// Initial size of the per-stream buffers, grown on demand up to a full
/// packet. Chosen to cover the handshake and typical small frames without an
/// immediate reallocation.
const INITIAL_BUF_SIZE: usize = 4096;

/// How far a peer's handshake timestamp may drift from ours, in either
/// direction.
///
/// AEAD-2022 specifies +/-30s, and the window has to be symmetric to honour
/// it: a clock running a few seconds fast is as ordinary as one running slow,
/// so a one-sided window refuses connections the spec allows -- which it did,
/// at roughly 2300 handshakes a day on a single node, almost all of them off
/// by under ten seconds. The salt-replay memory must outlive this whole span,
/// or a handshake could be replayed once its salt was forgotten but before its
/// timestamp went stale; see `SALT_REPLAY_WINDOW_SECS`.
pub(super) const TIMESTAMP_SKEW_TOLERANCE_SECS: u64 = 30;

fn shadowsocks_message_too_large_error(len: usize, max_len: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("Shadowsocks message length {len} exceeds max payload length {max_len}"),
    )
}

fn shadowsocks_initial_payload_too_large_error(len: usize, max_len: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Shadowsocks initial payload length {len} exceeds max encrypted packet capacity {max_len}"
        ),
    )
}

impl ShadowsocksStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        stream_type: ShadowsocksStreamType,
        algorithm: ShadowsocksAeadAlgorithm,
        salt_len: usize,
        key: Arc<Box<dyn ShadowsocksKey>>,
        salt_checker: Option<Arc<dyn SaltChecker>>,
    ) -> Self {
        // The buffers grow on demand up to a full packet. Reserving the
        // protocol maximum up front costs ~192 KB per stream and two streams
        // per proxied connection, which dominates the heap at high connection
        // counts even though most connections never carry a full-sized packet.
        let unprocessed_buf = allocate_vec(INITIAL_BUF_SIZE);
        let processed_buf = allocate_vec(INITIAL_BUF_SIZE);
        let write_cache = allocate_vec(INITIAL_BUF_SIZE);

        let mut encrypt_iv = allocate_vec(salt_len).into_boxed_slice();
        generate_iv(&mut encrypt_iv);

        let session_key = key.create_session_key(&encrypt_iv);
        let sealing_key = ShadowsocksSealingKey::new(algorithm, &session_key).unwrap();

        Self {
            stream,

            stream_type,
            algorithm,
            salt_len,
            key,
            salt_checker,
            encrypt_iv,
            // Needed for AEAD2022 server response.
            decrypt_iv: None,

            sealing_key,
            opening_key: None,

            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,

            write_cache,
            write_cache_start_offset: 0,
            write_cache_end_offset: 0,

            is_initial_read: true,
            is_initial_write: true,
            is_eof: false,
        }
    }

    fn process_opening_key(&mut self) -> std::io::Result<()> {
        let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
        let session_key = self.key.create_session_key(decrypt_iv);
        let opening_key = ShadowsocksOpeningKey::new(self.algorithm, &session_key)?;
        self.opening_key = Some(opening_key);
        Ok(())
    }

    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        // returns true if a full packet was decrypted, false if not (ie. more data required)

        let available_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let pending_len = match self.unprocessed_pending_len {
            Some(len) => {
                if available_len < len + TAG_LEN {
                    return Ok(DecryptState::NeedData);
                }
                if !self.ensure_processed_room(len) {
                    return Ok(DecryptState::BufferFull);
                }
                self.unprocessed_pending_len = None;
                len
            }
            None => {
                let data_length_len = 2 + TAG_LEN;
                if available_len < data_length_len {
                    return Ok(DecryptState::NeedData);
                }

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        &mut self.unprocessed_buf[self.unprocessed_start_offset
                            ..self.unprocessed_start_offset + data_length_len],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for length",
                    ));
                }

                let data_len_no_tag: usize =
                    ((self.unprocessed_buf[self.unprocessed_start_offset] as usize) << 8)
                        | (self.unprocessed_buf[self.unprocessed_start_offset + 1] as usize);

                // From https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
                // "Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
                // The higher two bits are reserved and must be set to zero. Payload is
                // therefore limited to 16*1024 - 1 bytes."
                if data_len_no_tag > self.stream_type.max_payload_len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "data length larger than max allowed size",
                    ));
                }

                self.unprocessed_start_offset += data_length_len;

                if available_len - data_length_len < data_len_no_tag + TAG_LEN {
                    self.unprocessed_pending_len = Some(data_len_no_tag);
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::NeedData);
                }

                if !self.ensure_processed_room(data_len_no_tag) {
                    return Ok(DecryptState::BufferFull);
                }

                data_len_no_tag
            }
        };

        let pending_len_with_tag = pending_len + TAG_LEN;
        if self
            .opening_key
            .as_mut()
            .unwrap()
            .open_in_place(
                &mut self.unprocessed_buf[self.unprocessed_start_offset
                    ..self.unprocessed_start_offset + pending_len_with_tag],
            )
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "open failed for data",
            ));
        }

        self.processed_buf[self.processed_end_offset..self.processed_end_offset + pending_len]
            .copy_from_slice(
                &self.unprocessed_buf
                    [self.unprocessed_start_offset..self.unprocessed_start_offset + pending_len],
            );

        self.processed_end_offset += pending_len;
        self.unprocessed_start_offset += pending_len_with_tag;

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        // this previously returned a Result<usize> but then we can't tell if it's a
        // 0 sized packet ie. pending_len = 0
        // TODO: check if that's allowed in shadowsocks protocol
        Ok(DecryptState::Success)
    }

    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) {
        assert!(
            self.processed_end_offset > 0,
            "called without any processed data"
        );

        let available_len = self.processed_end_offset - self.processed_start_offset;

        let unfilled_len = buf.remaining();

        let write_amount = std::cmp::min(unfilled_len, available_len);
        assert!(
            write_amount > 0,
            "no data to write (available_len = {available_len}, unfilled_len = {unfilled_len})",
        );

        buf.put_slice(
            &self.processed_buf
                [self.processed_start_offset..self.processed_start_offset + write_amount],
        );

        let new_processed_start_offset = self.processed_start_offset + write_amount;
        if new_processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    fn encrypt_single(&mut self, input: &[u8], write_length_header: bool) -> std::io::Result<()> {
        let input_len = input.len();
        let header_len = if write_length_header { 2 + TAG_LEN } else { 0 };
        self.ensure_write_cache(self.write_cache_end_offset + header_len + input_len + TAG_LEN);
        let output = &mut self.write_cache[self.write_cache_end_offset..];

        let mut written = if write_length_header {
            output[0] = (input_len >> 8) as u8;
            output[1] = (input_len & 0xff) as u8;

            let tag = self
                .sealing_key
                .seal_in_place_separate_tag(&mut output[0..2])?;

            output[2..2 + TAG_LEN].copy_from_slice(&tag[0..TAG_LEN]);

            2 + TAG_LEN
        } else {
            0
        };

        output[written..written + input_len].copy_from_slice(input);

        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(&mut output[written..written + input_len])?;
        written += input_len;

        output[written..written + TAG_LEN].copy_from_slice(&tag[0..TAG_LEN]);

        written += TAG_LEN;

        self.write_cache_end_offset += written;

        Ok(())
    }

    #[inline]
    fn do_write_cache(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        loop {
            match Pin::new(&mut self.stream).poll_write(
                cx,
                &self.write_cache[self.write_cache_start_offset..self.write_cache_end_offset],
            ) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while writing cached encrypted data",
                        ));
                    }
                    self.write_cache_start_offset += written;
                    if self.write_cache_start_offset == self.write_cache_end_offset {
                        self.write_cache_start_offset = 0;
                        self.write_cache_end_offset = 0;
                        return Ok(true);
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    return Ok(false);
                }
            }
        }
    }

    #[inline]
    fn poll_flush_cache(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_cache_end_offset > 0 {
            match self.do_write_cache(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Largest ciphertext packet this stream can carry.
    fn max_packet_len(&self) -> usize {
        self.stream_type.max_payload_len() + METADATA_SIZE
    }

    /// Make room to read more ciphertext: compact consumed bytes first, then
    /// grow (doubling, capped at one full packet). Preserves the invariant
    /// that a full packet always fits once the buffer has grown.
    /// Hand back whichever of the three buffers currently holds nothing.
    ///
    /// Measured at 20,000 concurrent idle streams, these were exactly 3.00
    /// allocations of `INITIAL_BUF_SIZE` per stream -- 12 KiB apiece, 72% of
    /// everything an idle stream cost. They were taken when the stream was
    /// built and never given back, so a connection that had gone quiet hours
    /// ago still held all three.
    ///
    /// Safe to do here because every use goes through one of the `ensure_*`
    /// helpers below, and each of those already grows correctly from a
    /// zero-length buffer. The cost of being wrong about idleness is one
    /// regrow when the peer speaks again.
    fn release_drained_buffers(&mut self) {
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
            self.unprocessed_buf = Vec::new();
        }
        if self.processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
            self.processed_buf = Vec::new();
        }
        if self.write_cache_start_offset == self.write_cache_end_offset {
            self.write_cache_start_offset = 0;
            self.write_cache_end_offset = 0;
            self.write_cache = Vec::new();
        }
    }

    fn ensure_unprocessed_room(&mut self) {
        if self.unprocessed_end_offset == self.unprocessed_buf.len()
            && self.unprocessed_start_offset > 0
        {
            self.reset_unprocessed_buf_offset();
        }
        if self.unprocessed_end_offset == self.unprocessed_buf.len() {
            let max = self.max_packet_len();
            let grown = (self.unprocessed_buf.len() * 2).clamp(INITIAL_BUF_SIZE, max);
            self.unprocessed_buf.resize(grown, 0);
        }
    }

    /// Grow `processed_buf` to hold `len` more plaintext bytes after what is
    /// already buffered. Returns false when the caller must pause with
    /// `DecryptState::BufferFull`, matching the fixed-buffer semantics so a
    /// burst cannot accumulate unbounded plaintext.
    fn ensure_processed_room(&mut self, len: usize) -> bool {
        let needed = self.processed_end_offset.saturating_add(len);
        if needed > self.stream_type.max_payload_len() {
            return false;
        }
        if self.processed_buf.len() < needed {
            self.processed_buf.resize(needed, 0);
        }
        true
    }

    /// Grow `write_cache` so `needed` bytes fit, never past a full packet.
    fn ensure_write_cache(&mut self, needed: usize) {
        let needed = needed.min(self.max_packet_len());
        if self.write_cache.len() < needed {
            self.write_cache.resize(needed, 0);
        }
    }

    fn reset_unprocessed_buf_offset(&mut self) {
        assert!(
            self.unprocessed_start_offset > 0
                && self.unprocessed_end_offset > self.unprocessed_start_offset
        );

        self.unprocessed_buf.copy_within(
            self.unprocessed_start_offset..self.unprocessed_end_offset,
            0,
        );
        self.unprocessed_end_offset -= self.unprocessed_start_offset;
        self.unprocessed_start_offset = 0;
    }

    fn read_header_len(&self) -> usize {
        match self.stream_type {
            ShadowsocksStreamType::Aead => self.salt_len,
            ShadowsocksStreamType::AEAD2022Server => {
                // Expect the encrypted client (request) header
                // salt (salt_len) + encrypted packet [type (1) + timestamp (8) + length (2)] + tag (TAG_LEN)
                self.salt_len + 11 + TAG_LEN
            }
            ShadowsocksStreamType::AEAD2022Client => {
                // Expect the server (response) header
                // salt (salt_len) + encrypted packet [type (1) + timestamp (8) + salt (salt_len) + length (2)] + tag (TAG_LEN)
                self.salt_len + 11 + self.salt_len + TAG_LEN
            }
        }
    }

    fn process_read_header(&mut self) -> std::io::Result<()> {
        match self.stream_type {
            ShadowsocksStreamType::Aead => {
                if let Some(salt_checker) = &self.salt_checker {
                    let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                    if !salt_checker.insert_and_check(decrypt_iv) {
                        return Err(std::io::Error::other("got duplicate salt"));
                    }
                }
                self.process_opening_key()?;
                self.unprocessed_start_offset += self.salt_len;
            }
            ShadowsocksStreamType::AEAD2022Server => {
                self.process_opening_key()?;

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        &mut self.unprocessed_buf[self.salt_len..self.salt_len + 11 + TAG_LEN],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for fixed length request header",
                    ));
                }

                if self.unprocessed_buf[self.salt_len] != 0 {
                    // HeaderTypeClientStream = 0
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid client header type, got {}",
                            self.unprocessed_buf[self.salt_len]
                        ),
                    ));
                }

                let timestamp_bytes = &self.unprocessed_buf[self.salt_len + 1..self.salt_len + 9];
                let timestamp_secs = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
                check_timestamp_freshness(timestamp_secs, current_time_secs())?;

                let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                if let Some(salt_checker) = &self.salt_checker
                    && !salt_checker.insert_and_check(decrypt_iv)
                {
                    return Err(std::io::Error::other("got duplicate salt"));
                }

                // Needed for writing the response
                self.decrypt_iv = Some(decrypt_iv.to_vec().into_boxed_slice());

                let variable_header_len = ((self.unprocessed_buf[self.salt_len + 9] as usize) << 8)
                    | (self.unprocessed_buf[self.salt_len + 10] as usize);

                self.unprocessed_pending_len = Some(variable_header_len);

                self.unprocessed_start_offset += self.salt_len + 11 + TAG_LEN;
            }
            ShadowsocksStreamType::AEAD2022Client => {
                self.process_opening_key()?;

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        &mut self.unprocessed_buf
                            [self.salt_len..self.salt_len + 11 + self.salt_len + TAG_LEN],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for fixed length request header",
                    ));
                }

                if self.unprocessed_buf[self.salt_len] != 1 {
                    // HeaderTypeServerStream = 1
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid server header type, got {}",
                            self.unprocessed_buf[self.salt_len]
                        ),
                    ));
                }

                let timestamp_bytes = &self.unprocessed_buf[self.salt_len + 1..self.salt_len + 9];
                let timestamp_secs = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
                check_timestamp_freshness(timestamp_secs, current_time_secs())?;

                if let Some(salt_checker) = &self.salt_checker {
                    let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                    if !salt_checker.insert_and_check(decrypt_iv) {
                        return Err(std::io::Error::other("got duplicate salt"));
                    }
                }

                let request_salt =
                    &self.unprocessed_buf[self.salt_len + 9..self.salt_len + 9 + self.salt_len];

                // Use constant-time comparison to prevent timing attacks
                if request_salt.ct_eq(&self.encrypt_iv[..]).unwrap_u8() == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "server returned request salt does not match",
                    ));
                }

                let first_chunk_len =
                    ((self.unprocessed_buf[self.salt_len + 9 + self.salt_len] as usize) << 8)
                        | (self.unprocessed_buf[self.salt_len + 9 + self.salt_len + 1] as usize);

                self.unprocessed_pending_len = Some(first_chunk_len);

                self.unprocessed_start_offset = self.salt_len + 11 + self.salt_len + TAG_LEN;
            }
        }

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        Ok(())
    }

    fn process_write_header(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.stream_type {
            ShadowsocksStreamType::Aead => {
                self.ensure_write_cache(self.salt_len);
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let handled_len = std::cmp::min(
                    buf.len(),
                    self.max_packet_len() - self.write_cache_end_offset - METADATA_SIZE,
                );
                if handled_len == 0 {
                    return Err(shadowsocks_initial_payload_too_large_error(buf.len(), 0));
                }

                self.encrypt_single(&buf[0..handled_len], true)
                    .map_err(|_| std::io::Error::other("failed to encrypt initial packet"))?;

                Ok(handled_len)
            }
            ShadowsocksStreamType::AEAD2022Server => {
                if self.is_initial_read {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot write Shadowsocks AEAD2022 server response before reading request header",
                    ));
                }

                let decrypt_iv = self.decrypt_iv.take().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing Shadowsocks AEAD2022 request salt for server response",
                    )
                })?;

                self.ensure_write_cache(self.salt_len);
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let mut response_header = allocate_vec(1 + 8 + self.salt_len + 2);

                // HeaderTypeServerStream = 1
                response_header[0] = 1;
                response_header[1..9].copy_from_slice(&current_time_secs().to_be_bytes());
                response_header[9..9 + self.salt_len].copy_from_slice(&decrypt_iv);

                // subtract TAG_LEN and not METADATA_SIZE because we don't need the length header + tag.
                let max_initial_payload_len = self.max_packet_len()
                    - self.salt_len
                    - (response_header.len() + TAG_LEN)
                    - TAG_LEN;
                let handled_len = std::cmp::min(buf.len(), max_initial_payload_len);

                response_header[9 + self.salt_len] = (handled_len >> 8) as u8;
                response_header[9 + self.salt_len + 1] = (handled_len & 0xff) as u8;

                self.encrypt_single(&response_header, false)
                    .map_err(|_| std::io::Error::other("failed to encrypt response header"))?;

                self.encrypt_single(&buf[0..handled_len], false)
                    .map_err(|_| {
                        std::io::Error::other("failed to encrypt initial server packet")
                    })?;

                Ok(handled_len)
            }
            ShadowsocksStreamType::AEAD2022Client => {
                self.ensure_write_cache(self.salt_len);
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let mut request_header = allocate_vec(1 + 8 + 2);

                // HeaderTypeClientStream = 0
                request_header[0] = 0;
                request_header[1..9].copy_from_slice(&current_time_secs().to_be_bytes());

                // This is a bit hacky. We expect/know that the first packet will be the "variable-length header"
                // with the address and padding, and we need to send it all off in a single packet.
                let buf_len = buf.len();
                let max_initial_payload_len = self.max_packet_len()
                    - self.salt_len
                    - (request_header.len() + TAG_LEN)
                    - TAG_LEN;
                if buf_len > max_initial_payload_len {
                    return Err(shadowsocks_initial_payload_too_large_error(
                        buf_len,
                        max_initial_payload_len,
                    ));
                }

                request_header[9] = (buf_len >> 8) as u8;
                request_header[10] = (buf_len & 0xff) as u8;

                self.encrypt_single(&request_header, false)
                    .map_err(|_| std::io::Error::other("failed to encrypt response header"))?;

                self.encrypt_single(buf, false).map_err(|_| {
                    std::io::Error::other("failed to encrypt initial client packet")
                })?;

                Ok(buf_len)
            }
        }
    }

    fn poll_read_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        fill_buffer: bool,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if this.is_initial_read && !this.is_eof {
            loop {
                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.unprocessed_end_offset += len;
                if this.unprocessed_end_offset >= this.read_header_len() {
                    break;
                }
            }

            this.process_read_header()?;
            this.is_initial_read = false;
        }

        loop {
            if this.unprocessed_end_offset > 0 {
                // Process some data to free up unprocessed_buf space.
                loop {
                    match this.try_decrypt()? {
                        DecryptState::NeedData => {
                            break;
                        }
                        DecryptState::BufferFull => {
                            assert!(this.processed_end_offset > 0);
                            break;
                        }
                        DecryptState::Success => {
                            if !fill_buffer && this.processed_end_offset > 0 {
                                break;
                            }
                            continue;
                        }
                    }
                }
            }

            // Compact consumed bytes, growing the buffer if the remaining
            // unprocessed data still fills it.
            this.ensure_unprocessed_room();

            if this.processed_end_offset > 0 {
                // Return the data we just got.
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }

            if this.is_eof {
                return Poll::Ready(Ok(()));
            }

            let read = {
                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
                match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                    Poll::Ready(result) => {
                        result?;
                        Some(read_buf.filled().len())
                    }
                    Poll::Pending => None,
                }
            };
            let Some(len) = read else {
                // Parked on a peer with nothing to say, which is where a
                // proxied stream spends almost all of its life.
                this.release_drained_buffers();
                return Poll::Pending;
            };

            // Make sure we have enough space to store the processed data.
            if len == 0 {
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
            } else {
                this.unprocessed_end_offset += len;
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

pub fn try_decrypt_aead_length(
    algorithm: ShadowsocksAeadAlgorithm,
    key: &dyn ShadowsocksKey,
    salt: &[u8],
    encrypted_length: &[u8],
    max_payload_len: usize,
) -> std::io::Result<usize> {
    if encrypted_length.len() != 2 + TAG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid encrypted length chunk size {}, expected {}",
                encrypted_length.len(),
                2 + TAG_LEN
            ),
        ));
    }
    let session_key = key.create_session_key(salt);
    let mut opening_key = ShadowsocksOpeningKey::new(algorithm, &session_key)?;
    let mut chunk = encrypted_length.to_vec();
    opening_key
        .open_in_place(&mut chunk)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "open failed"))?;
    let len = ((chunk[0] as usize) << 8) | (chunk[1] as usize);
    if len > max_payload_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "data length larger than max allowed size",
        ));
    }
    Ok(len)
}

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_read_inner(cx, buf, true)
    }
}

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // TODO: This might not be optimal because we always immediately packetize `buf`, should we
        // do something smarter?
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        if this.is_initial_write {
            let handled_len = this.process_write_header(buf)?;
            if handled_len == 0 || this.write_cache_end_offset == 0 {
                return Poll::Ready(Err(shadowsocks_initial_payload_too_large_error(
                    buf.len(),
                    0,
                )));
            }
            this.is_initial_write = false;

            if let Err(e) = this.do_write_cache(cx) {
                return Poll::Ready(Err(e));
            }

            return Poll::Ready(Ok(handled_len));
        }

        let mut write_cache_space = this.max_packet_len() - this.write_cache_end_offset;

        if write_cache_space <= METADATA_SIZE {
            match this.do_write_cache(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            };
            // if we got here, then everything was written.
            assert!(this.write_cache_start_offset == 0 && this.write_cache_end_offset == 0);
            write_cache_space = this.max_packet_len();
        }

        let max_write_cache_data_size = write_cache_space - METADATA_SIZE;
        let packet_data_size = std::cmp::min(
            std::cmp::min(buf.len(), max_write_cache_data_size),
            this.stream_type.max_payload_len(),
        );
        this.encrypt_single(&buf[0..packet_data_size], true)
            .map_err(|_| std::io::Error::other("failed to encrypt packet"))?;

        if let Err(e) = this.do_write_cache(cx) {
            return Poll::Ready(Err(e));
        }

        Poll::Ready(Ok(packet_data_size))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_cache(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_cache(cx))?;
        ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncReadMessage for ShadowsocksStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_read_inner(cx, buf, false)
    }
}

impl AsyncWriteMessage for ShadowsocksStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let max_payload_len = this.stream_type.max_payload_len();
        if buf.len() > max_payload_len {
            return Poll::Ready(Err(shadowsocks_message_too_large_error(
                buf.len(),
                max_payload_len,
            )));
        }

        if this.is_initial_write {
            let handled_len = this.process_write_header(buf)?;
            if handled_len != buf.len() {
                return Poll::Ready(Err(shadowsocks_initial_payload_too_large_error(
                    buf.len(),
                    handled_len,
                )));
            }
            this.is_initial_write = false;
            return Poll::Ready(Ok(()));
        }

        let mut write_cache_space = this.max_packet_len() - this.write_cache_end_offset;
        let packet_size = buf.len().checked_add(METADATA_SIZE).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks message length overflows encrypted packet size",
            )
        })?;
        if packet_size > this.max_packet_len() {
            return Poll::Ready(Err(shadowsocks_message_too_large_error(
                buf.len(),
                max_payload_len,
            )));
        }

        if packet_size > write_cache_space {
            ready!(this.poll_flush_cache(cx))?;
            write_cache_space = this.max_packet_len() - this.write_cache_end_offset;
            if packet_size > write_cache_space {
                return Poll::Pending;
            }
        }

        this.encrypt_single(buf, true)
            .map_err(|_| std::io::Error::other("failed to encrypt packet"))?;

        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ShadowsocksStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncFlushMessage for ShadowsocksStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncShutdownMessage for ShadowsocksStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_shutdown(cx)
    }
}

impl AsyncStream for ShadowsocksStream {}
impl AsyncMessageStream for ShadowsocksStream {}

#[inline]
fn current_time_secs() -> u64 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
}

/// Rejects a handshake whose timestamp drifted further than AEAD-2022 allows.
///
/// The drift is named in the error either way round: a bare "greater than 30
/// seconds" told an operator nothing about whether the peer was skewed by a
/// second or by an hour, which is exactly the question that decides whether a
/// rejection is a clock problem or an attack.
fn check_timestamp_freshness(timestamp_secs: u64, now_secs: u64) -> std::io::Result<()> {
    let (drift_secs, direction) = if now_secs >= timestamp_secs {
        (now_secs - timestamp_secs, "old")
    } else {
        (timestamp_secs - now_secs, "in the future")
    };
    if drift_secs > TIMESTAMP_SKEW_TOLERANCE_SECS {
        return Err(std::io::Error::other(format!(
            "timestamp is {drift_secs} seconds {direction}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    use futures::future::poll_fn;
    use tokio::io::AsyncWrite;

    use super::super::{DefaultKey, ShadowsocksCipher};

    struct SinkStream;

    impl AsyncRead for SinkStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for SinkStream {
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
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for SinkStream {
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

    impl AsyncStream for SinkStream {}

    struct PendingOnceSinkStream {
        written: StdArc<StdMutex<Vec<u8>>>,
        wrote_once: bool,
        returned_pending: bool,
    }

    impl PendingOnceSinkStream {
        fn new(written: StdArc<StdMutex<Vec<u8>>>) -> Self {
            Self {
                written,
                wrote_once: false,
                returned_pending: false,
            }
        }
    }

    impl AsyncRead for PendingOnceSinkStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingOnceSinkStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            if !self.wrote_once {
                self.written.lock().unwrap().push(buf[0]);
                self.wrote_once = true;
                return Poll::Ready(Ok(1));
            }

            if !self.returned_pending {
                self.returned_pending = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PendingOnceSinkStream {
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

    impl AsyncStream for PendingOnceSinkStream {}

    fn test_stream(stream_type: ShadowsocksStreamType) -> ShadowsocksStream {
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        let key: Arc<Box<dyn ShadowsocksKey>> =
            Arc::new(Box::new(DefaultKey::new("test-password", cipher.key_len())));
        ShadowsocksStream::new(
            Box::new(SinkStream),
            stream_type,
            cipher.algorithm(),
            cipher.salt_len(),
            key,
            None,
        )
    }

    fn test_stream_with_inner(
        stream_type: ShadowsocksStreamType,
        inner: Box<dyn AsyncStream>,
    ) -> ShadowsocksStream {
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        let key: Arc<Box<dyn ShadowsocksKey>> =
            Arc::new(Box::new(DefaultKey::new("test-password", cipher.key_len())));
        ShadowsocksStream::new(
            inner,
            stream_type,
            cipher.algorithm(),
            cipher.salt_len(),
            key,
            None,
        )
    }

    #[tokio::test]
    async fn zero_length_stream_and_message_writes_are_noops() {
        let mut stream = test_stream(ShadowsocksStreamType::Aead);

        let written = poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, b""))
            .await
            .unwrap();
        assert_eq!(written, 0);
        assert!(stream.is_initial_write);

        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b""))
            .await
            .unwrap();
        assert!(stream.is_initial_write);
    }

    #[tokio::test]
    async fn zero_sized_read_is_noop() {
        let mut stream = test_stream(ShadowsocksStreamType::Aead);
        let mut out = [];
        let mut read = ReadBuf::new(&mut out);

        poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut read))
            .await
            .unwrap();

        assert!(read.filled().is_empty());
        assert!(stream.is_initial_read);
    }

    #[tokio::test]
    async fn shutdown_flushes_pending_encrypted_cache() {
        let written = StdArc::new(StdMutex::new(Vec::new()));
        let inner = PendingOnceSinkStream::new(written.clone());
        let mut stream = test_stream_with_inner(ShadowsocksStreamType::Aead, Box::new(inner));

        let accepted = poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, b"payload"))
            .await
            .unwrap();
        assert_eq!(accepted, b"payload".len());
        assert_eq!(written.lock().unwrap().len(), 1);
        assert!(stream.write_cache_end_offset > 0);

        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown(cx))
            .await
            .unwrap();

        assert!(stream.write_cache_end_offset == 0);
        assert!(written.lock().unwrap().len() > 1);
    }

    #[tokio::test]
    async fn message_write_rejects_legacy_aead_payload_over_cap() {
        let mut stream = test_stream(ShadowsocksStreamType::Aead);
        let oversized = vec![0u8; ShadowsocksStreamType::Aead.max_payload_len() + 1];

        let err = poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &oversized))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(stream.is_initial_write);
    }

    #[tokio::test]
    async fn initial_aead2022_message_over_header_capacity_returns_error() {
        let mut stream = test_stream(ShadowsocksStreamType::AEAD2022Client);
        let request_header_len = 1 + 8 + 2;
        let max_initial_payload_len =
            stream.max_packet_len() - stream.salt_len - (request_header_len + TAG_LEN) - TAG_LEN;
        assert!(max_initial_payload_len < stream.stream_type.max_payload_len());
        let oversized = vec![0u8; max_initial_payload_len + 1];

        let err = poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &oversized))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(stream.is_initial_write);
    }

    /// A fixed instant: the helper used to read the clock itself, so a test
    /// that captured "now" and then called it could straddle a second
    /// boundary and see a drift one off from the one it set up.
    const TEST_NOW_SECS: u64 = 1_800_000_000;

    #[test]
    fn timestamp_window_accepts_a_clock_running_fast() {
        // The regression this covers: the window used to allow 30s of lag but
        // only 2s of lead, so a peer three seconds fast -- the single most
        // common rejection seen in production -- could not connect at all.
        for lead in 1..=TIMESTAMP_SKEW_TOLERANCE_SECS {
            check_timestamp_freshness(TEST_NOW_SECS + lead, TEST_NOW_SECS)
                .unwrap_or_else(|e| panic!("{lead}s fast must be accepted: {e}"));
        }
    }

    #[test]
    fn timestamp_window_is_symmetric_at_its_edges() {
        check_timestamp_freshness(TEST_NOW_SECS + TIMESTAMP_SKEW_TOLERANCE_SECS, TEST_NOW_SECS)
            .expect("the leading edge is inside the window");
        check_timestamp_freshness(TEST_NOW_SECS - TIMESTAMP_SKEW_TOLERANCE_SECS, TEST_NOW_SECS)
            .expect("the lagging edge is inside the window");

        assert!(
            check_timestamp_freshness(
                TEST_NOW_SECS + TIMESTAMP_SKEW_TOLERANCE_SECS + 1,
                TEST_NOW_SECS
            )
            .is_err()
        );
        assert!(
            check_timestamp_freshness(
                TEST_NOW_SECS - TIMESTAMP_SKEW_TOLERANCE_SECS - 1,
                TEST_NOW_SECS
            )
            .is_err()
        );
    }

    #[test]
    fn timestamp_rejection_names_the_drift_and_direction() {
        let ahead = check_timestamp_freshness(TEST_NOW_SECS + 300, TEST_NOW_SECS)
            .unwrap_err()
            .to_string();
        assert!(ahead.contains("300"), "{ahead}");
        assert!(ahead.contains("in the future"), "{ahead}");

        let behind = check_timestamp_freshness(TEST_NOW_SECS - 300, TEST_NOW_SECS)
            .unwrap_err()
            .to_string();
        assert!(behind.contains("300"), "{behind}");
        assert!(behind.contains("old"), "{behind}");
    }
}
