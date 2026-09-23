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
    key: Arc<dyn ShadowsocksKey>,
    salt_checker: Option<Arc<dyn SaltChecker>>,
    encrypt_iv: Box<[u8]>,
    decrypt_iv: Option<Box<[u8]>>,

    sealing_key: ShadowsocksSealingKey,
    opening_key: Option<ShadowsocksOpeningKey>,

    /// Bytes received from the transport. Its length is exactly how much has
    /// been filled, so growing it never initialises bytes that the next read
    /// overwrites anyway, and nothing ever sees memory that was not written.
    ///
    /// A chunk is decrypted where it lies, and its plaintext is handed to the
    /// caller straight from here: `plaintext_start..plaintext_end`, followed
    /// by the chunk's (spent) tag, followed by ciphertext not yet decrypted
    /// from `unprocessed_start_offset`. At most one chunk is decrypted ahead
    /// of the caller, which bounds buffered plaintext to one packet.
    unprocessed_buf: Vec<u8>,
    unprocessed_start_offset: usize,
    unprocessed_pending_len: Option<usize>,
    plaintext_start: usize,
    plaintext_end: usize,
    /// Most bytes buffered at once since the buffer was last reacquired. It
    /// sizes the next reacquisition, so a bulk transfer takes one allocation
    /// per wake instead of doubling up from `INITIAL_BUF_SIZE` every time,
    /// while a stream carrying small messages goes back to a small buffer.
    unprocessed_high_water: usize,
    unprocessed_reacquire_size: usize,

    /// Encrypted bytes waiting for the transport; its length is the end of
    /// what is queued, for the same reason as `unprocessed_buf`.
    write_cache: Vec<u8>,
    write_cache_start_offset: usize,

    is_initial_read: bool,
    is_initial_write: bool,
    is_eof: bool,
}

enum DecryptState {
    NeedData,
    Success,
}

const METADATA_SIZE: usize = 2 + (2 * TAG_LEN);

/// Initial size of the per-stream buffers, grown on demand up to a full
/// packet. Chosen to cover the handshake and typical small frames without an
/// immediate reallocation.
const INITIAL_BUF_SIZE: usize = 4096;

/// Largest session key any supported AEAD uses, so the multi-user probe can
/// derive one on the stack.
const MAX_SESSION_KEY_LEN: usize = 32;

/// How far a peer's handshake timestamp may drift from ours, in either
/// direction.
///
/// Deliberately wider than the +/-30s AEAD-2022 specifies, and symmetric: a
/// clock running fast is as ordinary as one running slow, so a one-sided
/// window refuses connections for a reason the peer cannot see or fix.
///
/// 180s is where the observed drift stops looking like a clock and starts
/// looking like a timezone. Eleven days across four nodes recorded 8199
/// refusals whose drift clustered under 60s and again at 154-155s, then
/// nothing until 8h and 15h -- devices serving local time as UTC, which no
/// tolerance should admit. A 180s window accepts 97% of what was refused and
/// still rejects every one of those. The clusters were not stray connections
/// either: one held a steady 47-108 refusals an hour for eight hours without
/// ever getting in, which is a device that simply cannot use the service.
///
/// The salt-replay memory must outlive this whole span, or a handshake could
/// be replayed once its salt was forgotten but before its timestamp went
/// stale; see `SALT_REPLAY_WINDOW_SECS`, which moves with this constant.
pub(super) const TIMESTAMP_SKEW_TOLERANCE_SECS: u64 = 180;

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
        key: Arc<dyn ShadowsocksKey>,
        salt_checker: Option<Arc<dyn SaltChecker>>,
    ) -> Self {
        // The buffers grow on demand up to a full packet. Reserving the
        // protocol maximum up front costs ~192 KB per stream and two streams
        // per proxied connection, which dominates the heap at high connection
        // counts even though most connections never carry a full-sized packet.
        let unprocessed_buf = Vec::with_capacity(INITIAL_BUF_SIZE);
        let write_cache = Vec::with_capacity(INITIAL_BUF_SIZE);

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
            unprocessed_pending_len: None,
            plaintext_start: 0,
            plaintext_end: 0,
            unprocessed_high_water: 0,
            unprocessed_reacquire_size: INITIAL_BUF_SIZE,

            write_cache,
            write_cache_start_offset: 0,

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

    /// Decrypt the next chunk in place, if all of it has arrived.
    ///
    /// Only called once the previous chunk's plaintext has been handed out:
    /// the plaintext stays where it was decrypted, so there is never more than
    /// one chunk of it buffered.
    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        debug_assert!(!self.has_plaintext());

        let available_len = self.unprocessed_buf.len() - self.unprocessed_start_offset;

        let pending_len = match self.unprocessed_pending_len {
            Some(len) => {
                if available_len < len + TAG_LEN {
                    return Ok(DecryptState::NeedData);
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
                    self.discard_consumed_unprocessed();
                    return Ok(DecryptState::NeedData);
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

        // The plaintext is read out from right here; see `read_plaintext`.
        self.plaintext_start = self.unprocessed_start_offset;
        self.plaintext_end = self.unprocessed_start_offset + pending_len;
        self.unprocessed_start_offset += pending_len_with_tag;
        if !self.has_plaintext() {
            self.discard_consumed_unprocessed();
        }

        // this previously returned a Result<usize> but then we can't tell if it's a
        // 0 sized packet ie. pending_len = 0
        // TODO: check if that's allowed in shadowsocks protocol
        Ok(DecryptState::Success)
    }

    #[inline]
    fn has_plaintext(&self) -> bool {
        self.plaintext_start < self.plaintext_end
    }

    /// Hand out decrypted bytes from where they were decrypted.
    fn read_plaintext(&mut self, buf: &mut ReadBuf<'_>) {
        let available_len = self.plaintext_end - self.plaintext_start;
        let write_amount = std::cmp::min(buf.remaining(), available_len);
        buf.put_slice(
            &self.unprocessed_buf[self.plaintext_start..self.plaintext_start + write_amount],
        );
        self.plaintext_start += write_amount;
        if !self.has_plaintext() {
            self.plaintext_start = 0;
            self.plaintext_end = 0;
            self.discard_consumed_unprocessed();
        }
    }

    /// Forget everything before `unprocessed_start_offset` once it has all
    /// been consumed, which costs nothing when no ciphertext is left over.
    fn discard_consumed_unprocessed(&mut self) {
        if !self.has_plaintext() && self.unprocessed_start_offset == self.unprocessed_buf.len() {
            self.unprocessed_buf.clear();
            self.unprocessed_start_offset = 0;
        }
    }

    /// Read more ciphertext from the transport into the unfilled tail.
    ///
    /// The tail is handed over uninitialised: only the bytes the transport
    /// reports as filled become part of the buffer, so no allocation is ever
    /// zeroed only to be overwritten.
    fn poll_fill_unprocessed(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        debug_assert!(self.unprocessed_buf.len() < self.unprocessed_buf.capacity());
        let filled_len = self.unprocessed_buf.len();
        let mut read_buf = ReadBuf::uninit(self.unprocessed_buf.spare_capacity_mut());
        ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
        let len = read_buf.filled().len();
        // SAFETY: `ReadBuf` only reports bytes as filled once they have been
        // initialised, and it was built over the spare capacity that starts at
        // `filled_len`, so the first `filled_len + len` bytes are initialised.
        unsafe {
            self.unprocessed_buf.set_len(filled_len + len);
        }
        self.unprocessed_high_water = self.unprocessed_high_water.max(filled_len + len);
        Poll::Ready(Ok(len))
    }

    fn encrypt_single(&mut self, input: &[u8], write_length_header: bool) -> std::io::Result<()> {
        let input_len = input.len();
        let header_len = if write_length_header { 2 + TAG_LEN } else { 0 };
        self.ensure_write_cache(header_len + input_len + TAG_LEN);
        let chunk_start = self.write_cache.len();
        let result = self.seal_into_write_cache(input, write_length_header);
        if result.is_err() {
            self.write_cache.truncate(chunk_start);
        }
        result
    }

    /// Append one sealed chunk to `write_cache`: the input is copied in once
    /// and sealed where it lands.
    fn seal_into_write_cache(
        &mut self,
        input: &[u8],
        write_length_header: bool,
    ) -> std::io::Result<()> {
        if write_length_header {
            let input_len = input.len();
            let length_start = self.write_cache.len();
            self.write_cache
                .extend_from_slice(&[(input_len >> 8) as u8, (input_len & 0xff) as u8]);
            let tag = self
                .sealing_key
                .seal_in_place_separate_tag(&mut self.write_cache[length_start..])?;
            self.write_cache.extend_from_slice(&tag);
        }

        let payload_start = self.write_cache.len();
        self.write_cache.extend_from_slice(input);
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(&mut self.write_cache[payload_start..])?;
        self.write_cache.extend_from_slice(&tag);

        Ok(())
    }

    #[inline]
    fn do_write_cache(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        loop {
            match Pin::new(&mut self.stream)
                .poll_write(cx, &self.write_cache[self.write_cache_start_offset..])
            {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while writing cached encrypted data",
                        ));
                    }
                    self.write_cache_start_offset += written;
                    if self.write_cache_start_offset == self.write_cache.len() {
                        self.write_cache_start_offset = 0;
                        self.write_cache.clear();
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
        while !self.write_cache.is_empty() {
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

    /// Hand back whichever of the buffers currently holds nothing.
    ///
    /// Measured at 20,000 concurrent idle streams, these were exactly 3.00
    /// allocations of `INITIAL_BUF_SIZE` per stream -- 12 KiB apiece, 72% of
    /// everything an idle stream cost. They were taken when the stream was
    /// built and never given back, so a connection that had gone quiet hours
    /// ago still held all three.
    ///
    /// Safe to do here because every use goes through `ensure_unprocessed_room`
    /// or `ensure_write_cache`, and each of those grows correctly from an empty
    /// buffer. The cost of being wrong about idleness is one allocation when
    /// the peer speaks again.
    fn release_drained_buffers(&mut self) {
        if !self.has_plaintext() && self.unprocessed_start_offset == self.unprocessed_buf.len() {
            // Size the next reacquisition by what this burst needed, so a bulk
            // transfer reacquires its working size in one step and a quiet
            // stream falls back to a small buffer.
            self.unprocessed_reacquire_size = self
                .unprocessed_high_water
                .clamp(INITIAL_BUF_SIZE, self.max_packet_len());
            self.unprocessed_high_water = 0;
            self.unprocessed_start_offset = 0;
            self.unprocessed_buf = Vec::new();
        }
        if self.write_cache_start_offset == self.write_cache.len() {
            self.write_cache_start_offset = 0;
            self.write_cache = Vec::new();
        }
    }

    /// Make room to read the rest of the chunk being assembled.
    ///
    /// Only called with no plaintext buffered -- nothing is read from the
    /// transport while there is still something to hand out -- so whatever
    /// precedes `unprocessed_start_offset` is spent and may be overwritten.
    /// Once the chunk's length has been decrypted its full size is known, and
    /// the buffer is sized for it in one step rather than doubled towards it.
    fn ensure_unprocessed_room(&mut self) {
        debug_assert!(!self.has_plaintext());
        let max_packet_len = self.max_packet_len();
        // Bytes the chunk being assembled needs from `unprocessed_start_offset`.
        let needed = match self.unprocessed_pending_len {
            Some(len) => len + TAG_LEN,
            None => 2 + TAG_LEN,
        };
        let start = self.unprocessed_start_offset;
        let filled = self.unprocessed_buf.len();
        let capacity = self.unprocessed_buf.capacity();

        // Room for the chunk being assembled and the start of the next one
        // behind it, so a bulk stream does not end every read on a partial
        // chunk that then has to be moved to the front.
        let grown_for_needed = needed.saturating_mul(2).min(max_packet_len);

        if capacity == 0 {
            // Reacquiring after a park, with nothing buffered.
            let size = if needed > self.unprocessed_reacquire_size {
                grown_for_needed
            } else {
                self.unprocessed_reacquire_size
            };
            self.unprocessed_buf = Vec::with_capacity(size);
            self.unprocessed_start_offset = 0;
            return;
        }

        if needed <= capacity {
            if start + needed > capacity || filled == capacity {
                // The chunk fits once the spent prefix is dropped.
                self.unprocessed_buf.copy_within(start..filled, 0);
                self.unprocessed_buf.truncate(filled - start);
                self.unprocessed_start_offset = 0;
            }
            // An incomplete chunk is shorter than `needed`, so this only
            // triggers if a caller broke that precondition; reading into a
            // full buffer would otherwise look exactly like EOF.
            if self.unprocessed_buf.len() == self.unprocessed_buf.capacity() {
                self.unprocessed_buf.reserve_exact(needed);
            }
            return;
        }

        // Too small for this chunk: move what is buffered into a buffer sized
        // for it, which is the only copy growing costs.
        let mut buf = Vec::with_capacity(grown_for_needed);
        buf.extend_from_slice(&self.unprocessed_buf[start..filled]);
        self.unprocessed_buf = buf;
        self.unprocessed_start_offset = 0;
    }

    /// Make sure `additional` more bytes can be appended to `write_cache`,
    /// never growing it past a full packet.
    fn ensure_write_cache(&mut self, additional: usize) {
        let needed = self.write_cache.len() + additional;
        let capacity = self.write_cache.capacity();
        if needed <= capacity {
            return;
        }
        let grown = needed.max(capacity.saturating_mul(2).min(self.max_packet_len()));
        self.write_cache
            .reserve_exact(grown - self.write_cache.len());
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

        self.discard_consumed_unprocessed();

        Ok(())
    }

    fn process_write_header(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.stream_type {
            ShadowsocksStreamType::Aead => {
                self.ensure_write_cache(self.salt_len);
                self.write_cache.extend_from_slice(&self.encrypt_iv);

                let handled_len = std::cmp::min(
                    buf.len(),
                    self.max_packet_len() - self.write_cache.len() - METADATA_SIZE,
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
                self.write_cache.extend_from_slice(&self.encrypt_iv);

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
                self.write_cache.extend_from_slice(&self.encrypt_iv);

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
                if this.unprocessed_buf.len() == this.unprocessed_buf.capacity() {
                    this.unprocessed_buf.reserve_exact(INITIAL_BUF_SIZE);
                }
                let len = match this.poll_fill_unprocessed(cx) {
                    Poll::Ready(result) => result?,
                    Poll::Pending => {
                        // Waiting on the peer's header holds nothing either.
                        this.release_drained_buffers();
                        return Poll::Pending;
                    }
                };
                if len == 0 {
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                if this.unprocessed_buf.len() >= this.read_header_len() {
                    break;
                }
            }

            this.process_read_header()?;
            this.is_initial_read = false;
        }

        let filled_before = buf.filled().len();
        loop {
            if this.has_plaintext() {
                this.read_plaintext(buf);
                // A message read is one chunk, and a full buffer is a full
                // buffer; otherwise carry on into whatever else is buffered.
                if buf.remaining() == 0 || !fill_buffer {
                    return Poll::Ready(Ok(()));
                }
            }

            // Nothing left to hand out: open the next chunk if all of it has
            // arrived. A zero-length chunk yields nothing and the loop simply
            // moves on to the one after it.
            if this.unprocessed_start_offset < this.unprocessed_buf.len()
                && let DecryptState::Success = this.try_decrypt()?
            {
                continue;
            }

            if buf.filled().len() > filled_before {
                // Return what was already buffered rather than wait for more.
                return Poll::Ready(Ok(()));
            }

            if this.is_eof {
                return Poll::Ready(Ok(()));
            }

            this.ensure_unprocessed_room();
            let read = match this.poll_fill_unprocessed(cx) {
                Poll::Ready(result) => Some(result?),
                Poll::Pending => None,
            };
            let Some(len) = read else {
                // Parked on a peer with nothing to say, which is where a
                // proxied stream spends almost all of its life.
                this.release_drained_buffers();
                return Poll::Pending;
            };

            if len == 0 {
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
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
    // On the multi-user path this runs once per candidate user on every
    // connection attempt, so it derives and decrypts entirely on the stack:
    // the heap traffic of the obvious spelling is two allocations per
    // candidate, which is thousands per connection on a large node.
    let mut session_key = [0u8; MAX_SESSION_KEY_LEN];
    let session_key_len = key
        .write_session_key(salt, &mut session_key)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks session key is longer than the largest supported AEAD key",
            )
        })?;
    let mut opening_key = ShadowsocksOpeningKey::new(algorithm, &session_key[..session_key_len])?;
    let mut chunk = [0u8; 2 + TAG_LEN];
    chunk.copy_from_slice(encrypted_length);
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
            if handled_len == 0 || this.write_cache.is_empty() {
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

        let mut write_cache_space = this.max_packet_len() - this.write_cache.len();

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
            assert!(this.write_cache_start_offset == 0 && this.write_cache.is_empty());
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

        let mut write_cache_space = this.max_packet_len() - this.write_cache.len();
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
            write_cache_space = this.max_packet_len() - this.write_cache.len();
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
        let key: Arc<dyn ShadowsocksKey> =
            Arc::new(DefaultKey::new("test-password", cipher.key_len()));
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
        let key: Arc<dyn ShadowsocksKey> =
            Arc::new(DefaultKey::new("test-password", cipher.key_len()));
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
        assert!(!stream.write_cache.is_empty());

        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown(cx))
            .await
            .unwrap();

        assert!(stream.write_cache.is_empty());
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

    /// The window exists to separate a clock from a timezone, so pin it
    /// against the shapes production actually produced rather than against
    /// the number alone: a device 2.5 minutes out retried for eight hours
    /// without ever connecting, while the drift beyond it was whole hours --
    /// local time served as UTC, which widening must never start admitting.
    #[test]
    fn timestamp_window_admits_clock_drift_and_still_refuses_a_wrong_timezone() {
        for drift in [39, 40, 44, 58, 92, 154, 155] {
            for stamp in [TEST_NOW_SECS + drift, TEST_NOW_SECS - drift] {
                check_timestamp_freshness(stamp, TEST_NOW_SECS)
                    .unwrap_or_else(|e| panic!("{drift}s of clock drift must connect: {e}"));
            }
        }
        for drift in [8 * 3600, 15 * 3600] {
            assert!(
                check_timestamp_freshness(TEST_NOW_SECS - drift, TEST_NOW_SECS).is_err(),
                "a {drift}s offset is a timezone, not a clock"
            );
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

    /// In-memory transport for round trips: records everything written, and
    /// serves reads from a shared inbound buffer in a repeating pattern of
    /// sizes, so chunk and header boundaries land at every offset. With
    /// `park_between_reads` it reports `Pending` once after every read, which
    /// is what makes the stream park, release its buffers and reacquire them
    /// in the middle of chunks.
    struct ScriptedTransport {
        inbound: StdArc<StdMutex<Vec<u8>>>,
        inbound_pos: usize,
        outbound: StdArc<StdMutex<Vec<u8>>>,
        read_sizes: Vec<usize>,
        read_step: usize,
        park_between_reads: bool,
        just_read: bool,
    }

    impl ScriptedTransport {
        fn new(read_sizes: &[usize], park_between_reads: bool) -> Self {
            Self {
                inbound: StdArc::new(StdMutex::new(Vec::new())),
                inbound_pos: 0,
                outbound: StdArc::new(StdMutex::new(Vec::new())),
                read_sizes: read_sizes.to_vec(),
                read_step: 0,
                park_between_reads,
                just_read: false,
            }
        }
    }

    impl AsyncRead for ScriptedTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.park_between_reads && self.just_read {
                self.just_read = false;
                return Poll::Pending;
            }
            let inbound = self.inbound.clone();
            let inbound = inbound.lock().unwrap();
            let remaining = inbound.len() - self.inbound_pos;
            if remaining == 0 {
                // Reads after the scripted bytes are EOF.
                return Poll::Ready(Ok(()));
            }
            let size = self.read_sizes[self.read_step % self.read_sizes.len()];
            self.read_step += 1;
            let len = size.min(remaining).min(buf.remaining());
            buf.put_slice(&inbound[self.inbound_pos..self.inbound_pos + len]);
            self.inbound_pos += len;
            self.just_read = true;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.outbound.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ScriptedTransport {
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

    impl AsyncStream for ScriptedTransport {}

    struct ScriptedStream {
        stream: ShadowsocksStream,
        inbound: StdArc<StdMutex<Vec<u8>>>,
        outbound: StdArc<StdMutex<Vec<u8>>>,
    }

    fn scripted_stream(
        stream_type: ShadowsocksStreamType,
        aead2022: bool,
        read_sizes: &[usize],
        park_between_reads: bool,
    ) -> ScriptedStream {
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        let key: Arc<dyn ShadowsocksKey> = if aead2022 {
            Arc::new(super::super::blake3_key::Blake3Key::new(
                vec![7u8; cipher.key_len()].into_boxed_slice(),
                cipher.key_len(),
            ))
        } else {
            Arc::new(DefaultKey::new("test-password", cipher.key_len()))
        };
        let transport = ScriptedTransport::new(read_sizes, park_between_reads);
        let inbound = transport.inbound.clone();
        let outbound = transport.outbound.clone();
        ScriptedStream {
            stream: ShadowsocksStream::new(
                Box::new(transport),
                stream_type,
                cipher.algorithm(),
                cipher.salt_len(),
                key,
                None,
            ),
            inbound,
            outbound,
        }
    }

    fn noop_context() -> Context<'static> {
        Context::from_waker(futures::task::noop_waker_ref())
    }

    fn write_all_now(stream: &mut ShadowsocksStream, mut data: &[u8]) {
        let mut cx = noop_context();
        while !data.is_empty() {
            match Pin::new(&mut *stream).poll_write(&mut cx, data) {
                Poll::Ready(Ok(written)) => data = &data[written..],
                other => panic!("write did not complete: {other:?}"),
            }
        }
        flush_now(stream);
    }

    fn flush_now(stream: &mut ShadowsocksStream) {
        let mut cx = noop_context();
        assert!(matches!(
            Pin::new(stream).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }

    /// Every park must leave nothing allocated that holds nothing: the only
    /// thing a parked stream may keep is a partial chunk it cannot yet open.
    fn assert_parked_state(stream: &ShadowsocksStream) {
        assert!(!stream.has_plaintext(), "parked with plaintext undelivered");
        if stream.unprocessed_start_offset == stream.unprocessed_buf.len() {
            assert_eq!(
                stream.unprocessed_buf.capacity(),
                0,
                "idle read buffer kept"
            );
        }
        if stream.write_cache.is_empty() {
            assert_eq!(stream.write_cache.capacity(), 0, "idle write cache kept");
        }
    }

    /// Read until EOF, cycling through `caller_sizes` for the caller buffer.
    fn read_to_end_now(
        stream: &mut ShadowsocksStream,
        caller_sizes: &[usize],
        message: bool,
    ) -> Vec<Vec<u8>> {
        let mut cx = noop_context();
        let mut reads = Vec::new();
        let mut step = 0;
        let mut parks = 0;
        loop {
            let size = caller_sizes[step % caller_sizes.len()];
            step += 1;
            let mut storage = vec![0u8; size];
            let mut buf = ReadBuf::new(&mut storage);
            let poll = if message {
                Pin::new(&mut *stream).poll_read_message(&mut cx, &mut buf)
            } else {
                Pin::new(&mut *stream).poll_read(&mut cx, &mut buf)
            };
            match poll {
                Poll::Ready(Ok(())) if buf.filled().is_empty() => return reads,
                Poll::Ready(Ok(())) => reads.push(buf.filled().to_vec()),
                Poll::Ready(Err(error)) => panic!("read failed: {error}"),
                Poll::Pending => {
                    assert_parked_state(stream);
                    parks += 1;
                    assert!(parks < 1_000_000, "read never completed");
                }
            }
        }
    }

    fn pattern(len: usize, seed: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((i * 31 + seed * 7) % 251) as u8)
            .collect()
    }

    /// Chunk sizes that straddle every boundary that matters: empty-ish,
    /// around the legacy 0x3FFF cap, exactly the AEAD-2022 0xFFFF maximum,
    /// and one past it so a single write becomes two chunks.
    fn round_trip_writes(max_payload_len: usize) -> Vec<Vec<u8>> {
        [
            1,
            2,
            17,
            0x3fff,
            0x4000,
            0x4001,
            max_payload_len,
            max_payload_len + 1,
            3,
        ]
        .into_iter()
        .enumerate()
        .map(|(seed, len)| pattern(len, seed))
        .collect()
    }

    fn round_trip(aead2022: bool, read_sizes: &[usize], caller_sizes: &[usize], park: bool) {
        let (writer_type, reader_type) = if aead2022 {
            (
                ShadowsocksStreamType::AEAD2022Client,
                ShadowsocksStreamType::AEAD2022Server,
            )
        } else {
            (ShadowsocksStreamType::Aead, ShadowsocksStreamType::Aead)
        };
        let mut writer = scripted_stream(writer_type, aead2022, &[usize::MAX], false);
        let mut reader = scripted_stream(reader_type, aead2022, read_sizes, park);

        // AEAD-2022 sends the variable-length request header as its own
        // first chunk; any first write works for the legacy stream.
        let mut expected = pattern(37, 99);
        write_all_now(&mut writer.stream, &expected);
        for (index, data) in round_trip_writes(writer_type.max_payload_len())
            .into_iter()
            .enumerate()
        {
            write_all_now(&mut writer.stream, &data);
            expected.extend_from_slice(&data);
            if index == 3 {
                // An empty chunk is legal on the wire and must be skipped.
                writer.stream.encrypt_single(&[], true).unwrap();
                flush_now(&mut writer.stream);
            }
        }
        *reader.inbound.lock().unwrap() = writer.outbound.lock().unwrap().clone();

        let received = read_to_end_now(&mut reader.stream, caller_sizes, false).concat();
        assert_eq!(received.len(), expected.len());
        assert!(
            received == expected,
            "plaintext differs (read sizes {read_sizes:?}, caller sizes {caller_sizes:?}, park {park})"
        );
    }

    const SPLIT_READS: &[usize] = &[1, 7, 3, 4096, 13, 65536, 2, 18, 19, 50_000, 34];
    const ODD_CALLER_READS: &[usize] = &[1, 3, 5, 7, 4096, 17, 65536, 16_383];

    #[test]
    fn aead2022_round_trip_survives_any_read_split() {
        for (read_sizes, caller_sizes, park) in [
            (&[usize::MAX][..], &[65536][..], false),
            (SPLIT_READS, ODD_CALLER_READS, false),
            (SPLIT_READS, ODD_CALLER_READS, true),
            (&[1][..], &[4096][..], true),
            (&[65536][..], &[1][..], false),
            (&[16_401][..], &[16_384][..], true),
        ] {
            round_trip(true, read_sizes, caller_sizes, park);
        }
    }

    #[test]
    fn legacy_aead_round_trip_survives_any_read_split() {
        for (read_sizes, caller_sizes, park) in [
            (&[usize::MAX][..], &[65536][..], false),
            (SPLIT_READS, ODD_CALLER_READS, true),
            (&[1][..], &[3][..], false),
        ] {
            round_trip(false, read_sizes, caller_sizes, park);
        }
    }

    #[test]
    fn aead2022_client_reads_server_chunks_across_splits() {
        let mut client = scripted_stream(ShadowsocksStreamType::AEAD2022Client, true, &[1], false);
        let mut server = scripted_stream(
            ShadowsocksStreamType::AEAD2022Server,
            true,
            &[usize::MAX],
            false,
        );

        let request = pattern(40, 1);
        write_all_now(&mut client.stream, &request);
        *server.inbound.lock().unwrap() = client.outbound.lock().unwrap().clone();
        let mut cx = noop_context();
        let mut storage = vec![0u8; 1024];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(matches!(
            Pin::new(&mut server.stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), &request[..]);

        let mut expected = Vec::new();
        for data in round_trip_writes(ShadowsocksStreamType::AEAD2022Server.max_payload_len()) {
            write_all_now(&mut server.stream, &data);
            expected.extend_from_slice(&data);
        }
        *client.inbound.lock().unwrap() = server.outbound.lock().unwrap().clone();

        // Rebuild the client's transport pattern: splits everywhere, parks
        // between reads, odd caller sizes.
        let received = {
            let transport = ScriptedTransport {
                inbound: client.inbound.clone(),
                inbound_pos: 0,
                outbound: client.outbound.clone(),
                read_sizes: SPLIT_READS.to_vec(),
                read_step: 0,
                park_between_reads: true,
                just_read: false,
            };
            client.stream.stream = Box::new(transport);
            read_to_end_now(&mut client.stream, ODD_CALLER_READS, false).concat()
        };
        assert!(received == expected, "server-to-client plaintext differs");
    }

    #[test]
    fn message_reads_return_one_chunk_each() {
        let mut writer = scripted_stream(ShadowsocksStreamType::AEAD2022Client, true, &[1], false);
        let mut reader = scripted_stream(
            ShadowsocksStreamType::AEAD2022Server,
            true,
            SPLIT_READS,
            true,
        );
        let messages: Vec<Vec<u8>> = [40, 5, 1, 300, 0xffff, 2, 16_384]
            .into_iter()
            .enumerate()
            .map(|(seed, len)| pattern(len, seed))
            .collect();
        let mut cx = noop_context();
        for message in &messages {
            assert!(matches!(
                Pin::new(&mut writer.stream).poll_write_message(&mut cx, message),
                Poll::Ready(Ok(()))
            ));
            flush_now(&mut writer.stream);
        }
        *reader.inbound.lock().unwrap() = writer.outbound.lock().unwrap().clone();

        let reads = read_to_end_now(&mut reader.stream, &[0x10000], true);
        assert_eq!(reads.len(), messages.len());
        for (read, message) in reads.iter().zip(&messages) {
            assert!(read == message, "message boundary not preserved");
        }
    }

    #[test]
    fn partial_message_read_resumes_the_same_chunk_only() {
        let mut writer = scripted_stream(ShadowsocksStreamType::AEAD2022Client, true, &[1], false);
        let mut reader = scripted_stream(
            ShadowsocksStreamType::AEAD2022Server,
            true,
            &[usize::MAX],
            false,
        );
        let first = pattern(40, 1);
        let second = pattern(10, 2);
        let mut cx = noop_context();
        for message in [&first, &second] {
            assert!(matches!(
                Pin::new(&mut writer.stream).poll_write_message(&mut cx, message),
                Poll::Ready(Ok(()))
            ));
        }
        flush_now(&mut writer.stream);
        *reader.inbound.lock().unwrap() = writer.outbound.lock().unwrap().clone();

        // A caller buffer shorter than the message gets it in pieces, and the
        // next message never rides along with the tail of the previous one.
        let reads = read_to_end_now(&mut reader.stream, &[16, 64], true);
        assert_eq!(reads.len(), 3);
        assert_eq!(reads[0], first[..16]);
        assert_eq!(reads[1], first[16..]);
        assert_eq!(reads[2], second);
    }

    #[test]
    fn bulk_stream_reacquires_its_working_size_after_parking() {
        let mut writer = scripted_stream(ShadowsocksStreamType::AEAD2022Client, true, &[1], false);
        let mut reader = scripted_stream(
            ShadowsocksStreamType::AEAD2022Server,
            true,
            &[usize::MAX],
            true,
        );
        write_all_now(&mut writer.stream, &pattern(40, 1));
        let chunk = pattern(16_384, 2);
        for _ in 0..8 {
            write_all_now(&mut writer.stream, &chunk);
        }
        *reader.inbound.lock().unwrap() = writer.outbound.lock().unwrap().clone();

        // One transport read per wake, each holding the whole remaining
        // stream: count how often the buffer had to grow while it was held.
        let mut cx = noop_context();
        let mut growths = 0;
        let mut last_capacity = reader.stream.unprocessed_buf.capacity();
        let mut received = 0;
        loop {
            let mut storage = vec![0u8; 16_384];
            let mut buf = ReadBuf::new(&mut storage);
            match Pin::new(&mut reader.stream).poll_read(&mut cx, &mut buf) {
                Poll::Ready(Ok(())) if buf.filled().is_empty() => break,
                Poll::Ready(Ok(())) => received += buf.filled().len(),
                Poll::Ready(Err(error)) => panic!("read failed: {error}"),
                Poll::Pending => assert_parked_state(&reader.stream),
            }
            let capacity = reader.stream.unprocessed_buf.capacity();
            if last_capacity != 0 && capacity > last_capacity {
                growths += 1;
            }
            last_capacity = capacity;
        }
        assert_eq!(received, 40 + 8 * 16_384);
        // Doubling up from 4 KiB took three reallocations per wake; sizing
        // from the decrypted length takes one, once.
        assert!(growths <= 1, "buffer grew {growths} times");
        assert!(reader.stream.unprocessed_reacquire_size > 16_384 + TAG_LEN);
    }

    #[test]
    fn quiet_stream_falls_back_to_a_small_buffer() {
        let mut writer = scripted_stream(ShadowsocksStreamType::AEAD2022Client, true, &[1], false);
        let mut reader = scripted_stream(
            ShadowsocksStreamType::AEAD2022Server,
            true,
            &[usize::MAX],
            true,
        );
        write_all_now(&mut writer.stream, &pattern(40, 1));
        write_all_now(&mut writer.stream, &pattern(0xffff, 2));
        *reader.inbound.lock().unwrap() = writer.outbound.lock().unwrap().clone();
        read_to_end_now(&mut reader.stream, &[0x10000], false);
        assert!(reader.stream.unprocessed_reacquire_size >= 0xffff + TAG_LEN);

        // Then only small chunks: the next reacquisition shrinks back.
        let offset = writer.outbound.lock().unwrap().len();
        for seed in 0..4 {
            write_all_now(&mut writer.stream, &pattern(10, seed));
        }
        let more = writer.outbound.lock().unwrap()[offset..].to_vec();
        reader.inbound.lock().unwrap().extend_from_slice(&more);
        reader.stream.is_eof = false;
        let _ = read_to_end_now(&mut reader.stream, &[64], false);
        assert_eq!(reader.stream.unprocessed_reacquire_size, INITIAL_BUF_SIZE);
    }
}
