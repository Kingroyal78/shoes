use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::shadow_tls_hmac::ShadowTlsHmac;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::LazyBuffer;

// see comment in shadow_tls_server_handler.rs
// TODO: remove duplicated consts
const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65535;

// the max size allowed for a payload ie. `buf` in poll_write.
// 2^14 - 4 (HMAC) = 16380
const MAX_WRITE_PAYLOAD_LEN: usize = 16380;
// 2^14 + 5 (header) = 16385
const WRITE_BUF_LEN: usize = 16389;

const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub struct ShadowTlsStream {
    stream: Box<dyn AsyncStream>,
    read_hmac: ShadowTlsHmac,
    write_hmac: ShadowTlsHmac,

    // the HMAC_ServerRandom used client-side to verify handshake app data frames.
    handshake_hmac: Option<ShadowTlsHmac>,

    is_eof: bool,

    /// Record staging buffers, taken on demand and given back as soon as they
    /// drain.
    ///
    /// Sized for the largest record a peer may send, these were 64 KiB apiece
    /// held for the whole life of every ShadowTLS connection -- 144 KiB with
    /// the write buffer -- while a parked connection needs none of it.
    unprocessed_buf: LazyBuffer,
    unprocessed_end_offset: usize,

    processed_buf: LazyBuffer,
    processed_start_offset: usize,
    processed_end_offset: usize,

    write_buf: LazyBuffer,
    write_buf_pos: usize,
    write_buf_end: usize,
}

impl ShadowTlsStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        initial_processed_data: &[u8],
        read_hmac: ShadowTlsHmac,
        write_hmac: ShadowTlsHmac,
        handshake_hmac: Option<ShadowTlsHmac>,
    ) -> std::io::Result<Self> {
        let mut processed_buf = LazyBuffer::new(TLS_FRAME_MAX_LEN);
        if initial_processed_data.len() > TLS_FRAME_MAX_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "initial processed data too large for read buffer",
            ));
        }
        if !initial_processed_data.is_empty() {
            processed_buf.ensure();
            processed_buf[..initial_processed_data.len()].copy_from_slice(initial_processed_data);
        }

        let write_buf = LazyBuffer::new(WRITE_BUF_LEN);

        Ok(Self {
            stream,
            read_hmac,
            write_hmac,
            handshake_hmac,
            is_eof: false,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: initial_processed_data.len(),
            unprocessed_buf: LazyBuffer::new(TLS_FRAME_MAX_LEN),
            unprocessed_end_offset: 0,
            write_buf,
            write_buf_pos: 0,
            write_buf_end: 0,
        })
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.unprocessed_end_offset != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "feed_initial_read_data called with pending unprocessed data",
            ));
        }

        if data.len() > TLS_FRAME_MAX_LEN {
            return Err(std::io::Error::other(
                "feed_initial_read_data called with too much data",
            ));
        }

        if data.is_empty() {
            return Ok(());
        }

        self.unprocessed_buf.ensure();
        self.unprocessed_buf[0..data.len()].copy_from_slice(data);
        self.unprocessed_end_offset = data.len();

        Ok(())
    }

    /// Give back whichever read-side staging buffer currently holds nothing.
    #[inline]
    fn release_drained_read_buffers(&mut self) {
        if self.unprocessed_end_offset == 0 {
            self.unprocessed_buf.release();
        }
        if self.processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
            self.processed_buf.release();
        }
    }

    /// Bytes currently held by the three staging buffers.
    #[cfg(test)]
    pub(crate) fn held_buffer_bytes(&self) -> usize {
        self.unprocessed_buf.held_bytes()
            + self.processed_buf.held_bytes()
            + self.write_buf.held_bytes()
    }

    #[inline]
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
            self.processed_buf.release();
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    #[inline]
    fn try_deframe(&mut self) -> std::io::Result<DeframeState> {
        // we should only deframe when there is no readily available processed data.
        assert!(self.processed_end_offset == 0);

        if self.unprocessed_end_offset < TLS_HEADER_LEN {
            return Ok(DeframeState::NeedData);
        }

        let header = &self.unprocessed_buf[0..TLS_HEADER_LEN];
        let content_type = header[0];
        if content_type == CONTENT_TYPE_ALERT {
            self.is_eof = true;
            return Ok(DeframeState::ReceivedAlert);
        }

        let frame_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let total_len = TLS_HEADER_LEN + frame_len;
        if self.unprocessed_end_offset < total_len {
            return Ok(DeframeState::NeedData);
        }

        if content_type != CONTENT_TYPE_APPLICATION_DATA {
            if self.handshake_hmac.is_some() {
                // Allow any other frame type while we haven't completed
                // the handshake, ie. we haven't received non-forwarded app
                // data.
                if total_len < self.unprocessed_end_offset {
                    self.unprocessed_buf
                        .copy_within(total_len..self.unprocessed_end_offset, 0);
                    self.unprocessed_end_offset -= total_len;
                    return Ok(DeframeState::SkippedFrame);
                } else {
                    self.unprocessed_end_offset = 0;
                    return Ok(DeframeState::NeedData);
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid record type",
            ));
        }

        if frame_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame length too short",
            ));
        }

        // frame length minus HMAC
        let payload_len = frame_len - 4;

        if payload_len > TLS_FRAME_MAX_LEN {
            return Err(std::io::Error::other(
                "Payload too large for processed buffer",
            ));
        }

        let frame_body = &self.unprocessed_buf[TLS_HEADER_LEN..total_len];
        let received_digest = &frame_body[0..4];
        let payload = &frame_body[4..];

        if let Some(ref mut handshake_hmac) = self.handshake_hmac {
            handshake_hmac.update(payload);
            let expected_digest = handshake_hmac.digest();
            if received_digest == expected_digest {
                if total_len < self.unprocessed_end_offset {
                    self.unprocessed_buf
                        .copy_within(total_len..self.unprocessed_end_offset, 0);
                    self.unprocessed_end_offset -= total_len;
                    return Ok(DeframeState::SkippedFrame);
                } else {
                    self.unprocessed_end_offset = 0;
                    return Ok(DeframeState::NeedData);
                }
            }
            // this must be the first non-handshake server data frame, or else
            // this is malformed and we error out in the follow hmac check.
            self.handshake_hmac = None;
        }

        self.read_hmac.update(payload);
        let expected_digest = self.read_hmac.digest();
        if received_digest != expected_digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }
        self.read_hmac.update(&expected_digest);

        if payload_len > 0 {
            // The only place bytes enter this buffer, so the only place it has
            // to exist.
            self.processed_buf.ensure();
            self.processed_buf[0..payload_len].copy_from_slice(payload);
            self.processed_end_offset = payload_len;
        }

        if total_len < self.unprocessed_end_offset {
            self.unprocessed_buf
                .copy_within(total_len..self.unprocessed_end_offset, 0);
            self.unprocessed_end_offset -= total_len;
        } else {
            self.unprocessed_end_offset = 0;
        }

        if payload_len == 0 {
            Ok(DeframeState::SkippedFrame)
        } else {
            Ok(DeframeState::Success)
        }
    }
}

enum DeframeState {
    NeedData,
    Success,
    ReceivedAlert,
    SkippedFrame,
}

impl AsyncRead for ShadowTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        }
        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        if this.unprocessed_end_offset > 0 {
            loop {
                match this.try_deframe()? {
                    DeframeState::Success => {
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DeframeState::NeedData => break,
                    DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
                    DeframeState::SkippedFrame => {}
                }
            }

            if this.unprocessed_end_offset == TLS_FRAME_MAX_LEN {
                return Poll::Ready(Err(std::io::Error::other("Unprocessed buffer full")));
            }
        }

        loop {
            // The only place bytes enter this buffer; a released buffer
            // reports a length of zero, so every capacity check above uses
            // the size it was created with.
            this.unprocessed_buf.ensure();
            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        this.release_drained_read_buffers();
                        return Poll::Ready(Ok(()));
                    }
                    this.unprocessed_end_offset += n;

                    loop {
                        match this.try_deframe()? {
                            DeframeState::Success => {
                                this.read_processed(buf);
                                return Poll::Ready(Ok(()));
                            }
                            DeframeState::NeedData => break,
                            DeframeState::ReceivedAlert => return Poll::Ready(Ok(())),
                            DeframeState::SkippedFrame => {}
                        }
                    }
                }
                Poll::Pending => {
                    // Parked on a peer with nothing to say, which is where a
                    // proxied stream spends almost all of its life.
                    this.release_drained_read_buffers();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for ShadowTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        while this.write_buf_pos < this.write_buf_end {
            let remaining = &this.write_buf[this.write_buf_pos..this.write_buf_end];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Failed to write pending data",
                        )));
                    }
                    this.write_buf_pos += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        this.write_buf_pos = 0;
        this.write_buf_end = 0;

        let consumed_buf_len = std::cmp::min(buf.len(), MAX_WRITE_PAYLOAD_LEN);
        let consumed_buf = &buf[0..consumed_buf_len];

        let frame_len = consumed_buf_len + 4; // HMAC(4) + payload

        // The only place bytes enter this buffer. The frame header prefix is
        // written per frame rather than once in the constructor, because the
        // buffer is given back whenever it drains.
        this.write_buf.ensure();
        this.write_buf[0] = CONTENT_TYPE_APPLICATION_DATA;
        this.write_buf[1] = 0x03; // TLS_MAJOR
        this.write_buf[2] = 0x03; // TLS_MINOR
        this.write_buf[3..5].copy_from_slice(&(frame_len as u16).to_be_bytes());

        this.write_hmac.update(consumed_buf);
        let digest = this.write_hmac.digest();
        this.write_hmac.update(&digest);

        this.write_buf[5..9].copy_from_slice(&digest);

        this.write_buf[9..9 + consumed_buf_len].copy_from_slice(consumed_buf);

        this.write_buf_end = TLS_HEADER_LEN + frame_len;

        Poll::Ready(Ok(consumed_buf_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();

        while this.write_buf_pos < this.write_buf_end {
            let remaining = &this.write_buf[this.write_buf_pos..this.write_buf_end];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Failed to flush pending data",
                        )));
                    }
                    this.write_buf_pos += n;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        this.write_buf_pos = 0;
        this.write_buf_end = 0;
        this.write_buf.release();

        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let this = self.as_mut().get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for ShadowTlsStream {
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

impl AsyncStream for ShadowTlsStream {}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };

    use super::*;
    use crate::async_stream::AsyncPing;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
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
            unreachable!("test stream does not support ping")
        }
    }

    impl AsyncStream for TestStream {}

    fn new_hmac() -> ShadowTlsHmac {
        let key = aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            b"shadowtls-test-password",
        );
        ShadowTlsHmac::new(&key)
    }

    fn make_app_data_frame(hmac: &mut ShadowTlsHmac, payload: &[u8]) -> Vec<u8> {
        hmac.update(payload);
        let digest = hmac.digest();
        hmac.update(&digest);

        let frame_len = 4 + payload.len();
        let mut frame = Vec::with_capacity(TLS_HEADER_LEN + frame_len);
        frame.extend_from_slice(&[
            CONTENT_TYPE_APPLICATION_DATA,
            0x03,
            0x03,
            (frame_len >> 8) as u8,
            frame_len as u8,
        ]);
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn empty_write_is_noop() {
        let (client_io, mut peer_io) = duplex(1024);
        let read_hmac = new_hmac();
        let write_hmac = new_hmac();
        let mut stream = ShadowTlsStream::new(
            Box::new(TestStream(client_io)),
            &[],
            read_hmac,
            write_hmac,
            None,
        )
        .unwrap();

        let written = stream.write(&[]).await.unwrap();
        assert_eq!(written, 0);
        stream.flush().await.unwrap();

        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), peer_io.read_exact(&mut byte))
                .await
                .is_err(),
            "empty write must not emit a ShadowTLS record"
        );
    }

    #[tokio::test]
    async fn read_skips_zero_payload_application_record() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut write_hmac = new_hmac();
        let read_hmac = new_hmac();
        let mut stream = ShadowTlsStream::new(
            Box::new(TestStream(server_io)),
            &[],
            read_hmac,
            new_hmac(),
            None,
        )
        .unwrap();

        let mut frames = make_app_data_frame(&mut write_hmac, &[]);
        frames.extend_from_slice(&make_app_data_frame(&mut write_hmac, b"ok"));
        peer_io.write_all(&frames).await.unwrap();

        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
    }

    #[tokio::test]
    async fn handshake_mode_skips_short_change_cipher_spec_record() {
        let (mut peer_io, server_io) = duplex(1024);
        let mut write_hmac = new_hmac();
        let read_hmac = new_hmac();
        let mut handshake_hmac_state = new_hmac();
        handshake_hmac_state.update(b"already-consumed-handshake-data");
        let handshake_hmac = Some(handshake_hmac_state);
        let mut stream = ShadowTlsStream::new(
            Box::new(TestStream(server_io)),
            &[],
            read_hmac,
            new_hmac(),
            handshake_hmac,
        )
        .unwrap();

        let mut frames = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        frames.extend_from_slice(&make_app_data_frame(&mut write_hmac, b"ok"));
        peer_io.write_all(&frames).await.unwrap();

        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
    }

    #[tokio::test]
    async fn zero_sized_read_is_noop() {
        let (client_io, _peer_io) = duplex(1024);
        let mut stream = ShadowTlsStream::new(
            Box::new(TestStream(client_io)),
            b"ready",
            new_hmac(),
            new_hmac(),
            None,
        )
        .unwrap();

        let mut empty = [];
        let n = stream.read(&mut empty).await.unwrap();
        assert_eq!(n, 0);
    }
    #[tokio::test]
    async fn parked_stream_gives_back_its_record_buffers() {
        let (mut peer_io, server_io) = duplex(4096);
        let mut write_hmac = new_hmac();
        let mut stream = ShadowTlsStream::new(
            Box::new(TestStream(server_io)),
            &[],
            new_hmac(),
            new_hmac(),
            None,
        )
        .unwrap();

        let mut out = [0u8; 64];
        // Park on a peer that has not said anything, which is where a proxied
        // stream spends almost all of its life.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut out))
                .await
                .is_err(),
            "the read must park, otherwise this is not testing the idle path"
        );
        assert_eq!(
            stream.held_buffer_bytes(),
            0,
            "a parked stream must not hold record buffers"
        );

        // Re-acquiring them must be invisible to the deframer.
        peer_io
            .write_all(&make_app_data_frame(&mut write_hmac, b"hello"))
            .await
            .unwrap();
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut out))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&out[..read], b"hello");

        // Same on the write side: taken to build the record, given back once
        // it has all reached the transport.
        stream.write_all(b"reply").await.unwrap();
        stream.flush().await.unwrap();

        // ...and the read buffer goes back the next time the stream parks,
        // rather than on every record, so a stream being read continuously
        // keeps the one buffer it is filling.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut out))
                .await
                .is_err(),
            "the read must park again"
        );
        assert_eq!(
            stream.held_buffer_bytes(),
            0,
            "a parked, flushed stream must not hold record buffers"
        );

        let mut header = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(1), peer_io.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(header[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(&header[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([header[3], header[4]]) as usize, 4 + 5);
    }
}
