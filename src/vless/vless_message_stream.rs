use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

/// A VLESS message carries at most a `u16` payload plus its 2-byte length
/// header, so the read buffer never needs more than this many bytes.
const MAX_MESSAGE_BUF_SIZE: usize = u16::MAX as usize + 2;

pub struct VlessMessageStream<S> {
    stream: S,
    /// Grows on demand up to `MAX_MESSAGE_BUF_SIZE` so idle or small-frame
    /// connections do not hold a 64 KB read buffer each.
    read_buf: Vec<u8>,
    read_end_index: usize,
    pending_write: Vec<u8>,
    write_offset: usize,
    is_eof: bool,
}

impl<S: AsyncStream> VlessMessageStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
            read_end_index: 0,
            pending_write: Vec::new(),
            write_offset: 0,
            is_eof: false,
        }
    }

    /// Grow the read buffer (doubling, capped at the maximum message size)
    /// when it has no room for another read. Keeps the framing invariant that
    /// `read_end_index <= read_buf.len()` and that a full message always fits.
    fn ensure_read_capacity(&mut self) {
        if self.read_end_index < self.read_buf.len() {
            return;
        }
        if self.read_buf.len() < MAX_MESSAGE_BUF_SIZE {
            let target = self
                .read_buf
                .len()
                .saturating_mul(2)
                .clamp(4096, MAX_MESSAGE_BUF_SIZE);
            self.read_buf.resize(target, 0);
        }
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > MAX_MESSAGE_BUF_SIZE {
            return Err(std::io::Error::other(
                "feed_initial_read_data called with too much data",
            ));
        }
        self.read_buf
            .resize(data.len().clamp(4096, MAX_MESSAGE_BUF_SIZE), 0);
        self.read_buf[0..data.len()].copy_from_slice(data);
        self.read_end_index = data.len();
        Ok(())
    }
}

impl<S: AsyncStream> AsyncReadMessage for VlessMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.read_end_index >= 2 {
                let payload_len = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]) as usize;
                let total_len = 2 + payload_len;
                if this.read_end_index >= total_len {
                    if payload_len == 0 {
                        if this.read_end_index > total_len {
                            this.read_buf.copy_within(total_len..this.read_end_index, 0);
                            this.read_end_index -= total_len;
                        } else {
                            this.read_end_index = 0;
                        }
                        continue;
                    }
                    if out_buf.remaining() < payload_len {
                        return Poll::Ready(Err(Error::other(
                            "out_buf is too small to hold the message",
                        )));
                    }
                    out_buf.put_slice(&this.read_buf[2..total_len]);
                    if this.read_end_index > total_len {
                        this.read_buf.copy_within(total_len..this.read_end_index, 0);
                        this.read_end_index -= total_len;
                    } else {
                        // this.read_end_index == total_len
                        this.read_end_index = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            // Make sure the read buffer has room before reading more data.
            // The buffer grows on demand up to MAX_MESSAGE_BUF_SIZE, which can
            // always hold a full message (u16 payload + 2-byte header).
            this.ensure_read_capacity();
            let read_buf_slice = &mut this.read_buf[this.read_end_index..];
            assert!(!read_buf_slice.is_empty());
            let mut tmp = ReadBuf::new(read_buf_slice);
            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let n = tmp.filled().len();
                    if n == 0 {
                        this.is_eof = true;
                        if this.read_end_index == 0 {
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "EOF reached in the middle of a message",
                            )));
                        }
                    }
                    this.read_end_index += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for VlessMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<()>> {
        let mut this = self.get_mut();

        if !this.pending_write.is_empty() {
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            // previously this checked this.write_offset < this.pending_write.len(), but
            // we want to make sure the message was flushed in the underlying stream.
            if !this.pending_write.is_empty() {
                return Poll::Pending;
            }
        }

        if buf.len() > 65535 {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "message size too large",
            )));
        }

        this.pending_write
            .extend_from_slice(&(buf.len() as u16).to_be_bytes());
        this.pending_write.extend_from_slice(buf);
        this.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for VlessMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        while this.write_offset < this.pending_write.len() {
            let chunk = &this.pending_write[this.write_offset..];
            match Pin::new(&mut this.stream).poll_write(cx, chunk) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::WriteZero,
                            "failed to write message",
                        )));
                    }
                    this.write_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Once complete, flush the underlying stream.
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_offset = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for VlessMessageStream<S> {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        match <Self as AsyncFlushMessage>::poll_flush_message(Pin::new(this), cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for VlessMessageStream<S> {
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

impl<S: AsyncStream> AsyncMessageStream for VlessMessageStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};

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
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[tokio::test]
    async fn read_message_skips_zero_length_frames() {
        let (mut writer, reader) = duplex(64);
        writer
            .write_all(&[0, 0, 0, 3, b'a', b'b', b'c'])
            .await
            .unwrap();
        let mut stream = VlessMessageStream::new(TestStream(reader));

        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .unwrap();

        assert_eq!(read_buf.filled(), b"abc");
    }

    #[tokio::test]
    async fn read_message_skips_zero_length_initial_data() {
        let (_writer, reader) = duplex(64);
        let mut stream = VlessMessageStream::new(TestStream(reader));
        stream
            .feed_initial_read_data(&[0, 0, 0, 3, b'x', b'y', b'z'])
            .unwrap();

        let mut buf = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut buf);
        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .unwrap();

        assert_eq!(read_buf.filled(), b"xyz");
    }

    #[tokio::test]
    async fn read_buffer_grows_lazily_and_handles_max_message() {
        let (writer, reader) = duplex(65536);
        let mut stream = VlessMessageStream::new(TestStream(reader));

        // No read happened yet: no 64 KB buffer is reserved upfront.
        assert!(stream.read_buf.len() < MAX_MESSAGE_BUF_SIZE);

        // A maximum-size message must still be readable end to end.
        let payload = vec![0x42u8; 65535];
        let mut frame = Vec::with_capacity(65537);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
        let writer2 = writer.clone();
        let write_task = tokio::spawn(async move {
            writer2.lock().await.write_all(&frame).await.unwrap();
        });

        let mut out = vec![0u8; 65535];
        let mut read_buf = ReadBuf::new(&mut out);
        poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .unwrap();
        write_task.await.unwrap();
        assert_eq!(read_buf.filled(), &payload[..]);
    }
}
