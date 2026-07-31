use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::record::{CONTENT_TYPE_APPLICATION_DATA, MAX_TLS_RECORD_PAYLOAD, invalid_data};

const MAX_PLAINTEXT_FRAGMENT: usize = 1 << 14;

enum ReadState {
    Header { bytes: [u8; 5], filled: usize },
    Payload { remaining: usize },
}

/// The post-authentication ShadowTLS v2 record stream.
pub struct ShadowTlsV2Stream<S> {
    inner: S,
    initial_read: VecDeque<u8>,
    read_state: ReadState,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
}

impl<S> ShadowTlsV2Stream<S> {
    pub(crate) fn new(inner: S, initial_read: Vec<u8>) -> Self {
        Self {
            inner,
            initial_read: initial_read.into(),
            read_state: ReadState::Header {
                bytes: [0; 5],
                filled: 0,
            },
            pending_write: Vec::new(),
            pending_write_offset: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsV2Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while output.remaining() > 0 {
            let filled_before_initial = output.filled().len();
            while output.remaining() > 0 {
                match self.initial_read.pop_front() {
                    Some(byte) => output.put_slice(&[byte]),
                    None => break,
                }
            }
            // AsyncRead must never return Pending after advancing the caller's
            // ReadBuf. In particular, the first authenticated Shadowsocks
            // bytes may be carried in the authentication record itself while
            // the underlying socket has no subsequent record ready yet.
            if output.filled().len() != filled_before_initial {
                return Poll::Ready(Ok(()));
            }

            let ShadowTlsV2Stream {
                inner, read_state, ..
            } = &mut *self;
            match read_state {
                ReadState::Header { bytes, filled } => {
                    let mut temporary = ReadBuf::new(&mut bytes[*filled..]);
                    match Pin::new(inner).poll_read(cx, &mut temporary) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = temporary.filled().len();
                            if read == 0 {
                                if *filled == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated ShadowTLS v2 record header",
                                )));
                            }
                            *filled += read;
                            if *filled < bytes.len() {
                                continue;
                            }

                            if bytes[0] != CONTENT_TYPE_APPLICATION_DATA
                                || u16::from_be_bytes([bytes[1], bytes[2]]) != 0x0303
                            {
                                return Poll::Ready(Err(invalid_data(
                                    "invalid ShadowTLS v2 application record header",
                                )));
                            }
                            let payload_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
                            if payload_len > MAX_TLS_RECORD_PAYLOAD {
                                return Poll::Ready(Err(invalid_data(
                                    "ShadowTLS v2 application record is oversized",
                                )));
                            }
                            self.read_state = ReadState::Payload {
                                remaining: payload_len,
                            };
                        }
                    }
                }
                ReadState::Payload { remaining } => {
                    if *remaining == 0 {
                        self.read_state = ReadState::Header {
                            bytes: [0; 5],
                            filled: 0,
                        };
                        continue;
                    }

                    let limit = (*remaining).min(output.remaining());
                    let target = output.initialize_unfilled_to(limit);
                    let mut temporary = ReadBuf::new(target);
                    match Pin::new(inner).poll_read(cx, &mut temporary) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let read = temporary.filled().len();
                            if read == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated ShadowTLS v2 application record",
                                )));
                            }
                            output.advance(read);
                            *remaining -= read;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsV2Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().poll_drain_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted = input.len().min(MAX_PLAINTEXT_FRAGMENT);
        self.pending_write.reserve(5 + accepted);
        self.pending_write.push(CONTENT_TYPE_APPLICATION_DATA);
        self.pending_write
            .extend_from_slice(&0x0303u16.to_be_bytes());
        self.pending_write
            .extend_from_slice(&(accepted as u16).to_be_bytes());
        self.pending_write.extend_from_slice(&input[..accepted]);
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_drain_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> ShadowTlsV2Stream<S> {
    fn poll_drain_pending(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_offset < self.pending_write.len() {
            let ShadowTlsV2Stream {
                inner,
                pending_write,
                pending_write_offset,
                ..
            } = &mut *self;
            match Pin::new(inner).poll_write(cx, &pending_write[*pending_write_offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write ShadowTLS v2 record",
                    )));
                }
                Poll::Ready(Ok(written)) => *pending_write_offset += written,
            }
        }
        self.pending_write.clear();
        self.pending_write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncPing for ShadowTlsV2Stream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for ShadowTlsV2Stream<S> {}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn fragmented_records_are_decoded() {
        let (mut peer, stream) = duplex(128);
        let mut stream = ShadowTlsV2Stream::new(stream, b"pre".to_vec());
        let writer = tokio::spawn(async move {
            for fragment in [
                &[23, 3][..],
                &[3, 0, 2, b'a'][..],
                &[b'b', 23, 3, 3, 0, 1, b'c'][..],
            ] {
                peer.write_all(fragment).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let mut output = [0u8; 6];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"preabc");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn initial_authenticated_bytes_are_ready_while_underlying_stream_is_pending() {
        let (_peer, stream) = duplex(128);
        let mut stream = ShadowTlsV2Stream::new(stream, b"initial".to_vec());
        let mut output = [0u8; 64];

        let read = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            stream.read(&mut output),
        )
        .await
        .expect("initial authenticated bytes must not wait for another TLS record")
        .unwrap();

        assert_eq!(&output[..read], b"initial");
    }

    #[tokio::test]
    async fn writes_are_tls_application_records() {
        let (stream, mut peer) = duplex(128);
        let mut stream = ShadowTlsV2Stream::new(stream, vec![]);
        stream.write_all(b"abc").await.unwrap();
        stream.flush().await.unwrap();

        let mut wire = [0u8; 8];
        peer.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire, &[23, 3, 3, 0, 3, b'a', b'b', b'c']);
    }

    #[tokio::test]
    async fn tampered_record_type_is_rejected() {
        let (mut peer, stream) = duplex(128);
        let mut stream = ShadowTlsV2Stream::new(stream, vec![]);
        peer.write_all(&[22, 3, 3, 0, 1, 0]).await.unwrap();

        let mut byte = [0u8; 1];
        let error = stream.read_exact(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
