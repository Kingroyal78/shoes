//! H2MUX Server Stream
//!
//! Wraps H2MuxStream with sing-mux server protocol handling:
//! - Status response is prepended to first write (like sing-mux serverConn)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::util::write_all;

use super::h2mux_protocol::{STATUS_SUCCESS, StreamResponse};
use super::h2mux_stream::H2MuxStream;

/// Server stream wrapper that prepends status response to first write.
///
/// This matches sing-mux's serverConn behavior where the status byte
/// is sent with the first data write rather than immediately.
pub struct H2MuxServerStream {
    inner: H2MuxStream,
    /// Whether we've written the status response
    response_written: bool,
}

impl H2MuxServerStream {
    /// Create a new server stream wrapper.
    pub fn new(inner: H2MuxStream) -> Self {
        Self {
            inner,
            response_written: false,
        }
    }

    /// Get reference to inner stream.
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut H2MuxStream {
        &mut self.inner
    }

    /// Send an error response to the client before closing.
    ///
    /// This should be called when rejecting a stream (e.g., UDP disabled).
    /// After calling this, the stream should be shut down.
    /// Returns error if response was already written.
    pub async fn write_error_response(&mut self, message: &str) -> io::Result<()> {
        if self.response_written {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Response already written",
            ));
        }

        let response = StreamResponse::error(message);
        let encoded = response.encode();
        write_all(&mut self.inner, &encoded).await?;
        self.response_written = true;
        Ok(())
    }
}

impl AsyncRead for H2MuxServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2MuxServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Write the one-byte response first, then let the inner stream register
        // the caller's waker if the user payload cannot be accepted yet. A
        // combined temporary buffer cannot safely report the case where only
        // the status byte was written.
        if !self.response_written {
            match Pin::new(&mut self.inner).poll_write(cx, &[STATUS_SUCCESS]) {
                Poll::Ready(Ok(1)) => {
                    self.response_written = true;
                }
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write h2mux success response",
                    )));
                }
                Poll::Ready(Ok(_)) => unreachable!("one-byte response wrote more than one byte"),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for H2MuxServerStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for H2MuxServerStream {}

impl AsyncStream for H2MuxServerStream {}
