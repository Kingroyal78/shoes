use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::async_stream::AsyncMessageStream;
use crate::util::allocate_vec;

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
pub const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;
const DEFAULT_ASSOCIATION_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

fn association_idle_timeout() -> Duration {
    if cfg!(test) {
        Duration::from_millis(20)
    } else {
        Duration::from_secs(DEFAULT_ASSOCIATION_TIMEOUT_SECS.into())
    }
}

fn association_close_timeout() -> Duration {
    if cfg!(test) {
        Duration::from_millis(20)
    } else {
        DEFAULT_ASSOCIATION_CLOSE_TIMEOUT
    }
}

struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    cache_length: usize,
    buf: Box<[u8]>,
    read_count: usize,
}

impl CopyBuffer {
    pub fn new(need_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush,
            need_write_ping: false,
            cache_length: 0,
            buf: allocate_vec(65535).into_boxed_slice(),
            read_count: 0,
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncMessageStream + ?Sized,
        W: AsyncMessageStream + ?Sized,
    {
        // Check tokio's cooperative budget to prevent task starvation
        let coop = ready!(tokio::task::coop::poll_proceed(cx));

        loop {
            let mut did_read = false;
            let mut did_write = false;
            let mut read_pending = false;
            let mut write_pending = false;

            if !self.read_done && self.cache_length == 0 {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                match reader.as_mut().poll_read_message(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length = n;
                            did_read = true;
                            self.read_count = self.read_count.wrapping_add(n);
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                    }
                }
            }

            if self.cache_length > 0 {
                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write_message(cx, &me.buf[0..me.cache_length])
                {
                    Poll::Ready(val) => {
                        val?;
                        self.cache_length = 0;
                        self.need_flush = true;
                        // Don't bother writing ping, since we just wrote.
                        self.need_write_ping = false;
                        did_write = true;
                        coop.made_progress();
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if !write_pending && self.need_write_ping {
                match writer.as_mut().poll_write_ping(cx) {
                    Poll::Ready(val) => {
                        let written = val?;
                        self.need_write_ping = false;
                        if written {
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                    }
                }
            }

            if did_read && did_write && !read_pending && !write_pending {
                continue;
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush_message(cx))?;
                self.need_flush = false;
                coop.made_progress();
                continue;
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                return Poll::Ready(Ok(()));
            }

            // Return Pending to prevent task starvation
            if read_pending || write_pending {
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running,
    ShuttingDown,
    Done,
}

impl TransferState {
    fn is_closing(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    ping_sleep: Pin<Box<tokio::time::Sleep>>,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    idle_timeout: Duration,
    close_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    close_timeout: Duration,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running => {
                ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                ready!(w.as_mut().poll_shutdown_message(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let CopyBidirectional {
            a,
            b,
            a_buf,
            b_buf,
            a_to_b,
            b_to_a,
            ping_sleep,
            idle_sleep,
            idle_timeout,
            close_sleep,
            close_timeout,
        } = &mut *self;

        let ping_fired = ping_sleep.as_mut().poll(cx).is_ready();
        if ping_fired {
            // a_buf writes to b - so we need to check if b supports ping, and similarly
            // for b_buf.
            a_buf.need_write_ping = b.supports_ping();
            b_buf.need_write_ping = a.supports_ping();
            ping_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
        }

        let a_count = a_buf.read_count;
        let b_count = b_buf.read_count;

        let a_to_b_poll = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a_poll = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        if a_buf.read_count != a_count || b_buf.read_count != b_count {
            idle_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + *idle_timeout);
        } else if idle_sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }

        if a_to_b_poll.is_ready() {
            return a_to_b_poll;
        } else if b_to_a_poll.is_ready() {
            return b_to_a_poll;
        }

        if a_to_b.is_closing() || b_to_a.is_closing() {
            let sleep =
                close_sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(*close_timeout)));
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
        } else {
            *close_sleep = None;
        }

        Poll::Pending
    }
}

/// Copies data in both directions between `a` and `b`.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from a to b
/// and the number of bytes copied from b to a, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `a`
/// or `b` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `a` to `b` and bytes copied `b` to `a`.
pub async fn copy_bidirectional_message<A, B>(
    a: &mut A,
    b: &mut B,
    a_initial_flush: bool,
    b_initial_flush: bool,
) -> Result<(), std::io::Error>
where
    A: AsyncMessageStream + ?Sized,
    B: AsyncMessageStream + ?Sized,
{
    // Unlike tcp copy_bidirectional, we always run a sleep future so that we can expire
    // connections.
    let ping_sleep = Box::pin(tokio::time::sleep(std::time::Duration::from_secs(60)));
    let idle_timeout = association_idle_timeout();
    let idle_sleep = Box::pin(tokio::time::sleep(idle_timeout));

    CopyBidirectional {
        a,
        b,
        // this is correctly reversed - CopyBuffer will copy from a (reader) to b (writer) using
        // a_buf, which means that the need_flush signal is for the writer (b), and vice versa for
        // b_buf.
        a_buf: CopyBuffer::new(b_initial_flush),
        b_buf: CopyBuffer::new(a_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        ping_sleep,
        idle_sleep,
        idle_timeout,
        close_sleep: None,
        close_timeout: association_close_timeout(),
    }
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
    };
    use tokio::io::ReadBuf;

    struct PendingShutdownMessageStream;

    impl AsyncReadMessage for PendingShutdownMessageStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWriteMessage for PendingShutdownMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for PendingShutdownMessageStream {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for PendingShutdownMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncPing for PendingShutdownMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for PendingShutdownMessageStream {}

    struct EofMessageStream;

    impl AsyncReadMessage for EofMessageStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWriteMessage for EofMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncFlushMessage for EofMessageStream {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for EofMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for EofMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for EofMessageStream {}

    #[tokio::test]
    async fn eof_does_not_wait_for_the_full_udp_association_idle_timeout() {
        let mut stalled = PendingShutdownMessageStream;
        let mut eof = EofMessageStream;

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            copy_bidirectional_message(&mut stalled, &mut eof, false, false),
        )
        .await
        .expect("message copy retained an EOF association until the general idle timeout")
        .unwrap();
    }

    #[tokio::test]
    async fn idle_association_is_reclaimed_without_stream_wakeups() {
        let mut a = PendingShutdownMessageStream;
        let mut b = PendingShutdownMessageStream;

        tokio::time::timeout(
            Duration::from_millis(100),
            copy_bidirectional_message(&mut a, &mut b, false, false),
        )
        .await
        .expect("idle association outlived its reclamation deadline")
        .unwrap();
    }
}
