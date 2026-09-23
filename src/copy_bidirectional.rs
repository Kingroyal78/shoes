// Forked from tokio's copy.rs and copy_bidirectional.rs.
//
// Changes:
// - Customizable buffer size
// - Don't bother initializing buffer
// - Read and write whenever there's a space
// - Circular buffer
// - Cooperative yielding via tokio's coop budget to prevent task starvation
// - Buffers that grow for bulk transfers (see `BULK_BUF_SIZE`)

use futures::ready;
use tokio::io::ReadBuf;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::async_stream::AsyncStream;
use crate::util::LazyBuffer;

const DEFAULT_BUF_SIZE: usize = 16384;

/// What a direction grows to once it is shown to be carrying a bulk transfer.
///
/// Every iteration of the copy loop is a read and a write on each side, and on
/// the encrypting side one protocol record per write, so a download moved in
/// 16 KiB bites pays four times the syscalls, records and wakeups it would at
/// 64 KiB. Measured on the SS2022 + gost path, 64 KiB buffers cut download CPU
/// per GiB by 20-26% and write syscalls by 4x. Fixed buffers of that size also
/// cost every interactive connection four times the memory for nothing, so the
/// larger size is only taken by a direction that has filled its base buffer.
///
/// 64 KiB less 64 bytes, not 64 KiB, so that one full buffer is one protocol
/// unit all the way down instead of a unit and a sliver:
/// - a Shadowsocks 2022 chunk carries at most 0xFFFF bytes, so this is a single
///   chunk rather than a chunk and a 1-byte trailer;
/// - that chunk's ciphertext (payload + 34 bytes of length header and tags)
///   still fits one 0xFFFF-byte smux frame, where 64 KiB would spill 35 bytes
///   into a second frame;
/// - legacy AEAD, capped at 0x3FFF per chunk, gets whole chunks and one large
///   remainder instead of a trailing few bytes.
const BULK_BUF_SIZE: usize = 64 * 1024 - 64;

// Once one side reaches EOF, keep the opposite direction alive briefly for
// protocol half-close semantics, then reclaim the whole proxy task.
const DEFAULT_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The buffer size one direction starts at, and the most it may grow to.
#[derive(Clone, Copy, Debug)]
struct BufferSizing {
    base: usize,
    max: usize,
}

impl BufferSizing {
    /// A buffer that stays at the size the caller asked for.
    fn fixed(size: usize) -> Self {
        Self {
            base: size,
            max: size,
        }
    }

    /// Starts at [`DEFAULT_BUF_SIZE`] and grows to [`BULK_BUF_SIZE`] for bulk
    /// transfers.
    fn adaptive() -> Self {
        Self {
            base: DEFAULT_BUF_SIZE,
            max: BULK_BUF_SIZE,
        }
    }
}

#[derive(Debug)]
struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    need_write_ping: bool,
    start_index: usize,
    cache_length: usize,
    /// Current capacity. Only ever changed while the buffer is empty, which is
    /// what keeps the circular arithmetic below valid across a resize.
    size: usize,
    sizing: BufferSizing,
    /// Whether a read since this direction last parked returned at least a
    /// whole base buffer's worth -- more than the base size could have taken
    /// in one read, so the larger buffer is paying for itself.
    ///
    /// Growth is granted on the first such read, kept across parks for as long
    /// as every active period shows one, and withdrawn after the first period
    /// that does not. Dropping back on *every* park instead would make a bulk
    /// flow re-prove itself on each wakeup, and at real network rates -- a
    /// wakeup per arriving burst -- that is an extra 16 KiB read and an extra
    /// allocation each time, which is most of what growing saves. It costs no
    /// idle memory either way: a parked, drained buffer is released regardless
    /// of its size, and the size only governs the next allocation.
    bulk_read_seen: bool,
    buf: LazyBuffer,
}

impl CopyBuffer {
    #[cfg(test)]
    pub fn new(size: usize, need_initial_flush: bool) -> Self {
        Self::with_sizing(BufferSizing::fixed(size), need_initial_flush)
    }

    fn with_sizing(sizing: BufferSizing, need_initial_flush: bool) -> Self {
        Self {
            read_done: false,
            need_flush: need_initial_flush,
            need_write_ping: false,
            start_index: 0,
            cache_length: 0,
            size: sizing.base,
            sizing,
            bulk_read_seen: false,
            buf: LazyBuffer::new(sizing.base),
        }
    }

    /// Switch to `size`, discarding the current (empty) allocation. The next
    /// `ensure` allocates at the new size.
    fn resize_empty(&mut self, size: usize) {
        debug_assert_eq!(self.cache_length, 0, "only an empty buffer may be resized");
        if size != self.size {
            self.buf = LazyBuffer::new(size);
            self.size = size;
        }
        self.start_index = 0;
    }

    /// Nothing is buffered and the direction is waiting on its peer: give the
    /// allocation back, and decide what size the next active period starts at.
    fn park_empty(&mut self) {
        self.buf.release();
        let next = if self.bulk_read_seen {
            self.sizing.max
        } else {
            self.sizing.base
        };
        self.resize_empty(next);
        self.bulk_read_seen = false;
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncStream + ?Sized,
        W: AsyncStream + ?Sized,
    {
        // Check tokio's cooperative budget at the start of each poll.
        // This ensures we yield to the runtime periodically during heavy I/O,
        // allowing other tasks (like QUIC keepalives) to run.
        let coop = ready!(tokio::task::coop::poll_proceed(cx));

        loop {
            let mut read_pending = false;
            let mut write_pending = false;

            // Read as much as possible before writing. Some AsyncStream implementations
            // packetize each poll_write call individually, so this reduces the overhead.
            // Other AsyncStream implementations cache on poll_write, and
            // packetize/write to the stream on poll_flush - and this also ends up being
            // beneficial since we are calling poll_flush each external loop iteration.
            while !self.read_done && self.cache_length < self.size {
                // A read this active period filled a whole base buffer, so this
                // is a bulk transfer: take the larger size now that everything
                // read so far has been written out. Waiting for an empty buffer
                // keeps the resize clear of the circular arithmetic.
                if self.bulk_read_seen && self.cache_length == 0 && self.size < self.sizing.max {
                    self.resize_empty(self.sizing.max);
                }
                // The only place bytes enter this buffer, so the only place it
                // has to exist. All the circular arithmetic below is in terms
                // of `self.size`, which a released buffer does not change.
                self.buf.ensure();
                let unused_start_index = (self.start_index + self.cache_length) % self.size;
                let unused_end_index_exclusive = if unused_start_index < self.start_index {
                    self.start_index
                } else {
                    self.size
                };

                let me = &mut *self;
                let mut buf =
                    ReadBuf::new(&mut me.buf[unused_start_index..unused_end_index_exclusive]);
                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(val) => {
                        val?;
                        let n = buf.filled().len();
                        if n == 0 {
                            self.read_done = true;
                        } else {
                            self.cache_length += n;
                            if n >= self.sizing.base {
                                self.bulk_read_seen = true;
                            }
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        read_pending = true;
                        break;
                    }
                }
            }

            if self.need_write_ping {
                // if we just read data and we are going to write anyway, no need for a ping
                if self.cache_length == 0 {
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
                } else {
                    self.need_write_ping = false;
                }
            }

            // If our buffer has some data, let's write it out!
            // Loop and try to write out as much as possible to minimize forwarding
            // latency, and so that we increase the chance we have an optimal read
            // with start_index at zero.
            while self.cache_length > 0 {
                let used_start_index = self.start_index;
                let used_end_index_exclusive =
                    std::cmp::min(self.start_index + self.cache_length, self.size);

                let me = &mut *self;
                match writer
                    .as_mut()
                    .poll_write(cx, &me.buf[used_start_index..used_end_index_exclusive])
                {
                    Poll::Ready(val) => {
                        let written = val?;
                        if written == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write zero byte into writer",
                            )));
                        } else {
                            self.cache_length -= written;
                            if self.cache_length == 0 {
                                self.start_index = 0;
                            } else {
                                self.start_index = (self.start_index + written) % self.size;
                            }
                            self.need_flush = true;
                            coop.made_progress();
                        }
                    }
                    Poll::Pending => {
                        write_pending = true;
                        break;
                    }
                }
            }

            if self.need_flush {
                ready!(writer.as_mut().poll_flush(cx))?;
                self.need_flush = false;
                coop.made_progress();
            }

            // If we've written all the data and we've seen EOF, finish the transfer.
            if self.read_done && self.cache_length == 0 {
                self.buf.release();
                return Poll::Ready(Ok(()));
            }

            // Return Pending to prevent task starvation
            if read_pending || write_pending {
                // Parked with nothing buffered. A proxied connection spends
                // almost all of its life here -- an idle tunnel would otherwise
                // hold both directions' buffers for as long as it stays open.
                if self.cache_length == 0 {
                    self.park_empty();
                }
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
    fn has_seen_eof(&self) -> bool {
        !matches!(self, Self::Running)
    }

    fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_buf: CopyBuffer,
    b_buf: CopyBuffer,
    a_to_b: TransferState,
    b_to_a: TransferState,
    ping_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    half_close_timeout: Option<Duration>,
    half_close_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    buf: &mut CopyBuffer,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<()>>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
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
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
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
            half_close_timeout,
            half_close_sleep,
        } = &mut *self;

        if let Some(sleep) = ping_sleep {
            let ping_fired = sleep.as_mut().poll(cx).is_ready();
            if ping_fired {
                // a_buf writes to b - so we need to check if b supports ping, and similarly
                // for b_buf.
                a_buf.need_write_ping = b.supports_ping();
                b_buf.need_write_ping = a.supports_ping();
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
            }
        }

        let a_to_b_poll = transfer_one_direction(cx, a_to_b, &mut *a_buf, &mut *a, &mut *b);
        let b_to_a_poll = transfer_one_direction(cx, b_to_a, &mut *b_buf, &mut *b, &mut *a);

        let one_side_half_closed = a_to_b.has_seen_eof() || b_to_a.has_seen_eof();
        let both_sides_done = a_to_b.is_done() && b_to_a.is_done();
        if one_side_half_closed && !both_sides_done {
            if let Some(timeout) = *half_close_timeout {
                let sleep =
                    half_close_sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                if sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Ok(()));
                }
            }
        } else {
            *half_close_sleep = None;
        }

        match (a_to_b_poll, b_to_a_poll) {
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)),
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            _ => Poll::Pending,
        }
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
/// The future will complete successfully once both directions of communication has been shut down
/// or once the half-close grace period expires after one direction has shut down.
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
pub async fn copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_half_close_timeout_and_sizing(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        Some(DEFAULT_HALF_CLOSE_TIMEOUT),
        BufferSizing::adaptive(),
        BufferSizing::adaptive(),
    )
    .await
}

/// Copies data in both directions between `a` and `b` using buffers of the specified size.
///
/// This method is the same as the [`copy_bidirectional()`], except that it allows you to set the
/// size of the internal buffers used when copying data. The sizes are fixed: a caller that asks
/// for a size gets exactly that, with none of the bulk-transfer growth the default applies.
pub async fn copy_bidirectional_with_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_half_close_timeout_and_sizing(
        a,
        b,
        a_need_initial_flush,
        b_need_initial_flush,
        Some(DEFAULT_HALF_CLOSE_TIMEOUT),
        BufferSizing::fixed(a_to_b_buf_size),
        BufferSizing::fixed(b_to_a_buf_size),
    )
    .await
}

async fn copy_bidirectional_with_half_close_timeout_and_sizing<A, B>(
    a: &mut A,
    b: &mut B,
    a_need_initial_flush: bool,
    b_need_initial_flush: bool,
    half_close_timeout: Option<Duration>,
    a_to_b_sizing: BufferSizing,
    b_to_a_sizing: BufferSizing,
) -> io::Result<()>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let ping_sleep = if a.supports_ping() || b.supports_ping() {
        Some(Box::pin(tokio::time::sleep(
            std::time::Duration::from_secs(60),
        )))
    } else {
        None
    };

    CopyBidirectional {
        a,
        b,
        // this is correctly reversed - CopyBuffer will copy from a (reader) to b (writer) using
        // a_buf, which means that the need_flush signal is for the writer (b), and vice versa for
        // b_buf.
        a_buf: CopyBuffer::with_sizing(a_to_b_sizing, b_need_initial_flush),
        b_buf: CopyBuffer::with_sizing(b_to_a_sizing, a_need_initial_flush),
        a_to_b: TransferState::Running,
        b_to_a: TransferState::Running,
        ping_sleep,
        half_close_timeout,
        half_close_sleep: None,
    }
    .await
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::{BULK_BUF_SIZE, BufferSizing, CopyBuffer, DEFAULT_BUF_SIZE};
    use crate::async_stream::{AsyncPing, AsyncStream};

    /// Yields one chunk, then parks -- the shape of a connection that has just
    /// finished forwarding and is waiting for its peer to say something else.
    struct OnceThenPendingStream {
        remaining: Option<&'static [u8]>,
        written: Vec<u8>,
    }

    impl AsyncRead for OnceThenPendingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.remaining.take() {
                Some(data) => {
                    buf.put_slice(data);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for OnceThenPendingStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for OnceThenPendingStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for OnceThenPendingStream {}

    #[tokio::test]
    async fn a_parked_copy_holds_no_buffer() {
        let mut copy = CopyBuffer::new(DEFAULT_BUF_SIZE, false);
        assert_eq!(
            copy.buf.held_bytes(),
            0,
            "a connection that has not moved a byte should not have paid for a buffer"
        );

        let mut reader = OnceThenPendingStream {
            remaining: Some(b"hello"),
            written: Vec::new(),
        };
        let mut writer = OnceThenPendingStream {
            remaining: None,
            written: Vec::new(),
        };

        let result = futures::future::poll_fn(|cx| {
            Poll::Ready(copy.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer)))
        })
        .await;

        assert!(result.is_pending(), "the reader parks after its one chunk");
        assert_eq!(
            writer.written, b"hello",
            "the chunk still has to get through"
        );
        // Forwarded and drained, so the buffer goes back until the peer speaks
        // again. An idle tunnel used to hold this for as long as it stayed open.
        assert_eq!(
            copy.buf.held_bytes(),
            0,
            "a drained, parked copy must not hold a buffer"
        );
    }

    struct PendingReadStream {
        shutdown_called: bool,
    }

    impl AsyncRead for PendingReadStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingReadStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_called = true;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PendingReadStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for PendingReadStream {}

    struct PendingShutdownStream {
        shutdown_called: bool,
    }

    impl AsyncRead for PendingShutdownStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingShutdownStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_called = true;
            Poll::Pending
        }
    }

    impl AsyncPing for PendingShutdownStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for PendingShutdownStream {}

    struct EofReadStream;

    impl AsyncRead for EofReadStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for EofReadStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for EofReadStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for EofReadStream {}

    #[tokio::test]
    async fn copy_completes_when_peer_never_finishes_after_half_close_timeout() {
        let mut stalled = PendingReadStream {
            shutdown_called: false,
        };
        let mut eof = EofReadStream;

        let result = super::copy_bidirectional_with_half_close_timeout_and_sizing(
            &mut stalled,
            &mut eof,
            false,
            false,
            Some(Duration::from_millis(10)),
            BufferSizing::fixed(8),
            BufferSizing::fixed(8),
        )
        .await;

        result.unwrap();
        assert!(stalled.shutdown_called);
    }

    #[tokio::test]
    async fn half_close_timeout_covers_a_shutdown_that_remains_pending() {
        let mut stalled = PendingShutdownStream {
            shutdown_called: false,
        };
        let mut eof = EofReadStream;

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            super::copy_bidirectional_with_half_close_timeout_and_sizing(
                &mut stalled,
                &mut eof,
                false,
                false,
                Some(Duration::from_millis(10)),
                BufferSizing::fixed(8),
                BufferSizing::fixed(8),
            ),
        )
        .await
        .expect("copy remained stuck in poll_shutdown after its half-close deadline");

        result.unwrap();
        assert!(stalled.shutdown_called);
    }

    /// What one `poll_read` of [`ScriptedReader`] does next.
    enum ReadStep {
        /// This many bytes are available now; a read takes as many as fit.
        Data(usize),
        Pending,
    }

    /// A reader that serves a deterministic byte pattern according to a
    /// script, recording how much room each read was offered.
    struct ScriptedReader {
        steps: std::collections::VecDeque<ReadStep>,
        next_byte: usize,
        offered: Vec<usize>,
    }

    impl ScriptedReader {
        fn new(steps: impl IntoIterator<Item = ReadStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                next_byte: 0,
                offered: Vec::new(),
            }
        }
    }

    fn pattern_byte(index: usize) -> u8 {
        (index
            .wrapping_mul(31)
            .wrapping_add(index >> 8)
            .wrapping_add(17)) as u8
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.steps.pop_front() {
                // Script exhausted: EOF.
                None => Poll::Ready(Ok(())),
                Some(ReadStep::Pending) => Poll::Pending,
                Some(ReadStep::Data(available)) => {
                    let offered = buf.remaining();
                    self.offered.push(offered);
                    let take = available.min(offered);
                    for _ in 0..take {
                        let byte = pattern_byte(self.next_byte);
                        buf.put_slice(&[byte]);
                        self.next_byte += 1;
                    }
                    if take < available {
                        self.steps.push_front(ReadStep::Data(available - take));
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for ScriptedReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ScriptedReader {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for ScriptedReader {}

    /// A writer that takes at most the next of `limits` bytes per call (cycling)
    /// and refuses every `stall_period`-th call -- so the copy buffer is drained
    /// in pieces, its free region wraps around, and it still empties at times.
    struct ShortWriter {
        limits: Vec<usize>,
        stall_period: Option<usize>,
        calls: usize,
        written: Vec<u8>,
    }

    impl ShortWriter {
        fn new(limits: &[usize], stall_period: Option<usize>) -> Self {
            Self {
                limits: limits.to_vec(),
                stall_period,
                calls: 0,
                written: Vec::new(),
            }
        }

        fn unlimited() -> Self {
            Self::new(&[usize::MAX], None)
        }
    }

    impl AsyncRead for ShortWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.calls += 1;
            if self
                .stall_period
                .is_some_and(|period| self.calls.is_multiple_of(period))
            {
                return Poll::Pending;
            }
            let limit = self.limits[self.calls % self.limits.len()];
            let take = buf.len().min(limit);
            self.written.extend_from_slice(&buf[..take]);
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ShortWriter {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for ShortWriter {}

    /// Poll the copy once. The mocks never register a waker, so callers simply
    /// poll again; outside a runtime tokio's coop budget is unconstrained.
    fn poll_copy_once(
        copy: &mut CopyBuffer,
        reader: &mut ScriptedReader,
        writer: &mut ShortWriter,
    ) -> Poll<io::Result<()>> {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        copy.poll_copy(&mut cx, Pin::new(reader), Pin::new(writer))
    }

    /// Poll until the reader's script ends in EOF and everything is written.
    fn run_to_completion(
        copy: &mut CopyBuffer,
        reader: &mut ScriptedReader,
        writer: &mut ShortWriter,
    ) {
        for _ in 0..1_000_000 {
            if let Poll::Ready(result) = poll_copy_once(copy, reader, writer) {
                result.unwrap();
                return;
            }
        }
        panic!("copy did not finish");
    }

    fn assert_pattern(written: &[u8], expected_len: usize) {
        assert_eq!(written.len(), expected_len, "bytes lost or duplicated");
        for (index, byte) in written.iter().enumerate() {
            assert_eq!(
                *byte,
                pattern_byte(index),
                "corrupted or reordered at byte {index}"
            );
        }
    }

    #[test]
    fn a_full_read_grows_the_buffer_for_the_rest_of_the_transfer() {
        let mut copy = CopyBuffer::with_sizing(BufferSizing::adaptive(), false);
        let mut reader = ScriptedReader::new([ReadStep::Data(512 * 1024), ReadStep::Pending]);
        let mut writer = ShortWriter::unlimited();

        assert!(poll_copy_once(&mut copy, &mut reader, &mut writer).is_pending());

        assert_eq!(
            reader.offered[0], DEFAULT_BUF_SIZE,
            "every direction starts at the base size"
        );
        assert!(
            reader.offered[1..]
                .iter()
                .all(|&offered| offered == BULK_BUF_SIZE),
            "after one full read the transfer continues at the bulk size: {:?}",
            reader.offered
        );
        assert_pattern(&writer.written, 512 * 1024);
        // Parked and drained: nothing held, but the next active period starts
        // large because this one was a bulk transfer.
        assert_eq!(copy.buf.held_bytes(), 0);
        assert_eq!(copy.size, BULK_BUF_SIZE);
    }

    #[test]
    fn small_reads_never_grow_the_buffer_even_when_they_fill_it() {
        let mut copy = CopyBuffer::with_sizing(BufferSizing::adaptive(), false);
        // Interactive traffic: many small messages, some back to back so they
        // pile up past the base size before the writer drains them, and parks
        // in between.
        let mut steps = Vec::new();
        for round in 0..40 {
            for _ in 0..(1 + round % 25) {
                steps.push(ReadStep::Data(1200));
            }
            steps.push(ReadStep::Pending);
        }
        let expected: usize = (0..40).map(|round| (1 + round % 25) * 1200).sum();
        let mut reader = ScriptedReader::new(steps);
        // A writer that only drains in pieces, so small reads really do fill the
        // base buffer at times.
        let mut writer = ShortWriter::new(&[5000], Some(2));

        run_to_completion(&mut copy, &mut reader, &mut writer);

        assert!(
            reader
                .offered
                .iter()
                .all(|&offered| offered <= DEFAULT_BUF_SIZE),
            "a buffer filled by many small reads is not a bulk transfer"
        );
        assert_eq!(copy.size, DEFAULT_BUF_SIZE);
        assert_pattern(&writer.written, expected);
    }

    #[test]
    fn growth_is_withdrawn_after_an_active_period_without_a_bulk_read() {
        let mut copy = CopyBuffer::with_sizing(BufferSizing::adaptive(), false);
        let mut reader = ScriptedReader::new([
            ReadStep::Data(200 * 1024),
            ReadStep::Pending,
            // The flow turns interactive.
            ReadStep::Data(300),
            ReadStep::Pending,
        ]);
        let mut writer = ShortWriter::unlimited();

        assert!(poll_copy_once(&mut copy, &mut reader, &mut writer).is_pending());
        assert_eq!(
            copy.size, BULK_BUF_SIZE,
            "a bulk period keeps the larger size"
        );

        assert!(poll_copy_once(&mut copy, &mut reader, &mut writer).is_pending());
        assert_eq!(
            copy.size, DEFAULT_BUF_SIZE,
            "a period with no bulk read drops back, so the size must be re-earned"
        );
        assert_eq!(copy.buf.held_bytes(), 0);
        assert_pattern(&writer.written, 200 * 1024 + 300);
    }

    #[test]
    fn data_survives_growth_wrap_around_and_short_writes() {
        let mut copy = CopyBuffer::with_sizing(BufferSizing::adaptive(), false);
        let sizes = [
            100,
            DEFAULT_BUF_SIZE,
            70_000,
            3,
            40_000,
            BULK_BUF_SIZE + 1,
            9_999,
            1,
            250_000,
            17,
        ];
        let mut steps = Vec::new();
        for (index, size) in sizes.iter().cycle().take(60).enumerate() {
            steps.push(ReadStep::Data(*size));
            if index % 3 == 2 {
                steps.push(ReadStep::Pending);
            }
        }
        let expected: usize = sizes.iter().cycle().take(60).sum();
        let mut reader = ScriptedReader::new(steps);
        // Odd-sized and occasionally stalling writes leave the buffer partly
        // drained, so reads land in the wrapped free region before and after
        // growth, while the larger limits still empty it often enough to grow.
        let mut writer = ShortWriter::new(&[7_001, 20_001, 3, 70_000, 12_345], Some(4));

        run_to_completion(&mut copy, &mut reader, &mut writer);

        assert!(
            reader.offered.contains(&BULK_BUF_SIZE),
            "the transfer should have grown"
        );
        assert_pattern(&writer.written, expected);
        assert_eq!(copy.buf.held_bytes(), 0, "a finished copy holds nothing");
    }

    #[test]
    fn explicit_sizes_never_grow() {
        let mut copy = CopyBuffer::new(32 * 1024, false);
        let mut reader = ScriptedReader::new([
            ReadStep::Data(1024 * 1024),
            ReadStep::Pending,
            ReadStep::Data(1024 * 1024),
        ]);
        let mut writer = ShortWriter::new(&[11_000], Some(2));

        run_to_completion(&mut copy, &mut reader, &mut writer);

        assert!(
            reader.offered.iter().all(|&offered| offered <= 32 * 1024),
            "a caller that asked for a size gets exactly that size"
        );
        assert_eq!(copy.size, 32 * 1024);
        assert_pattern(&writer.written, 2 * 1024 * 1024);
    }

    #[tokio::test]
    async fn default_copy_moves_a_bulk_transfer_intact_in_both_directions() {
        let (mut client, mut proxy_client_side) = tokio::io::duplex(256 * 1024);
        let (mut proxy_remote_side, mut remote) = tokio::io::duplex(256 * 1024);

        let proxy = tokio::spawn(async move {
            super::copy_bidirectional(
                &mut TokioStream(&mut proxy_client_side),
                &mut TokioStream(&mut proxy_remote_side),
                false,
                false,
            )
            .await
        });

        let upload: Vec<u8> = (0..3 * 1024 * 1024).map(pattern_byte).collect();
        let download: Vec<u8> = (0..5 * 1024 * 1024).map(|i| pattern_byte(i + 7)).collect();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upload_clone = upload.clone();
        let client_task = tokio::spawn(async move {
            let (mut read_half, mut write_half) = tokio::io::split(&mut client);
            let writer = async {
                write_half.write_all(&upload_clone).await.unwrap();
                write_half.shutdown().await.unwrap();
            };
            let reader = async {
                let mut received = Vec::new();
                read_half.read_to_end(&mut received).await.unwrap();
                received
            };
            let ((), received) = tokio::join!(writer, reader);
            received
        });
        let download_clone = download.clone();
        let remote_task = tokio::spawn(async move {
            let (mut read_half, mut write_half) = tokio::io::split(&mut remote);
            let writer = async {
                write_half.write_all(&download_clone).await.unwrap();
                write_half.shutdown().await.unwrap();
            };
            let reader = async {
                let mut received = Vec::new();
                read_half.read_to_end(&mut received).await.unwrap();
                received
            };
            let ((), received) = tokio::join!(writer, reader);
            received
        });

        let client_received = client_task.await.unwrap();
        let remote_received = remote_task.await.unwrap();
        proxy.await.unwrap().unwrap();
        assert!(client_received == download, "download corrupted");
        assert!(remote_received == upload, "upload corrupted");
    }

    /// Lets a tokio stream stand in for a proxied connection.
    struct TokioStream<'a, T>(&'a mut T);

    impl<T: AsyncRead + Unpin> AsyncRead for TokioStream<'_, T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.0).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for TokioStream<'_, T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut *self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.0).poll_shutdown(cx)
        }
    }

    impl<T: Send + Sync + Unpin> AsyncPing for TokioStream<'_, T> {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for TokioStream<'_, T> {}
}
