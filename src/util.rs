use tokio::io::AsyncWriteExt;

#[inline]
#[allow(clippy::uninit_vec)]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
}

// a cancellable alternative to AsyncWriteExt::write_all
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}

/// A buffer that is only held while it has something in it.
///
/// At any instant the overwhelming majority of a proxy's connections are parked
/// waiting on a peer that is saying nothing, and a parked connection needs no
/// buffer at all. Holding tens of kilobytes apiece for the lifetime of every
/// connection is the largest per-connection cost in the process, so the
/// allocation is taken on demand and given back as soon as the buffer drains.
/// Re-acquiring it costs one allocation out of jemalloc's thread cache, against
/// a socket read that was going to cost a syscall anyway.
///
/// Deref lets callers index it exactly as before. The one rule is that
/// [`LazyBuffer::ensure`] must run before any use, because a released buffer
/// reports a length of zero -- so anything deriving capacity from it must use
/// the size it was created with instead.
#[derive(Debug)]
pub struct LazyBuffer {
    buf: Box<[u8]>,
    size: usize,
}

impl LazyBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buf: Vec::new().into_boxed_slice(),
            size,
        }
    }

    pub fn ensure(&mut self) {
        if self.buf.is_empty() {
            self.buf = allocate_vec(self.size).into_boxed_slice();
        }
    }

    pub fn release(&mut self) {
        if !self.buf.is_empty() {
            self.buf = Vec::new().into_boxed_slice();
        }
    }

    #[cfg(test)]
    pub fn held_bytes(&self) -> usize {
        self.buf.len()
    }
}

impl std::ops::Deref for LazyBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for LazyBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}
