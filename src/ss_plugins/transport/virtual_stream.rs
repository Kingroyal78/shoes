use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::async_stream::{AsyncPing, AsyncStream};

pub(super) enum InboundEvent {
    Data(InboundData),
    Finished,
    Failed(String),
}

pub(super) struct ReceiveBudget {
    used: AtomicUsize,
    max: usize,
}

impl ReceiveBudget {
    pub(super) fn new(max: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max,
        }
    }

    pub(super) fn track(self: &Arc<Self>, bytes: Vec<u8>) -> io::Result<InboundData> {
        let length = bytes.len();
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(length).filter(|next| *next <= self.max)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "smux physical receive buffer limit exceeded",
                )
            })?;
        Ok(InboundData {
            bytes,
            budget: Some(ReceiveBudgetPermit {
                budget: self.clone(),
                remaining: length,
            }),
        })
    }
}

struct ReceiveBudgetPermit {
    budget: Arc<ReceiveBudget>,
    remaining: usize,
}

impl ReceiveBudgetPermit {
    fn release(&mut self, count: usize) {
        debug_assert!(count <= self.remaining);
        self.remaining -= count;
        self.budget.used.fetch_sub(count, Ordering::AcqRel);
    }
}

impl Drop for ReceiveBudgetPermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.remaining, Ordering::AcqRel);
    }
}

pub(super) struct InboundData {
    bytes: Vec<u8>,
    budget: Option<ReceiveBudgetPermit>,
}

impl InboundData {
    pub(super) fn untracked(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            budget: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn release(&mut self, count: usize) {
        if let Some(budget) = &mut self.budget {
            budget.release(count);
        }
    }
}

pub(super) enum OutboundCommand {
    Data {
        stream_id: u32,
        data: Vec<u8>,
    },
    Finished {
        stream_id: u32,
    },
    Barrier {
        complete: oneshot::Sender<io::Result<()>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowUpdate {
    pub stream_id: u32,
    pub consumed: u32,
    pub window: u32,
}

pub(super) struct SmuxV2FlowControl {
    num_written: AtomicU32,
    peer_consumed: AtomicU32,
    peer_window: AtomicU32,
    write_waker: AtomicWaker,
}

impl SmuxV2FlowControl {
    const INITIAL_PEER_WINDOW: u32 = 262_144;

    pub(super) fn new() -> Self {
        Self {
            num_written: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(Self::INITIAL_PEER_WINDOW),
            write_waker: AtomicWaker::new(),
        }
    }

    pub(super) fn update(&self, consumed: u32, window: u32) -> io::Result<()> {
        let written = self.num_written.load(Ordering::Acquire);
        if (written.wrapping_sub(consumed) as i32) < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "smux v2 peer consumed more bytes than were sent",
            ));
        }
        self.peer_consumed.store(consumed, Ordering::Release);
        self.peer_window.store(window, Ordering::Release);
        self.write_waker.wake();
        Ok(())
    }

    pub(super) fn available(&self) -> io::Result<usize> {
        let written = self.num_written.load(Ordering::Acquire);
        let consumed = self.peer_consumed.load(Ordering::Acquire);
        let inflight = written.wrapping_sub(consumed) as i32;
        if inflight < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "smux v2 peer consumed more bytes than were sent",
            ));
        }
        Ok((self.peer_window.load(Ordering::Acquire) as i32 - inflight).max(0) as usize)
    }

    fn poll_available(&self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let available = self.available()?;
        if available > 0 {
            return Poll::Ready(Ok(available));
        }
        self.write_waker.register(cx.waker());
        let available = self.available()?;
        if available > 0 {
            Poll::Ready(Ok(available))
        } else {
            Poll::Pending
        }
    }

    pub(super) fn record_write(&self, count: usize) {
        self.num_written.fetch_add(count as u32, Ordering::Release);
    }
}

struct SmuxV2StreamState {
    flow: Arc<SmuxV2FlowControl>,
    updates: mpsc::Sender<WindowUpdate>,
    update_permit: Option<WindowPermitFuture>,
    consumed: u32,
    consumed_since_update: u32,
    receive_window: u32,
}

type PermitFuture = Pin<
    Box<
        dyn Future<Output = io::Result<mpsc::OwnedPermit<OutboundCommand>>> + Send + Sync + 'static,
    >,
>;

type WindowPermitFuture = Pin<
    Box<dyn Future<Output = io::Result<mpsc::OwnedPermit<WindowUpdate>>> + Send + Sync + 'static>,
>;

enum BarrierState {
    Idle,
    Reserving {
        permit: PermitFuture,
        complete_tx: Option<oneshot::Sender<io::Result<()>>>,
        complete_rx: oneshot::Receiver<io::Result<()>>,
    },
    Waiting(oneshot::Receiver<io::Result<()>>),
}

/// Bounded logical byte stream shared by Mux.Cool and smux v1.
pub(super) struct VirtualStream {
    stream_id: u32,
    inbound: mpsc::Receiver<InboundEvent>,
    inbound_chunk: Option<InboundData>,
    inbound_offset: usize,
    outbound: mpsc::Sender<OutboundCommand>,
    write_permit: Option<PermitFuture>,
    finish_permit: Option<PermitFuture>,
    barrier: BarrierState,
    max_frame_payload: usize,
    read_finished: bool,
    write_finished: bool,
    smux_v2: Option<SmuxV2StreamState>,
    drop_close_permit: Option<mpsc::OwnedPermit<u32>>,
}

impl VirtualStream {
    pub(super) fn new(
        stream_id: u32,
        inbound: mpsc::Receiver<InboundEvent>,
        outbound: mpsc::Sender<OutboundCommand>,
        max_frame_payload: usize,
    ) -> Self {
        Self {
            stream_id,
            inbound,
            inbound_chunk: None,
            inbound_offset: 0,
            outbound,
            write_permit: None,
            finish_permit: None,
            barrier: BarrierState::Idle,
            max_frame_payload,
            read_finished: false,
            write_finished: false,
            smux_v2: None,
            drop_close_permit: None,
        }
    }

    pub(super) fn new_smux_v2(
        stream_id: u32,
        inbound: mpsc::Receiver<InboundEvent>,
        outbound: mpsc::Sender<OutboundCommand>,
        max_frame_payload: usize,
        flow: Arc<SmuxV2FlowControl>,
        updates: mpsc::Sender<WindowUpdate>,
        receive_window: u32,
    ) -> Self {
        let mut stream = Self::new(stream_id, inbound, outbound, max_frame_payload);
        stream.smux_v2 = Some(SmuxV2StreamState {
            flow,
            updates,
            update_permit: None,
            consumed: 0,
            consumed_since_update: 0,
            receive_window,
        });
        stream
    }

    pub(super) fn set_drop_close_permit(&mut self, permit: mpsc::OwnedPermit<u32>) {
        debug_assert!(self.drop_close_permit.is_none());
        self.drop_close_permit = Some(permit);
    }

    fn reserve(sender: mpsc::Sender<OutboundCommand>) -> PermitFuture {
        Box::pin(async move {
            sender.reserve_owned().await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "multiplexed session writer closed",
                )
            })
        })
    }

    fn reserve_window_update(sender: mpsc::Sender<WindowUpdate>) -> WindowPermitFuture {
        Box::pin(async move {
            sender.reserve_owned().await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "smux v2 window-update writer closed",
                )
            })
        })
    }

    fn poll_barrier(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.barrier {
                BarrierState::Idle => {
                    let (complete_tx, complete_rx) = oneshot::channel();
                    self.barrier = BarrierState::Reserving {
                        permit: Self::reserve(self.outbound.clone()),
                        complete_tx: Some(complete_tx),
                        complete_rx,
                    };
                }
                BarrierState::Reserving {
                    permit,
                    complete_tx,
                    ..
                } => {
                    let permit = match permit.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(permit)) => permit,
                        Poll::Ready(Err(error)) => {
                            self.barrier = BarrierState::Idle;
                            return Poll::Ready(Err(error));
                        }
                    };
                    let complete = complete_tx
                        .take()
                        .expect("barrier completion sender exists while reserving");
                    permit.send(OutboundCommand::Barrier { complete });
                    let BarrierState::Reserving { complete_rx, .. } =
                        std::mem::replace(&mut self.barrier, BarrierState::Idle)
                    else {
                        unreachable!()
                    };
                    self.barrier = BarrierState::Waiting(complete_rx);
                }
                BarrierState::Waiting(receiver) => {
                    let result = match Pin::new(receiver).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(result)) => result,
                        Poll::Ready(Err(_)) => Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "multiplexed session writer dropped a flush barrier",
                        )),
                    };
                    self.barrier = BarrierState::Idle;
                    return Poll::Ready(result);
                }
            }
        }
    }
}

impl AsyncRead for VirtualStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.read_finished {
            return Poll::Ready(Ok(()));
        }

        loop {
            if let Some(mut chunk) = self.inbound_chunk.take() {
                let remaining = &chunk.bytes[self.inbound_offset..];
                let copy_len = remaining.len().min(buf.remaining());
                let pending_update = self.smux_v2.as_ref().and_then(|v2| {
                    let consumed = v2.consumed.wrapping_add(copy_len as u32);
                    let consumed_since_update =
                        v2.consumed_since_update.wrapping_add(copy_len as u32);
                    let first_read = v2.consumed == 0;
                    (copy_len > 0
                        && (first_read || consumed_since_update >= (v2.receive_window / 2).max(1)))
                    .then_some(WindowUpdate {
                        stream_id: self.stream_id,
                        consumed,
                        window: v2.receive_window,
                    })
                });

                if let Some(update) = pending_update {
                    let v2 = self
                        .smux_v2
                        .as_mut()
                        .expect("pending update requires smux v2 state");
                    if v2.update_permit.is_none() {
                        v2.update_permit = Some(Self::reserve_window_update(v2.updates.clone()));
                    }
                    let permit = match v2
                        .update_permit
                        .as_mut()
                        .expect("window update permit initialized")
                        .as_mut()
                        .poll(cx)
                    {
                        Poll::Pending => {
                            self.inbound_chunk = Some(chunk);
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            v2.update_permit = None;
                            match result {
                                Ok(permit) => permit,
                                Err(error) => {
                                    self.inbound_chunk = Some(chunk);
                                    return Poll::Ready(Err(error));
                                }
                            }
                        }
                    };
                    permit.send(update);
                }

                buf.put_slice(&remaining[..copy_len]);
                chunk.release(copy_len);
                self.inbound_offset += copy_len;
                if self.inbound_offset < chunk.len() {
                    self.inbound_chunk = Some(chunk);
                } else {
                    self.inbound_offset = 0;
                }
                if copy_len > 0
                    && let Some(v2) = self.smux_v2.as_mut()
                {
                    v2.consumed = v2.consumed.wrapping_add(copy_len as u32);
                    v2.consumed_since_update =
                        v2.consumed_since_update.wrapping_add(copy_len as u32);
                    let first_read = v2.consumed == copy_len as u32;
                    if first_read || v2.consumed_since_update >= (v2.receive_window / 2).max(1) {
                        v2.consumed_since_update = 0;
                    }
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inbound).poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(InboundEvent::Data(data))) if data.is_empty() => continue,
                Poll::Ready(Some(InboundEvent::Data(data))) => {
                    self.inbound_chunk = Some(data);
                }
                Poll::Ready(Some(InboundEvent::Finished)) | Poll::Ready(None) => {
                    self.read_finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(InboundEvent::Failed(message))) => {
                    self.read_finished = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        message,
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for VirtualStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "multiplexed logical stream is shut down",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let flow_capacity = if let Some(v2) = &self.smux_v2 {
            match v2.flow.poll_available(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => Some(result?),
            }
        } else {
            None
        };
        if self.write_permit.is_none() {
            self.write_permit = Some(Self::reserve(self.outbound.clone()));
        }
        let permit = match self
            .write_permit
            .as_mut()
            .expect("write permit initialized")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => {
                self.write_permit = None;
                result?
            }
        };
        let length = buf
            .len()
            .min(self.max_frame_payload)
            .min(flow_capacity.unwrap_or(usize::MAX));
        if length == 0 {
            return Poll::Pending;
        }
        permit.send(OutboundCommand::Data {
            stream_id: self.stream_id,
            data: buf[..length].to_vec(),
        });
        if let Some(v2) = &self.smux_v2 {
            v2.flow.record_write(length);
        }
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_finished {
            if self.finish_permit.is_none() {
                self.finish_permit = Some(Self::reserve(self.outbound.clone()));
            }
            let permit = match self
                .finish_permit
                .as_mut()
                .expect("finish permit initialized")
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.finish_permit = None;
                    result?
                }
            };
            permit.send(OutboundCommand::Finished {
                stream_id: self.stream_id,
            });
            self.write_finished = true;
            self.drop_close_permit = None;
        }
        self.poll_barrier(cx)
    }
}

impl AsyncPing for VirtualStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for VirtualStream {}

impl Drop for VirtualStream {
    fn drop(&mut self) {
        if !self.write_finished {
            if let Some(permit) = self.drop_close_permit.take() {
                permit.send(self.stream_id);
            } else if let Err(error) = self.outbound.try_send(OutboundCommand::Finished {
                stream_id: self.stream_id,
            }) {
                log::debug!(
                    "logical stream {} could not enqueue close during drop: {error}",
                    self.stream_id
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drop_uses_a_reserved_close_slot_when_the_outbound_queue_is_full() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        outbound_tx
            .send(OutboundCommand::Data {
                stream_id: 99,
                data: vec![1],
            })
            .await
            .unwrap();
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let close_permit = close_tx.clone().reserve_owned().await.unwrap();
        let mut stream = VirtualStream::new(7, inbound_rx, outbound_tx, 1024);
        stream.set_drop_close_permit(close_permit);

        drop(stream);

        assert_eq!(close_rx.recv().await, Some(7));
        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Data { stream_id: 99, .. })
        ));
    }
}
