use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Sleep;

use crate::async_stream::{AsyncPing, AsyncStream};

pub(super) enum InboundEvent {
    Data(InboundData),
}

#[derive(Debug)]
pub(super) enum InboundTerminal {
    Finished,
    Failed(InboundFailure),
}

/// A terminal failure that keeps its semantic `io::ErrorKind` while it is
/// fanned out to every logical stream in a multiplexed session.
///
/// This used to be a `String`; [`VirtualStream`] then reconstructed every
/// failure as `ConnectionReset`. That made an ordinary physical close, a local
/// receive-budget overflow and a malformed protocol frame indistinguishable to
/// callers such as the UDP router, which consequently logged them all as WARN.
#[derive(Clone, Debug)]
pub(super) struct InboundFailure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl InboundFailure {
    pub(super) fn new(kind: io::ErrorKind, message: impl Into<Arc<str>>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(super) fn from_error(error: &io::Error) -> Self {
        Self::new(error.kind(), error.to_string())
    }

    fn into_error(self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

pub(super) struct InboundChannels {
    data: mpsc::Receiver<InboundEvent>,
    terminal: oneshot::Receiver<InboundTerminal>,
}

impl InboundChannels {
    pub(super) fn new(
        data: mpsc::Receiver<InboundEvent>,
        terminal: oneshot::Receiver<InboundTerminal>,
    ) -> Self {
        Self { data, terminal }
    }
}

const BUDGET_EVICTED: u64 = 1 << 63;
const BUDGET_USED_MASK: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReceiveBudgetScope {
    Stream,
    Session,
    Listener,
}

impl std::fmt::Display for ReceiveBudgetScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream => f.write_str("stream"),
            Self::Session => f.write_str("session"),
            Self::Listener => f.write_str("listener"),
        }
    }
}

#[derive(Debug)]
pub(super) struct ReceiveBudgetExceeded {
    pub(super) scope: ReceiveBudgetScope,
}

impl std::fmt::Display for ReceiveBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "smux {} receive buffer limit exceeded", self.scope)
    }
}

impl std::error::Error for ReceiveBudgetExceeded {}

#[derive(Clone, Copy, Debug)]
pub(super) struct BudgetEviction {
    pub(super) stream_id: u32,
    pub(super) scope: ReceiveBudgetScope,
}

#[derive(Clone)]
struct EvictionTarget {
    stream_id: u32,
    sender: mpsc::UnboundedSender<BudgetEviction>,
}

pub(super) struct ReceiveBudget {
    /// Upper 31 bits are a permit generation, bit 63 marks an evicted leaf,
    /// and the lower 32 bits are queued bytes. Keeping both in one atomic
    /// prevents an old permit from refunding a newly reused accounting state.
    state: AtomicU64,
    max: usize,
    /// A budget every session on the listener also draws from.
    ///
    /// The per-session limit alone bounds nothing in aggregate: it is charged
    /// once per physical session, so N concurrent sessions may queue N times
    /// `max` bytes. Charging a shared parent as well puts a ceiling on the
    /// listener as a whole.
    parent: Option<Arc<ReceiveBudget>>,
    children: Mutex<Vec<Weak<ReceiveBudget>>>,
    registered: AtomicBool,
    eviction_lock: Arc<Mutex<()>>,
    eviction: Option<EvictionTarget>,
}

impl ReceiveBudget {
    pub(super) fn new(max: usize) -> Self {
        Self {
            state: AtomicU64::new(0),
            max,
            parent: None,
            children: Mutex::new(Vec::new()),
            registered: AtomicBool::new(true),
            eviction_lock: Arc::new(Mutex::new(())),
            eviction: None,
        }
    }

    pub(super) fn with_parent(max: usize, parent: Option<Arc<ReceiveBudget>>) -> Self {
        Self::with_parent_and_eviction(max, parent, None)
    }

    pub(super) fn stream(
        max: usize,
        parent: Arc<ReceiveBudget>,
        stream_id: u32,
        eviction_tx: mpsc::UnboundedSender<BudgetEviction>,
    ) -> Self {
        Self::with_parent_and_eviction(
            max,
            Some(parent),
            Some(EvictionTarget {
                stream_id,
                sender: eviction_tx,
            }),
        )
    }

    fn with_parent_and_eviction(
        max: usize,
        parent: Option<Arc<ReceiveBudget>>,
        eviction: Option<EvictionTarget>,
    ) -> Self {
        let eviction_lock = parent.as_ref().map_or_else(
            || Arc::new(Mutex::new(())),
            |parent| parent.eviction_lock.clone(),
        );
        Self {
            state: AtomicU64::new(0),
            max,
            parent,
            children: Mutex::new(Vec::new()),
            registered: AtomicBool::new(false),
            eviction_lock,
            eviction,
        }
    }

    fn ensure_registered(self: &Arc<Self>) {
        let Some(parent) = &self.parent else { return };
        parent.ensure_registered();
        if self
            .registered
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            parent.children.lock().push(Arc::downgrade(self));
        }
    }

    fn used(&self) -> usize {
        (self.state.load(Ordering::Acquire) & BUDGET_USED_MASK) as usize
    }

    fn charge_one(&self, length: usize) -> Option<u32> {
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & BUDGET_EVICTED != 0 {
                    return None;
                }
                let used = (state & BUDGET_USED_MASK) as usize;
                let next = used.checked_add(length)?;
                (next <= self.max).then_some((state & !BUDGET_USED_MASK) | next as u64)
            })
            .ok()
            .map(|state| (state >> 32) as u32)
    }

    fn refund_one(&self, count: usize) {
        self.state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                let used = (state & BUDGET_USED_MASK) as usize;
                debug_assert!(count <= used);
                Some((state & !BUDGET_USED_MASK) | used.saturating_sub(count) as u64)
            })
            .expect("budget refund always updates");
    }

    fn chain(self: &Arc<Self>) -> Vec<Arc<Self>> {
        let mut chain = Vec::new();
        let mut current = Some(self.clone());
        while let Some(budget) = current {
            current = budget.parent.clone();
            chain.push(budget);
        }
        chain.reverse();
        chain
    }

    fn try_charge(self: &Arc<Self>, length: usize) -> Result<u32, Arc<Self>> {
        let chain = self.chain();
        let mut charged = Vec::with_capacity(chain.len());
        let mut generation = 0;
        for budget in chain {
            match budget.charge_one(length) {
                Some(value) => {
                    generation = value;
                    charged.push(budget);
                }
                None => {
                    for budget in charged.into_iter().rev() {
                        budget.refund_one(length);
                    }
                    return Err(budget);
                }
            }
        }
        Ok(generation)
    }

    fn refund_permit(&self, count: usize, generation: u32) {
        let refunded = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if (state >> 32) as u32 != generation || state & BUDGET_EVICTED != 0 {
                    return None;
                }
                let used = (state & BUDGET_USED_MASK) as usize;
                debug_assert!(count <= used);
                Some((state & !BUDGET_USED_MASK) | used.saturating_sub(count) as u64)
            })
            .is_ok();
        if !refunded {
            return;
        }
        if let Some(parent) = &self.parent {
            parent.refund_one(count);
            parent.refund_ancestors(count);
        }
    }

    fn refund_ancestors(&self, count: usize) {
        if let Some(parent) = &self.parent {
            parent.refund_one(count);
            parent.refund_ancestors(count);
        }
    }

    fn largest_leaf(self: &Arc<Self>) -> Option<(Arc<Self>, usize)> {
        let children = {
            let mut children = self.children.lock();
            children.retain(|child| child.strong_count() > 0);
            children
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        if children.is_empty() {
            let state = self.state.load(Ordering::Acquire);
            return (state & BUDGET_EVICTED == 0)
                .then_some((self.clone(), (state & BUDGET_USED_MASK) as usize));
        }
        children
            .into_iter()
            .filter_map(|child| child.largest_leaf())
            .max_by_key(|(_, used)| *used)
    }

    fn evict(&self, scope: ReceiveBudgetScope) {
        let previous = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & BUDGET_EVICTED == 0)
                    .then_some(BUDGET_EVICTED | (((state >> 32).wrapping_add(1)) << 32))
            });
        let Ok(previous) = previous else { return };
        let reclaimed = (previous & BUDGET_USED_MASK) as usize;
        if reclaimed > 0
            && let Some(parent) = &self.parent
        {
            parent.refund_one(reclaimed);
            parent.refund_ancestors(reclaimed);
        }
        if let Some(target) = &self.eviction {
            let _ = target.sender.send(BudgetEviction {
                stream_id: target.stream_id,
                scope,
            });
        }
    }

    fn scope_of(&self, failed: &Arc<Self>) -> ReceiveBudgetScope {
        if std::ptr::eq(self, Arc::as_ptr(failed)) {
            ReceiveBudgetScope::Stream
        } else if failed.parent.is_none()
            && self
                .parent
                .as_ref()
                .is_some_and(|p| !Arc::ptr_eq(p, failed))
        {
            ReceiveBudgetScope::Listener
        } else {
            ReceiveBudgetScope::Session
        }
    }

    pub(super) fn track(
        self: &Arc<Self>,
        bytes: Vec<u8>,
    ) -> Result<InboundData, ReceiveBudgetExceeded> {
        let length = bytes.len();
        self.ensure_registered();
        let generation = loop {
            match self.try_charge(length) {
                Ok(generation) => break generation,
                Err(failed) => {
                    let scope = self.scope_of(&failed);
                    let _eviction = self.eviction_lock.lock();
                    if let Ok(generation) = self.try_charge(length) {
                        break generation;
                    }
                    let current_after_charge = self.used().saturating_add(length);
                    let victim = failed.largest_leaf();
                    if victim.as_ref().is_none_or(|(victim, used)| {
                        Arc::ptr_eq(victim, self) || current_after_charge >= *used
                    }) {
                        self.evict(scope);
                        return Err(ReceiveBudgetExceeded { scope });
                    }
                    victim.expect("checked above").0.evict(scope);
                }
            }
        };
        Ok(InboundData {
            bytes,
            budget: Some(ReceiveBudgetPermit {
                budget: self.clone(),
                remaining: length,
                generation,
            }),
        })
    }
}

impl Drop for ReceiveBudget {
    fn drop(&mut self) {
        if !self.registered.load(Ordering::Acquire) {
            return;
        }
        if let Some(parent) = &self.parent {
            let self_ptr: *const ReceiveBudget = self;
            parent
                .children
                .lock()
                .retain(|child| child.as_ptr() != self_ptr);
        }
    }
}

struct ReceiveBudgetPermit {
    budget: Arc<ReceiveBudget>,
    remaining: usize,
    generation: u32,
}

impl ReceiveBudgetPermit {
    fn release(&mut self, count: usize) {
        debug_assert!(count <= self.remaining);
        self.remaining -= count;
        self.budget.refund_permit(count, self.generation);
    }
}

impl Drop for ReceiveBudgetPermit {
    fn drop(&mut self) {
        self.budget.refund_permit(self.remaining, self.generation);
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
    Waiting {
        complete_rx: oneshot::Receiver<io::Result<()>>,
    },
}

/// Bounded logical byte stream shared by Mux.Cool and smux v1.
pub(super) struct VirtualStream {
    stream_id: u32,
    inbound: mpsc::Receiver<InboundEvent>,
    terminal: oneshot::Receiver<InboundTerminal>,
    inbound_chunk: Option<InboundData>,
    inbound_offset: usize,
    outbound: mpsc::Sender<OutboundCommand>,
    write_permit: Option<PermitFuture>,
    write_timeout: Option<Pin<Box<Sleep>>>,
    finish_permit: Option<PermitFuture>,
    finish_timeout: Option<Pin<Box<Sleep>>>,
    barrier: BarrierState,
    /// Deadline for the barrier currently in flight, reused across barriers so
    /// each flush does not allocate and register fresh timer entries.
    barrier_timeout: Option<Pin<Box<Sleep>>>,
    /// Whether any payload has been queued since the last completed barrier.
    /// A flush with nothing outstanding is a no-op, so it must not pay for a
    /// round trip through the session writer.
    write_dirty: bool,
    max_frame_payload: usize,
    read_finished: bool,
    write_finished: bool,
    smux_v2: Option<SmuxV2StreamState>,
    drop_close_permit: Option<mpsc::OwnedPermit<u32>>,
}

impl VirtualStream {
    pub(super) fn new(
        stream_id: u32,
        inbound: InboundChannels,
        outbound: mpsc::Sender<OutboundCommand>,
        max_frame_payload: usize,
    ) -> Self {
        Self {
            stream_id,
            inbound: inbound.data,
            terminal: inbound.terminal,
            inbound_chunk: None,
            inbound_offset: 0,
            outbound,
            write_permit: None,
            write_timeout: None,
            finish_permit: None,
            finish_timeout: None,
            barrier: BarrierState::Idle,
            barrier_timeout: None,
            write_dirty: false,
            max_frame_payload,
            read_finished: false,
            write_finished: false,
            smux_v2: None,
            drop_close_permit: None,
        }
    }

    pub(super) fn new_smux_v2(
        stream_id: u32,
        inbound: InboundChannels,
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

    /// Arm the shared barrier deadline, reusing the existing timer entry.
    ///
    /// `Sleep::reset` re-uses one registration where a fresh `sleep()` would
    /// allocate and insert another; a flush-heavy session performs this on
    /// every barrier, and the timer wheel is process-wide and lock-guarded.
    fn arm_barrier_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + barrier_timeout();
        match &mut self.barrier_timeout {
            Some(timeout) => timeout.as_mut().reset(deadline),
            None => self.barrier_timeout = Some(Box::pin(tokio::time::sleep_until(deadline))),
        }
    }

    /// Poll the shared barrier deadline. Absent means the barrier just started
    /// within this call and cannot have expired yet.
    fn poll_barrier_timeout(&mut self, cx: &mut Context<'_>) -> bool {
        match &mut self.barrier_timeout {
            Some(timeout) => timeout.as_mut().poll(cx).is_ready(),
            None => false,
        }
    }

    fn finish_barrier(&mut self) {
        self.barrier = BarrierState::Idle;
        // Release the timer entry so an idle stream holds no wheel slot.
        self.barrier_timeout = None;
    }

    fn poll_barrier(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Nothing has been queued since the last barrier completed, so there is
        // nothing for the session writer to push out. Skipping the round trip
        // here is what keeps a per-poll flush from costing a channel reservation
        // and two timer registrations.
        if matches!(self.barrier, BarrierState::Idle) && !self.write_dirty {
            return Poll::Ready(Ok(()));
        }

        loop {
            match &mut self.barrier {
                BarrierState::Idle => {
                    let (complete_tx, complete_rx) = oneshot::channel();
                    self.barrier = BarrierState::Reserving {
                        permit: Self::reserve(self.outbound.clone()),
                        complete_tx: Some(complete_tx),
                        complete_rx,
                    };
                    self.arm_barrier_timeout();
                }
                BarrierState::Reserving {
                    permit,
                    complete_tx,
                    ..
                } => {
                    let permit = match permit.as_mut().poll(cx) {
                        Poll::Pending => {
                            if self.poll_barrier_timeout(cx) {
                                self.finish_barrier();
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "multiplexed stream flush barrier queue timed out",
                                )));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(permit)) => permit,
                        Poll::Ready(Err(error)) => {
                            self.finish_barrier();
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
                    // The deadline stays armed across the transition so the two
                    // phases share one bound rather than restarting the clock.
                    self.barrier = BarrierState::Waiting { complete_rx };
                }
                BarrierState::Waiting { complete_rx } => {
                    match Pin::new(complete_rx).poll(cx) {
                        Poll::Ready(Ok(result)) => {
                            self.finish_barrier();
                            // Everything queued before this barrier has reached
                            // the physical stream.
                            self.write_dirty = false;
                            return Poll::Ready(result);
                        }
                        Poll::Ready(Err(_)) => {
                            self.finish_barrier();
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "multiplexed session writer dropped a flush barrier",
                            )));
                        }
                        Poll::Pending => {}
                    }
                    if self.poll_barrier_timeout(cx) {
                        self.finish_barrier();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "multiplexed stream flush barrier timed out",
                        )));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_stalled_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let timeout = self
            .write_timeout
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(barrier_timeout())));
        if timeout.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }

        self.write_permit = None;
        self.write_timeout = None;
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "multiplexed stream data write timed out",
        )))
    }

    fn finish_read(&mut self, terminal: InboundTerminal) -> Poll<io::Result<()>> {
        self.read_finished = true;
        match terminal {
            InboundTerminal::Finished => Poll::Ready(Ok(())),
            InboundTerminal::Failed(failure) => Poll::Ready(Err(failure.into_error())),
        }
    }

    fn poll_terminal(&mut self, cx: &mut Context<'_>) -> Poll<Option<InboundTerminal>> {
        match Pin::new(&mut self.terminal).poll(cx) {
            Poll::Ready(Ok(terminal)) => Poll::Ready(Some(terminal)),
            Poll::Ready(Err(_)) => Poll::Ready(Some(InboundTerminal::Finished)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn barrier_timeout() -> std::time::Duration {
    if cfg!(test) {
        std::time::Duration::from_millis(20)
    } else {
        std::time::Duration::from_secs(5)
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
                Poll::Pending => match self.poll_terminal(cx) {
                    Poll::Ready(Some(terminal)) => return self.finish_read(terminal),
                    Poll::Ready(None) => {
                        self.read_finished = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                Poll::Ready(Some(InboundEvent::Data(data))) if data.is_empty() => continue,
                Poll::Ready(Some(InboundEvent::Data(data))) => {
                    self.inbound_chunk = Some(data);
                }
                Poll::Ready(None) => match self.poll_terminal(cx) {
                    Poll::Ready(Some(terminal)) => return self.finish_read(terminal),
                    Poll::Ready(None) | Poll::Pending => {
                        self.read_finished = true;
                        return Poll::Ready(Ok(()));
                    }
                },
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
                Poll::Pending => return self.poll_stalled_write(cx),
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
            Poll::Pending => return self.poll_stalled_write(cx),
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
            return self.poll_stalled_write(cx);
        }
        permit.send(OutboundCommand::Data {
            stream_id: self.stream_id,
            data: buf[..length].to_vec(),
        });
        if let Some(v2) = &self.smux_v2 {
            v2.flow.record_write(length);
        }
        self.write_timeout = None;
        // A later flush now has real work to wait for.
        self.write_dirty = true;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_finished {
            if self.finish_permit.is_none() {
                self.finish_permit = Some(Self::reserve(self.outbound.clone()));
                self.finish_timeout = Some(Box::pin(tokio::time::sleep(barrier_timeout())));
            }
            let permit = match self
                .finish_permit
                .as_mut()
                .expect("finish permit initialized")
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => {
                    let timed_out = self
                        .finish_timeout
                        .as_mut()
                        .expect("finish timeout initialized with permit")
                        .as_mut()
                        .poll(cx)
                        .is_ready();
                    if timed_out {
                        self.finish_permit = None;
                        self.finish_timeout = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "multiplexed stream close queue timed out",
                        )));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(result) => {
                    self.finish_permit = None;
                    self.finish_timeout = None;
                    result?
                }
            };
            permit.send(OutboundCommand::Finished {
                stream_id: self.stream_id,
            });
            self.write_finished = true;
            self.drop_close_permit = None;
            // The FIN itself must reach the peer, so the barrier below has to
            // run even when no payload was queued since the last flush.
            self.write_dirty = true;
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
    #[test]
    fn listener_pressure_evicts_the_largest_buffered_stream_not_the_next_sender() {
        let listener = Arc::new(ReceiveBudget::new(12));
        let first_session = Arc::new(ReceiveBudget::with_parent(12, Some(listener.clone())));
        let second_session = Arc::new(ReceiveBudget::with_parent(12, Some(listener)));
        let (eviction_tx, mut eviction_rx) = mpsc::unbounded_channel();
        let first = Arc::new(ReceiveBudget::stream(
            12,
            first_session,
            1,
            eviction_tx.clone(),
        ));
        let second = Arc::new(ReceiveBudget::stream(12, second_session, 2, eviction_tx));

        let _first_held = first.track(vec![0_u8; 8]).expect("within all limits");
        let _second_held = second.track(vec![0_u8; 1]).expect("within all limits");
        let _new_data = second
            .track(vec![0_u8; 4])
            .expect("the light sender must survive listener pressure");

        let eviction = eviction_rx
            .try_recv()
            .expect("the debtor must be identified");
        assert_eq!(eviction.stream_id, 1);
        assert_eq!(eviction.scope, ReceiveBudgetScope::Listener);
        let Err(error) = first.track(vec![0_u8; 1]) else {
            panic!("an evicted stream cannot consume the reclaimed budget again")
        };
        assert_eq!(error.scope, ReceiveBudgetScope::Stream);
    }

    #[test]
    fn session_pressure_evicts_its_largest_buffered_stream() {
        let session = Arc::new(ReceiveBudget::new(8));
        let (eviction_tx, mut eviction_rx) = mpsc::unbounded_channel();
        let debtor = Arc::new(ReceiveBudget::stream(
            8,
            session.clone(),
            10,
            eviction_tx.clone(),
        ));
        let sender = Arc::new(ReceiveBudget::stream(8, session, 11, eviction_tx));

        let _debtor_data = debtor.track(vec![0_u8; 6]).unwrap();
        let _sender_data = sender.track(vec![0_u8; 1]).unwrap();
        let _new_data = sender
            .track(vec![0_u8; 2])
            .expect("the stream using less memory must not be the victim");

        let eviction = eviction_rx.try_recv().unwrap();
        assert_eq!(eviction.stream_id, 10);
        assert_eq!(eviction.scope, ReceiveBudgetScope::Session);
    }

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn drop_uses_a_reserved_close_slot_when_the_outbound_queue_is_full() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
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
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );
        stream.set_drop_close_permit(close_permit);

        drop(stream);

        assert_eq!(close_rx.recv().await, Some(7));
        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Data { stream_id: 99, .. })
        ));
    }

    #[tokio::test]
    async fn terminal_finished_bypasses_a_full_inbound_data_queue() {
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        inbound_tx
            .send(InboundEvent::Data(InboundData::untracked(b"x".to_vec())))
            .await
            .unwrap();
        terminal_tx.send(InboundTerminal::Finished).unwrap();

        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);

        let mut eof = [0_u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn terminal_failed_preserves_queued_data_before_reset() {
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        inbound_tx
            .send(InboundEvent::Data(InboundData::untracked(b"x".to_vec())))
            .await
            .unwrap();
        terminal_tx
            .send(InboundTerminal::Failed(InboundFailure::new(
                io::ErrorKind::ConnectionAborted,
                "physical closed",
            )))
            .unwrap();

        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'x']);

        let error = stream.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(error.to_string().contains("physical closed"));
    }

    #[tokio::test]
    async fn flush_barrier_times_out_when_writer_keeps_completion_open() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        // Only a stream with queued payload raises a barrier, so write first
        // and drain the resulting data command.
        stream.write_all(b"payload").await.unwrap();
        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Data { .. })
        ));

        let mut flush = Box::pin(stream.flush());
        match futures::future::poll_fn(|cx| flush.as_mut().poll(cx)).await {
            Ok(()) => panic!("flush barrier completed without a writer"),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
        }

        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Barrier { .. })
        ));
    }

    #[tokio::test]
    async fn flush_without_queued_writes_skips_the_barrier() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        // A flush with nothing outstanding must complete without a round trip
        // through the session writer: the copy loop flushes on every poll, and
        // paying a channel reservation plus timer registrations each time is
        // what saturated the runtime's timer wheel.
        tokio::time::timeout(std::time::Duration::from_millis(100), stream.flush())
            .await
            .expect("no-op flush must not block")
            .expect("no-op flush must succeed");
        assert!(outbound_rx.try_recv().is_err(), "no command should be sent");

        // After a write, the flush does raise a barrier again.
        stream.write_all(b"payload").await.unwrap();
        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Data { .. })
        ));
        let mut flush = Box::pin(stream.flush());
        let _ = futures::future::poll_fn(|cx| {
            let poll = flush.as_mut().poll(cx);
            // Drive it once; the barrier is queued but never completed here.
            Poll::Ready(poll)
        })
        .await;
        assert!(matches!(
            outbound_rx.recv().await,
            Some(OutboundCommand::Barrier { .. })
        ));
    }

    #[tokio::test]
    async fn flush_barrier_times_out_while_the_outbound_queue_is_full() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        outbound_tx
            .send(OutboundCommand::Data {
                stream_id: 99,
                data: vec![1],
            })
            .await
            .unwrap();
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );
        // The queue is already full, so a real write cannot be issued here;
        // mark the stream as having queued payload so the flush raises a
        // barrier and exercises the blocked-reservation timeout.
        stream.write_dirty = true;

        let error = tokio::time::timeout(std::time::Duration::from_millis(100), stream.flush())
            .await
            .expect("flush remained stuck while reserving an outbound queue slot")
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn shutdown_times_out_while_the_outbound_queue_is_full() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        outbound_tx
            .send(OutboundCommand::Data {
                stream_id: 99,
                data: vec![1],
            })
            .await
            .unwrap();
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        let error = tokio::time::timeout(std::time::Duration::from_millis(100), stream.shutdown())
            .await
            .expect("shutdown remained stuck while reserving an outbound queue slot")
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn write_times_out_while_the_outbound_queue_is_full() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        outbound_tx
            .send(OutboundCommand::Data {
                stream_id: 99,
                data: vec![1],
            })
            .await
            .unwrap();
        let mut stream = VirtualStream::new(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
        );

        let error = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(b"blocked"),
        )
        .await
        .expect("write remained stuck while reserving an outbound queue slot")
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn write_times_out_while_smux_v2_flow_control_is_stalled() {
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        let (_terminal_tx, terminal_rx) = oneshot::channel();
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let (updates_tx, _updates_rx) = mpsc::channel(1);
        let flow = Arc::new(SmuxV2FlowControl::new());
        flow.update(0, 0).unwrap();
        let mut stream = VirtualStream::new_smux_v2(
            7,
            InboundChannels::new(inbound_rx, terminal_rx),
            outbound_tx,
            1024,
            flow,
            updates_tx,
            1024,
        );

        let error = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.write_all(b"blocked"),
        )
        .await
        .expect("write remained stuck behind smux v2 flow control")
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
