//! Trusted-Rust scheduling support for isolated HTTP cancellation proofs.
//! Compiled for held integration tests; ordinary commands have no task scope.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ControlCommitTestPhase {
    BeforeDriver,
    AfterDurableBeforeCompletion,
}

/// No transaction, account, payload, or completion authority is exposed.
#[doc(hidden)]
#[derive(Default)]
pub struct ControlCommitTestGate {
    entered: AtomicBool,
    released: AtomicBool,
    completion: AtomicUsize,
    reached: Notify,
    release: Notify,
}

impl ControlCommitTestGate {
    pub async fn wait_until_reached(&self) {
        loop {
            let notified = self.reached.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    /// True only when an actual request marker was present and still unmarked
    /// at this command's gate. Absence is not evidence of an unmarked request.
    pub fn request_completion_unmarked(&self) -> bool {
        self.completion.load(Ordering::Acquire) == 1
    }

    pub fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release.notify_one();
    }

    /// Keep this guard OUTSIDE the HTTP future before its first poll.
    pub fn release_on_drop(self: &Arc<Self>) -> ControlCommitTestRelease {
        ControlCommitTestRelease(Arc::clone(self))
    }

    async fn checkpoint(&self, completion: Option<bool>) {
        // Only the first matching command in the explicitly scoped future.
        if self.entered.load(Ordering::Acquire) {
            return;
        }
        self.completion.store(
            match completion {
                Some(false) => 1,
                Some(true) => 2,
                None => 3,
            },
            Ordering::Release,
        );
        self.entered.store(true, Ordering::Release);
        self.reached.notify_one();
        loop {
            let notified = self.release.notified();
            if self.released.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

#[doc(hidden)]
pub struct ControlCommitTestRelease(Arc<ControlCommitTestGate>);
impl Drop for ControlCommitTestRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Scope {
    handle: uuid::Uuid,
    phase: ControlCommitTestPhase,
    gate: Arc<ControlCommitTestGate>,
}

tokio::task_local! {
    static CONTROL_COMMIT_TEST: Scope;
}

pub(super) async fn scoped<F: Future>(
    handle: uuid::Uuid,
    phase: ControlCommitTestPhase,
    gate: Arc<ControlCommitTestGate>,
    future: F,
) -> F::Output {
    CONTROL_COMMIT_TEST
        .scope(
            Scope {
                handle,
                phase,
                gate,
            },
            future,
        )
        .await
}

pub(super) async fn checkpoint(
    handle: uuid::Uuid,
    phase: ControlCommitTestPhase,
    completion: impl FnOnce() -> Option<bool>,
) {
    // Real default-path cost: one task-local miss at each boundary. Identity
    // comparison/Arc clone/marker observation occur only in a matching scope.
    let gate = CONTROL_COMMIT_TEST
        .try_with(|scope| {
            (scope.handle == handle && scope.phase == phase).then(|| Arc::clone(&scope.gate))
        })
        .ok()
        .flatten();
    if let Some(gate) = gate {
        gate.checkpoint(completion()).await;
    }
}

// Real driver probe: ownership lives in the workspace pool release chain,
// which runs in SQLx's return task rather than the cancelled request scope.
use sqlx::{Connection, SqliteConnection};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub enum PendingControlCommitMark {
    Armed,
    Pending,
    Entered,
    HeldPending,
    Cancelled,
    Released,
    Deadline,
    Exited,
    Drained,
    Removed,
    CleanupClean,
    Unresolved,
}
struct PendingState {
    start: Instant,
    held: bool,
    held_since: Option<Instant>,
    released: bool,
    deadline: bool,
    fresh_pending: bool,
    cancelled: bool,
    completion: Option<bool>,
    entries: usize,
    cleanup: Option<bool>,
    timeline: [Option<(PendingControlCommitMark, u128)>; 24],
}
impl PendingState {
    fn mark(&mut self, mark: PendingControlCommitMark) {
        if let Some(slot) = self.timeline.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((mark, self.start.elapsed().as_micros()));
        }
    }
    fn currently_held(&self) -> bool {
        self.held
            && !self.released
            && !self.deadline
            && self
                .held_since
                .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
    }
}
/// Opaque trusted-Rust scheduling observation; no SQL/account/payload authority.
#[doc(hidden)]
pub struct PendingControlCommitProbe {
    claimed: AtomicBool,
    state: Mutex<PendingState>,
    permit: Condvar,
    entered: Notify,
    witnessed: Notify,
    cleaned: Notify,
}
impl Default for PendingControlCommitProbe {
    fn default() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            state: Mutex::new(PendingState {
                start: Instant::now(),
                held: false,
                held_since: None,
                released: false,
                deadline: false,
                fresh_pending: false,
                cancelled: false,
                completion: None,
                entries: 0,
                cleanup: None,
                timeline: [None; 24],
            }),
            permit: Condvar::new(),
            entered: Notify::new(),
            witnessed: Notify::new(),
            cleaned: Notify::new(),
        }
    }
}
impl PendingControlCommitProbe {
    fn lock(&self) -> std::sync::MutexGuard<'_, PendingState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn callback(&self) -> bool {
        let mut s = self.lock();
        s.entries = s.entries.saturating_add(1);
        if s.entries != 1 || s.released {
            return true;
        }
        s.held = true;
        s.held_since = Some(Instant::now());
        s.mark(PendingControlCommitMark::Entered);
        self.entered.notify_one();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !s.released {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                s.deadline = true;
                s.mark(PendingControlCommitMark::Deadline);
                break;
            }
            let (next, _) = self
                .permit
                .wait_timeout(s, remaining)
                .unwrap_or_else(|p| p.into_inner());
            s = next;
        }
        s.held = false;
        s.mark(PendingControlCommitMark::Exited);
        true // ALWAYS permit; never manufacture rollback or driver error.
    }
    pub fn release(&self) {
        let mut s = self.lock();
        if !s.released {
            s.released = true;
            s.mark(PendingControlCommitMark::Released);
        }
        drop(s);
        self.permit.notify_all();
    }
    pub fn release_on_drop(self: &Arc<Self>) -> PendingControlCommitRelease {
        PendingControlCommitRelease(self.clone())
    }
    pub async fn wait_held_pending(&self) {
        loop {
            let notified = self.witnessed.notified();
            if self.lock().fresh_pending {
                return;
            }
            notified.await;
        }
    }
    /// Caller must drop its actual owned HTTP future here. No await/SQLite
    /// work occurs under this short lock; release stays outside the caller.
    pub fn cancel_if_currently_held(&self, cancel: impl FnOnce()) -> bool {
        let mut s = self.lock();
        if !s.fresh_pending || !s.currently_held() || s.cancelled {
            return false;
        }
        cancel();
        s.cancelled = true;
        s.mark(PendingControlCommitMark::Cancelled);
        true
    }
    pub fn request_completion_unmarked(&self) -> bool {
        self.lock().completion == Some(false)
    }
    pub fn callback_entries(&self) -> usize {
        self.lock().entries
    }
    pub fn timeline(&self) -> [Option<(PendingControlCommitMark, u128)>; 24] {
        self.lock().timeline
    }
    pub async fn wait_cleanup_ack(&self) -> bool {
        loop {
            let notified = self.cleaned.notified();
            if let Some(clean) = self.lock().cleanup {
                return clean;
            }
            notified.await;
        }
    }
    fn finish(&self, clean: bool) {
        let mut s = self.lock();
        if s.cleanup.is_none() {
            s.cleanup = Some(clean);
            s.mark(if clean {
                PendingControlCommitMark::CleanupClean
            } else {
                PendingControlCommitMark::Unresolved
            });
        }
        drop(s);
        self.cleaned.notify_waiters();
    }
    async fn monitor<F: Future>(&self, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut entered = Box::pin(self.entered.notified());
        std::future::poll_fn(|cx| {
            let mut s = self.lock();
            if !s.currently_held() && entered.as_mut().poll(cx).is_ready() {
                entered = Box::pin(self.entered.notified());
                let _ = entered.as_mut().poll(cx);
            }
            let result = future.as_mut().poll(cx);
            if result.is_pending() {
                if s.currently_held() {
                    if !s.fresh_pending {
                        s.fresh_pending = true;
                        s.mark(PendingControlCommitMark::HeldPending);
                        self.witnessed.notify_one();
                    }
                } else {
                    s.mark(PendingControlCommitMark::Pending);
                }
            }
            result
        })
        .await
    }
}
#[doc(hidden)]
pub struct PendingControlCommitRelease(Arc<PendingControlCommitProbe>);
impl Drop for PendingControlCommitRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Default)]
pub(super) struct PoolProbeRegistry {
    active: AtomicBool,
    leases: Mutex<HashMap<usize, Arc<Lease>>>,
}
impl std::fmt::Debug for PoolProbeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoolProbeRegistry(<private>)")
    }
}
struct Lease {
    key: usize,
    token: uuid::Uuid,
    registry: Weak<PoolProbeRegistry>,
    probe: Arc<PendingControlCommitProbe>,
    removing: AtomicBool,
}
impl Lease {
    fn unregister(&self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut leases = registry.leases.lock().unwrap_or_else(|p| p.into_inner());
            if leases
                .get(&self.key)
                .is_some_and(|lease| lease.token == self.token)
            {
                leases.remove(&self.key);
            }
            registry.active.store(!leases.is_empty(), Ordering::Release);
        }
    }
}
struct HookCapture(Arc<Lease>);
impl HookCapture {
    fn permit(&self) -> bool {
        self.0.probe.callback()
    }
}
impl Drop for HookCapture {
    fn drop(&mut self) {
        if !self.0.removing.load(Ordering::Acquire) {
            self.0.unregister();
            self.0.probe.finish(false); // destruction/retirement is NOT clean ACK.
        }
    }
}
struct Reservation(Arc<Lease>, bool);
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.1 {
            self.0.unregister();
            self.0.probe.finish(false);
        }
    }
}
struct PendingScope {
    handle: uuid::Uuid,
    registry: Arc<PoolProbeRegistry>,
    probe: Arc<PendingControlCommitProbe>,
}
tokio::task_local! { static PENDING_CONTROL_COMMIT: PendingScope; }
pub(super) async fn pending_scoped<F: Future>(
    handle: uuid::Uuid,
    registry: Arc<PoolProbeRegistry>,
    probe: Arc<PendingControlCommitProbe>,
    future: F,
) -> F::Output {
    PENDING_CONTROL_COMMIT
        .scope(
            PendingScope {
                handle,
                registry,
                probe,
            },
            future,
        )
        .await
}
pub(super) async fn commit(
    handle: uuid::Uuid,
    registry: Option<&Arc<PoolProbeRegistry>>,
    mut tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    completion: impl FnOnce() -> Option<bool>,
) -> crate::Result<()> {
    // Exactly one task-local miss on the default path. No extra driver await.
    let scope = PENDING_CONTROL_COMMIT
        .try_with(|s| {
            (s.handle == handle && registry.is_some_and(|r| Arc::ptr_eq(r, &s.registry)))
                .then(|| (s.registry.clone(), s.probe.clone()))
        })
        .ok()
        .flatten();
    let Some((registry, probe)) = scope else {
        return tx.commit().await.map_err(Into::into);
    };
    if probe.claimed.swap(true, Ordering::AcqRel) {
        return tx.commit().await.map_err(Into::into);
    }
    {
        let mut locked = tx.lock_handle().await?;
        // Derive from SAME lock; connection_key would recursively lock here.
        let key = locked.as_raw_handle().as_ptr() as usize;
        let lease = Arc::new(Lease {
            key,
            token: uuid::Uuid::new_v4(),
            registry: Arc::downgrade(&registry),
            probe: probe.clone(),
            removing: AtomicBool::new(false),
        });
        {
            let mut leases = registry.leases.lock().unwrap_or_else(|p| p.into_inner());
            if leases.contains_key(&key) {
                return Err(crate::error::Error::engine(
                    "pending commit probe owner collision",
                ));
            }
            leases.insert(key, lease.clone());
            registry.active.store(true, Ordering::Release);
        }
        let mut reservation = Reservation(lease.clone(), false);
        let capture = HookCapture(lease);
        locked.set_commit_hook(move || capture.permit());
        reservation.1 = true;
        let mut s = probe.lock();
        s.completion = completion();
        s.mark(PendingControlCommitMark::Armed);
    } // no locked handle, SQL or other await before actual driver commit.
    probe.monitor(tx.commit()).await.map_err(Into::into)
}

pub(super) struct CleanupLease(Arc<Lease>);
impl Drop for CleanupLease {
    fn drop(&mut self) {
        self.0.unregister();
        self.0.probe.finish(false); // no-op after successful clean ACK
    }
}
pub(super) fn matching(registry: &PoolProbeRegistry, key: Option<usize>) -> Option<CleanupLease> {
    if !registry.active.load(Ordering::Acquire) {
        return None;
    }
    let lease = registry
        .leases
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&key?)
        .cloned();
    lease.map(CleanupLease) // mutex gone BEFORE driver awaits
}
impl CleanupLease {
    pub(super) async fn remove(&self, connection: &mut SqliteConnection) -> sqlx::Result<bool> {
        connection.ping().await?;
        self.0.probe.lock().mark(PendingControlCommitMark::Drained);
        let mut locked = connection.lock_handle().await?;
        if locked.as_raw_handle().as_ptr() as usize != self.0.key {
            return Ok(false);
        }
        self.0.removing.store(true, Ordering::Release);
        // No callback/registry state lock while removal destroys HookCapture.
        locked.remove_commit_hook();
        drop(locked);
        let mut s = self.0.probe.lock();
        s.mark(PendingControlCommitMark::Removed);
        Ok(!s.deadline)
    }
    pub(super) fn clean(&self) {
        self.0.unregister();
        self.0.probe.finish(true);
    }
}
