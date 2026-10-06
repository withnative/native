//! Scoped deterministic test machinery. Ordinary callers install no controls.
//! No Db, account, incarnation, fingerprint or executor leaves this module.
use super::personal_registry::PersonalAlphaRegistryFingerprint;
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::task::Poll;
use tokio::sync::Notify;

#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PersonalAlphaRegistryReadTestPoint {
    Projection,
    IdentityObservation,
    FinalIdentity,
}
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PersonalAlphaRegistryStageTestPoint {
    BeforeLock,
    HoldingLock,
}

#[derive(Default)]
struct Gate {
    reached: Notify,
    release: Notify,
    sync_release: (Mutex<bool>, Condvar),
}
impl Gate {
    async fn async_checkpoint(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
    fn sync_checkpoint(&self) {
        self.reached.notify_one();
        let (released, cv) = &self.sync_release;
        let mut released = released.lock().expect("test gate poisoned");
        while !*released {
            released = cv.wait(released).expect("test gate poisoned");
        }
    }
    fn release(&self) {
        self.release.notify_one();
        *self.sync_release.0.lock().expect("test gate poisoned") = true;
        self.sync_release.1.notify_one();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct BaselineSnapshot {
    pub initial: bool,
    pub fingerprint: Option<PersonalAlphaRegistryFingerprint>,
}
struct StageResult {
    before: BaselineSnapshot,
    after: BaselineSnapshot,
    refused: bool,
}

/// One-shot task-scoped controls for actual hosted body polling. Not a
/// production authority/callback interface; fields and observed state private.
#[doc(hidden)]
pub struct PersonalAlphaRegistryTestControls {
    read: Option<PersonalAlphaRegistryReadTestPoint>,
    stage: Option<PersonalAlphaRegistryStageTestPoint>,
    update_only: bool,
    entered: std::sync::atomic::AtomicBool,
    gate: Gate,
    read_pending: Notify,
    retirement_contended: Notify,
    result: Mutex<Option<StageResult>>,
}
impl PersonalAlphaRegistryTestControls {
    fn new(
        read: Option<PersonalAlphaRegistryReadTestPoint>,
        stage: Option<PersonalAlphaRegistryStageTestPoint>,
    ) -> Arc<Self> {
        Arc::new(Self {
            read,
            stage,
            update_only: false,
            entered: false.into(),
            gate: Gate::default(),
            read_pending: Notify::new(),
            retirement_contended: Notify::new(),
            result: Mutex::new(None),
        })
    }
    pub fn pending_read(point: PersonalAlphaRegistryReadTestPoint) -> Arc<Self> {
        Self::new(Some(point), None)
    }
    pub fn stage_order(point: PersonalAlphaRegistryStageTestPoint) -> Arc<Self> {
        Self::new(None, Some(point))
    }
    pub fn stage_update_order(point: PersonalAlphaRegistryStageTestPoint) -> Arc<Self> {
        let mut controls = Self::new(None, Some(point));
        Arc::get_mut(&mut controls)
            .expect("new test controls")
            .update_only = true;
        controls
    }
    pub fn assert_no_stage(&self) {
        assert!(
            self.result.lock().expect("test result poisoned").is_none(),
            "pending observation cannot stage a baseline"
        );
    }
    pub fn assert_refused_known_baseline_unchanged(&self) {
        self.assert_refused_without_baseline_advance();
        let result = self.result.lock().expect("test result poisoned");
        let result = result.as_ref().expect("actual stage result required");
        assert!(
            result.before.initial && result.before.fingerprint.is_some(),
            "failed update must preserve an established complete baseline"
        );
    }
    pub async fn wait_until_reached(&self) {
        self.gate.reached.notified().await;
    }
    pub async fn wait_until_read_pending(&self) {
        self.read_pending.notified().await;
    }
    pub async fn wait_until_retirement_contended(&self) {
        self.retirement_contended.notified().await;
    }
    pub fn release(&self) {
        self.gate.release();
    }
    pub fn assert_refused_without_baseline_advance(&self) {
        let result = self.result.lock().expect("test result poisoned");
        let result = result.as_ref().expect("actual stage result required");
        assert!(
            result.refused && result.before == result.after,
            "failed final fence must preserve the private baseline"
        );
    }
    pub fn assert_staged_complete_initial(&self) {
        let result = self.result.lock().expect("test result poisoned");
        let result = result.as_ref().expect("actual stage result required");
        assert!(
            !result.refused
                && !result.before.initial
                && result.after.initial
                && result.after.fingerprint.is_some()
                && result.before != result.after,
            "owned prompt and complete initial baseline must stage together"
        );
    }
    pub(super) fn stage_checkpoint(
        &self,
        point: PersonalAlphaRegistryStageTestPoint,
        initial: bool,
    ) {
        if self.stage == Some(point)
            && (!self.update_only || !initial)
            && !self.entered.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.gate.sync_checkpoint();
        }
    }
    pub(super) fn record_stage(
        &self,
        before: BaselineSnapshot,
        after: BaselineSnapshot,
        refused: bool,
    ) {
        *self.result.lock().expect("test result poisoned") = Some(StageResult {
            before,
            after,
            refused,
        });
    }
    pub(super) fn retirement_contended(&self) {
        self.retirement_contended.notify_one();
    }
}

tokio::task_local! { static CONTROLS: Arc<PersonalAlphaRegistryTestControls>; }
pub(super) fn current() -> Option<Arc<PersonalAlphaRegistryTestControls>> {
    CONTROLS.try_with(Arc::clone).ok()
}

#[doc(hidden)]
pub async fn with_personal_alpha_registry_test_controls<F: Future>(
    controls: Arc<PersonalAlphaRegistryTestControls>,
    future: F,
) -> F::Output {
    CONTROLS.scope(controls, future).await
}
#[doc(hidden)]
pub fn with_personal_alpha_registry_test_controls_sync<T>(
    controls: Arc<PersonalAlphaRegistryTestControls>,
    operation: impl FnOnce() -> T,
) -> T {
    CONTROLS.sync_scope(controls, operation)
}

pub(super) async fn read<F: Future>(
    point: PersonalAlphaRegistryReadTestPoint,
    future: F,
) -> F::Output {
    let Some(controls) = current().filter(|controls| {
        controls.read == Some(point)
            && !controls
                .entered
                .swap(true, std::sync::atomic::Ordering::SeqCst)
    }) else {
        return future.await;
    };
    controls.gate.async_checkpoint().await;
    // Poll the REAL read future. A pool-saturated fixture makes its read
    // snapshot acquisition Pending. No fake result or after-return delay.
    let mut future = Box::pin(future);
    let ready = std::future::poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending => {
            controls.read_pending.notify_one();
            Poll::Ready(None)
        }
    })
    .await;
    match ready {
        Some(value) => value,
        None => future.await,
    }
}
