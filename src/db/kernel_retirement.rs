//! Explicit inactive kernel retirement cohort. Kernel readiness, body/enrolled
//! readiness and actual per-handle physical ACK are independent conjuncts.
use super::*;
use crate::coedit::live::{
    self, KernelLifecycleRegistration, KernelRetirementState, KernelRetirementWitness,
};
use futures::FutureExt;

// Preserve Db's existing derived Debug without exposing the opaque owner graph.
impl fmt::Debug for KernelLifecycleRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KernelLifecycleRegistration(..)")
    }
}

#[allow(dead_code)] // Private native observations; no public/host status API yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Observation {
    Kernel(KernelRetirementState),
    EnrolledUnresolved,
    BodyUnresolved,
    PoolsClosing,
    Uncertain,
    Complete,
}

struct Retained {
    db: Db,
    kernel: KernelRetirementWitness,
}
#[derive(Clone, Copy)]
struct Acknowledged {
    handle: uuid::Uuid,
    #[allow(dead_code)] // Exact acknowledged correlation retained after graph release.
    seal: uuid::Uuid,
}
struct State {
    // Deliberate unresolved custody cycle: Db -> cache -> coordinator -> Db.
    // acknowledge() breaks it ONLY after actual semantic AND physical ACK.
    retained: Option<Arc<Retained>>,
    physical: Option<BodyRetirementFuture>,
    physical_started: bool,
    acknowledged: Option<Acknowledged>,
    background_running: bool,
    background_generation: u64,
    background: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct Coordinator {
    state: Mutex<State>,
    uncertain: AtomicBool,
    #[cfg(test)]
    physical_starts: AtomicUsize,
    #[cfg(test)]
    physical_checkpoint: Mutex<Option<Arc<PhysicalCheckpoint>>>,
    #[cfg(test)]
    background_publication: Mutex<Option<Arc<BackgroundPublicationCheckpoint>>>,
}
impl fmt::Debug for Coordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KernelRetirementCoordinator(..)")
    }
}
impl Coordinator {
    pub(super) fn sealed(db: &Db) -> Arc<Self> {
        // The private marker, not filename/schema/room absence, selects us.
        debug_assert!(db.kernel_lifecycle.is_some());
        let kernel = live::seal_kernel_retirement(db);
        Arc::new(Self {
            state: Mutex::new(State {
                retained: Some(Arc::new(Retained {
                    db: db.clone(),
                    kernel,
                })),
                physical: None,
                physical_started: false,
                acknowledged: None,
                background_running: false,
                background_generation: 0,
                background: None,
            }),
            uncertain: AtomicBool::new(false),
            #[cfg(test)]
            physical_starts: AtomicUsize::new(0),
            #[cfg(test)]
            physical_checkpoint: Mutex::new(None),
            #[cfg(test)]
            background_publication: Mutex::new(None),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| {
            self.uncertain.store(true, Ordering::Release);
            poisoned.into_inner()
        })
    }

    #[allow(dead_code)] // Exercised by native proofs before a host consumer exists.
    pub(super) fn observe(&self) -> Observation {
        if self.uncertain.load(Ordering::Acquire) {
            return Observation::Uncertain;
        }
        let state = self.lock();
        if self.uncertain.load(Ordering::Acquire) {
            return Observation::Uncertain;
        }
        if state.acknowledged.is_some() {
            return Observation::Complete;
        }
        let Some(retained) = state.retained.clone() else {
            return Observation::Uncertain;
        };
        drop(state);
        let kernel = retained.kernel.observe();
        if kernel != KernelRetirementState::Quiescent {
            return Observation::Kernel(kernel);
        }
        if !retained
            .db
            .execution_jobs
            .retirement_ready(retained.db.execution_owner.as_ref())
        {
            return Observation::EnrolledUnresolved;
        }
        if !retained.db.body_jobs.retirement_ready() {
            return Observation::BodyUnresolved;
        }
        Observation::PoolsClosing
    }

    pub(super) fn complete_for(&self, db: &Db) -> bool {
        if self.uncertain.load(Ordering::Acquire) {
            return false;
        }
        let acknowledged = self.lock().acknowledged;
        !self.uncertain.load(Ordering::Acquire)
            && acknowledged.is_some_and(|ack| ack.handle == db.handle_id())
            && db.body_jobs.retirement_ready()
            && db.enrolled_retirement_complete()
    }

    #[allow(dead_code)] // Correlation only, never retirement/append authority.
    pub(super) fn seal_id(&self) -> uuid::Uuid {
        let state = self.lock();
        state
            .acknowledged
            .map(|ack| ack.seal)
            .or_else(|| state.retained.as_ref().map(|r| r.kernel.seal_id()))
            .expect("retirement coordinator retains exact seal evidence")
    }

    pub(super) async fn drain(self: &Arc<Self>) -> bool {
        // Panic is actual unknown work; dropping this observer is not. The
        // original L1 pass and physical future remain retained in the cache.
        match std::panic::AssertUnwindSafe(self.attempt())
            .catch_unwind()
            .await
        {
            Ok(complete) => complete,
            Err(_) => {
                self.uncertain.store(true, Ordering::Release);
                false
            }
        }
    }

    async fn attempt(self: &Arc<Self>) -> bool {
        if self.uncertain.load(Ordering::Acquire) {
            return false;
        }
        let retained = {
            let state = self.lock();
            if state.acknowledged.is_some() {
                return !self.uncertain.load(Ordering::Acquire);
            }
            state.retained.clone()
        };
        let Some(retained) = retained else {
            return false;
        };
        if retained.kernel.drive_once().await != KernelRetirementState::Quiescent {
            return false; // recoverable policy observations are NOT cached.
        }
        if !retained
            .db
            .execution_jobs
            .stop_and_drain(retained.db.execution_owner.as_ref())
            .await
        {
            return false;
        }
        if !retained.db.body_jobs.drain().await {
            return false;
        }
        if self.uncertain.load(Ordering::Acquire) {
            return false;
        }
        let physical = {
            let mut state = self.lock();
            if self.uncertain.load(Ordering::Acquire) {
                return false;
            }
            if state.acknowledged.is_some() {
                return true;
            }
            if let Some(physical) = &state.physical {
                physical.clone()
            } else {
                if state.physical_started {
                    self.uncertain.store(true, Ordering::Release);
                    return false;
                }
                state.physical_started = true;
                #[cfg(test)]
                self.physical_starts.fetch_add(1, Ordering::SeqCst);
                let weak = Arc::downgrade(self);
                let original = retained.clone();
                #[cfg(test)]
                let checkpoint = self.physical_checkpoint.lock().unwrap().clone();
                // This future is stored BEFORE first poll. Its completion
                // callback runs within the original future, not after an
                // observer await (which could otherwise abandon the cycle).
                let physical = async move {
                    let result = std::panic::AssertUnwindSafe(async {
                        #[cfg(test)]
                        if let Some(checkpoint) = checkpoint {
                            checkpoint.entered.notify_one();
                            checkpoint.release.notified().await;
                            assert!(!checkpoint.panic, "injected original physical future panic");
                        }
                        let db = &original.db;
                        if !db.demand_root_aliases.stop().await {
                            return false;
                        }
                        db.capture_queue.initiate_shutdown();
                        db.capture_queue.drain_capped().await;
                        if let Some(pool) = db.capture_pool.get() {
                            close_pool_and_drain(pool).await;
                        }
                        db.mark_pools_closed();
                        tokio::join!(
                            close_pool_and_drain(&db.read_pool),
                            close_pool_and_drain(&db.write_pool),
                            close_pool_and_drain(&db.governed_pool)
                        );
                        original.kernel.observe() == KernelRetirementState::Quiescent
                            && db.body_jobs.retirement_ready()
                            && db.enrolled_retirement_complete()
                    })
                    .catch_unwind()
                    .await;
                    let Some(coordinator) = weak.upgrade() else {
                        return false;
                    };
                    if matches!(result, Ok(true)) {
                        coordinator.acknowledge(&original)
                    } else {
                        coordinator.uncertain.store(true, Ordering::Release);
                        false
                    }
                }
                .boxed()
                .shared();
                state.physical = Some(physical.clone());
                physical
            }
        };
        physical.await && self.complete_for(&retained.db)
    }

    fn acknowledge(&self, original: &Retained) -> bool {
        let mut state = self.lock();
        if self.uncertain.load(Ordering::Acquire) {
            return false;
        }
        // Actual original-future completion is the ONLY writer of this proof.
        state.acknowledged = Some(Acknowledged {
            handle: original.db.handle_id(),
            seal: original.kernel.seal_id(),
        });
        // Break BOTH handle/future cycles. Running observers may still own
        // local clones, but the retained cache no longer pins a completed Db.
        state.retained.take();
        state.physical.take();
        true
    }

    pub(super) fn start_background(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let generation = {
            let mut state = self.lock();
            if state.background_running
                || state.acknowledged.is_some()
                || self.uncertain.load(Ordering::Acquire)
            {
                return;
            }
            let Some(generation) = state.background_generation.checked_add(1) else {
                self.uncertain.store(true, Ordering::Release);
                return;
            };
            state.background_generation = generation;
            state.background_running = true;
            generation
        };
        // Spawn can synchronously reject/drop its future on a stopped runtime.
        // Never hold state while spawning or destroying the pre-spawn guard.
        let guard = Background {
            coordinator: self.clone(),
            generation,
            finished: false,
        };
        let mut handle = Some(runtime.spawn(async move {
            let mut guard = guard;
            let _ = guard.coordinator.drain().await;
            guard.finished = true;
        }));
        #[cfg(test)]
        {
            let checkpoint = self.background_publication.lock().unwrap().clone();
            if let Some(checkpoint) = checkpoint {
                checkpoint.entered.send(()).unwrap();
                checkpoint.release.lock().unwrap().recv().unwrap();
            }
        }
        {
            let mut state = self.lock();
            // Completion/drop may precede publication, and a completed known
            // refusal may already have permitted a newer attempt. Never revive
            // the old slot or replace that newer attempt's retained handle.
            if state.background_running && state.background_generation == generation {
                debug_assert!(state.background.is_none());
                state.background = handle.take();
            }
        }
        // A stale/completed handle owns no running observer; drop outside state.
        drop(handle);
    }
}

struct Background {
    coordinator: Arc<Coordinator>,
    generation: u64,
    finished: bool,
}
impl Drop for Background {
    fn drop(&mut self) {
        let handle = {
            let mut state = self.coordinator.lock();
            if !self.finished {
                self.coordinator.uncertain.store(true, Ordering::Release);
            }
            if state.background_generation != self.generation {
                return;
            }
            state.background_running = false;
            // Drop before handle publication leaves this attempt inactive;
            // its spawning caller must discard the subsequently returned handle.
            state.background.take()
        };
        // Dropping a JoinHandle does not abort its task. Clear its reference
        // cycle outside state, including cancellation before the first poll.
        drop(handle);
    }
}

/// Private test factories alone call this after verified creation/open succeeds
/// and before publishing any Db, pool, registry or operation to their fixture.
/// Arc exclusivity detects outstanding Db clones, not historical raw pool
/// publication; the audited owning wrappers provide that additional proof.
#[cfg(test)]
pub(super) fn install_verified_owned(mut db: Db) -> Result<Db> {
    if db.kernel_lifecycle.is_some() {
        return Ok(db);
    }
    if db.execution_owner.is_some()
        || db.body_retirement.get().is_some()
        || db.read_pool.is_closed()
        || db.write_pool.is_closed()
        || db.governed_pool.is_closed()
        || db.execution_jobs.retirement_ready(None)
        || Arc::get_mut(&mut db.body_retirement).is_none()
        || Arc::get_mut(&mut db.body_jobs).is_none()
        || Arc::get_mut(&mut db.execution_jobs).is_none()
    {
        return Err(Error::engine(
            "kernel lifecycle fixture requires an unpublished unfenced handle",
        ));
    }
    // Existing supported ticket/no-start settlement checks body stopping and
    // unknown state without reading/mutating the private body ledger directly.
    db.body_jobs.register()?.no_physical_started()?;
    db.kernel_lifecycle = Some(live::register_kernel_lifecycle(&db));
    Ok(db)
}

#[cfg(test)]
struct PhysicalCheckpoint {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    panic: bool,
}

#[cfg(test)]
struct BackgroundPublicationCheckpoint {
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
#[path = "kernel_retirement_tests.rs"]
mod tests;
