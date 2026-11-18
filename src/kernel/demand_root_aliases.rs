//! Once-per-open-generation verification of the logical-root alias invariant.
//! Never scan events on a request: unknown/failed checks cost speed, not rows.
use super::*;
use futures::FutureExt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum State {
    #[default]
    Unknown,
    NoRecordlessRootAliases,
    HasAliases,
}

#[derive(Default)]
struct Stop {
    requested: AtomicBool,
    changed: tokio::sync::Notify,
}
impl Stop {
    fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    async fn cancelled(&self) {
        let changed = self.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if !self.requested.load(Ordering::Acquire) {
            changed.await;
        }
    }
}
#[derive(Clone)]
struct Job {
    completion: Completion,
    stop: Arc<Stop>,
    terminal: Arc<AtomicU8>,
}
fn slots() -> Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
        .clone()
}

type Completion = futures::future::Shared<futures::future::BoxFuture<'static, bool>>;
#[derive(Default)]
struct Inner {
    generation: u64,
    started: bool,
    completed: bool,
    stopping: bool,
    state: State,
    jobs: Vec<Job>,
}

/// Owned by one Db incarnation; clones share it. A replacement/adopted
/// generation opens a new Db (and thus a new unknown Check). Explicit replay
/// and pending-copy generation changes invalidate it before reuse.
#[derive(Default)]
pub(crate) struct Check {
    inner: Mutex<Inner>,
    changed: tokio::sync::Notify,
    #[cfg(test)]
    hold: Mutex<Option<Arc<tokio::sync::Notify>>>,
    #[cfg(test)]
    close_hold: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    #[cfg(test)]
    test_slots: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    #[cfg(test)]
    pub(crate) stop_entered: tokio::sync::Notify,
    #[cfg(test)]
    slot_waiting: tokio::sync::Notify,
}
impl std::fmt::Debug for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootAliasCheck")
            .field("state", &self.state())
            .finish()
    }
}

impl Check {
    pub(crate) fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    pub(crate) fn invalidate(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.generation += 1;
        inner.started = false;
        inner.completed = false;
        inner.state = State::Unknown;
        // Retain original physical completions across invalidation. Never
        // abort a query and mistake cancellation for its driver's close ACK.
        for job in &inner.jobs {
            job.stop.request();
        }
        // Preserve a failed physical close as uncertain; only acknowledged
        // jobs can be discarded across a generation change.
        inner
            .jobs
            .retain(|job| job.terminal.load(Ordering::Acquire) != 1);
        drop(inner);
        self.changed.notify_waiters();
    }

    pub(crate) fn fence(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.stopping = true;
        for job in &inner.jobs {
            job.stop.request();
        }
        inner.generation += 1;
        inner.state = State::Unknown;
    }

    pub(crate) fn retirement_complete(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .jobs
            .iter()
            // Observation never polls physical work (including without a
            // runtime). Only the original future publishes its close ACK.
            .all(|job| job.terminal.load(Ordering::Acquire) == 1)
    }

    /// Retirement observes the same retained completions even if an earlier
    /// close observer was cancelled. Each worker explicitly closes its lease
    /// before completing. The scan itself has a SQLite worker deadline.
    // Keep S1b's retained-work observer out of callers' inline async layout.
    pub(crate) fn stop(&self) -> futures::future::BoxFuture<'_, bool> {
        async move {
            self.fence();
            let jobs = self.inner.lock().unwrap().jobs.clone();
            #[cfg(test)]
            self.stop_entered.notify_one();
            let mut complete = true;
            for job in jobs {
                complete &= job.completion.await;
            }
            complete
        }
        .boxed()
    }

    pub(crate) fn start(db: &Db) {
        Self::start_pool(db.demand_root_aliases.clone(), db.pool().clone());
    }

    fn start_pool(check: Arc<Self>, pool: sqlx::SqlitePool) {
        let mut inner = check.inner.lock().unwrap();
        if inner.started || inner.stopping {
            return;
        }
        inner.started = true;
        // A verifier must never occupy the sole read slot (e.g. a standby
        // head writer). Unknown selects the existing request fallback.
        if pool.options().get_max_connections() <= 1 {
            inner.completed = true;
            return;
        }
        let generation = inner.generation;
        // Retain only the read-only pool, never lifecycle/writer Db authority.
        #[cfg(test)]
        let hold = check.hold.lock().unwrap().clone();
        #[cfg(test)]
        let close_hold = check.close_hold.lock().unwrap().clone();
        let capacity = slots();
        #[cfg(test)]
        let capacity = check.test_slots.lock().unwrap().clone().unwrap_or(capacity);
        let stop = Arc::<Stop>::default();
        let worker_stop = stop.clone();
        // A panic before acquisition carries no lease uncertainty. After
        // acquisition only the actual close ACK clears this flag.
        let held = Arc::new(AtomicBool::new(false));
        let worker_held = held.clone();
        let worker_check = check.clone();
        // Retain the ORIGINAL future, not a JoinHandle's observer outcome.
        // Runtime shutdown may cancel the background observer after acquiring
        // a lease; stop() on a later runtime must resume that same close.
        let terminal = Arc::new(AtomicU8::new(0));
        let worker_terminal = terminal.clone();
        let work = async move {
            #[cfg(test)]
            if let Some(hold) = hold {
                tokio::select! {
                    biased;
                    _ = worker_stop.cancelled() => {},
                    _ = tokio::time::timeout(BUDGET, hold.notified()) => {},
                }
            }
            #[cfg(test)]
            worker_check.slot_waiting.notify_one();
            let (state, complete) = verify(
                &pool,
                capacity,
                worker_stop,
                worker_held,
                #[cfg(test)]
                close_hold,
            )
            .await;
            let mut inner = worker_check.inner.lock().unwrap();
            if inner.generation == generation {
                inner.state = state;
                inner.completed = true;
            }
            drop(inner);
            worker_check.changed.notify_waiters();
            complete
        };
        let completion = async move {
            let complete = std::panic::AssertUnwindSafe(work)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| !held.load(Ordering::Acquire));
            worker_terminal.store(if complete { 1 } else { 2 }, Ordering::Release);
            complete
        }
        .boxed()
        .shared();
        inner.jobs.push(Job {
            stop,
            terminal,
            completion: completion.clone(),
        });
        tokio::spawn(async move {
            let _ = completion.await;
        });
    }

    #[cfg(test)]
    pub(crate) async fn settle(db: &Db) -> State {
        Self::start(db);
        tokio::time::timeout(Duration::from_secs(35), async {
            loop {
                let changed = db.demand_root_aliases.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let inner = db.demand_root_aliases.inner.lock().unwrap();
                    if inner.completed {
                        return inner.state;
                    }
                }
                changed.await;
            }
        })
        .await
        .expect("alias verification completed")
    }

    #[cfg(test)]
    pub(crate) fn pause(db: &Db) -> Arc<tokio::sync::Notify> {
        db.demand_root_aliases.invalidate();
        let gate = Arc::new(tokio::sync::Notify::new());
        *db.demand_root_aliases.hold.lock().unwrap() = Some(gate.clone());
        Self::start(db);
        gate
    }
    #[cfg(test)]
    pub(crate) async fn pause_close(db: &Db) -> Arc<tokio::sync::Notify> {
        db.demand_root_aliases.invalidate();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *db.demand_root_aliases.close_hold.lock().unwrap() =
            Some((entered.clone(), release.clone()));
        Self::start(db);
        tokio::time::timeout(BUDGET, entered.notified())
            .await
            .unwrap();
        release
    }
}

async fn verify(
    pool: &sqlx::SqlitePool,
    capacity: Arc<tokio::sync::Semaphore>,
    stop: Arc<Stop>,
    held: Arc<AtomicBool>,
    #[cfg(test)] close_hold: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
) -> (State, bool) {
    let _slot = tokio::select! {
        biased;
        _ = stop.cancelled() => return (State::Unknown, true),
        acquired = tokio::time::timeout(BUDGET, capacity.acquire_owned()) => match acquired {
            Ok(Ok(slot)) => slot,
            Ok(Err(_)) => return (State::Unknown, true),
            Err(_) => {
                // One attempt per generation: this warning is emitted once.
                tracing::warn!(target: "native_ce::read_staging", "root alias verifier capacity wait timed out");
                return (State::Unknown, true);
            }
        }
    };
    let mut conn = tokio::select! {
        biased;
        _ = stop.cancelled() => return (State::Unknown, true),
        acquired = tokio::time::timeout(BUDGET, pool.acquire()) => match acquired {
            Ok(Ok(conn)) => conn,
            _ => return (State::Unknown, true),
        }
    };
    held.store(true, Ordering::Release);
    // No timeout drops the physical query. Bound it in SQLite, await its
    // terminal result, and retain the original close until actual ACK.
    let result = async {
        let deadline = Instant::now() + BUDGET;
        conn.lock_handle().await?.set_progress_handler(10_000, move || !stop.requested.load(Ordering::Acquire) && Instant::now() < deadline);
        // Native bindings required an existing source from introduction
        // (ffcf23cf2, 19 Oct 2026); import mappings rejected native:root from
        // introduction (752b9eb81, 16 Oct). New canonical writes cannot create
        // recordless aliases. Still verify historical generations rather than
        // relying on history alone. Detect aliases even if a root record
        // exists now: each request checks its own snapshot's root existence.
        let aliases: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type IN ('kernel.import_home.v1','kernel.home_created.v1') AND record_id<>?1 AND json_extract(payload,'$.source_record_id')='native:root')")
            .bind(crate::events::KERNEL_ROOT_ID).fetch_one(&mut *conn).await?;
        Ok::<_, Error>(if aliases { State::HasAliases } else { State::NoRecordlessRootAliases })
    }.await;
    // PoolConnection::close consumes the actual lease and awaits its driver;
    // close_on_drop alone would not be a retirement acknowledgement.
    #[cfg(test)]
    if let Some((entered, release)) = close_hold {
        entered.notify_one();
        release.notified().await;
    }
    let closed = conn.close().await;
    if closed.is_ok() {
        held.store(false, Ordering::Release);
        (result.unwrap_or(State::Unknown), true)
    } else {
        (State::Unknown, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn demand_root_alias_stop_cancels_semaphore_wait_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("stop.db").display()),
            "account",
            "Admin",
            "admin",
        )
        .await
        .unwrap();
        assert!(db.pool().options().get_max_connections() > 1);
        Check::settle(&db).await;
        let _ = db
            .demand_root_aliases
            .slot_waiting
            .notified()
            .now_or_never();
        db.demand_root_aliases.invalidate();
        let capacity = Arc::new(tokio::sync::Semaphore::new(0));
        *db.demand_root_aliases.test_slots.lock().unwrap() = Some(capacity.clone());
        Check::start(&db);
        // The worker is runnable but cannot acquire any verifier slot.
        db.demand_root_aliases.slot_waiting.notified().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), db.demand_root_aliases.stop())
                .await
                .unwrap()
        );
        assert_eq!(capacity.available_permits(), 0);
        assert!(db.demand_root_aliases.retirement_complete());
        db.close().await;
    }
    #[tokio::test]
    async fn demand_root_alias_single_connection_pool_stays_unknown() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let check = Arc::<Check>::default();
        Check::start_pool(check.clone(), pool.clone());
        assert_eq!(check.state(), State::Unknown);
        assert!(check.inner.lock().unwrap().jobs.is_empty());
        // No background verifier occupies the only read slot.
        let conn = tokio::time::timeout(Duration::from_secs(1), pool.acquire())
            .await
            .unwrap()
            .unwrap();
        assert!(check.stop().await);
        conn.close().await.unwrap();
        pool.close().await;
    }

    #[test]
    fn demand_root_alias_original_close_survives_creating_runtime_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (db, _) = runtime
            .block_on(create_v2_database(
                &format!("sqlite://{}", dir.path().join("runtime-loss.db").display()),
                "account",
                "Admin",
                "admin",
            ))
            .unwrap();
        // The verifier owns a real lease, not merely a queued semaphore wait.
        let release = runtime.block_on(Check::pause_close(&db));
        drop(runtime);
        let witness = db.fence_body_retirement();
        assert!(!witness.retirement_complete());
        release.notify_one();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), witness.drain()).await })
            .unwrap());
        assert!(witness.retirement_complete());
    }
}
