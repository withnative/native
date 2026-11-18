//! Original SQLx-wrapper custody for the private manager. No replay, identity,
//! normalization, hosted verdict or commit classifier is implemented here.
//!
//! SQLx is pinned to 0.8.6 (Cargo.lock): sqlx-core/src/transaction.rs Drop
//! queues start_rollback while `open` is true; sqlx-sqlite/src/connection/worker.rs
//! makes that command a no-op at acknowledged depth zero. PoolConnection return
//! pings/flushed worker work before reuse (sqlx-core/src/pool/connection.rs).
//! Therefore a settled ORIGINAL wrapper is dropped before ANY subsequent BEGIN.
//! An unsettled wrapper is never dropped or returned to the pool.
use super::{WorkingPublication, WorkingState};
use crate::mcp::kernel_v2::PinnedWorkingRead;
use crate::{db::Db, Error, Result};
use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use tokio::sync::{Mutex, MutexGuard};

// Slots cover active AND retained uncertain jobs. There is no growing global
// vector, eviction, reaper, automatic retry or last-owner handoff on Drop.
const MAX_OWNED_WORKING_WRITES: usize = 8;
type Slot = Option<Box<dyn Any + Send>>;
static SLOTS: LazyLock<[Mutex<Slot>; MAX_OWNED_WORKING_WRITES]> =
    LazyLock::new(|| std::array::from_fn(|_| Mutex::new(None)));

/// The inner actor owns the continuously checked-out connection, collector and
/// any real borrowed Transaction in its async frame. The slot owns that frame
/// before its first poll, including connection creation and BEGIN construction.
/// A driver only borrows it. Dropping a driver cannot release the writer graph.
struct RetainedWriterActor {
    future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    _state: Arc<StdMutex<WorkingState>>,
}

/// Concrete working-owner callers must return only after acknowledged
/// settlement and connection close. An uncertain/panicked phase parks INSIDE
/// the inner actor while its actual Transaction remains outside catch_unwind;
/// it must never return an error or use `?` to leave that ownership frame.
pub(in crate::fork) fn retain_writer_actor(
    future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    state: Arc<StdMutex<WorkingState>>,
) -> Result<WriterActorHandle> {
    if *state.lock().unwrap_or_else(|e| e.into_inner()) != WorkingState::Published {
        return Err(Error::engine("working acknowledgements paused"));
    }
    let mut available = None;
    for (index, slot) in SLOTS.iter().enumerate() {
        if let Ok(mut slot) = slot.try_lock() {
            if slot.is_none() {
                *slot = Some(Box::new(RetainedWriterActor {
                    future,
                    _state: state.clone(),
                }));
                available = Some(index);
                break;
            }
        }
    }
    let index =
        available.ok_or_else(|| Error::engine("working writer custody capacity exhausted"))?;
    let driver = drive_writer_actor(index, state.clone());
    // JoinHandle Drop detaches; no caller-facing abort capability is issued.
    #[cfg(not(test))]
    drop(driver);
    Ok(WriterActorHandle {
        #[cfg(test)]
        index,
        #[cfg(test)]
        state,
        #[cfg(test)]
        driver,
    })
}

/// Called inside the retained actor, before private DDL or any published read
/// checkout. The input is the owner's exclusively held disposable verified W;
/// it must never be an accepted serving generation. Closing all shared pools
/// first makes every old clone refuse acquisition before capture can start.
pub(in crate::fork) async fn open_pinned_writer(
    handle: &super::super::ForkHandle,
) -> Result<(Db, sqlx::SqliteConnection)> {
    use sqlx::Connection;
    let disposable = &handle.db;
    if disposable.open_mode() != crate::db::DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "pinned working writer needs its disposable writable copy",
        ));
    }
    let path = disposable.path().to_path_buf();
    let retirement = disposable.fence_body_retirement();
    if !retirement.drain().await
        || !retirement.retirement_complete()
        || [
            disposable.pool(),
            disposable.write_pool(),
            disposable.governed_pool(),
        ]
        .iter()
        .any(|pool| !pool.is_closed() || pool.size() != 0)
    {
        return Err(Error::engine(
            "old working pools have not acknowledged complete retirement",
        ));
    }
    // This is the LAST verified opener. Populated private undo is never
    // submitted to accepted-generation verification or certification.
    let reader = crate::db::open_kernel_v2_standby_read_only(
        path.to_str()
            .ok_or_else(|| Error::engine("working path is not UTF-8"))?,
    )
    .await?;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        .foreign_keys(true)
        .with_regexp()
        .pragma("recursive_triggers", "ON");
    let connection = sqlx::SqliteConnection::connect_with(&options).await?;
    Ok((reader, connection))
}

/// Catch only construction while the outer retained actor still owns the
/// physical connection. Before Ok returns a wrapper, constructor disposition
/// remains SQLx-owned. On Err the actor reports failure and parks that outer
/// frame; this helper never disposes, retries, or fabricates a Transaction.
pub(in crate::fork) async fn construct_pinned_transaction(
    connection: &mut sqlx::SqliteConnection,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>> {
    use futures::FutureExt;
    use sqlx::Connection;
    match std::panic::AssertUnwindSafe(connection.begin_with("BEGIN IMMEDIATE"))
        .catch_unwind()
        .await
    {
        Ok(Ok(transaction)) => Ok(transaction),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(Error::engine(
            "working BEGIN construction panicked; retain its connection",
        )),
    }
}

pub(in crate::fork) struct WriterActorHandle {
    #[cfg(test)]
    index: usize,
    #[cfg(test)]
    state: Arc<StdMutex<WorkingState>>,
    #[cfg(test)]
    driver: tokio::task::JoinHandle<()>,
}

fn drive_writer_actor(
    index: usize,
    state: Arc<StdMutex<WorkingState>>,
) -> tokio::task::JoinHandle<()> {
    struct DriverFence {
        state: Arc<StdMutex<WorkingState>>,
        completed: bool,
    }
    impl Drop for DriverFence {
        fn drop(&mut self) {
            if !self.completed {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !matches!(
                    *state,
                    WorkingState::Closed | WorkingState::AwaitingQualifiedUndo
                ) {
                    *state = WorkingState::Quarantined;
                }
            }
        }
    }
    // Arm before spawning, so cancellation before the driver's first poll or
    // while acquiring the slot also pauses acknowledgements.
    let fence = DriverFence {
        state,
        completed: false,
    };
    tokio::spawn(async move {
        let mut fence = fence;
        let mut slot = SLOTS[index].lock().await;
        // Never take the future out: cancellation at ANY await retains it.
        if let Some(actor) = slot
            .as_mut()
            .and_then(|value| value.downcast_mut::<RetainedWriterActor>())
        {
            actor.future.as_mut().await;
            // Only normal, fully settled completion releases this slot. There
            // is no production reaper, uncertain cleanup or actor replacement.
            slot.take();
            fence.completed = true;
        }
    })
}

#[cfg(test)]
impl WriterActorHandle {
    pub(in crate::fork) async fn abort_driver(&mut self) {
        self.driver.abort();
        let _ = (&mut self.driver).await;
    }
    pub(in crate::fork) fn retained(&self) -> bool {
        SLOTS[self.index].try_lock().is_ok_and(|slot| {
            slot.as_ref()
                .is_some_and(|value| value.is::<RetainedWriterActor>())
        })
    }
    /// Tests may resume only to obtain actual rollback/close acknowledgements.
    /// This never changes the paused state or restores admission.
    pub(in crate::fork) fn resume_for_settlement(&mut self) {
        self.driver = drive_writer_actor(self.index, self.state.clone());
    }
    pub(in crate::fork) async fn joined(self) {
        self.driver.await.unwrap();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Constructing,
    Open,
    CommitMayHaveRun,
    CommittedUnpublished,
}
struct Graph<O: Send + 'static> {
    db: Db,
    tx: Option<sqlx::Transaction<'static, sqlx::Sqlite>>,
    // Concrete manager custody belongs here: generation lease, original
    // caller/ticket, journal fence and old complete published read handle.
    ownership: O,
    expected: WorkingPublication,
    phase: Phase,
}

/// A detached writer actor owns this, never the result receiver. The slot
/// already owns the entire boxed graph BEFORE BEGIN is polled. Normal Drop
/// leaves it IN that slot; it cannot drop the original SQLx wrapper.
pub(crate) struct OwnedWorkingTransaction<O: Send + 'static> {
    slot: Option<MutexGuard<'static, Slot>>,
    state: Arc<StdMutex<WorkingState>>,
    _type: std::marker::PhantomData<O>,
}
impl<O: Send + 'static> OwnedWorkingTransaction<O> {
    pub(crate) async fn begin(
        db: Db,
        ownership: O,
        expected: WorkingPublication,
        state: Arc<StdMutex<WorkingState>>,
    ) -> Result<Self> {
        expected.validate()?;
        let graph = Box::new(Graph {
            db: db.clone(),
            tx: None,
            ownership,
            expected,
            phase: Phase::Constructing,
        });
        let mut available = None;
        for slot in &*SLOTS {
            if let Ok(guard) = slot.try_lock() {
                if guard.is_none() {
                    available = Some(guard);
                    break;
                }
            }
        }
        let mut slot =
            available.ok_or_else(|| Error::engine("working writer custody capacity exhausted"))?;
        {
            let mut current = state.lock().unwrap_or_else(|error| error.into_inner());
            if *current != WorkingState::Published {
                return Err(Error::engine("working acknowledgements paused"));
            }
            *current = WorkingState::Applying;
        }
        *slot = Some(graph);
        let mut owner = Self {
            slot: Some(slot),
            state,
            _type: std::marker::PhantomData,
        };
        // Before this returns a Transaction, constructor disposition remains
        // SQLx-owned. No returned native lease or physical drain is asserted.
        let tx = crate::db::begin_write(db.write_pool()).await?;
        // No await, callback or allocation between Ok and actual attachment.
        owner.graph().tx = Some(tx);
        owner.graph().phase = Phase::Open;
        Ok(owner)
    }
    fn graph(&mut self) -> &mut Graph<O> {
        self.slot
            .as_mut()
            .expect("owned slot")
            .as_mut()
            .expect("owned graph")
            .downcast_mut::<Graph<O>>()
            .expect("original concrete graph")
    }
    pub(crate) fn parts(&mut self) -> (&mut sqlx::Transaction<'static, sqlx::Sqlite>, &mut O) {
        let graph = self.graph();
        assert!(graph.phase == Phase::Open);
        (
            graph.tx.as_mut().expect("original Transaction"),
            &mut graph.ownership,
        )
    }
    fn settle_original_wrapper(&mut self) {
        // Only existing Db settlement ACKs admit this call. SQLx's wrapper
        // still has open=true after borrowed completion. Queue its depth-zero
        // no-op now, before another BEGIN or release of the owner slot.
        drop(self.graph().tx.take());
    }
    fn restore_old_state(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if *state == WorkingState::Applying {
            *state = WorkingState::Published;
        }
    }
    pub(crate) async fn rollback(mut self, original: Error) -> Error {
        let result = Db::rollback_owned_kernel_connection(
            self.graph().tx.as_mut().expect("original Transaction"),
        )
        .await;
        match result {
            Ok(()) => {
                self.settle_original_wrapper();
                self.restore_old_state();
                self.slot.as_mut().expect("owned slot").take();
                original
            }
            Err(error) => Error::engine(format!(
                "working rollback uncertain; acknowledgements paused: {error}"
            )),
        }
    }
    /// The actor computes the exact next header on this same transaction.
    /// Changing identity/base or skipping more than one publication is refused.
    pub(crate) fn expect_publication(&mut self, expected: WorkingPublication) -> Result<()> {
        expected.validate()?;
        let old = &self.graph().expected;
        if old.binding != expected.binding
            || old.generation != expected.generation
            || old.accepted_frontier != expected.accepted_frontier
            || !(old.publication == expected.publication
                || old.publication.checked_add(1) == Some(expected.publication))
        {
            return Err(Error::engine(
                "working expected publication changed identity",
            ));
        }
        self.graph().expected = expected;
        Ok(())
    }
    pub(crate) async fn commit(mut self) -> Result<CommittedWorkingTransaction<O>> {
        // Verify the private header ON this original transaction. Domain replay
        // and working_applied must have been recorded before this boundary.
        let graph = self.graph();
        let encoded: String = match sqlx::query_scalar(
            "SELECT state FROM main._native_working_publication WHERE singleton=1",
        )
        .fetch_one(&mut **graph.tx.as_mut().expect("original Transaction"))
        .await
        {
            Ok(value) => value,
            Err(error) => return Err(self.rollback(error.into()).await),
        };
        if serde_json::from_str::<WorkingPublication>(&encoded)? != self.graph().expected {
            return Err(self
                .rollback(Error::engine("working commit publication mismatch"))
                .await);
        }
        let graph = self.graph();
        graph.phase = Phase::CommitMayHaveRun; // Armed BEFORE commit is polled.
        let db = graph.db.clone();
        let outcome = db
            .commit_owned_kernel_connection(graph.tx.as_mut().expect("original Transaction"), None)
            .await;
        match outcome {
            crate::db::KernelCommitOutcome::Committed => {
                self.settle_original_wrapper();
                self.graph().phase = Phase::CommittedUnpublished;
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if *state == WorkingState::Applying {
                    *state = WorkingState::CommittedUnpublished;
                }
                drop(state);
                Ok(CommittedWorkingTransaction { owner: Some(self) })
            }
            crate::db::KernelCommitOutcome::RolledBack(error) => {
                self.settle_original_wrapper();
                self.restore_old_state();
                self.slot.as_mut().expect("owned slot").take();
                Err(error)
            }
            crate::db::KernelCommitOutcome::Refused(error) => Err(self.rollback(error).await),
            crate::db::KernelCommitOutcome::Uncertain(error) => Err(Error::engine(format!(
                "working commit uncertain; acknowledgements paused: {error}"
            ))),
        }
    }
}
impl<O: Send + 'static> Drop for OwnedWorkingTransaction<O> {
    fn drop(&mut self) {
        if self.slot.as_ref().is_some_and(|slot| slot.is_some()) {
            // Retention already exists in the bounded static slot. Only now
            // expose paused state, before releasing its mutex. This covers
            // panic/cancel and post-commit/pre-publication installation loss.
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !matches!(
                *state,
                WorkingState::Closed | WorkingState::AwaitingQualifiedUndo
            ) {
                *state = WorkingState::Quarantined;
            }
        }
    }
}

pub(crate) struct CommittedWorkingTransaction<O: Send + 'static> {
    owner: Option<OwnedWorkingTransaction<O>>,
}
impl<O: Send + 'static> CommittedWorkingTransaction<O> {
    /// Called only AFTER the manager installs this very pinned native snapshot.
    /// A failed install keeps the whole old publication and retained job slot.
    pub(crate) fn finish_installed(mut self, installed: &PinnedWorkingRead) -> Result<O> {
        installed.ensure_open()?;
        let owner = self.owner.as_mut().expect("committed owner");
        if installed.publication() != &owner.graph().expected {
            return Err(Error::engine("installed working publication mismatch"));
        }
        let mut state = owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *state != WorkingState::CommittedUnpublished {
            return Err(Error::engine(
                "working publication paused before acknowledgement",
            ));
        }
        *state = WorkingState::Published;
        drop(state);
        let graph = owner
            .slot
            .as_mut()
            .expect("owned slot")
            .take()
            .expect("owned graph")
            .downcast::<Graph<O>>()
            .expect("original concrete graph");
        Ok(graph.ownership)
    }
}

#[cfg(test)]
pub(crate) fn retained_for_test<O: Send + 'static>() -> usize {
    retained_matching_for_test::<O>(|_| true)
}
#[cfg(test)]
pub(crate) fn retained_matching_for_test<O: Send + 'static>(matches: impl Fn(&O) -> bool) -> usize {
    SLOTS
        .iter()
        .filter(|slot| {
            slot.try_lock().is_ok_and(|slot| {
                slot.as_ref()
                    .and_then(|graph| graph.downcast_ref::<Graph<O>>())
                    .is_some_and(|graph| matches(&graph.ownership))
            })
        })
        .count()
}

/// Fixture cleanup only, after an actual worker-acknowledged rollback of the
/// retained ORIGINAL lease. It never reenables a quarantined manager.
#[cfg(test)]
pub(crate) async fn settle_retained_for_test<O: Send + 'static>() {
    settle_matching_for_test::<O>(|_| true).await;
}
#[cfg(test)]
pub(crate) async fn settle_matching_for_test<O: Send + 'static>(matches: impl Fn(&O) -> bool) {
    for slot in &*SLOTS {
        let Ok(mut slot) = slot.try_lock() else {
            continue;
        };
        let Some(graph) = slot
            .as_mut()
            .and_then(|graph| graph.downcast_mut::<Graph<O>>())
        else {
            continue;
        };
        if !matches(&graph.ownership) {
            continue;
        }
        if let Some(tx) = graph.tx.as_mut() {
            Db::rollback_owned_kernel_connection(tx).await.unwrap();
        }
        drop(graph.tx.take());
        slot.take();
    }
}
