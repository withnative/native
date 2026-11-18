//! Off-default installed append coordinator. The journal and verified canonical
//! queue own admission/verdicts; this one physical W writer owns publication.
mod actor;
mod resume;
use super::*;
use crate::mcp::{
    kernel_v2::{
        writes::replay::{self, ReplayCaller, ReplayOutcome, ReplayProposal, ReplaySavepoint},
        PinnedWorkingCollection, PinnedWorkingRead,
    },
    Caller,
};
use crate::node::working_v2::{DurableAppend, JournalFence, WorkingJournal};
use crate::store::{current_event_annotations, with_event_annotations, EventAnnotations};

use serde_json::Value;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, RwLock, Semaphore};

/// Original provider identity/passive context captured once, synchronously,
/// before node preparation/detachment. No serialized or ambient replay ingress.
pub(crate) struct CapturedAppend {
    caller: Caller,
    proposal: ReplayProposal,
    annotations: EventAnnotations,
    record: Option<RecordProjection>,
    create_context: Option<replay::FirstPartyCreateContext>,
    preparation: Option<tokio::sync::OwnedMutexGuard<()>>,
}
#[derive(Clone)]
struct RecordProjection {
    operation: replay::RecordOperation,
    arguments: Value,
}
impl CapturedAppend {
    /// The sealed legacy append selection, before admission or persistence.
    /// Record-family and create captures cannot supply this witness.
    pub(crate) fn legacy_append_proposal(&self) -> Option<&ReplayProposal> {
        (self.record.is_none()
            && self.create_context.is_none()
            && self.proposal.tool() == "update_record")
            .then_some(&self.proposal)
    }
    pub(crate) fn proposal(&self) -> &ReplayProposal {
        &self.proposal
    }
    pub(crate) fn caller(&self) -> &Caller {
        &self.caller
    }
    pub(crate) fn with_preparation(mut self, turn: tokio::sync::OwnedMutexGuard<()>) -> Self {
        self.preparation = Some(turn);
        self
    }
    pub(crate) fn wire_arguments(&self) -> &Value {
        self.record
            .as_ref()
            .map(|record| &record.arguments)
            .unwrap_or(self.proposal.args())
    }
}

/// Only the synchronous original-scope constructor and native principal check
/// can produce this value. Neither the journal nor a caller supplies its actor.
#[derive(Clone)]
pub(crate) struct AdmittedAppend {
    caller: Caller,
    actor: String,
    binding: WorkingBinding,
    proposal: ReplayProposal,
    annotations: EventAnnotations,
    contract: Option<String>,
    record: Option<RecordProjection>,
    #[cfg(test)]
    fsynced_at: Option<std::time::Instant>,
}
impl AdmittedAppend {
    pub(crate) fn actor(&self) -> &str {
        &self.actor
    }
    pub(crate) fn binding(&self) -> &WorkingBinding {
        &self.binding
    }
    pub(crate) fn proposal(&self) -> &ReplayProposal {
        &self.proposal
    }
    pub(crate) fn annotations(&self) -> EventAnnotations {
        self.annotations.clone()
    }
    pub(crate) fn record_operation(&self) -> Option<replay::RecordOperation> {
        self.record.as_ref().map(|record| record.operation)
    }
    pub(crate) fn wire_arguments(&self) -> Option<&Value> {
        self.record.as_ref().map(|record| &record.arguments)
    }
}
struct Generation {
    factory: Arc<super::super::ForkManager>,
    handle: super::super::ForkHandle,
    reservation: u64,
}
#[derive(Clone)]
pub(super) enum ReadScope {
    DeclaredNotes(Vec<String>),
    Workspace,
}
impl ReadScope {
    fn allows(&self, id: &str) -> bool {
        match self {
            Self::Workspace => true,
            Self::DeclaredNotes(notes) => notes.iter().any(|note| note == id),
        }
    }
}
struct Shared {
    base: OwnerPinnedBase,
    generation: Arc<Generation>,
    journal: WorkingJournal,
    state: Arc<StdMutex<WorkingState>>,
    publication: RwLock<Option<Published>>,
    publication_notice: tokio::sync::Notify,
    signals: std::sync::atomic::AtomicU64,
    base_signal: std::sync::atomic::AtomicU64,
    observed_serving_act: std::sync::atomic::AtomicI64,
    reconciling: std::sync::atomic::AtomicBool,
    // Bounded evidence for the first lost handoff; terminal Q never consumes
    // it as permission to resume. Canonical accepted storage remains durable.
    quarantined_delta: StdMutex<Option<Box<crate::standby::AcceptedKernelDelta>>>,
    #[cfg(test)]
    parked: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    parked_notice: tokio::sync::Notify,
    #[cfg(test)]
    settle: Semaphore,
    guard: BindingGuard,
    scope: ReadScope,
    contract: String,
    create_context: std::sync::OnceLock<replay::FirstPartyCreateContext>,
    #[cfg(test)]
    replay_cleanup_fault: StdMutex<Option<Arc<replay::ReplayCleanupFault>>>,
    #[cfg(test)]
    hook: StdMutex<Option<Arc<TestHook>>>,
}
#[derive(Clone)]
struct Published {
    read: PinnedWorkingRead,
    collection: PinnedWorkingCollection,
    base: PublicationBase,
}
/// A notification carries actual trusted transport evidence, never verdict
/// mutation authority. A full/closed channel pauses explicitly, never drops a
/// delta and continues acknowledging on the wrong accepted cut.
pub(crate) struct MaterializationWait {
    epoch: u64,
    prior_base: u64,
}
#[derive(Clone)]
pub(crate) struct WorkingControl {
    shared: Arc<Shared>,
    send: mpsc::WeakSender<actor::Command>,
}
impl WorkingControl {
    pub(crate) fn requires_undo(&self) {
        let _ = self.wait_signal(false);
    }
    pub(crate) fn awaiting_materialization(&self) -> Option<MaterializationWait> {
        self.wait_signal(true)
    }
    pub(crate) fn no_publication(&self, wait: MaterializationWait) {
        let state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(*state, WorkingState::Quarantined | WorkingState::Closed)
            || self
                .shared
                .base_signal
                .load(std::sync::atomic::Ordering::Acquire)
                != wait.epoch
        {
            return;
        }
        // Resolve only this known unchanged-base attempt, never a newer handoff.
        self.shared
            .base_signal
            .store(wait.prior_base, std::sync::atomic::Ordering::Release);
        drop(state);
        // The actor re-audits the latest journal before restoring ACK permission.
        self.canonical_changed();
    }
    fn wait_signal(&self, may_wait: bool) -> Option<MaterializationWait> {
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        self.shared
            .reconciling
            .store(may_wait, std::sync::atomic::Ordering::Release);
        let prior_base = self
            .shared
            .base_signal
            .load(std::sync::atomic::Ordering::Acquire);
        if let Some(epoch) = self.advance_signal(&mut state) {
            self.shared
                .base_signal
                .store(epoch, std::sync::atomic::Ordering::Release);
            if *state == WorkingState::Published {
                *state = WorkingState::AwaitingQualifiedUndo;
            }
            Some(MaterializationWait { epoch, prior_base })
        } else {
            None
        }
    }
    fn advance_signal(&self, state: &mut WorkingState) -> Option<u64> {
        let old = self
            .shared
            .signals
            .load(std::sync::atomic::Ordering::Acquire);
        let Some(next) = old.checked_add(1) else {
            if *state != WorkingState::Closed {
                *state = WorkingState::Quarantined;
            }
            return None;
        };
        self.shared
            .signals
            .store(next, std::sync::atomic::Ordering::Release);
        Some(next)
    }
    fn notify(&self, base_changed: bool, command: impl FnOnce(u64) -> actor::Command) {
        // Existing short state fence linearizes epoch AND enqueue. Concurrent
        // producers cannot leave a stale epoch notification behind a newer one.
        // try_send never waits for the actor/journal/canonical transport.
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(epoch) = self.advance_signal(&mut state) else {
            return;
        };
        if base_changed {
            self.shared
                .base_signal
                .store(epoch, std::sync::atomic::Ordering::Release);
        }
        self.shared
            .reconciling
            .store(true, std::sync::atomic::Ordering::Release);
        if *state == WorkingState::Published {
            *state = WorkingState::AwaitingQualifiedUndo;
        }
        let command = command(epoch);
        let rejected = match self.send.upgrade() {
            Some(send) => send.try_send(command).err().map(|error| error.into_inner()),
            None => Some(command),
        };
        if let Some(command) = rejected {
            if let actor::Command::Reconcile(delta, _) = command {
                let mut retained = self
                    .shared
                    .quarantined_delta
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if retained.is_none() {
                    *retained = Some(delta);
                }
            }
            if *state != WorkingState::Closed {
                *state = WorkingState::Quarantined;
            }
        }
    }
    pub(crate) fn canonical_changed(&self) {
        self.notify(false, actor::Command::CanonicalChanged);
    }
    pub(crate) fn accepted_kernel(&self, accepted: crate::standby::AcceptedKernelDelta) {
        self.notify(true, move |epoch| {
            actor::Command::Reconcile(Box::new(accepted), epoch)
        });
    }
}
#[derive(Clone)]
pub(crate) struct WorkingManager {
    shared: Arc<Shared>,
    send: mpsc::Sender<actor::Command>,
    capacity: Arc<Semaphore>,
    #[cfg(test)]
    stopped: tokio::sync::watch::Receiver<bool>,
    #[cfg(test)]
    processed: tokio::sync::watch::Receiver<u64>,
}
struct Job {
    admitted: AdmittedAppend,
    permit: OwnedSemaphorePermit,
    reply: oneshot::Sender<Result<WorkingAck>>,
    preparation: Option<tokio::sync::OwnedMutexGuard<()>>,
}
/// Local pending publication only. This is never a hosted receipt or accepted
/// version. The native keyed receipt remains inside the private W/journal.
#[derive(Clone, Debug)]
pub(crate) struct WorkingAck {
    pub proposal_id: String,
    pub record_id: String,
    pub publication: WorkingPublication,
}
fn paused() -> Error {
    Error::engine("working acknowledgements paused")
}
fn check_state(shared: &Shared) -> Result<()> {
    shared.guard.check()?;
    if *shared.state.lock().unwrap_or_else(|e| e.into_inner()) != WorkingState::Published {
        return Err(paused());
    }
    Ok(())
}
// A known materialization wait can queue bounded work, while uncertain native
// disposition never admits another acknowledgement. The actor serializes it
// behind the actual delta, not an accepted-only fallback.
fn check_admission(shared: &Shared) -> Result<()> {
    shared.guard.check()?;
    if shared.journal.has_resolution() {
        return Err(paused());
    }
    let state = *shared.state.lock().unwrap_or_else(|e| e.into_inner());
    if matches!(state, WorkingState::Quarantined | WorkingState::Closed)
        || (state == WorkingState::AwaitingQualifiedUndo
            && !shared
                .reconciling
                .load(std::sync::atomic::Ordering::Acquire))
    {
        return Err(paused());
    }
    Ok(())
}
fn fork_error(error: super::super::ForkError) -> Error {
    Error::engine(error.to_string())
}
impl WorkingManager {
    /// Startup/failure recovery copies the pinned accepted base ONCE, replays
    /// every retained pending proposal before exposing any replacement view.
    /// The standalone proof uses its trusted-owner capability. The installed
    /// bridge supplies a verified serving lease; general auth closure is unwired.
    pub(in crate::fork) async fn open(
        base: OwnerPinnedBase,
        caller: Caller,
        notes: Vec<String>,
        storage: (super::super::ForkArea, super::super::ForkLimits),
        journal_root: &std::path::Path,
        guard: BindingGuard,
        contract: String,
    ) -> Result<(Self, WorkingControl)> {
        let journal = WorkingJournal::open(journal_root, base.binding.clone())?;
        Self::open_shared(base, caller, notes, storage, journal, guard, contract).await
    }
    pub(crate) async fn open_shared(
        base: OwnerPinnedBase,
        caller: Caller,
        notes: Vec<String>,
        storage: (super::super::ForkArea, super::super::ForkLimits),
        journal: WorkingJournal,
        guard: BindingGuard,
        contract: String,
    ) -> Result<(Self, WorkingControl)> {
        Self::open_shared_context(
            base,
            caller,
            ReadScope::DeclaredNotes(notes),
            storage,
            journal,
            guard,
            (contract, None),
        )
        .await
    }
    pub(crate) async fn open_create_shared(
        base: OwnerPinnedBase,
        caller: Caller,
        note: String,
        storage: (super::super::ForkArea, super::super::ForkLimits),
        journal: WorkingJournal,
        guard: BindingGuard,
        contract: (String, replay::FirstPartyCreateContext),
    ) -> Result<(Self, WorkingControl)> {
        Self::open_shared_context(
            base,
            caller,
            ReadScope::DeclaredNotes(vec![note]),
            storage,
            journal,
            guard,
            (contract.0, Some(contract.1)),
        )
        .await
    }
    pub(crate) async fn open_workspace_shared(
        base: OwnerPinnedBase,
        caller: Caller,
        storage: (super::super::ForkArea, super::super::ForkLimits),
        journal: WorkingJournal,
        guard: BindingGuard,
        contract: (String, Option<replay::FirstPartyCreateContext>),
    ) -> Result<(Self, WorkingControl)> {
        Self::open_shared_context(
            base,
            caller,
            ReadScope::Workspace,
            storage,
            journal,
            guard,
            contract,
        )
        .await
    }
    async fn open_shared_context(
        mut base: OwnerPinnedBase,
        caller: Caller,
        scope: ReadScope,
        storage: (super::super::ForkArea, super::super::ForkLimits),
        journal: WorkingJournal,
        guard: BindingGuard,
        contract: (String, Option<replay::FirstPartyCreateContext>),
    ) -> Result<(Self, WorkingControl)> {
        let (contract, create_context) = contract;
        guard.check()?;
        if contract.len() != 64 || !contract.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::engine("working contract digest is invalid"));
        }
        let location = journal.location()?;
        let fence = journal.capture().await?;
        for original in fence.view().proposals() {
            if original.actor() != base.principal || original.binding() != &base.binding {
                return Err(Error::engine("retained working original owner mismatch"));
            }
            if original.operation() == "create_record"
                && create_context
                    .as_ref()
                    .is_none_or(|context| context.identity() != original.proposal_identity())
            {
                return Err(Error::engine("retained create requires a matching observed execution context; original retained"));
            }
        }
        if let Some(location) = location {
            let factory = super::super::ForkManager::new_kernel_v2(storage.0, storage.1)
                .map_err(fork_error)?;
            return resume::start(resume::Request {
                base,
                caller,
                scope,
                factory,
                journal,
                guard,
                contract: (contract, create_context),
                fence,
                location,
            })
            .await;
        }
        if journal.location_scope().is_some() && !fence.view().proposals().is_empty() {
            return Err(Error::engine(
                "retained working location missing; original files and custody retained",
            ));
        }
        journal.bind_base(&base.read_binding())?;
        if fence.view().requires_reconciliation() {
            return Err(Error::engine(
                "AwaitingQualifiedUndo: retained canonical outcome requires reconciliation",
            ));
        }
        let factory =
            super::super::ForkManager::new_kernel_v2(storage.0, storage.1).map_err(fork_error)?;
        let key = base.stable_key();
        factory
            .prepare(key.clone(), base.db.clone())
            .await
            .map_err(fork_error)?;
        let slot = factory
            .entries
            .lock()
            .await
            .items
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::engine("working copy slot missing"))?;
        // Register before checking state, avoiding a lost notification. This
        // does not poll native Get, and no accepted-only view is published.
        loop {
            let changed = slot.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match slot.state() {
                super::super::ForkState::Ready => break,
                super::super::ForkState::Preparing => changed.await,
                _ => return Err(Error::engine("working copy preparation failed")),
            }
        }
        let handle = slot
            .inner
            .lock()
            .await
            .handle
            .take()
            .ok_or_else(|| Error::engine("working copy missing"))?;
        base.check_native(&handle.db).await?;
        // Fresh W now proves the exact verified source cut. Acknowledge the
        // source read rollback before unrelated private-pool retirement/open;
        // retained-W recovery above keeps its SAME pin through grounding.
        if let Some(source) = base.source_snapshot.take() {
            source.rollback().await?;
        }
        drop(base.source_checkpoint.take());
        // The static bounded slot owns preparation/base/journal BEFORE any
        // collector or pinned connection constructor is polled. Cancelling the
        // opener's result receiver cannot abandon this owner graph.
        let state = Arc::new(StdMutex::new(WorkingState::Published));
        let (send, receive) = mpsc::channel(16);
        let (ready_send, ready) = oneshot::channel();
        #[cfg(test)]
        let (stopped_send, stopped) = tokio::sync::watch::channel(false);
        #[cfg(test)]
        let (processed_send, processed) = tokio::sync::watch::channel(0u64);
        let owner = actor::Prepared {
            base,
            caller,
            factory,
            handle,
            reservation: slot.reservation,
            journal,
            guard,
            scope,
            contract,
            create_context,
            state: state.clone(),
            fence,
            receive,
            ready: Some(ready_send),
            #[cfg(test)]
            stopped: stopped_send,
            #[cfg(test)]
            processed: processed_send,
        };
        let _driver = super::transaction::retain_writer_actor(Box::pin(owner.run()), state)?;
        let shared = ready
            .await
            .map_err(|_| Error::engine("working owner stopped during preparation"))??;
        let control = WorkingControl {
            shared: shared.clone(),
            send: send.downgrade(),
        };
        Ok((
            Self {
                shared,
                send,
                capacity: Arc::new(Semaphore::new(8)),
                #[cfg(test)]
                stopped,
                #[cfg(test)]
                processed,
            },
            control,
        ))
    }
    /// Synchronous capture is intentional: calling this inside the original
    /// authenticated dispatch captures identity/annotations BEFORE a future is
    /// returned, polled elsewhere or detached. No default identity substitution.
    pub(crate) fn append(
        &self,
        caller: Caller,
        args: Value,
    ) -> Result<Pin<Box<dyn Future<Output = Result<WorkingAck>> + Send>>> {
        self.append_original(Self::capture_original(caller, args)?)
    }
    pub(crate) fn capture_original(caller: Caller, args: Value) -> Result<CapturedAppend> {
        if caller.host_asserted_app().is_some() {
            return Err(Error::engine("working append is first-party only"));
        }
        let proposal = ReplayProposal::from_current_first_party(
            "update_record",
            args.clone(),
            args.get("idempotency_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )?;
        super::super::validate_shape_kernel_v2("update_record", proposal.args(), 1024 * 1024)
            .map_err(fork_error)?;
        let id = proposal.args()["id"]
            .as_str()
            .ok_or_else(|| Error::engine("working target required"))?;
        if uuid::Uuid::parse_str(id).is_err()
            || proposal.idempotency_key().is_none()
            || proposal
                .args()
                .get("idempotency_key")
                .and_then(Value::as_str)
                != proposal.idempotency_key()
        {
            return Err(Error::engine(
                "working append requires a full UUID and its exact original key",
            ));
        }
        Ok(CapturedAppend {
            caller,
            proposal,
            annotations: current_event_annotations(),
            record: None,
            create_context: None,
            preparation: None,
        })
    }
    pub(crate) fn capture_record_original(
        caller: Caller,
        operation: replay::RecordOperation,
        arguments: Value,
    ) -> Result<CapturedAppend> {
        if caller.host_asserted_app().is_some() || operation == replay::RecordOperation::Create {
            return Err(Error::engine(
                "record create requires its original provider capture; apps remain hosted-only",
            ));
        }
        let (tool, native) =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()?
                .working_native_arguments(
                    operation.executor(),
                    operation.catalog_operation(),
                    &arguments,
                )?;
        if tool != operation.source_tool() {
            return Err(Error::engine("native record selector changed"));
        }
        operation.validate(&native)?;
        let proposal = ReplayProposal::from_current_first_party(
            &tool,
            native,
            arguments["idempotency_key"].as_str().map(str::to_owned),
        )?;
        Ok(CapturedAppend {
            caller,
            proposal,
            annotations: current_event_annotations(),
            record: Some(RecordProjection {
                operation,
                arguments,
            }),
            create_context: None,
            preparation: None,
        })
    }
    pub(crate) fn captured_create(
        original: &replay::CapturedFirstPartyCreate,
        proposal: ReplayProposal,
    ) -> Result<CapturedAppend> {
        let mut source = proposal.args().clone();
        if let Some(object) = source.as_object_mut() {
            object.remove("id");
            object.remove("id_nonce");
        }
        if source != *original.source()
            || proposal.tool() != "create_record"
            || proposal.identity() != &original.context().identity()
        {
            return Err(Error::engine("create provider identity changed"));
        }
        Ok(CapturedAppend {
            caller: original.caller().clone(),
            proposal,
            annotations: original.annotations(),
            record: None,
            create_context: Some(original.context().clone()),
            preparation: None,
        })
    }
    pub(crate) fn captured_record_create(
        original: &replay::CapturedFirstPartyCreate,
        proposal: ReplayProposal,
    ) -> Result<CapturedAppend> {
        let arguments = proposal.args().clone();
        let mut captured = Self::captured_create(original, proposal)?;
        captured.record = Some(RecordProjection {
            operation: replay::RecordOperation::Create,
            arguments,
        });
        Ok(captured)
    }
    pub(crate) fn append_original(
        &self,
        captured: CapturedAppend,
    ) -> Result<Pin<Box<dyn Future<Output = Result<WorkingAck>> + Send>>> {
        self.append_original_contract(captured, None)
    }
    pub(crate) fn append_original_contract(
        &self,
        captured: CapturedAppend,
        contract: Option<String>,
    ) -> Result<Pin<Box<dyn Future<Output = Result<WorkingAck>> + Send>>> {
        let CapturedAppend {
            caller,
            proposal,
            annotations,
            record,
            create_context,
            preparation,
        } = captured;
        let id = record
            .as_ref()
            .and_then(|record| record.operation.primary_target(proposal.args()))
            .or_else(|| proposal.args()["id"].as_str())
            .ok_or_else(|| Error::engine("working target required"))?;
        if !self.shared.scope.allows(id) {
            return Err(Error::engine("append outside declared note set"));
        }
        check_admission(&self.shared)?;
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::engine("working admission capacity exhausted"))?;
        let manager = self.clone();
        Ok(Box::pin(async move {
            let mut snapshot = manager.shared.base.db.pool().begin().await?;
            let actor = crate::mcp::kernel_v2::principal_on(&mut snapshot, &caller).await?;
            snapshot.rollback().await?;
            if actor != manager.shared.base.principal {
                return Err(Error::engine("working admission principal mismatch"));
            }
            check_admission(&manager.shared)?;
            if let Some(context) = create_context {
                if manager
                    .shared
                    .create_context
                    .get()
                    .is_some_and(|old| old.identity() != context.identity())
                {
                    return Err(Error::engine("record provider execution context changed"));
                }
                let _ = manager.shared.create_context.set(context);
            }
            let admitted = AdmittedAppend {
                caller,
                actor,
                binding: manager.shared.base.binding.clone(),
                proposal,
                annotations,
                contract,
                record,
                #[cfg(test)]
                fsynced_at: None,
            };
            let (reply, result) = oneshot::channel();
            manager
                .send
                .try_send(actor::Command::Append(Box::new(Job {
                    admitted,
                    permit,
                    reply,
                    preparation,
                })))
                .map_err(|_| Error::engine("working writer unavailable or full"))?;
            result
                .await
                .map_err(|_| Error::engine("working writer stopped; no acknowledgement"))?
        }))
    }
    async fn current(&self) -> Result<PinnedWorkingRead> {
        self.shared.guard.check()?;
        self.shared
            .publication
            .read()
            .await
            .as_ref()
            .map(|published| published.read.clone())
            .ok_or_else(|| Error::engine("working publication unavailable"))
    }
    pub(crate) async fn await_terminal_draft(
        &self,
        id: &str,
        deadline: std::time::Instant,
    ) -> Result<WorkingPublication> {
        loop {
            let notice = self.shared.publication_notice.notified();
            tokio::pin!(notice);
            notice.as_mut().enable();
            self.shared.guard.check()?;
            {
                let cell = self.shared.publication.read().await;
                if let Some(published) = cell.as_ref().filter(|p| {
                    p.base
                        .recovery_dispositions
                        .iter()
                        .any(|draft| draft.proposal_id == id)
                }) {
                    return self
                        .shared
                        .guard
                        .while_open(|| published.base.publication.clone());
                }
            }
            if matches!(
                *self.shared.state.lock().unwrap_or_else(|e| e.into_inner()),
                WorkingState::Quarantined | WorkingState::Closed
            ) {
                return Err(paused());
            }
            tokio::time::timeout_at(deadline.into(), notice)
                .await
                .map_err(|_| {
                    Error::engine("Terminal proof retained; native recovery publication pending")
                })?;
        }
    }
    pub(crate) fn check_recovery_owner(
        &self,
        binding: &WorkingBinding,
        principal: &str,
    ) -> Result<()> {
        self.shared.guard.check()?;
        if &self.shared.base.binding != binding || self.shared.base.principal != principal {
            return Err(Error::engine("recovery owner differs"));
        }
        Ok(())
    }
    pub(crate) async fn published_prefix(&self) -> Result<i64> {
        self.shared.guard.check()?;
        self.shared
            .publication
            .read()
            .await
            .as_ref()
            .map(|p| p.base.original_prefix)
            .ok_or_else(|| Error::engine("working publication unavailable"))
    }
    /// A serving-status observation can only pause. It does not manufacture
    /// an unresolved data epoch after that exact cut was already grounded.
    pub(crate) async fn observe_serving_act(&self, act: i64) {
        let publication = self.shared.publication.read().await;
        let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        self.shared
            .observed_serving_act
            .fetch_max(act, std::sync::atomic::Ordering::AcqRel);
        if *state == WorkingState::Published
            && publication
                .as_ref()
                .map(|published| act > published.base.native.head_act)
                .unwrap_or_else(|| {
                    self.shared.create_context.get().is_none()
                        || act > self.shared.base.native.head_act
                })
        {
            *state = WorkingState::AwaitingQualifiedUndo;
            self.shared
                .reconciling
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
    pub(crate) async fn accepted_act(&self) -> Result<i64> {
        self.shared.guard.check()?;
        self.shared
            .publication
            .read()
            .await
            .as_ref()
            .map(|p| p.base.native.head_act)
            .ok_or_else(|| Error::engine("working publication unavailable"))
    }
    pub(crate) fn awaiting_reconciliation(&self) -> bool {
        matches!(
            *self.shared.state.lock().unwrap_or_else(|e| e.into_inner()),
            WorkingState::AwaitingQualifiedUndo | WorkingState::Quarantined
        )
    }
    pub(in crate::fork) async fn pin(&self, caller: Caller) -> Result<PinnedWorkingRead> {
        let pinned = self.current().await?;
        pinned.authorize(caller).await?;
        Ok(pinned)
    }
    pub(crate) async fn discover(
        &self,
        caller: Caller,
        operation: &str,
        args: Value,
    ) -> Result<(WorkingPublication, Value)> {
        self.shared.guard.check()?;
        let pin = self
            .shared
            .publication
            .read()
            .await
            .as_ref()
            .map(|p| p.collection.clone())
            .ok_or_else(|| Error::engine("working publication unavailable"))?;
        let result = pin.query(caller, operation, args).await?;
        Ok((result.publication, result.value))
    }
    pub(crate) async fn read(
        &self,
        caller: Caller,
        id: &str,
    ) -> Result<(WorkingPublication, Value)> {
        let result = self.current().await?.get(caller, id).await?;
        Ok((result.publication, result.value))
    }
    pub(crate) async fn get(&self, caller: Caller, id: &str) -> Result<Value> {
        Ok(self.read(caller, id).await?.1)
    }
    pub(crate) async fn read_arguments(
        &self,
        caller: Caller,
        args: Value,
    ) -> Result<(WorkingPublication, Value)> {
        let result = self.current().await?.get_arguments(caller, args).await?;
        Ok((result.publication, result.value))
    }
}
fn pause_uncertain(shared: &Shared) {
    let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    if *state != WorkingState::Closed {
        *state = WorkingState::Quarantined;
    }
}

/// Accepted materialization evidence on the current accepted cut of W, not
/// merely a queue answer/head or W's later speculative keyed receipt. The
/// private caller grounds `base` in its verified initial owner or the actual
/// trusted delta just folded on this SAME transaction.
async fn terminal_draft_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ticket: &DurableAppend,
    resolution: &crate::node::working_v2::WorkingResolution,
    base: &PublicationBase,
    owner: replay::WorkingReplayOwner<'_>,
    ordinal: usize,
) -> Result<Option<TerminalDraft>> {
    let Some(answer) = resolution.answer() else {
        return Ok(None);
    };
    if answer["verdict"] != "unapplied_terminal" {
        return Ok(None);
    }
    use crate::kernel::original_settlement::{outcome_profile::OutcomeLookup, KeyedOutcome};
    let mut snapshot = owner.outcomes(tx).await?;
    if let Some(install) = ticket.binding().install_id.as_deref() {
        let native = crate::kernel::original_settlement::installed::prove_terminal_inclusion(
            &mut snapshot,
            ticket.actor(),
            install,
            resolution.binding(),
            answer,
        )
        .await?;
        let Some(native) = native else {
            return Ok(None);
        };
        if native.origin_database_id != base.origin
            || native.genesis_event_id != base.genesis
            || native.local_seq > base.native.content_event_seq
            || native.act > base.native.head_act
        {
            return Err(Error::engine(
                "terminal settlement and grounded original differ",
            ));
        }
        return terminal_draft(ticket, answer, ordinal).map(Some);
    }
    let outcome = snapshot
        .lookup(
            ticket.actor(),
            ticket.operation(),
            ticket.arguments()["idempotency_key"]
                .as_str()
                .ok_or_else(paused)?,
        )
        .await
        .map_err(|error| Error::engine(error.code()))?;
    let (fact, native) = match outcome {
        OutcomeLookup::Typed(KeyedOutcome::Terminal { fact, native }) => (fact, native),
        OutcomeLookup::Typed(KeyedOutcome::Absent) | OutcomeLookup::Legacy(None) => {
            return Ok(None)
        }
        _ => {
            return Err(Error::engine(
                "terminal settlement contradicts grounded canonical outcome",
            ))
        }
    };
    let fence = &answer["fence"];
    if answer["original_binding_sha256"] != resolution.binding()
        || answer["namespace_sha256"] != fact.terminal.namespace_sha256
        || fence["fence_id"] != fact.terminal.fence_id
        || fence["fenced_original_binding_sha256"] != fact.terminal.original_binding_sha256
        || fence["retired_record_id"] != serde_json::to_value(&fact.terminal.retired_record_id)?
        || serde_json::to_value(native)? != fence["native"]
        || native.origin_database_id != base.origin
        || native.genesis_event_id != base.genesis
        || native.local_seq > base.native.content_event_seq
        || native.act > base.native.head_act
        || fact.terminal.account_id != ticket.binding().account_id
        || fact.terminal.principal_id != ticket.actor()
        || fact.terminal.database_id != ticket.binding().database_id
        || fact.terminal.origin_database_id != ticket.binding().origin_database_id
    {
        return Err(Error::engine(
            "terminal settlement and grounded original differ",
        ));
    }
    terminal_draft(ticket, answer, ordinal).map(Some)
}

fn terminal_draft(ticket: &DurableAppend, answer: &Value, ordinal: usize) -> Result<TerminalDraft> {
    use sha2::Digest;
    Ok(TerminalDraft {
        original_ordinal: i64::try_from(ordinal).map_err(|_| paused())?,
        proposal_id: ticket.id().into(),
        verified_answer_sha256: hex::encode(sha2::Sha256::digest(serde_json::to_vec(answer)?)),
    })
}

async fn materialized_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ticket: &DurableAppend,
    base: &PublicationBase,
    owner: replay::WorkingReplayOwner<'_>,
) -> Result<bool> {
    let key = ticket.arguments()["idempotency_key"]
        .as_str()
        .ok_or_else(|| Error::engine("original key missing"))?;
    let (request, receipt, typed_native) = {
        use crate::kernel::original_settlement::{outcome_profile::OutcomeLookup, KeyedOutcome};
        let mut snapshot = owner.outcomes(tx).await?;
        let outcome = snapshot
            .lookup(ticket.actor(), ticket.operation(), key)
            .await
            .map_err(|error| Error::engine(error.code()))?;
        if let Some(conflict) = outcome.terminal_conflict() {
            return Err(Error::OriginalConflict(Box::new(conflict)));
        }
        match outcome {
            OutcomeLookup::Legacy(None) | OutcomeLookup::Typed(KeyedOutcome::Absent) => {
                return Ok(false)
            }
            OutcomeLookup::Legacy(Some((request, receipt))) => {
                (request.clone(), receipt.clone(), None)
            }
            OutcomeLookup::Typed(KeyedOutcome::Accepted {
                request,
                receipt,
                native,
            }) => (request.clone(), receipt.clone(), Some(native.clone())),
            OutcomeLookup::Typed(KeyedOutcome::Terminal { .. }) => {
                unreachable!("terminal handled above")
            }
        }
    };
    // Copied bytes are correlation only: the root has not mutated since its
    // borrowed lookup. Grounding below still requires the exact success event
    // and complete native effects on this accepted cut.
    if request != ticket.fingerprint() {
        return Err(Error::engine(
            "materialized key belongs to different original bytes",
        ));
    }
    let facts: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT seq,act,payload FROM main.content_events WHERE record_id=? AND type=? AND actor=? AND CAST(json_extract(payload,'$.operation') AS TEXT)=? AND CAST(json_extract(payload,'$.operation_key') AS TEXT)=? AND act<=? AND seq<=? ORDER BY seq"
    ).bind(crate::kernel::mcp_write_receipts::STREAM).bind(crate::kernel::mcp_write_receipts::EVENT)
        .bind(ticket.actor()).bind(ticket.operation()).bind(key).bind(base.native.head_act)
        .bind(base.publication.accepted_frontier).fetch_all(&mut **tx).await?;
    if facts.is_empty() {
        return Ok(false);
    }
    if facts.len() != 1 {
        return Err(Error::engine(
            "materialized keyed outcome history is ambiguous",
        ));
    }
    let (fact_seq, fact_act, raw_fact) = &facts[0];
    if let Some(native) = &typed_native {
        if native.origin_database_id != base.origin
            || native.genesis_event_id != base.genesis
            || native.local_seq != *fact_seq
            || native.act != *fact_act
            || native.local_seq > base.publication.accepted_frontier
            || native.act > base.native.head_act
        {
            return Err(Error::engine(
                "materialized typed receipt coordinates differ",
            ));
        }
    }

    let fact: Value = serde_json::from_str(raw_fact)?;
    if fact["request_json"].as_str() != Some(&request)
        || fact["receipt_json"].as_str() != Some(&receipt)
    {
        return Err(Error::engine(
            "materialized receipt projection differs from canonical event",
        ));
    }
    let receipt: Value = serde_json::from_str(&receipt)?;
    if let Some(operation) = ticket.record_operation() {
        return replay::record_materialized_on(
            tx,
            ticket.actor(),
            operation,
            ticket.arguments(),
            &receipt,
            *fact_seq,
            *fact_act,
        )
        .await;
    }
    let target = ticket.arguments()["id"]
        .as_str()
        .ok_or_else(|| Error::engine("original target missing"))?;
    let append = ticket.arguments()[if ticket.operation() == "create_record" {
        "body"
    } else {
        "body_append"
    }]
    .as_str()
    .ok_or_else(|| Error::engine("original append missing"))?;
    if receipt["id"].as_str() != Some(target)
        || receipt["changed"] != true
        || receipt
            .pointer("/write_receipt/kind")
            .and_then(Value::as_str)
            != Some("kernel_content_event")
    {
        return Err(Error::engine(
            "materialized append receipt has unsupported effect",
        ));
    }
    let event = receipt
        .pointer("/write_receipt/event/event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("materialized append lacks its native effect reference"))?;
    type Effect = (i64, String, String, Option<String>, Option<i64>, String);
    let effect: Option<Effect> = sqlx::query_as("SELECT seq,type,record_id,actor,act,payload FROM main.content_events WHERE id=? AND act<=? AND seq<=?")
        .bind(event).bind(base.native.head_act).bind(base.publication.accepted_frontier)
        .fetch_optional(&mut **tx).await?;
    let Some((seq, kind, record, actor, act, payload)) = effect else {
        return Err(Error::engine(
            "materialized receipt native effect is missing",
        ));
    };
    let payload: Value = serde_json::from_str(&payload)?;
    if kind != "kernel.body_set.v1"
        || record != target
        || actor.as_deref() != Some(ticket.actor())
        || receipt
            .pointer("/write_receipt/event/seq")
            .and_then(Value::as_i64)
            != Some(seq)
        || receipt["act"].as_i64() != act
        || !payload["body"].as_str().is_some_and(|body| {
            if ticket.operation() == "create_record" {
                body == append
            } else {
                body.ends_with(append)
            }
        })
    {
        return Err(Error::engine(
            "materialized receipt does not bind the original native append effect",
        ));
    }
    if ticket.operation() == "create_record" {
        let created:Vec<String>=sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type='kernel.record_created.v1' AND actor=? AND act=? AND seq<=? ORDER BY seq")
            .bind(target).bind(ticket.actor()).bind(act).bind(base.publication.accepted_frontier).fetch_all(&mut **tx).await?;
        if created.len() != 1 {
            return Err(Error::engine(
                "materialized create lacks its unique native creation",
            ));
        }
        let created: Value = serde_json::from_str(&created[0])?;
        if created.pointer("/origin/record_id_mint/nonce") != ticket.arguments().get("id_nonce")
            || created
                .pointer("/origin/record_id_mint/context")
                .and_then(Value::as_str)
                != Some("first-party")
            || created
                .pointer("/origin/record_id_mint/principal")
                .and_then(Value::as_str)
                != Some(crate::record_id::qualified_principal(ticket.actor()).as_str())
            || receipt["effect"] != "created"
            || receipt["type"] != "Document"
            || receipt["kind"] != "note"
            || receipt["name"] != ticket.arguments()["name"]
        {
            return Err(Error::engine(
                "materialized create does not bind original final ID proof and note",
            ));
        }
    }
    Ok(true)
}
fn check_size(shared: &Shared) -> Result<()> {
    shared
        .generation
        .handle
        .check(&shared.generation.factory.area)
        .map_err(fork_error)?;
    if super::super::footprint(&shared.generation.handle.directory).map_err(fork_error)?
        > shared.generation.reservation
    {
        return Err(Error::engine("working generation exceeds reservation"));
    }
    Ok(())
}
async fn authorize(
    tx: &mut sqlx::SqliteConnection,
    shared: &Shared,
    caller: &Caller,
) -> Result<String> {
    shared.guard.check()?;
    let actor = crate::mcp::kernel_v2::principal_on(tx, caller).await?;
    if actor != shared.base.principal {
        return Err(Error::engine("working writer principal mismatch"));
    }
    Ok(actor)
}
async fn replay_ticket(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    shared: &Shared,
    caller: &Caller,
    ticket: &DurableAppend,
    retry: bool,
    owner: replay::WorkingReplayOwner<'_>,
) -> Result<Value> {
    let actor = authorize(tx, shared, caller).await?;
    if actor != ticket.actor() || ticket.binding() != &shared.base.binding {
        return Err(Error::engine("working ticket owner mismatch"));
    }
    let id = ticket
        .primary_target()
        .ok_or_else(|| Error::engine("working ticket target missing"))?;
    if !shared.scope.allows(id) {
        return Err(Error::engine("retained proposal outside declared note set"));
    }
    if ticket.record_operation().is_none() && ticket.operation() == "update_record" {
        // Authorize before kind diagnostics, on the SAME writer transaction.
        let visible = crate::kernel::read_record_on(tx, &actor, id)
            .await?
            .ok_or_else(|| Error::engine(crate::kernel::HIDDEN_OR_MISSING))?;
        type Kind = (Option<String>, Option<String>, Option<String>, Option<i64>);
        let (ty, kind, family, version): Kind = sqlx::query_as(
            "SELECT primary_type,kind,pin_family,pin_version FROM main.kernel_records WHERE id=?",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        let plain = if family.as_deref() == Some(crate::v2_standard::DOCUMENT_FAMILY) {
            ty.as_deref() == Some("Document") && kind.as_deref() == Some("note")
        } else if family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY)
            && version == Some(1)
        {
            visible
                .fields
                .get("v1_type")
                .and_then(Value::as_str)
                .or(ty.as_deref())
                == Some("Document")
                && visible
                    .fields
                    .get("v1_kind")
                    .and_then(Value::as_str)
                    .or(kind.as_deref())
                    == Some("note")
        } else {
            false
        };
        if !plain {
            return Err(Error::engine("working append requires plain Document/note"));
        }
    }
    let proposal = ReplayProposal::from_original(
        ticket.operation(),
        ticket.arguments().clone(),
        ticket
            .arguments()
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::to_owned),
        &ticket.proposal_identity(),
    )?;
    if proposal.request_fingerprint().as_bytes() != ticket.fingerprint().as_bytes() {
        return Err(Error::engine("working proposal fingerprint changed"));
    }
    let before = native_base_coordinates(tx).await?.1;
    let savepoint = ReplaySavepoint::claim();
    #[cfg(test)]
    let savepoint =
        savepoint.with_cleanup_fault(shared.replay_cleanup_fault.lock().unwrap().take());
    let caller = ReplayCaller {
        actor,
        mint: Default::default(),
    };
    let captured = if ticket.operation() == "create_record" {
        Some(
            shared
                .create_context
                .get()
                .ok_or_else(|| Error::engine("retained create needs current observed context"))?,
        )
    } else {
        None
    };
    let replay = with_event_annotations(
        ticket.annotations(),
        replay::replay_working_in_transaction(
            &shared.generation.handle.db,
            tx,
            &caller,
            &proposal,
            &savepoint,
            (ticket.record_operation(), captured, owner),
        ),
    );
    #[cfg(test)]
    let outcome = if captured.is_some() {
        // The test actor is detached from ingress task locals. Its already
        // observed create fixture supplies the same explicit pilot setting.
        crate::mcp::kernel_v2::writes::with_minted_ids_for_settlement_test(replay).await?
    } else {
        replay.await?
    };
    #[cfg(not(test))]
    let outcome = replay.await?;

    match outcome {
        ReplayOutcome::Applied { receipt, .. } => {
            if retry && native_base_coordinates(tx).await?.1 != before {
                return Err(Error::engine(
                    "working retry missing coherent native keyed receipt",
                ));
            }
            Ok(receipt)
        }
        ReplayOutcome::LocallyRefused { reason } => Err(Error::engine(format!(
            "local replay refused; proposal retained (not a hosted verdict): {reason}"
        ))),
    }
}
// Deterministic test barriers, never production cancellation or failure knobs.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::fork) enum TestPoint {
    Fsynced,
    Replayed,
    Committed,
    ReconcileCommitted,
    NativeWait,
}
#[cfg(test)]
pub(in crate::fork) struct TestHook {
    point: TestPoint,
    pub entered: Semaphore,
    pub release: Semaphore,
    fail: bool,
    panic: bool,
}
#[cfg(test)]
impl TestHook {
    pub(in crate::fork) fn new(point: TestPoint, fail: bool, panic: bool) -> Arc<Self> {
        Arc::new(Self {
            point,
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            fail,
            panic,
        })
    }
}
#[cfg(test)]
async fn checkpoint(shared: &Shared, point: TestPoint) -> Result<()> {
    let hook = {
        let mut current = shared.hook.lock().unwrap();
        if current.as_ref().is_some_and(|hook| hook.point == point) {
            current.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook.entered.add_permits(1);
        hook.release.acquire().await.unwrap().forget();
        assert!(!hook.panic, "injected working actor panic");
        if hook.fail {
            return Err(Error::engine("injected working boundary failure"));
        }
    }
    Ok(())
}
#[cfg(test)]
impl WorkingManager {
    pub(in crate::fork) async fn drain_notifications_for_test(&self) {
        let (reply, result) = oneshot::channel();
        self.send
            .send(actor::Command::Drained(reply))
            .await
            .unwrap_or_else(|_| panic!("fixture drain channel"));
        result.await.expect("actual terminal owner drain");
    }
    pub(in crate::fork) fn stale_wake_for_test(&self, epoch: u64) {
        // Model epoch2 already handled before delayed epoch1 delivery. This
        // intentionally bypasses the normal signal+enqueue ordering fence.
        self.send
            .try_send(actor::Command::CanonicalChanged(epoch))
            .unwrap_or_else(|_| panic!("fixture wake channel"));
    }
    pub(in crate::fork) fn fail_replay_cleanup_for_test(
        &self,
        fault: Arc<replay::ReplayCleanupFault>,
    ) {
        *self.shared.replay_cleanup_fault.lock().unwrap() = Some(fault);
    }
    pub(in crate::fork) fn set_hook(&self, hook: Arc<TestHook>) {
        *self.shared.hook.lock().unwrap() = Some(hook);
    }
    pub(in crate::fork) async fn journal_view(
        &self,
    ) -> crate::node::working_v2::WorkingJournalView {
        self.shared.journal.capture().await.unwrap().view().clone()
    }
    pub(in crate::fork) fn state(&self) -> WorkingState {
        *self.shared.state.lock().unwrap()
    }
    pub(in crate::fork) async fn discovery_pin_for_test(&self) -> PinnedWorkingCollection {
        self.shared
            .publication
            .read()
            .await
            .as_ref()
            .unwrap()
            .collection
            .clone()
    }
    pub(in crate::fork) fn native_db(&self) -> crate::Db {
        self.shared.generation.handle.db.clone()
    }
    pub(in crate::fork) fn retained_count(&self) -> usize {
        usize::from(
            self.shared
                .parked
                .load(std::sync::atomic::Ordering::Acquire),
        )
    }
    pub(in crate::fork) async fn await_retained_for_test(&self) {
        loop {
            let notice = self.shared.parked_notice.notified();
            tokio::pin!(notice);
            notice.as_mut().enable();
            if self
                .shared
                .parked
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notice.await;
        }
    }
    pub(in crate::fork) async fn settle_retained(&self) {
        self.shared.settle.add_permits(1);
        let mut stopped = self.stopped.clone();
        let _ = stopped.wait_for(|value| *value).await;
    }
    pub(in crate::fork) async fn unpublished_suffix_for_test(
        &self,
        ticket: &DurableAppend,
        answer: crate::node::working_v2::WorkingCanonicalAnswer,
        uncertain: bool,
    ) -> Result<bool> {
        let (reply, result) = oneshot::channel();
        self.send
            .send(actor::Command::ProbeSuffix(
                Box::new(ticket.clone()),
                answer,
                uncertain,
                reply,
            ))
            .await
            .map_err(|_| paused())?;
        result.await.map_err(|_| paused())?
    }
    pub(in crate::fork) async fn remove_marker_for_test(&self, id: String) {
        let (reply, result) = oneshot::channel();
        self.send
            .send(actor::Command::RemoveMarker(id, reply))
            .await
            .unwrap();
        result.await.unwrap().unwrap();
    }
    pub(in crate::fork) fn processed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.processed.clone()
    }
}

#[cfg(test)]
impl WorkingManager {
    pub(in crate::fork) async fn stop_for_test(self) {
        let mut stopped = self.stopped.clone();
        drop(self);
        stopped
            .wait_for(|value| *value)
            .await
            .expect("actual working writer close acknowledgement");
    }
    pub(in crate::fork) fn stopped(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stopped.clone()
    }
    pub(in crate::fork) fn retained_journal_count(&self) -> usize {
        self.shared.journal.retained_count_for_test()
    }
    pub(in crate::fork) async fn fixture_accepted_verdict(&self, id: &str, receipt: Value) {
        self.shared
            .journal
            .fixture_accepted_verdict(id, receipt)
            .await;
    }
    pub(in crate::fork) async fn fixture_refused_verdict(&self, id: &str) {
        self.shared.journal.fixture_refused_verdict(id).await;
    }
    pub(in crate::fork) fn fail_fsync_for_test(&self) {
        self.shared.journal.fail_fsync_for_test();
    }
}
