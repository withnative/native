//! Inactive kernel lifecycle custody. No pool retirement or hosted open.
use super::kernel_writes::{self, KernelBodyWrite};
use super::*;
use crate::coedit::backend::SessionBackend;
use crate::{Error, Result};

/// Sealing closes admission, not custody. Never reset/remove a sealed owner.
pub(super) struct Admission {
    pub(super) serial: StdMutex<Ledger>,
    pub(super) changed: tokio::sync::watch::Sender<u64>,
    seal_id: uuid::Uuid,
    pub(super) sealed: tokio::sync::watch::Sender<bool>,
    rechecks: StdMutex<HashMap<String, bool>>,
}
impl Admission {
    pub(super) fn new() -> Self {
        Self {
            serial: StdMutex::new(Ledger::default()),
            changed: tokio::sync::watch::channel(0).0,
            seal_id: uuid::Uuid::new_v4(),
            sealed: tokio::sync::watch::channel(false).0,
            rechecks: StdMutex::new(HashMap::new()),
        }
    }
}

#[derive(Default)]
pub(super) struct Ledger {
    pub(super) registered: std::collections::HashSet<uuid::Uuid>,
    pub(super) accepted_jobs: usize,
    pub(super) cleanup_running: bool,
    pub(super) cleanup_finished: bool,
    pub(super) cleanup_generation: u64,
    pub(super) quiescent: bool,
    blocked: Option<KernelBlockedReason>,
    pub(super) driver_unknown: Option<String>,
}
pub(super) fn changed(owner: &DbSessions) {
    owner
        .kernel_lifecycle
        .changed
        .send_modify(|generation| *generation = generation.wrapping_add(1));
}

/// Only this module mints cleanup authority, for an already sealed owner.
/// This permits completion under the seal; it confers no record/app authority.
#[derive(Clone)]
pub(super) struct CleanupPurpose {
    owner: Arc<DbSessions>,
    key: PathBuf,
    pub(super) generation: u64,
}
tokio::task_local! { static CLEANUP: CleanupPurpose; }
impl CleanupPurpose {
    pub(super) fn matches(&self, db: &Db, owner: &Arc<DbSessions>) -> bool {
        self.key == session_key(db) && Arc::ptr_eq(&self.owner, owner)
    }
}
pub(super) fn current_cleanup() -> Option<CleanupPurpose> {
    CLEANUP.try_with(Clone::clone).ok()
}
pub(super) async fn with_cleanup<T>(
    purpose: CleanupPurpose,
    future: impl std::future::Future<Output = T>,
) -> T {
    CLEANUP.scope(purpose, future).await
}
/// Test-only entry into the actual cleanup scope of an actual sealed witness.
/// This does not drive owned cleanup or grant record/app authority.
#[cfg(test)]
pub(super) async fn with_cleanup_scope_for_peer_ingress_test<T>(
    witness: &KernelRetirementWitness,
    work: impl std::future::Future<Output = T>,
) -> T {
    with_cleanup(witness.purpose.clone(), work).await
}

pub(super) fn ensure_admission(db: &Db) -> Result<()> {
    let Some(owner) = existing_db_sessions(db) else {
        return Ok(());
    };
    if !*owner.kernel_lifecycle.sealed.borrow() {
        return Ok(());
    }
    let cleanup = CLEANUP
        .try_with(|purpose| purpose.key == session_key(db) && Arc::ptr_eq(&purpose.owner, &owner))
        .unwrap_or(false);
    if cleanup {
        Ok(())
    } else {
        Err(Error::engine(
            "kernel storage admission is sealed; custody is retained",
        ))
    }
}
pub(super) fn sealed(db: &Db) -> bool {
    existing_db_sessions(db).is_some_and(|owner| *owner.kernel_lifecycle.sealed.borrow())
}

/// Immutable target identity, never permission to replace a newer room.
#[derive(Clone)]
pub(super) struct Target {
    room: Arc<LiveSession>,
    session: SessionId,
    key: PathBuf,
}
impl Target {
    pub(super) fn new(db: &Db, room: Arc<LiveSession>) -> Self {
        let session = room.state().session.clone();
        Self {
            room,
            session,
            key: session_key(db),
        }
    }
    pub(super) fn room(&self) -> &Arc<LiveSession> {
        &self.room
    }
    pub(super) fn validate(&self, db: &Db) -> Result<()> {
        if self.key != session_key(db)
            || self.room.backend != SessionBackend::KernelV2
            || !existing_session(db, &self.room.record_id)
                .is_some_and(|r| Arc::ptr_eq(&r, &self.room))
            || self.room.state().session != self.session
        {
            return Err(Error::engine("kernel lifecycle target incarnation changed"));
        }
        Ok(())
    }
}

/// Correlation only: no author, permit, durable ACK or mutable-handle authority.
#[derive(Clone)]
pub(super) struct FailureFence {
    room: Arc<LiveSession>,
    owner: Arc<DbSessions>,
    seed: Db,
    session: SessionId,
    basis: FailureBasis,
}
#[derive(Clone, PartialEq, Eq)]
struct FailureBasis {
    event: Option<BodyEvent>,
    present: bool,
    digest: String,
}
impl FailureBasis {
    fn on(state: &State) -> Option<Self> {
        let event = match (
            &state.base.proof.body_event_id,
            state.base.proof.body_event_seq,
        ) {
            (None, None) if state.base.body_sha256 == sha256_hex("") => None,
            (Some(id), Some(seq)) if !id.is_empty() && seq > 0 => Some(BodyEvent {
                id: id.clone(),
                seq,
            }),
            _ => return None,
        };
        Some(Self {
            present: event.is_some(),
            event,
            digest: state.base.body_sha256.clone(),
        })
    }
}
impl FailureFence {
    pub(super) fn capture(db: &Db, room: &Arc<LiveSession>, session: &SessionId) -> Option<Self> {
        if room.backend != SessionBackend::KernelV2 {
            return None;
        }
        let seed = room.kernel_origin.as_ref()?;
        if !seed.same_handle(db) {
            return None;
        }
        let owner = room.owner.upgrade()?;
        if !existing_db_sessions(db).is_some_and(|current| Arc::ptr_eq(&current, &owner)) {
            return None;
        }
        let registered = lock(&owner.records).get(&room.record_id).cloned();
        if !registered.is_some_and(|current| Arc::ptr_eq(&current, room)) {
            return None;
        }
        // All map guards have gone before waiting for State.
        let state = room.state();
        if state.closed || &state.session != session {
            return None;
        }
        let basis = FailureBasis::on(&state)?;
        Some(Self {
            room: room.clone(),
            owner,
            seed: seed.clone(),
            session: session.clone(),
            basis,
        })
    }
    pub(super) fn publish_if_current(&self) {
        if self.room.backend != SessionBackend::KernelV2
            || !self
                .room
                .kernel_origin
                .as_ref()
                .is_some_and(|seed| seed.same_handle(&self.seed))
            || !self
                .room
                .owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
        {
            return;
        }
        let registered = lock(&self.owner.records).get(&self.room.record_id).cloned();
        if !registered.is_some_and(|current| Arc::ptr_eq(&current, &self.room)) {
            return;
        }
        // No map/ledger/SERVICE lookup occurs under this State borrow. A retained
        // old Arc cannot mutate a replacement. Close is checked again.
        let mut state = self.room.state();
        if state.closed
            || state.session != self.session
            || FailureBasis::on(&state).as_ref() != Some(&self.basis)
        {
            return;
        }
        // New accepted edits on the same committed basis MUST NOT evade a mark.
        if state
            .registry
            .mutation_epoch(&self.session)
            .is_ok_and(|epoch| epoch != state.versioned_epoch)
        {
            state.kernel_finalization_blocked = true;
        }
    }
}

/// MUST precede KernelLiveWrite::_ops. Declaration-order Drop publishes before
/// that exact guard is released when a transaction consumes/drops ownership.
/// This guard never belongs to a result observer.
pub(super) struct ArmedFailureMark {
    fence: FailureFence,
    armed: bool,
}
impl ArmedFailureMark {
    pub(super) fn new(fence: FailureFence) -> Self {
        Self { fence, armed: true }
    }
    pub(super) fn armed(&self) -> bool {
        self.armed
    }
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for ArmedFailureMark {
    fn drop(&mut self) {
        if self.armed {
            self.fence.publish_if_current();
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Intent {
    Flush,
    GraceExpire,
    Shutdown,
    Retire,
}
#[derive(Debug)]
pub(super) struct RetainedBasis {
    pub(super) session: SessionId,
    pub(super) body_event_id: Option<String>,
    pub(super) body_event_seq: Option<i64>,
    pub(super) body_sha256: String,
    pub(super) dirty: bool,
}
#[derive(Debug)]
pub(super) enum Outcome {
    Active,
    Clean,
    Versioned(Versioned),
    RetainedBlocked {
        record: String,
        reason: String,
        basis: RetainedBasis,
    },
    Uncertain {
        record: String,
        operation: String,
        basis: RetainedBasis,
    },
}
impl Outcome {
    fn refused(db: &Db, target: &Target, error: impl std::fmt::Display) -> Self {
        let state = target.room.state();
        let basis = RetainedBasis {
            session: state.session.clone(),
            body_event_id: state.base.proof.body_event_id.clone(),
            body_event_seq: state.base.proof.body_event_seq,
            body_sha256: state.base.body_sha256.clone(),
            dirty: state.registry.live_body(&state.session).is_ok() && state.dirty(),
        };
        let record = target.room.record_id.clone();
        drop(state);
        let operation =
            existing_db_sessions(db).and_then(|o| lock(&o.kernel_quarantine_identity).clone());
        match operation {
            Some(operation) => Self::Uncertain {
                record,
                operation,
                basis,
            },
            None => Self::RetainedBlocked {
                record,
                reason: error.to_string(),
                basis,
            },
        }
    }
}

/// Explicit inactive participation; stored by L2 before publishing a Db.
/// A clone retains the same owner; this is not a caller or write capability.
#[derive(Clone)]
pub(crate) struct KernelLifecycleRegistration {
    _owner: Arc<DbSessions>,
    _handle: uuid::Uuid,
}
pub(crate) fn register_kernel_lifecycle(db: &Db) -> KernelLifecycleRegistration {
    // The Arc pin is published under SERVICE. Idle removal requires exclusive
    // Arc::get_mut access, so it cannot detach this lookup before registration.
    let owner = db_sessions(db);
    #[cfg(test)]
    test_pin_checkpoint(db, PinStage::Registration);
    {
        let mut ledger = lock(&owner.kernel_lifecycle.serial);
        ledger.registered.insert(db.handle_id());
        changed(&owner);
    }
    KernelLifecycleRegistration {
        _owner: owner,
        _handle: db.handle_id(),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KernelBlockedReason {
    NotRegistered,
    CurrentAuthority,
    NativeValidation,
    Capacity,
    Custody,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KernelRetirementState {
    Pending {
        accepted_jobs: usize,
        cleanup_running: bool,
    },
    RetainedBlocked {
        room_count: usize,
        reason: KernelBlockedReason,
    },
    Uncertain {
        operation_ids: Vec<String>,
    },
    Quiescent,
}
/// Terminal storage seal, never physical pool ACK or authorization to write.
#[derive(Clone)]
pub(crate) struct KernelRetirementWitness {
    purpose: CleanupPurpose,
    db: Db,
    intent: Intent,
}
pub(crate) fn seal_kernel_retirement(db: &Db) -> KernelRetirementWitness {
    let owner = db_sessions(db);
    {
        let _ledger = lock(&owner.kernel_lifecycle.serial);
        owner.kernel_lifecycle.sealed.send_replace(true);
        changed(&owner);
    }
    KernelRetirementWitness {
        purpose: CleanupPurpose {
            owner,
            key: session_key(db),
            generation: 0,
        },
        db: db.clone(),
        intent: Intent::Retire,
    }
}
impl KernelRetirementWitness {
    pub(crate) fn seal_id(&self) -> uuid::Uuid {
        self.purpose.owner.kernel_lifecycle.seal_id
    }
    pub(crate) fn observe(&self) -> KernelRetirementState {
        let owner = &self.purpose.owner;
        let mut ledger = lock(&owner.kernel_lifecycle.serial);
        let mut operation_ids = Vec::new();
        if let Some(operation) = lock(&owner.kernel_quarantine_identity).clone() {
            operation_ids.push(operation);
        }
        if let Some(operation) = &ledger.driver_unknown {
            if !operation_ids.contains(operation) {
                operation_ids.push(operation.clone());
            }
        }
        if *owner.kernel_quarantine.borrow() || !operation_ids.is_empty() {
            return KernelRetirementState::Uncertain { operation_ids };
        }
        let room_count = lock(&owner.records)
            .values()
            .filter(|r| r.backend == SessionBackend::KernelV2)
            .count();
        if !ledger.registered.contains(&self.db.handle_id()) {
            return KernelRetirementState::RetainedBlocked {
                room_count,
                reason: KernelBlockedReason::NotRegistered,
            };
        }
        if ledger.quiescent {
            return KernelRetirementState::Quiescent;
        }
        if ledger.accepted_jobs != 0 || ledger.cleanup_running {
            return KernelRetirementState::Pending {
                accepted_jobs: ledger.accepted_jobs,
                cleanup_running: ledger.cleanup_running,
            };
        }
        if room_count == 0 {
            // SAME lock as seal/reservation, with actual permits released before
            // accepted_jobs was decremented. No new cleanup can cross this latch.
            ledger.quiescent = true;
            return KernelRetirementState::Quiescent;
        }
        match &ledger.blocked {
            Some(reason) => KernelRetirementState::RetainedBlocked {
                room_count,
                reason: reason.clone(),
            },
            None => KernelRetirementState::Pending {
                accepted_jobs: 0,
                cleanup_running: false,
            },
        }
    }
    pub(crate) async fn drive_once(&self) -> KernelRetirementState {
        let owner = Arc::clone(&self.purpose.owner);
        let mut changes = owner.kernel_lifecycle.changed.subscribe();
        if let state @ (KernelRetirementState::Quiescent
        | KernelRetirementState::Uncertain { .. }
        | KernelRetirementState::RetainedBlocked {
            reason: KernelBlockedReason::NotRegistered,
            ..
        }) = self.observe()
        {
            return state;
        }
        let (start, observed_generation) = {
            let mut ledger = lock(&owner.kernel_lifecycle.serial);
            if ledger.quiescent {
                return KernelRetirementState::Quiescent;
            }
            if ledger.cleanup_running {
                (None, ledger.cleanup_generation)
            } else {
                ledger.cleanup_running = true;
                ledger.cleanup_finished = false;
                ledger.cleanup_generation = ledger.cleanup_generation.wrapping_add(1);
                ledger.blocked = None;
                (Some(ledger.cleanup_generation), ledger.cleanup_generation)
            }
        };
        if let Some(generation) = start {
            let db = self.db.clone();
            let pass_owner = owner.clone();
            let intent = self.intent;
            let mut purpose = self.purpose.clone();
            purpose.generation = generation;
            let start_result = with_cleanup(purpose, async {
                kernel_writes::start_owned_with(self.db.clone(), move || {
                    // Constructed only AFTER capacity/runtime admission; known
                    // refusal before spawn is blocked, not driver uncertainty.
                    let guard = DriveGuard {
                        db: db.clone(),
                        owner: pass_owner.clone(),
                        finished: false,
                    };
                    async move {
                        let mut guard = guard;
                        let rooms = lock(&pass_owner.records)
                            .values()
                            .filter(|r| r.backend == SessionBackend::KernelV2)
                            .cloned()
                            .collect::<Vec<_>>();
                        let mut blocked = None;
                        for room in rooms {
                            let result = finalize_in_owner(
                                db.clone(),
                                Target::new(&db, room),
                                intent,
                                if matches!(intent, Intent::Shutdown) {
                                    "server shutdown"
                                } else {
                                    "kernel owner retirement"
                                }
                                .into(),
                                None,
                            )
                            .await;
                            match result {
                                Ok(Outcome::Clean | Outcome::Versioned(_)) => {}
                                Ok(_) => blocked = Some(KernelBlockedReason::Custody),
                                Err(error) => {
                                    blocked = Some(
                                        if error.to_string().contains("no current native caller") {
                                            KernelBlockedReason::CurrentAuthority
                                        } else {
                                            KernelBlockedReason::NativeValidation
                                        },
                                    );
                                }
                            }
                            if *pass_owner.kernel_quarantine.borrow() {
                                break;
                            }
                        }
                        {
                            let mut ledger = lock(&pass_owner.kernel_lifecycle.serial);
                            ledger.blocked = blocked;
                            ledger.cleanup_finished = true;
                            guard.finished = true;
                            changed(&pass_owner);
                        }
                        #[cfg(test)]
                        kernel_writes::test_checkpoint(
                            &db,
                            kernel_writes::TestStage::LifecyclePassFinished,
                        )
                        .await?;
                        Ok(())
                    }
                })
            })
            .await;
            if let Err(error) = start_result {
                let mut ledger = lock(&owner.kernel_lifecycle.serial);
                ledger.cleanup_running = false;
                ledger.blocked = Some(if error.to_string().contains("capacity") {
                    KernelBlockedReason::Capacity
                } else {
                    KernelBlockedReason::Custody
                });
                changed(&owner);
                drop(ledger);
                return self.observe();
            }
            // Receiver is only observation. The driver remains owned even if
            // drive_once itself is cancelled before this completion watch.
        }
        loop {
            let (running, generation) = {
                let ledger = lock(&owner.kernel_lifecycle.serial);
                (ledger.cleanup_running, ledger.cleanup_generation)
            };
            // This observer joins exactly one pass, never a later retry.
            if !running || generation != observed_generation {
                return self.observe();
            }
            if matches!(self.observe(), KernelRetirementState::Uncertain { .. }) {
                return self.observe();
            }
            if changes.changed().await.is_err() {
                return self.observe();
            }
        }
    }
}
struct DriveGuard {
    db: Db,
    owner: Arc<DbSessions>,
    finished: bool,
}
impl Drop for DriveGuard {
    fn drop(&mut self) {
        if !self.finished {
            let operation = uuid::Uuid::new_v4().to_string();
            {
                let mut ledger = lock(&self.owner.kernel_lifecycle.serial);
                ledger.driver_unknown = Some(operation.clone());
                changed(&self.owner);
            }
            kernel_writes::quarantine_storage(&self.db, &operation);
        }
    }
}
pub(super) async fn shutdown_room(db: Db, _room: Arc<LiveSession>) -> KernelRetirementState {
    let mut witness = seal_kernel_retirement(&db);
    witness.intent = Intent::Shutdown;
    witness.drive_once().await
}

pub(super) async fn finalize(
    db: Db,
    target: Target,
    intent: Intent,
    reason: String,
    hint: Option<Caller>,
) -> Outcome {
    let failure_target = target.clone();
    // Original stamp precedes runtime/capacity admission. Observer cancellation
    // never publishes a mark; the admitted job retains actual work/ownership.
    let fallback = FailureFence::capture(&db, &target.room, &target.session);
    let future = finalize_with_fence(db.clone(), target, intent, reason, hint, fallback.clone());
    let result = kernel_writes::owned_result(db.clone(), future).await;
    match result {
        Ok(outcome) => outcome,
        Err(error) => {
            #[cfg(test)]
            let _ = kernel_writes::test_checkpoint(
                &db,
                kernel_writes::TestStage::LifecycleBeforeOuterFailurePublication,
            )
            .await;
            if let Some(fence) = fallback {
                fence.publish_if_current();
            }
            Outcome::refused(&db, &failure_target, error)
        }
    }
}

async fn finalize_in_owner(
    db: Db,
    target: Target,
    intent: Intent,
    reason: String,
    hint: Option<Caller>,
) -> Result<Outcome> {
    let fallback = FailureFence::capture(&db, &target.room, &target.session);
    finalize_with_fence(db, target, intent, reason, hint, fallback).await
}
async fn finalize_with_fence(
    db: Db,
    target: Target,
    intent: Intent,
    reason: String,
    hint: Option<Caller>,
    fallback: Option<FailureFence>,
) -> Result<Outcome> {
    let acquired = async {
        #[cfg(test)]
        kernel_writes::test_checkpoint(&db, kernel_writes::TestStage::LifecycleBeforeAcquire)
            .await?;
        KernelBodyWrite::acquire_lifecycle(&db, &target).await
    }
    .await;
    let mut owner = match acquired {
        Ok(owner) => owner,
        Err(error) => {
            #[cfg(test)]
            let _ = kernel_writes::test_checkpoint(
                &db,
                kernel_writes::TestStage::LifecycleBeforeFailurePublication,
            )
            .await;
            if let Some(fence) = fallback {
                fence.publish_if_current();
            }
            return Err(error);
        }
    };
    if matches!(intent, Intent::GraceExpire) {
        let state = target.room.state();
        if !state.peers.is_empty() || !state.grace_until.is_some_and(|t| t <= Instant::now()) {
            return Ok(Outcome::Active);
        }
    }
    let dirty = target.room.state().dirty();
    let version = if dirty {
        // Current basis refreshed under acquired ops before actor/snapshot/SQL
        // errors; the original pre-owner fallback is never recaptured.
        owner.arm_finalization_failure();
        #[cfg(test)]
        kernel_writes::test_checkpoint(&db, kernel_writes::TestStage::LifecycleAfterArm).await?;
        let callers = owner.lifecycle_callers(hint);
        let mut actor = None;
        for caller in callers {
            if SessionBackend::KernelV2
                .load_committed(&db, &caller, &target.room.record_id, PeerKind::Edit)
                .await
                .is_ok()
            {
                actor = Some(caller);
                break;
            }
        }
        let actor = actor.ok_or_else(|| {
            Error::engine("no current native caller can finalize dirty kernel custody")
        })?;
        let (returned, version) = owner.flush(&actor, &reason).await?;
        owner = returned;
        version
    } else {
        None
    };
    if !matches!(intent, Intent::Flush) {
        owner.close_lifecycle(
            &target,
            match intent {
                Intent::Shutdown => CloseReason::ServerShutdown,
                Intent::GraceExpire => CloseReason::Left,
                _ => CloseReason::Superseded,
            },
        )?;
    }
    Ok(match version {
        Some(version) => Outcome::Versioned(version),
        None => Outcome::Clean,
    })
}

pub(super) async fn cut_room(
    db: Db,
    room: Arc<LiveSession>,
    reason: String,
    hint: Option<Caller>,
) -> std::result::Result<Option<Versioned>, Refused> {
    match finalize(
        db.clone(),
        Target::new(&db, room),
        Intent::Flush,
        reason,
        hint,
    )
    .await
    {
        Outcome::Clean | Outcome::Active => Ok(None),
        Outcome::Versioned(version) => Ok(Some(version)),
        Outcome::RetainedBlocked { reason, .. } => Err(unavailable(reason)),
        Outcome::Uncertain { operation, .. } => Err(unavailable(format!(
            "kernel lifecycle outcome uncertain ({operation}); do not retry"
        ))),
    }
}

struct RecheckTicket {
    owner: Arc<DbSessions>,
    session: String,
    armed: bool,
}
impl Drop for RecheckTicket {
    fn drop(&mut self) {
        if self.armed {
            lock(&self.owner.kernel_lifecycle.rechecks).remove(&self.session);
        }
    }
}
pub(super) fn schedule_recheck(db: Db, room: Arc<LiveSession>) {
    // Background observation never inherits a cleanup-purpose seal exception.
    if sealed(&db) {
        return;
    }
    let owner = db_sessions(&db);
    let session = room.state().session.0.clone();
    {
        let mut queued = lock(&owner.kernel_lifecycle.rechecks);
        if let Some(again) = queued.get_mut(&session) {
            *again = true;
            return;
        }
        queued.insert(session.clone(), false);
    }
    let ticket = RecheckTicket {
        owner: owner.clone(),
        session: session.clone(),
        armed: true,
    };
    let job_db = db.clone();
    let future = async move {
        let mut ticket = ticket;
        loop {
            let ops = kernel_writes::acquire_peer_ops(&room)
                .await
                .map_err(|e| Error::engine(e.to_string()))?;
            kernel_writes::recheck_room(&room, &db).await;
            drop(ops);
            let again = {
                let mut queued = lock(&owner.kernel_lifecycle.rechecks);
                match queued.get_mut(&session) {
                    Some(again) if *again => {
                        *again = false;
                        true
                    }
                    _ => {
                        queued.remove(&session);
                        ticket.armed = false;
                        false
                    }
                }
            };
            if !again {
                return Ok(());
            }
        }
    };
    // Admission/capacity is synchronous and precedes the sole background spawn.
    // Dropping the receiver cannot cancel the reserved result owner.
    let _ = kernel_writes::start_owned(job_db, future);
}
fn db_for_room(room: &Arc<LiveSession>) -> Db {
    room.state().db.clone()
}

pub(super) async fn wait_until(room: &Arc<LiveSession>, until: Instant) -> Result<()> {
    let db = db_for_room(room);
    let owner = db_sessions(&db);
    let mut quarantine = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    kernel_writes::ensure_available(&db)?;
    tokio::select! {
        _ = tokio::time::sleep_until(until) => {},
        _ = quarantine.changed() => return Err(Error::engine("kernel storage quarantined")),
        _ = sealed.changed() => return Err(Error::engine("kernel lifecycle admission sealed")),
    }
    kernel_writes::ensure_available(&db)
}

#[cfg(test)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum AdmissionKind {
    Dirty,
    Fleet,
}
#[cfg(test)]
static ADMISSION_HOOKS: LazyLock<StdMutex<HashMap<(PathBuf, AdmissionKind), WriteAdmission>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(super) struct TestAdmissionHook {
    key: PathBuf,
    kind: AdmissionKind,
}
#[cfg(test)]
impl Drop for TestAdmissionHook {
    fn drop(&mut self) {
        lock(&ADMISSION_HOOKS).remove(&(self.key.clone(), self.kind));
    }
}
#[cfg(test)]
pub(super) fn test_admission_hook(
    db: &Db,
    kind: AdmissionKind,
    hook: WriteAdmission,
) -> TestAdmissionHook {
    lock(&ADMISSION_HOOKS).insert((session_key(db), kind), hook);
    TestAdmissionHook {
        key: session_key(db),
        kind,
    }
}
#[cfg(test)]
pub(super) fn test_admission(db: &Db, kind: AdmissionKind) -> Option<WriteAdmission> {
    lock(&ADMISSION_HOOKS)
        .get(&(session_key(db), kind))
        .cloned()
}

#[cfg(test)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum PinStage {
    Registration,
    Reservation,
}
#[cfg(test)]
pub(super) struct PinGate {
    pub(super) entered: std::sync::Barrier,
    pub(super) release: std::sync::Barrier,
}
#[cfg(test)]
type PinGateMap = HashMap<(PathBuf, PinStage), Arc<PinGate>>;
#[cfg(test)]
static PIN_GATES: LazyLock<StdMutex<PinGateMap>> = LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(super) fn pin_gate(db: &Db, stage: PinStage) -> Arc<PinGate> {
    let gate = Arc::new(PinGate {
        entered: std::sync::Barrier::new(2),
        release: std::sync::Barrier::new(2),
    });
    lock(&PIN_GATES).insert((session_key(db), stage), gate.clone());
    gate
}
#[cfg(test)]
pub(super) fn test_pin_checkpoint(db: &Db, stage: PinStage) {
    let gate = lock(&PIN_GATES).remove(&(session_key(db), stage));
    if let Some(gate) = gate {
        gate.entered.wait();
        gate.release.wait();
    }
}

#[cfg(test)]
#[path = "kernel_lifecycle_tests.rs"]
mod tests;
