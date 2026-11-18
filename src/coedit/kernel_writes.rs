//! Kernel writer ownership. This module is a child of `live`, so room/registry
//! implementation details stay private to the service. Native event assembly
//! consumes a read-only candidate view, never this owner's locks or registry.
use super::*;
use crate::coedit::{backend::SessionBackend, kernel_v2};
use crate::{Error, Result};
use serde_json::Value;
use sqlx::{Sqlite, SqliteConnection};

// Inactive native apply/sync proof unit; no production entry caller.
#[path = "kernel_peer_reads.rs"]
mod peer_reads;

/// Replay-only ownership never flushes, retires grace, or prepares a candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelWriteMode {
    RouteBody,
    ReplayOnly,
    RefuseLive,
    Metadata,
}

pub(crate) fn ensure_available(db: &Db) -> Result<()> {
    if existing_db_sessions(db).is_some_and(|owner| *owner.kernel_quarantine.borrow()) {
        return Err(Error::engine(
            "kernel storage is quarantined; explicit reconciliation required",
        ));
    }
    super::kernel_lifecycle::ensure_admission(db)
}

pub(super) fn quarantine_storage(db: &Db, operation: &str) {
    let owner = db_sessions(db);
    let mut identity = lock(&owner.kernel_quarantine_identity);
    if identity.is_none() {
        *identity = Some(operation.to_owned());
    }
    owner.kernel_quarantine.send_replace(true);
}

async fn acquire_lane(db: &Db, owner: &Arc<DbSessions>) -> Result<OwnedMutexGuard<()>> {
    let mut quarantined = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    ensure_available(db)?;
    let mut waiting = Box::pin(Arc::clone(&owner.kernel_lane).lock_owned());
    #[cfg(test)]
    match futures::poll!(&mut waiting) {
        std::task::Poll::Ready(lane) => {
            ensure_available(db)?;
            return Ok(lane);
        }
        std::task::Poll::Pending => test_checkpoint(db, TestStage::LaneQueued).await?,
    }
    let lane = tokio::select! {
        lane = &mut waiting => lane,
        _ = quarantined.changed() => return Err(Error::engine("kernel storage is quarantined")),
        _ = sealed.changed(), if super::kernel_lifecycle::current_cleanup().is_none() => return Err(Error::engine("kernel storage admission sealed")),
    };
    ensure_available(db)?;
    Ok(lane)
}

pub(super) async fn acquire_read_gate(
    db: &Db,
    owner: &Arc<DbSessions>,
) -> Result<OwnedRwLockReadGuard<()>> {
    let mut quarantined = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    ensure_available(db)?;
    let gate = tokio::select! {
        gate = Arc::clone(&owner.open_gate).read_owned() => gate,
        _ = quarantined.changed() => return Err(Error::engine("kernel storage is quarantined")),
        _ = sealed.changed(), if super::kernel_lifecycle::current_cleanup().is_none() => return Err(Error::engine("kernel storage admission sealed")),
    };
    ensure_available(db)?;
    Ok(gate)
}

/// First seed owns the lane before waiting for exclusive publication access.
/// Subscribe before checking admission, so seal/quarantine can cancel that wait
/// without requiring any shared gate holder to release its custody.
async fn acquire_write_gate(
    db: &Db,
    owner: &Arc<DbSessions>,
) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>> {
    let mut quarantined = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    ensure_available(db)?;
    let cleanup = super::kernel_lifecycle::current_cleanup()
        .is_some_and(|purpose| purpose.matches(db, owner));
    let mut waiting = Box::pin(Arc::clone(&owner.open_gate).write_owned());
    #[cfg(test)]
    match futures::poll!(&mut waiting) {
        std::task::Poll::Ready(gate) => {
            ensure_available(db)?;
            return Ok(gate);
        }
        std::task::Poll::Pending => test_checkpoint(db, TestStage::SeedGateQueued).await?,
    }
    let gate = tokio::select! {
        gate = &mut waiting => gate,
        _ = quarantined.changed() => return Err(Error::engine("kernel storage is quarantined")),
        _ = sealed.changed(), if !cleanup => return Err(Error::engine("kernel storage admission sealed")),
    };
    ensure_available(db)?;
    Ok(gate)
}

pub(super) async fn acquire_peer_ops(
    room: &Arc<LiveSession>,
) -> std::result::Result<OwnedMutexGuard<()>, Refused> {
    let db = room.state().db.clone();
    let owner = db_sessions(&db);
    let mut quarantined = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    ensure_available(&db).map_err(unavailable)?;
    let mut waiting = Box::pin(Arc::clone(&room.ops).lock_owned());
    #[cfg(test)]
    match futures::poll!(&mut waiting) {
        std::task::Poll::Ready(ops) => {
            ensure_available(&db).map_err(unavailable)?;
            return Ok(ops);
        }
        std::task::Poll::Pending => test_checkpoint(&db, TestStage::OpsQueued)
            .await
            .map_err(unavailable)?,
    }
    let ops = tokio::select! {
        ops = &mut waiting => ops,
        _ = quarantined.changed() => return Err(Refused::new(RefusalCode::RecordUnsupported,
            "kernel storage quarantined; explicit reconciliation required")),
        _ = sealed.changed(), if super::kernel_lifecycle::current_cleanup().is_none() => return Err(unavailable("kernel storage admission sealed")),
    };
    ensure_available(&db).map_err(unavailable)?;
    Ok(ops)
}

/// Native mutations serialize before BEGIN. Quarantine retains this lane, and
/// its watch wakes queued requests to refuse instead of accumulating waiters.
pub(crate) struct KernelBodyWrite {
    db: Db,
    caller: Option<Caller>,
    _owner: Arc<DbSessions>,
    _lane: OwnedMutexGuard<()>,
    _gate: OwnedRwLockReadGuard<()>,
    _admission: Option<Box<dyn Send>>,
    live: Option<KernelLiveWrite>,
    timestamps: FlushTimestamps,
    // Slot-last only: preserve the existing lane/gate/admission/live drop order.
    _earlier_loader_slot: Option<Arc<OwnedJobSlot>>,
    #[cfg(test)]
    _fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
}

struct KernelLiveWrite {
    room: Arc<LiveSession>,
    // Fields drop in declaration order: mark BEFORE releasing _ops, including
    // consuming BEGIN/rollback/commit failures. Do not reorder these fields.
    failure_mark: Option<super::kernel_lifecycle::ArmedFailureMark>,
    _ops: OwnedMutexGuard<()>,
    session: SessionId,
    body: String,
    expected_body_seq: Option<i64>,
    prepared: Option<PreparedKernelBody>,
    committed: Option<kernel_v2::NativeBodyCommit>,
    author: Option<Author>,
    reason: String,
}

pub(in crate::coedit) struct ExplicitAppend<'tx, 'request> {
    db: &'tx Db,
    tx: &'tx mut SqliteConnection,
    acts: &'tx mut crate::act::ActAllocation,
    request: &'request peer_reads::OwnedExplicitVersionRequest,
    snapshot: &'request super::super::VersionSnapshot,
    expected_body_seq: Option<i64>,
    permit: KernelAppendPermit,
}
impl<'tx, 'request> ExplicitAppend<'tx, 'request> {
    pub(in crate::coedit) fn into_parts(
        self,
    ) -> (
        &'tx Db,
        &'tx mut SqliteConnection,
        &'tx mut crate::act::ActAllocation,
        &'request peer_reads::OwnedExplicitVersionRequest,
        &'request super::super::VersionSnapshot,
        Option<i64>,
        KernelAppendPermit,
    ) {
        (
            self.db,
            self.tx,
            self.acts,
            self.request,
            self.snapshot,
            self.expected_body_seq,
            self.permit,
        )
    }
}

pub(crate) struct PreparedKernelBody {
    candidate: PreparedUpdate,
    body: String,
    contributors: Vec<AcknowledgedContributor>,
    span_map: SpanMap,
    session: SessionId,
}

impl PreparedKernelBody {
    fn view(&self) -> kernel_v2::NativeCandidateView<'_> {
        kernel_v2::NativeCandidateView {
            body: &self.body,
            contributors: &self.contributors,
            span_map: &self.span_map,
            session: &self.session,
        }
    }
}

impl KernelBodyWrite {
    /// Batch bodies deliberately do not flush or route active rooms. The held
    /// seed gate prevents an inactive target acquiring a new room before commit.
    pub(crate) fn require_inactive_batch_body(&self, record: &str) -> Result<()> {
        ensure_available(&self.db)?;
        if existing_session(&self.db, record).is_some_and(|room| !room.state().closed) {
            return Err(Error::conflict("batch body target has an active or grace coedit session; use update_record for routed live edits"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn permit_for_test(
        &self,
        tx: &mut SqliteConnection,
        payload: &Value,
    ) -> Result<KernelAppendPermit> {
        KernelAppendPermit::mint(&self.db, tx, &self.live.as_ref().unwrap().room, payload).await
    }
    pub(crate) async fn acquire(
        db: &Db,
        caller: &Caller,
        record: Option<&str>,
        mode: KernelWriteMode,
    ) -> Result<Self> {
        Self::acquire_inner(
            db,
            Some(caller),
            record,
            mode,
            None,
            #[cfg(test)]
            None,
        )
        .await
    }

    pub(super) async fn acquire_lifecycle(
        db: &Db,
        target: &super::kernel_lifecycle::Target,
    ) -> Result<Self> {
        Self::acquire_inner(
            db,
            None,
            Some(&target.room().record_id),
            KernelWriteMode::RouteBody,
            Some(target),
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn acquire_inner(
        db: &Db,
        caller: Option<&Caller>,
        record: Option<&str>,
        mode: KernelWriteMode,
        target: Option<&super::kernel_lifecycle::Target>,
        #[cfg(test)] mut _fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
    ) -> Result<Self> {
        let mut admission = admit_write(db).map_err(|error| Error::engine(error.to_string()))?;
        #[cfg(test)]
        test_checkpoint(db, TestStage::BeforeOwnedLane).await?;
        let owner = db_sessions(db);
        let mut lane = acquire_lane(db, &owner).await?;
        let mut gate = acquire_read_gate(db, &owner).await?;
        if let Some(target) = target {
            target.validate(db)?;
        }
        let mut live = None;
        let mut admitted_caller = None;
        let mut earlier_loader_slot = None;
        if mode != KernelWriteMode::Metadata {
            if let Some(room) = record.and_then(|id| lock(&owner.records).get(id).cloned()) {
                if !room
                    .kernel_origin
                    .as_ref()
                    .is_some_and(|origin| origin.same_handle(db))
                {
                    return Err(Error::engine("native room belongs to another seed handle"));
                }
                if room.backend != SessionBackend::KernelV2 {
                    return Err(Error::engine("kernel writer backend mismatch"));
                }
                let mut ops = acquire_peer_ops(&room)
                    .await
                    .map_err(|e| Error::engine(e.to_string()))?;
                // Revalidate after the awaited ops acquisition. A record key or
                // mutable State.db is never evidence of the retained target.
                if !existing_db_sessions(db).is_some_and(|current| Arc::ptr_eq(&current, &owner))
                    || !lock(&owner.records)
                        .get(&room.record_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &room))
                    || !room
                        .kernel_origin
                        .as_ref()
                        .is_some_and(|origin| origin.same_handle(db))
                {
                    return Err(Error::engine("native writer target changed while waiting"));
                }
                if let Some(target) = target {
                    target.validate(db)?;
                }
                let closed = room.state().closed;
                if !closed {
                    if mode == KernelWriteMode::RefuseLive {
                        return Err(Error::engine(
                            "unported kernel scope writer refused while live",
                        ));
                    }
                    // Replay is authorized by the adapter's actual tx and never
                    // flushes/retire grace. RouteBody rechecks supported scope.
                    if mode == KernelWriteMode::RouteBody && target.is_none() {
                        let caller =
                            caller.ok_or_else(|| Error::auth("kernel writer Caller missing"))?;
                        let session = room.state().session.clone();
                        // Production clones its EXACT admitted slot. Standalone
                        // private callers reserve once, before graph arming/SQL.
                        let slot = match OWNED_JOB_SLOT.try_with(Arc::clone) {
                            Ok(slot) => slot,
                            Err(_) => reserve_job_slot(db)?,
                        };
                        if !Arc::ptr_eq(&slot.owner, &owner) {
                            return Err(Error::engine("earlier loader job owner mismatch"));
                        }
                        let loader = EarlierLoaderGuard::new(EarlierLoaderOwnership {
                            db: db.clone(),
                            caller: caller.clone(),
                            owner: Arc::clone(&owner),
                            room: Arc::clone(&room),
                            session,
                            _ops: ops,
                            _gate: gate,
                            _lane: lane,
                            _admission: admission,
                            slot,
                            #[cfg(test)]
                            fixture_owner: _fixture_owner.take(),
                        });
                        #[cfg(test)]
                        let loader = loader_test_drop_mode(loader)?;
                        let carried = loader.admit().await?;
                        // Move the SAME Caller and guard objects; do not clone
                        // again or change KernelBodyWrite's existing drop order.
                        admitted_caller = Some(carried.caller);
                        ops = carried._ops;
                        gate = carried._gate;
                        lane = carried._lane;
                        admission = carried._admission;
                        earlier_loader_slot = Some(carried.slot);
                        #[cfg(test)]
                        {
                            _fixture_owner = carried.fixture_owner;
                        }
                    }
                    let (session, body, expected_body_seq) = {
                        let state = room.state();
                        (
                            state.session.clone(),
                            state
                                .registry
                                .live_body(&state.session)
                                .map_err(|error| Error::engine(error.to_string()))?,
                            state.base.proof.body_event_seq,
                        )
                    };
                    live = Some(KernelLiveWrite {
                        room,
                        failure_mark: None,
                        _ops: ops,
                        session,
                        body,
                        expected_body_seq,
                        prepared: None,
                        committed: None,
                        author: None,
                        reason: String::new(),
                    });
                }
            }
        }
        Ok(Self {
            db: db.clone(),
            caller: admitted_caller.or_else(|| caller.cloned()),
            _owner: owner,
            _lane: lane,
            _gate: gate,
            _admission: admission,
            live,
            timestamps: FlushTimestamps::default(),
            _earlier_loader_slot: earlier_loader_slot,
            #[cfg(test)]
            _fixture_owner,
        })
    }

    #[cfg(test)]
    pub(crate) async fn acquire_fixture_owned_update_for_test(
        db: &Db,
        caller: &Caller,
        record: Option<&str>,
        mode: KernelWriteMode,
        fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
    ) -> Result<Self> {
        Self::acquire_inner(db, Some(caller), record, mode, None, fixture_owner).await
    }

    pub(super) async fn acquire_explicit_version(
        request: &peer_reads::OwnedExplicitVersionRequest,
    ) -> Result<Self> {
        let target = super::kernel_lifecycle::Target::new(request.db(), Arc::clone(request.room()));
        let mut owner = Self::acquire_inner(
            request.db(),
            Some(request.caller()),
            Some(request.record()),
            KernelWriteMode::RouteBody,
            Some(&target),
            #[cfg(test)]
            request.fixture_owner(),
        )
        .await?;
        request.require_owned_identity(&owner)?;
        // Clone the SAME admitted seat, never reserve another. Retained known-
        // commit installation custody disposes guards/slot before test directory.
        owner._earlier_loader_slot = Some(OWNED_JOB_SLOT.with(Arc::clone));
        Ok(owner)
    }

    pub(super) async fn append_explicit_snapshot(
        transaction: &mut KernelTransaction<KernelBodyWrite>,
        request: &peer_reads::OwnedExplicitVersionRequest,
        snapshot: &super::super::VersionSnapshot,
        acts: &mut crate::act::ActAllocation,
    ) -> Result<BaseVersion> {
        let (tx, owner) = transaction.parts();
        request.require_same_dispatch()?;
        let facts =
            kernel_v2::peer_facts_on(tx, request.caller(), request.record(), PeerKind::Edit)
                .await?;
        request.require_owned_basis(owner, &facts, snapshot)?;
        let (room, expected_body_seq) = {
            let live = owner
                .live
                .as_ref()
                .ok_or_else(|| Error::engine("explicit room missing"))?;
            (Arc::clone(&live.room), live.expected_body_seq)
        };
        let candidate = kernel_v2::NativeCandidateView {
            body: snapshot.body(),
            contributors: snapshot.contributors(),
            span_map: snapshot.span_map(),
            session: snapshot.session_id(),
        };
        let payload = kernel_v2::candidate_payload(&candidate, None)?;
        let permit = KernelAppendPermit::mint(&owner.db, tx, &room, &payload).await?;
        drop(payload);
        request.require_owned_basis(owner, &facts, snapshot)?;
        kernel_v2::cut_explicit_in(ExplicitAppend {
            db: &owner.db,
            tx,
            acts,
            request,
            snapshot,
            expected_body_seq,
            permit,
        })
        .await
    }

    pub(super) fn arm_finalization_failure(&mut self) {
        let Some(live) = self.live.as_mut() else {
            return;
        };
        if live.failure_mark.as_ref().is_some_and(|mark| mark.armed()) {
            return;
        }
        live.failure_mark =
            super::kernel_lifecycle::FailureFence::capture(&self.db, &live.room, &live.session)
                .map(super::kernel_lifecycle::ArmedFailureMark::new);
    }

    pub(super) fn lifecycle_callers(&self, hint: Option<Caller>) -> Vec<Caller> {
        let Some(live) = &self.live else {
            return Vec::new();
        };
        let state = live.room.state();
        let last = state
            .registry
            .last_accepted_contributor(&live.session)
            .ok()
            .flatten();
        let mut callers = Vec::new();
        if let Some(last) = last {
            callers.extend(
                state
                    .peers
                    .values()
                    .filter(|peer| peer.author.contributor.principal == last.principal)
                    .map(|peer| peer.caller.clone()),
            );
        }
        callers.extend(hint);
        callers.extend(state.callers.values().cloned());
        callers
    }

    pub(super) fn close_lifecycle(
        &self,
        target: &super::kernel_lifecycle::Target,
        reason: CloseReason,
    ) -> Result<()> {
        self.validate_precommit()?;
        target.validate(&self.db)?;
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| Error::engine("kernel lifecycle room missing"))?;
        if !Arc::ptr_eq(&live.room, target.room()) || live.room.state().dirty() {
            return Err(Error::engine(
                "kernel lifecycle cannot close dirty or replacement custody",
            ));
        }
        close_session(&live.room, reason);
        Ok(())
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live.is_some()
    }

    pub(crate) fn live_body(&self) -> Option<&str> {
        self.live.as_ref().map(|live| live.body.as_str())
    }

    pub(crate) fn guard_updated_at<'a>(&'a self, current: &'a str) -> &'a str {
        guarded_updated_at(
            self.timestamps.before.as_deref(),
            self.timestamps.after.as_deref(),
            current,
        )
    }

    pub(crate) fn quarantine(&mut self, operation: &str) {
        quarantine_storage(&self.db, operation);
        if let Some(live) = &self.live {
            // Preserve registry/dirty admissions and reservation for explicit
            // reconciliation. No new peer operation is acknowledged.
            live.room.state().closed = true;
            live.room.emit(SessionEvent::Closed {
                peer: None,
                reason: CloseReason::Superseded,
            });
            tracing::error!(record = %live.room.record_id, operation, "kernel writer quarantined");
        }
    }

    pub(crate) fn validate_precommit(&self) -> Result<()> {
        ensure_available(&self.db)?;
        if let Some(live) = &self.live {
            let state = live.room.state();
            if state.closed || state.session != live.session {
                return Err(Error::engine("kernel writer session binding changed"));
            }
            if let Some(prepared) = &live.prepared {
                state
                    .registry
                    .validate_prepared_update(&live.session, None, &prepared.candidate)
                    .map_err(|_| Error::engine("kernel writer candidate binding changed"))?;
            }
        }
        Ok(())
    }

    pub(crate) async fn validate_in(&mut self, tx: &mut SqliteConnection) -> Result<()> {
        self.validate_precommit()?;
        if let Some(live) = &mut self.live {
            let loaded = kernel_v2::load_committed_on(
                tx,
                self.caller
                    .as_ref()
                    .ok_or_else(|| Error::auth("kernel ordinary writer Caller missing"))?,
                &live.room.record_id,
                PeerKind::Edit,
            )
            .await?;
            let expected = live
                .committed
                .as_ref()
                .map(|event| event.body_event_seq)
                .or(live.expected_body_seq);
            if loaded.base.proof.body_event_seq != expected {
                return Err(Error::conflict(
                    "kernel writer body event changed before commit",
                ));
            }
            if let Some(committed) = &mut live.committed {
                if loaded.base.proof.body_event_id.as_deref()
                    != Some(committed.body_event_id.as_str())
                    || loaded.base.body_sha256 != committed.body_sha256
                {
                    return Err(Error::engine("kernel final body evidence disagrees"));
                }
                committed.record_version = loaded.base.version;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)] // Fixed outer scope plus sealed binding.
    pub(crate) async fn append_dispatched_body_in(
        &mut self,
        tx: &mut SqliteConnection,
        record: &str,
        body: &str,
        origin: Option<Value>,
        reason: &str,
        acts: &mut crate::act::ActAllocation,
        binding: Option<crate::kernel::app_installs::RoutedActionBinding<'_>>,
    ) -> Result<bool> {
        self.append_dispatched_body_with_basis_in(
            tx, record, body, origin, None, reason, acts, binding,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn append_dispatched_body_with_basis_in(
        &mut self,
        tx: &mut SqliteConnection,
        record: &str,
        body: &str,
        origin: Option<Value>,
        basis: Option<Value>,
        reason: &str,
        acts: &mut crate::act::ActAllocation,
        binding: Option<crate::kernel::app_installs::RoutedActionBinding<'_>>,
    ) -> Result<bool> {
        let Some(live) = self.live.as_mut() else {
            return Ok(false);
        };
        if live.room.record_id != record || live.prepared.is_some() {
            return Err(Error::engine("kernel writer target/candidate mismatch"));
        }
        let caller = self
            .caller
            .clone()
            .ok_or_else(|| Error::auth("kernel ordinary writer Caller missing"))?;
        let principal = crate::mcp::kernel_v2::principal_on(tx, &caller).await?;
        let binding = binding.ok_or_else(|| Error::auth("live routed action binding missing"))?;
        binding.require_update_scope(&caller, &principal, record, acts)?;
        let contributor = kernel_v2::contributor_on(tx, &caller).await?;
        let (old, new) = (live.body.clone(), body.to_owned());
        let splices =
            tokio::task::spawn_blocking(move || super::super::text_diff::splices(&old, &new))
                .await
                .map_err(|error| Error::engine(format!("kernel body diff failed: {error}")))?;
        let prepared = {
            let state = live.room.state();
            let candidate = state
                .registry
                .prepare_server_write(&live.session, body, &splices, &contributor)
                .map_err(|error| Error::engine(error.to_string()))?
                .ok_or_else(|| Error::engine("kernel routed body has no candidate change"))?;
            let span_map = state
                .registry
                .span_map_for_prepared(&live.session, &candidate)
                .map_err(|error| Error::engine(error.to_string()))?;
            state
                .registry
                .validate_prepared_update(&live.session, None, &candidate)
                .map_err(|_| Error::engine("kernel candidate binding mismatch before append"))?;
            PreparedKernelBody {
                body: candidate.body(),
                contributors: candidate.contributors(),
                candidate,
                span_map,
                session: live.session.clone(),
            }
        };
        let payload = kernel_v2::candidate_payload_with_basis(
            &prepared.view(),
            origin.clone(),
            basis.clone(),
        )?;
        let permit = KernelAppendPermit::mint(&self.db, tx, &live.room, &payload).await?;
        let committed = kernel_v2::cut_routed_in(
            &self.db,
            tx,
            &caller,
            record,
            live.expected_body_seq,
            prepared.view(),
            origin,
            basis,
            acts,
            permit,
        )
        .await?;
        drop(binding);
        live.author = Some(Author {
            contributor,
            kind: author_for(&caller).kind,
        });
        live.reason = reason.to_owned();
        live.prepared = Some(prepared);
        live.committed = Some(committed);
        Ok(true)
    }

    /// Synchronous after known durability, with ops still held. A mismatch
    /// quarantines and withholds success rather than acknowledging stale text.
    pub(crate) fn install_committed(&mut self) -> Result<()> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };
        let Some(committed) = live.committed.take() else {
            return Ok(());
        };
        let mut state = live.room.state();
        let operation = committed.body_event_id.clone();
        let result = (|| {
            let prepared = live
                .prepared
                .take()
                .ok_or_else(|| Error::engine("kernel committed candidate missing"))?;
            let ack = state
                .registry
                .install_prepared_update(&live.session, None, prepared.candidate)
                .map_err(|_| Error::engine("kernel committed candidate installation mismatch"))?;
            let snapshot = state
                .registry
                .version_snapshot(&live.session)
                .map_err(|error| Error::engine(error.to_string()))?;
            if sha256_hex(snapshot.body()) != committed.body_sha256 {
                return Err(Error::engine(
                    "kernel installed body disagrees with committed body",
                ));
            }
            let event = BodyEvent {
                id: committed.body_event_id.clone(),
                seq: committed.body_event_seq,
            };
            let proof = base_proof(&snapshot, &committed.body_sha256, Some(&event));
            let contributors = snapshot.contributors().to_vec();
            if state.registry.drain_version_snapshot(&snapshot)
                != Ok(super::super::DrainOutcome::Drained)
            {
                return Err(Error::engine("kernel committed snapshot drain mismatch"));
            }
            state.versioned_epoch = state.epoch();
            state.dirty_admission.take();
            state.last_op = Instant::now();
            let new_body_event = distinct_body_event(&state.base.proof, &proof);
            state.base = BaseVersion {
                version: committed.record_version.clone(),
                body_sha256: committed.body_sha256.clone(),
                proof: proof.clone(),
            };
            if new_body_event {
                state.kernel_finalization_blocked = false;
                if let Some(mark) = live.failure_mark.as_mut() {
                    mark.disarm();
                }
            }
            Ok((
                ack,
                Versioned {
                    session: live.session.clone(),
                    version: committed.record_version,
                    body_sha256: committed.body_sha256,
                    event_id: committed.body_event_id,
                    contributors,
                    reason: live.reason.clone(),
                    proof,
                    updated_at_around_cut: None,
                },
            ))
        })();
        drop(state);
        match result {
            Ok((ack, versioned)) => {
                live.room.emit(SessionEvent::Remote {
                    update: Arc::new(ack.broadcast),
                    origin: None,
                    from: live
                        .author
                        .clone()
                        .ok_or_else(|| Error::engine("kernel routed author missing"))?,
                });
                live.room.emit(SessionEvent::Versioned(versioned));
                Ok(())
            }
            Err(error) => {
                self.quarantine(&operation);
                Err(Error::engine(format!(
                    "kernel committed body event {operation} requires reconciliation; do not retry: {error}"
                )))
            }
        }
    }

    /// Flush is a separately durable peer version, before the ordinary write's
    /// BEGIN. Move the whole owner into its transaction through settlement.
    pub(crate) async fn flush(
        mut self,
        caller: &Caller,
        reason: &str,
    ) -> Result<(Self, Option<Versioned>)> {
        let dirty = self.live.as_ref().is_some_and(|live| {
            let state = live.room.state();
            !state.closed && state.dirty()
        });
        if !dirty {
            return Ok((self, None));
        }
        self.arm_finalization_failure();
        let snapshot = {
            let live = self.live.as_ref().unwrap();
            let state = live.room.state();
            state
                .registry
                .version_snapshot(&live.session)
                .map_err(|error| Error::engine(error.to_string()))?
        };
        let db = self.db.clone();
        let mut transaction = KernelTransaction::begin(&db, self, Self::quarantine).await?;
        let result = async {
            let (tx, ownership) = transaction.parts();
            let (room, record, expected_body_seq) = {
                let live = ownership.live.as_ref().unwrap();
                (
                    Arc::clone(&live.room),
                    live.room.record_id.clone(),
                    live.expected_body_seq,
                )
            };
            let before = crate::kernel::record_metadata::updated_at_on(tx, &record).await?;
            let view = kernel_v2::NativeCandidateView {
                body: snapshot.body(),
                contributors: snapshot.contributors(),
                span_map: snapshot.span_map(),
                session: snapshot.session_id(),
            };
            let payload = kernel_v2::candidate_payload(&view, None)?;
            let permit = KernelAppendPermit::mint(&db, tx, &room, &payload).await?;
            let mut acts = crate::act::ActAllocation::new();
            let base = kernel_v2::cut_installed_in(
                &db,
                tx,
                caller,
                &record,
                expected_body_seq,
                &snapshot,
                &mut acts,
                Some(permit),
            )
            .await?;
            let after = crate::kernel::record_metadata::updated_at_on(tx, &record).await?;
            ownership.validate_precommit()?;
            Ok::<_, Error>((base, before, after))
        }
        .await;
        let (base, before, after) = match result {
            Ok(result) => result,
            Err(error) => return Err(transaction.rollback(error).await),
        };
        let mut ownership = transaction.commit().await?;
        let live = ownership.live.as_mut().unwrap();
        let mut state = live.room.state();
        if state.closed
            || state.registry.drain_version_snapshot(&snapshot)
                != Ok(super::super::DrainOutcome::Drained)
        {
            drop(state);
            ownership.quarantine(
                base.proof
                    .body_event_id
                    .as_deref()
                    .unwrap_or("postcommit-flush"),
            );
            return Err(Error::engine("kernel committed flush binding mismatch"));
        }
        state.versioned_epoch = state.epoch();
        state.dirty_admission.take();
        let new_body_event = distinct_body_event(&state.base.proof, &base.proof);
        state.base = base.clone();
        if new_body_event {
            state.kernel_finalization_blocked = false;
            if let Some(mark) = live.failure_mark.as_mut() {
                mark.disarm();
            }
        }
        live.expected_body_seq = base.proof.body_event_seq;
        live.body = snapshot.body().to_owned();
        let versioned = Versioned {
            session: live.session.clone(),
            version: base.version,
            body_sha256: base.body_sha256,
            event_id: base.proof.body_event_id.clone().unwrap(),
            contributors: snapshot.contributors().to_vec(),
            reason: reason.to_owned(),
            proof: base.proof,
            updated_at_around_cut: Some((before.clone(), after.clone())),
        };
        drop(state);
        live.room.emit(SessionEvent::Versioned(versioned.clone()));
        ownership.timestamps = FlushTimestamps {
            before: Some(before),
            after: Some(after),
        };
        Ok((ownership, Some(versioned)))
    }
}

pub(crate) fn after_commit(db: &Db) {
    let Some(owner) = existing_db_sessions(db) else {
        return;
    };
    let rooms = lock(&owner.records)
        .values()
        .filter(|room| room.backend == SessionBackend::KernelV2)
        .cloned()
        .collect::<Vec<_>>();
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        spawn_recheck(&runtime, db.clone(), rooms);
    }
}

pub(super) async fn recheck_room(room: &Arc<LiveSession>, db: &Db) {
    let callers = room.state().callers.values().cloned().collect::<Vec<_>>();
    let mut unavailable_read = false;
    for caller in callers {
        match SessionBackend::KernelV2
            .revalidate(db, &caller, &room.record_id, PeerKind::View)
            .await
        {
            Ok(_) => return,
            Err(error) if error.code == RefusalCode::Unavailable => unavailable_read = true,
            Err(_) => {}
        }
    }
    let mut state = room.state();
    if state.dirty() || unavailable_read {
        // A revoked contributor cannot be silently discarded or rescued by a
        // fabricated service principal. Keep reservation and dirty admission.
        state.pending_recheck = true;
    } else {
        drop(state);
        close_session(room, CloseReason::AccessLost);
    }
}

pub(super) async fn recheck_peer(
    peer: &SessionPeer,
    caller: &Caller,
    db: &Db,
    mode: SessionMode,
) -> std::result::Result<(), Refused> {
    ensure_available(db).map_err(unavailable)?;
    match SessionBackend::KernelV2
        .revalidate(db, caller, &peer.inner.session.record_id, mode)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.code == RefusalCode::Unavailable => Err(error),
        Err(error) => {
            if !peer.inner.left.swap(true, Ordering::AcqRel) {
                leave_peer(
                    &peer.inner.session,
                    &peer.inner.peer,
                    peer.inner.incarnation,
                    CloseReason::AccessLost,
                )
                .await;
            }
            Err(error)
        }
    }
}

/// Borrowed lifecycle callers have not transferred their ops guard into an
/// owned completion job. Refuse rather than enter v1 storage or lose a guard.
pub(super) async fn cut_by_contributor(
    _: &Arc<LiveSession>,
    _: &Db,
    _: &str,
    _: Option<Caller>,
) -> std::result::Result<Option<Versioned>, Refused> {
    Err(Refused::new(
        RefusalCode::Unavailable,
        "kernel cut requires owned completion",
    ))
}

pub(super) async fn cut_session_owned(
    room: Arc<LiveSession>,
    db: Db,
    reason: String,
    hint: Option<Caller>,
) -> std::result::Result<Option<Versioned>, Refused> {
    super::kernel_lifecycle::cut_room(db, room, reason, hint).await
}

// Metadata CAS, replay receipts and text equality are not this transition.
fn distinct_body_event(previous: &CutProof, next: &CutProof) -> bool {
    matches!((&next.body_event_id, next.body_event_seq), (Some(id), Some(seq)) if !id.is_empty() && seq > 0)
        && (previous.body_event_id != next.body_event_id
            || previous.body_event_seq != next.body_event_seq)
}

/// An append capability is neither serialized provenance nor an actor bypass.
/// It is consumed on the exact connection while its operation holds `ops`.
/// There is deliberately no Clone, public constructor or metadata constructor.
pub(crate) struct KernelAppendPermit {
    database: PathBuf,
    record: String,
    room: Weak<LiveSession>,
    session: SessionId,
    epoch: u64,
    connection: usize,
    payload_digest: String,
}

fn connection_identity(conn: &mut SqliteConnection) -> usize {
    // Correlation only: never dereferenced. The transaction remains owned and
    // its connection cannot be returned to the pool between mint and consume.
    std::ptr::from_mut(conn) as usize
}

impl KernelAppendPermit {
    async fn mint(
        db: &Db,
        tx: &mut SqliteConnection,
        room: &Arc<LiveSession>,
        payload: &Value,
    ) -> Result<Self> {
        let rows = sqlx::query("PRAGMA database_list")
            .fetch_all(&mut *tx)
            .await?;
        let mut file = None;
        for row in rows {
            let name: String = row.try_get("name")?;
            if name == "main" {
                file = Some(row.try_get::<String, _>("file")?);
            }
        }
        let file =
            file.ok_or_else(|| Error::engine("kernel append connection has no main database"))?;
        let file = std::fs::canonicalize(&file).unwrap_or_else(|_| PathBuf::from(file));
        if file != session_key(db)
            || !existing_session(db, &room.record_id)
                .is_some_and(|registered| Arc::ptr_eq(&registered, room))
        {
            return Err(Error::engine(
                "kernel append connection/storage binding mismatch",
            ));
        }
        let state = room.state();
        if state.closed {
            return Err(Error::engine("kernel writer room has closed"));
        }
        Ok(Self {
            database: session_key(db),
            record: room.record_id.clone(),
            room: Arc::downgrade(room),
            session: state.session.clone(),
            epoch: state.epoch(),
            connection: connection_identity(tx),
            payload_digest: sha256_hex(&serde_json::to_string(payload)?),
        })
    }

    pub(crate) fn consume(
        self,
        db: &Db,
        tx: &mut SqliteConnection,
        record: &str,
        event_type: &str,
        payload: &Value,
    ) -> Result<()> {
        let room = self
            .room
            .upgrade()
            .ok_or_else(|| Error::engine("kernel append owner is gone"))?;
        let registered =
            existing_session(db, record).is_some_and(|current| Arc::ptr_eq(&current, &room));
        let state = room.state();
        if self.database != session_key(db)
            || self.record != record
            || event_type != "kernel.body_set.v1"
            || self.connection != connection_identity(tx)
            || self.payload_digest != sha256_hex(&serde_json::to_string(payload)?)
            || !registered
            || state.closed
            || state.session != self.session
            || state.epoch() != self.epoch
        {
            return Err(Error::engine("kernel append permit binding mismatch"));
        }
        Ok(())
    }
}

/// The opaque permit is the sole exception for body events. Scope events are
/// conservatively refused while a room exists, including dirty/clean grace.
/// No room is closed here: this transaction may still roll back.
pub(crate) fn admit_unowned_event(
    db: &Db,
    record: &str,
    event_type: &str,
    payload: &Value,
) -> Result<()> {
    ensure_available(db)?;
    if (event_type.starts_with("kernel.import_") || event_type == "kernel.v1_state_imported.v1")
        && has_kernel_rooms(db)
    {
        return Err(Error::engine(
            "kernel imports refuse a live serving generation",
        ));
    }
    let Some(room) = existing_session(db, record) else {
        return Ok(());
    };
    let state = room.state();
    if state.closed {
        return Ok(());
    }
    let body_or_scope = matches!(
        event_type,
        "kernel.body_set.v1"
            | "kernel.record_created.v1"
            | "kernel.import_state.v1"
            | "kernel.import_state_delta.v1"
            | "kernel.record_deleted.v1"
            | "kernel.record_rehomed.v1"
            | "kernel.record_rehomed.v2"
            | "kernel.record_rebound.v1"
    ) || (event_type == "kernel.facet_observed.v1"
        && payload["key"] == "runtime")
        || (matches!(
            event_type,
            "kernel.record_revised.v1" | "kernel.record_revised.v2"
        ) && payload["fields"].as_object().is_some_and(|fields| {
            fields
                .keys()
                .any(|field| !matches!(field.as_str(), "title" | "summary" | "lifecycle"))
        }));
    if body_or_scope {
        return Err(Error::engine(
            "a kernel live session owns this record; unported body or scope writes are refused",
        ));
    }
    Ok(())
}

fn has_kernel_rooms(db: &Db) -> bool {
    existing_db_sessions(db).is_some_and(|owner| {
        lock(&owner.records)
            .values()
            .any(|room| room.backend == SessionBackend::KernelV2)
    })
}

/// Specialized import paths own only a connection. Identify its actual main
/// file and refuse a live/quarantined generation before any legacy insert.
pub(crate) async fn admit_import_on(conn: &mut SqliteConnection) -> Result<()> {
    let rows = sqlx::query("PRAGMA database_list").fetch_all(conn).await?;
    for row in rows {
        let name: String = row.try_get("name")?;
        let file: String = row.try_get("file")?;
        if name != "main" {
            continue;
        }
        let path = std::fs::canonicalize(&file).unwrap_or_else(|_| PathBuf::from(file));
        if lock(&SERVICE).get(&path).is_some_and(|owner| {
            *owner.kernel_quarantine.borrow()
                || *owner.kernel_lifecycle.sealed.borrow()
                || lock(&owner.records)
                    .values()
                    .any(|room| room.backend == SessionBackend::KernelV2)
        }) {
            return Err(Error::engine(
                "kernel import refuses a live or quarantined generation",
            ));
        }
    }
    Ok(())
}

/// Launch before ownership/BEGIN. A response receiver is only a result waiter;
/// dropping it cannot abort SQL completion or release the writer's locks.
// Bound both queued result owners and retained uncertain connections. Admission
// never waits in the response task, so dropping a receiver cannot enqueue more
// work than this process budget. Quarantine retains the operation's slot.
const MAX_OWNED_KERNEL_JOBS: usize = 128;
pub(super) const MAX_OWNED_KERNEL_JOBS_PER_DATABASE: usize = 8;
struct OwnedJobSlot {
    process: Option<tokio::sync::OwnedSemaphorePermit>,
    database: Option<tokio::sync::OwnedSemaphorePermit>,
    owner: Arc<DbSessions>,
    cleanup_generation: Option<u64>,
    // Test-only original directory custody, after all actual permits/owner.
    #[cfg(test)]
    _fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
}
impl Drop for OwnedJobSlot {
    fn drop(&mut self) {
        // Physical resource bounds are released BEFORE logical settlement is
        // observable under the same seal/reservation ledger.
        drop(self.process.take());
        drop(self.database.take());
        let mut ledger = lock(&self.owner.kernel_lifecycle.serial);
        ledger.accepted_jobs = ledger
            .accepted_jobs
            .checked_sub(1)
            .expect("kernel job accounting underflow");
        if self.cleanup_generation == Some(ledger.cleanup_generation) {
            if !ledger.cleanup_finished {
                let operation = ledger
                    .driver_unknown
                    .get_or_insert_with(|| uuid::Uuid::new_v4().to_string())
                    .clone();
                let mut identity = lock(&self.owner.kernel_quarantine_identity);
                if identity.is_none() {
                    *identity = Some(operation);
                }
                self.owner.kernel_quarantine.send_replace(true);
            }
            ledger.cleanup_running = false;
        }
        super::kernel_lifecycle::changed(&self.owner);
    }
}
static OWNED_JOBS: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(MAX_OWNED_KERNEL_JOBS)));
tokio::task_local! {
    static OWNED_JOB_SLOT: Arc<OwnedJobSlot>;
}

fn reserve_job_slot(db: &Db) -> Result<Arc<OwnedJobSlot>> {
    ensure_available(db)?;
    let owner = db_sessions(db);
    #[cfg(test)]
    super::kernel_lifecycle::test_pin_checkpoint(
        db,
        super::kernel_lifecycle::PinStage::Reservation,
    );
    let mut ledger = lock(&owner.kernel_lifecycle.serial);
    ensure_available(db)?;
    if ledger.quiescent {
        return Err(Error::engine("kernel storage is terminally quiescent"));
    }
    let cleanup_generation = super::kernel_lifecycle::current_cleanup()
        .filter(|purpose| purpose.matches(db, &owner))
        .map(|purpose| purpose.generation);
    if cleanup_generation.is_some() && !ledger.cleanup_running {
        return Err(Error::engine("kernel cleanup pass is not registered"));
    }
    let database = Arc::clone(&owner.kernel_jobs)
        .try_acquire_owned()
        .map_err(|_| {
            Error::engine(
                "kernel database owned-operation capacity exhausted; no operation started",
            )
        })?;
    let process = Arc::clone(&OWNED_JOBS).try_acquire_owned().map_err(|_| {
        Error::engine("kernel process owned-operation capacity exhausted; no operation started")
    })?;
    ledger.accepted_jobs += 1;
    super::kernel_lifecycle::changed(&owner);
    drop(ledger);
    Ok(Arc::new(OwnedJobSlot {
        process: Some(process),
        database: Some(database),
        owner,
        cleanup_generation,
        #[cfg(test)]
        _fixture_owner: capture_writer_fixture_owner_for_test(db),
    }))
}

#[cfg(test)]
pub(crate) fn hold_job_slots_for_test(db: &Db, count: usize) -> Vec<Box<dyn Send>> {
    (0..count)
        .map(|_| Box::new(reserve_job_slot(db).unwrap()) as Box<dyn Send>)
        .collect()
}

pub(super) fn start_owned<T, F>(
    db: Db,
    future: F,
) -> Result<tokio::sync::oneshot::Receiver<Result<T>>>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    start_owned_with(db, || future)
}

pub(super) fn start_owned_with<T, F>(
    db: Db,
    build: impl FnOnce() -> F,
) -> Result<tokio::sync::oneshot::Receiver<Result<T>>>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| Error::engine("kernel owner runtime unavailable; custody retained"))?;
    let slot = reserve_job_slot(&db)?;
    let future = build();
    let diagnostics = crate::write_diagnostics::current()
        .unwrap_or_else(|| crate::write_diagnostics::Context::background("kernel_background"));
    let dispatch = crate::provenance::current_dispatch();
    let annotations = crate::store::current_event_annotations();
    let cleanup = super::kernel_lifecycle::current_cleanup();
    let (result, waiter) = tokio::sync::oneshot::channel();
    let task = runtime.spawn(async move {
        let execution = OWNED_JOB_SLOT.scope(
            slot,
            crate::store::with_event_annotations(annotations, async move {
                match dispatch {
                    Some(dispatch) => dispatch.scope(future).await,
                    None => future.await,
                }
            }),
        );
        let execution = diagnostics.scope(execution);
        let completed = match cleanup {
            Some(purpose) => super::kernel_lifecycle::with_cleanup(purpose, execution).await,
            None => execution.await,
        };
        let _ = result.send(completed);
    });
    #[cfg(test)]
    observe_spawn(&db, &task);
    #[cfg(not(test))]
    drop(task);
    Ok(waiter)
}

pub(crate) async fn owned_result<T, F>(db: Db, future: F) -> Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T>> + Send + 'static,
{
    start_owned(db, future)?
        .await
        .map_err(|_| Error::engine("kernel operation owner stopped; outcome is uncertain"))?
}

#[cfg(test)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) enum TestStage {
    LoaderBeforeAcquire,
    LoaderAcquirePending,
    LoaderLeaseAttached,
    LoaderBeginPending,
    LoaderBegun,
    LoaderLoadPending,
    LoaderLoaded,
    LoaderRollbackPending,
    LoaderBeforeDisposal,
    LoaderNotifyPanic,
    CheckoutBeforeAcquire,
    CheckoutPending,
    LeaseAttached,
    BeforeBorrowedBegin,
    BorrowedBeginPending,
    BorrowedBeginRefused,
    BorrowedCommitPending,
    BeginAcknowledged,
    CleanupStarted,
    CleanupPanic,
    CleanupRollbackPending,
    CleanupBeforeDisposal,
    CleanupDisposed,
    LifecyclePassFinished,
    V1GateQueued,
    LifecycleBeforeAcquire,
    LifecycleAfterArm,
    LifecycleBeforeFailurePublication,
    LifecycleBeforeOuterFailurePublication,
    BeforeOwnedLane,
    LaneQueued,
    OpsQueued,
    SeedBeforeLane,
    SeedBeforeFence,
    SeedAfterFence,
    SeedGateQueued,
    AfterMutation,
    AfterFlush,
    BeforeCommit,
    AfterDurability,
}

#[cfg(test)]
pub(crate) struct TestGate {
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
    pub(crate) fail: bool,
    task: StdMutex<Option<tokio::task::Id>>,
}

#[cfg(test)]
type TestGateMap = HashMap<(PathBuf, TestStage), Arc<TestGate>>;

#[cfg(test)]
static TEST_GATES: LazyLock<StdMutex<TestGateMap>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

#[cfg(test)]
pub(crate) fn test_gate(db: &Db, stage: TestStage, fail: bool) -> Arc<TestGate> {
    let gate = Arc::new(TestGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        fail,
        task: StdMutex::new(None),
    });
    lock(&TEST_GATES).insert((session_key(db), stage), Arc::clone(&gate));
    gate
}

#[cfg(test)]
pub(crate) async fn test_checkpoint(db: &Db, stage: TestStage) -> Result<()> {
    // One shot: follow-up cuts/commits cannot accidentally reuse the barrier.
    let gate = lock(&TEST_GATES).remove(&(session_key(db), stage));
    if let Some(gate) = gate {
        *lock(&gate.task) = tokio::task::try_id();
        gate.entered.notify_one();
        gate.release.notified().await;
        if gate.fail {
            if stage == TestStage::CleanupPanic {
                panic!("native cleanup boundary unwind stimulus");
            }
            return Err(Error::engine("injected kernel mutation tail failure"));
        }
    }
    Ok(())
}

// Non-authorizing, storage-key-scoped observations of actual spawned tasks.
// No arbitrary future, ACK, result or connection can be supplied here.
#[cfg(test)]
#[derive(Default)]
struct ObservedTasks {
    handles: StdMutex<HashMap<tokio::task::Id, tokio::task::AbortHandle>>,
    changed: tokio::sync::Notify,
    leases: StdMutex<Vec<(String, usize)>>,
    loader_same_task_slot: StdMutex<Vec<bool>>,
    begin_failures: StdMutex<usize>,
    operation_tasks: StdMutex<HashMap<String, tokio::task::Id>>,
}
#[cfg(test)]
static OBSERVED_TASKS: LazyLock<StdMutex<HashMap<PathBuf, Arc<ObservedTasks>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(crate) struct TaskObservation {
    key: PathBuf,
    observed: Arc<ObservedTasks>,
}
#[cfg(test)]
impl Drop for TaskObservation {
    fn drop(&mut self) {
        let mut observers = lock(&OBSERVED_TASKS);
        if observers
            .get(&self.key)
            .is_some_and(|v| Arc::ptr_eq(v, &self.observed))
        {
            observers.remove(&self.key);
        }
    }
}
#[cfg(test)]
impl TaskObservation {
    pub(crate) fn earlier_loader_same_task_slot(&self) -> bool {
        *lock(&self.observed.loader_same_task_slot).last().unwrap()
    }
    pub(crate) fn attached_lease(&self) -> (String, usize) {
        lock(&self.observed.leases).last().unwrap().clone()
    }
    pub(crate) fn begin_failures(&self) -> usize {
        *lock(&self.observed.begin_failures)
    }
    pub(crate) async fn abort_at(&self, gate: &TestGate) {
        let id = lock(&gate.task).expect("actual spawned task reached checkpoint");
        self.abort_id(id).await;
    }
    pub(crate) async fn abort_operation(&self, operation: &str) {
        let id = *lock(&self.observed.operation_tasks)
            .get(operation)
            .expect("actual native operation task");
        self.abort_id(id).await;
    }
    async fn abort_id(&self, id: tokio::task::Id) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let changed = self.observed.changed.notified();
                let handle = lock(&self.observed.handles).get(&id).cloned();
                if let Some(handle) = handle {
                    handle.abort();
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("spawned task capture did not complete");
    }
}
#[cfg(test)]
pub(crate) fn observe_tasks_for_test(db: &Db) -> TaskObservation {
    let key = session_key(db);
    let observed = Arc::new(ObservedTasks::default());
    let mut observers = lock(&OBSERVED_TASKS);
    assert!(observers.len() < 64 && !observers.contains_key(&key));
    observers.insert(key.clone(), observed.clone());
    TaskObservation { key, observed }
}
#[cfg(test)]
fn observe_spawn<T>(db: &Db, task: &tokio::task::JoinHandle<T>) {
    let observer = lock(&OBSERVED_TASKS).get(&session_key(db)).cloned();
    if let Some(observer) = observer {
        let mut handles = lock(&observer.handles);
        assert!(handles.len() < 32, "bounded native task observation");
        handles.insert(task.id(), task.abort_handle());
        drop(handles);
        observer.changed.notify_one();
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum WorkerVmStage {
    LoaderBegin,
    LoaderLoad,
    LoaderRollback,
    Begin,
    Policy,
    Commit,
}
#[cfg(test)]
struct PolicyWorkerGate {
    entered: tokio::sync::Notify,
    fired: AtomicBool,
    released: StdMutex<bool>,
    release: std::sync::Condvar,
}
#[cfg(test)]
type PolicyWorkerMap = HashMap<(PathBuf, WorkerVmStage), Arc<PolicyWorkerGate>>;
#[cfg(test)]
static POLICY_WORKERS: LazyLock<StdMutex<PolicyWorkerMap>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(crate) struct PolicyWorkerPause {
    key: (PathBuf, WorkerVmStage),
    gate: Arc<PolicyWorkerGate>,
}
#[cfg(test)]
impl PolicyWorkerPause {
    pub(crate) async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(30), self.gate.entered.notified())
            .await
            .unwrap();
    }
    pub(crate) fn release(&self) {
        *lock(&self.gate.released) = true;
        self.gate.release.notify_all();
    }
}
#[cfg(test)]
impl Drop for PolicyWorkerPause {
    fn drop(&mut self) {
        self.release();
        let mut workers = lock(&POLICY_WORKERS);
        if workers
            .get(&self.key)
            .is_some_and(|v| Arc::ptr_eq(v, &self.gate))
        {
            workers.remove(&self.key);
        }
    }
}
#[cfg(test)]
fn pause_worker_for_test(db: &Db, stage: WorkerVmStage) -> PolicyWorkerPause {
    let key = (session_key(db), stage);
    let gate = Arc::new(PolicyWorkerGate {
        entered: tokio::sync::Notify::new(),
        fired: AtomicBool::new(false),
        released: StdMutex::new(false),
        release: std::sync::Condvar::new(),
    });
    let mut workers = lock(&POLICY_WORKERS);
    assert!(workers.len() < 64 && !workers.contains_key(&key));
    workers.insert(key.clone(), gate.clone());
    PolicyWorkerPause { key, gate }
}
#[cfg(test)]
pub(crate) fn pause_policy_worker_for_test(db: &Db) -> PolicyWorkerPause {
    pause_worker_for_test(db, WorkerVmStage::Policy)
}
#[cfg(test)]
pub(crate) fn pause_begin_worker_for_test(db: &Db) -> PolicyWorkerPause {
    pause_worker_for_test(db, WorkerVmStage::Begin)
}
#[cfg(test)]
pub(crate) fn pause_commit_worker_for_test(db: &Db) -> PolicyWorkerPause {
    pause_worker_for_test(db, WorkerVmStage::Commit)
}
#[cfg(test)]
pub(crate) async fn arm_policy_worker_for_test(db: &Db, conn: &mut SqliteConnection) -> Result<()> {
    arm_worker_for_test(db, conn, WorkerVmStage::Policy).await
}
#[cfg(test)]
pub(crate) async fn arm_commit_worker_for_test(db: &Db, conn: &mut SqliteConnection) -> Result<()> {
    arm_worker_for_test(db, conn, WorkerVmStage::Commit).await
}
#[cfg(test)]
async fn arm_worker_for_test(
    db: &Db,
    conn: &mut SqliteConnection,
    stage: WorkerVmStage,
) -> Result<()> {
    let gate = lock(&POLICY_WORKERS)
        .get(&(session_key(db), stage))
        .cloned();
    if let Some(gate) = gate {
        conn.lock_handle().await?.set_progress_handler(1, move || {
            if !gate.fired.swap(true, Ordering::AcqRel) {
                gate.entered.notify_one();
                let mut released = lock(&gate.released);
                while !*released {
                    released = gate
                        .release
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }
            true
        });
    }
    Ok(())
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct RetainedObservation {
    pub(crate) operation: String,
    pub(crate) has_original_lease: bool,
    pub(crate) phase: String,
    pub(crate) connection_address: Option<usize>,
    pub(crate) owns_original_job_slot: bool,
}
#[cfg(test)]
pub(crate) fn retained_observations_for_test(db: &Db) -> Vec<RetainedObservation> {
    let owner = db_sessions(db);
    lock(&QUARANTINED)
        .iter_mut()
        .filter(|e| e._database == session_key(db))
        .map(|e| {
            assert!(Arc::ptr_eq(&e._owner, &owner));
            let (phase, connection_address) = match &mut e._connection {
                UnknownConnection::CheckoutNativeUnknown => {
                    ("CheckoutNativeUnknown".to_owned(), None)
                }
                UnknownConnection::OwnedConnectionUnknown {
                    _connection: connection,
                    _phase: phase,
                } => (
                    format!("{phase:?}"),
                    Some(connection_identity(
                        connection.as_mut().as_mut().unwrap().as_mut(),
                    )),
                ),
            };
            let owns_original_job_slot = e
                ._job_slot
                .as_ref()
                .is_some_and(|slot| Arc::ptr_eq(&slot.owner, &owner));
            RetainedObservation {
                operation: e._operation.clone(),
                has_original_lease: connection_address.is_some(),
                phase,
                connection_address,
                owns_original_job_slot,
            }
        })
        .collect()
}
#[cfg(test)]
pub(crate) fn accepted_jobs_for_test(db: &Db) -> usize {
    let owner = db_sessions(db);
    let count = lock(&owner.kernel_lifecycle.serial).accepted_jobs;
    count
}

#[cfg(test)]
pub(crate) fn live_text_for_test(db: &Db, record: &str) -> Option<String> {
    live_text(db, record)
}

/// Diagnostic over the fixture's actual peer-owned room, not a storage lookup.
/// Does not reopen, authorize, unquarantine, or acknowledge the retained state.
#[cfg(test)]
pub(crate) fn assert_quarantined_peer_body_for_test(peer: &super::SessionPeer, expected: &str) {
    let room = &peer.inner.session;
    assert!(room.backend == SessionBackend::KernelV2);
    let state = room.state();
    assert!(state.closed);
    assert_eq!(&state.session, &peer.inner.session_id);
    assert_eq!(state.registry.live_body(&state.session).unwrap(), expected);
}

#[cfg(test)]
pub(crate) fn base_for_test(db: &Db, record: &str) -> Option<BaseVersion> {
    existing_session(db, record).map(|room| room.state().base.clone())
}

#[cfg(test)]
pub(crate) fn quarantine_for_test(db: &Db) -> Option<String> {
    existing_db_sessions(db).and_then(|owner| lock(&owner.kernel_quarantine_identity).clone())
}

#[cfg(test)]
pub(crate) fn retained_transactions_for_test(db: &Db) -> usize {
    lock(&QUARANTINED)
        .iter()
        .filter(|entry| entry._database == session_key(db))
        .count()
}

#[cfg(test)]
pub(crate) async fn dispose_settled_quarantine_for_test(db: &Db) {
    // This test-only observer cannot release custody on cancellation/panic.
    struct Disposal {
        entry: Option<QuarantinedTransaction>,
    }
    impl Drop for Disposal {
        fn drop(&mut self) {
            if let Some(entry) = self.entry.take() {
                lock(&QUARANTINED).push(entry);
            }
        }
    }
    let entry = {
        let mut held = lock(&QUARANTINED);
        let index = held
            .iter()
            .position(|entry| entry._database == session_key(db))
            .unwrap();
        assert!(
            matches!(
                &held[index]._connection,
                UnknownConnection::OwnedConnectionUnknown { .. }
            ),
            "checkout native fence has no original lease to roll back"
        );
        held.remove(index)
    };
    let mut disposal = Disposal { entry: Some(entry) };
    if let UnknownConnection::OwnedConnectionUnknown {
        _connection: connection,
        ..
    } = &mut disposal.entry.as_mut().unwrap()._connection
    {
        Db::rollback_owned_kernel_connection(connection.as_mut().as_mut().unwrap())
            .await
            .unwrap();
    }
    let entry = disposal.entry.take().unwrap();
    drop(entry._connection);
    drop(entry._ownership);
    drop(entry._job_slot);
    // No product unquarantine: this key remains refused.
}

// Earlier live-route admission: a separate read-pool snapshot, never a
// write permit or a one-snapshot claim across the subsequent W0 transaction.
struct EarlierLoaderOwnership {
    db: Db,
    caller: Caller,
    owner: Arc<DbSessions>,
    room: Arc<LiveSession>,
    session: SessionId,
    // This order describes ONLY the read carrier, not KernelBodyWrite.
    _ops: OwnedMutexGuard<()>,
    _gate: OwnedRwLockReadGuard<()>,
    _lane: OwnedMutexGuard<()>,
    _admission: Option<Box<dyn Send>>,
    slot: Arc<OwnedJobSlot>,
    #[cfg(test)]
    fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EarlierLoaderPhase {
    PoolOwnedCheckout,
    LeaseReady,
    DriverCheck,
    BeginMayHaveRun,
    Loading,
    RollingBack,
    CheckingClean,
    Settled,
}
struct EarlierLoaderGraph {
    operation: String,
    phase: EarlierLoaderPhase,
    connection: Box<Option<sqlx::pool::PoolConnection<Sqlite>>>,
    outcome: Option<Result<LoadedBody>>,
    ownership: EarlierLoaderOwnership,
}
impl EarlierLoaderGraph {
    fn connection(&mut self) -> &mut SqliteConnection {
        self.connection
            .as_mut()
            .as_mut()
            .expect("original read lease")
            .as_mut()
    }
}
struct EarlierLoaderGuard {
    graph: Option<Box<EarlierLoaderGraph>>,
}
// Bounded by the SAME128/8 admitted job permits, not an extra allowance.
// No product reconciliation, reaper, automatic replay or unquarantine.
#[allow(clippy::vec_box)] // Move the preconstructed concrete graph intact; never rebox on loss.
static RETAINED_EARLIER_LOADERS: LazyLock<StdMutex<Vec<Box<EarlierLoaderGraph>>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));
fn earlier_loader_error(error: Error) -> Error {
    Error::engine(crate::coedit::backend::kernel_refusal(error).to_string())
}
impl EarlierLoaderGuard {
    fn new(ownership: EarlierLoaderOwnership) -> Self {
        Self {
            graph: Some(Box::new(EarlierLoaderGraph {
                operation: uuid::Uuid::new_v4().to_string(),
                phase: EarlierLoaderPhase::PoolOwnedCheckout,
                connection: Box::new(None),
                ownership,
                outcome: None,
            })),
        }
    }
    async fn admit(mut self) -> Result<EarlierLoaderOwnership> {
        self.checkout().await?;
        self.begin_deferred().await.map_err(|error| {
            Error::engine(format!(
                "earlier loader BEGIN/driver outcome uncertain: {error}"
            ))
        })?;
        self.load().await;
        if let Err(error) = self.settle().await {
            // Original result stays IN the retained graph, including refusal.
            return Err(Error::engine(format!(
                "earlier loader settlement uncertain: {error}"
            )));
        }
        self.into_settled()
    }
    async fn checkout(&mut self) -> Result<()> {
        let db = self.graph.as_ref().unwrap().ownership.db.clone();
        #[cfg(test)]
        test_checkpoint(&db, TestStage::LoaderBeforeAcquire).await?;
        let acquired = {
            let checkout = db.pool().acquire();
            tokio::pin!(checkout);
            #[cfg(test)]
            match futures::poll!(checkout.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    test_checkpoint(&db, TestStage::LoaderAcquirePending).await?;
                    checkout.await
                }
            }
            #[cfg(not(test))]
            checkout.await
        };
        match acquired {
            Ok(connection) => {
                let graph = self.graph.as_mut().unwrap();
                // NO await/callback/allocation between Ok and attachment.
                *graph.connection = Some(connection);
                graph.phase = EarlierLoaderPhase::LeaseReady;
                #[cfg(test)]
                observe_earlier_loader_lease(graph);
            }
            Err(error) => {
                // Explicit standard SQLx pre-checkout disposition. There is no
                // returned lease, no constructor SQL and no physical-drain ACK.
                let graph = self.graph.take().unwrap();
                drop(graph);
                return Err(earlier_loader_error(error.into()));
            }
        }
        #[cfg(test)]
        test_checkpoint(&db, TestStage::LoaderLeaseAttached).await?;
        Ok(())
    }
    async fn begin_deferred(&mut self) -> Result<()> {
        use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
        let graph = self.graph.as_mut().unwrap();
        graph.phase = EarlierLoaderPhase::DriverCheck;
        if SqliteTransactionManager::get_transaction_depth(graph.connection()) != 0 {
            return Err(Error::engine("earlier loader refuses nested read lease"));
        }
        {
            let mut handle = graph.connection().lock_handle().await?;
            // SAFETY: exclusive live handle borrowed from the actual owned lease;
            // SQLx's worker cannot use it while this locked guard exists.
            if unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) }
                == 0
            {
                return Err(Error::engine("earlier loader read lease is not clean"));
            }
        }
        graph.phase = EarlierLoaderPhase::BeginMayHaveRun;
        #[cfg(test)]
        let inject_nested = lock(&LOADER_NESTED_BEGIN).remove(&session_key(&graph.ownership.db));
        #[cfg(test)]
        if inject_nested {
            // Deliberate invalid-driver injection, not a valid native mutation.
            sqlx::query("BEGIN")
                .execute(&mut *graph.connection())
                .await?;
        }
        #[cfg(test)]
        let db = graph.ownership.db.clone();
        #[cfg(test)]
        arm_worker_for_test(&db, graph.connection(), WorkerVmStage::LoaderBegin).await?;
        {
            let begin = SqliteTransactionManager::begin(graph.connection(), None);
            tokio::pin!(begin);
            #[cfg(test)]
            let result = match futures::poll!(begin.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    test_checkpoint(&db, TestStage::LoaderBeginPending).await?;
                    begin.await
                }
            };
            #[cfg(not(test))]
            let result = begin.await;
            result.map_err(|e| Error::engine(format!("earlier loader BEGIN uncertain: {e}")))?;
        }
        if SqliteTransactionManager::get_transaction_depth(graph.connection()) != 1 {
            return Err(Error::engine("earlier loader BEGIN depth not acknowledged"));
        }
        #[cfg(test)]
        test_checkpoint(&db, TestStage::LoaderBegun).await?;
        Ok(())
    }
    async fn load(&mut self) {
        let graph = self.graph.as_mut().unwrap();
        graph.phase = EarlierLoaderPhase::Loading;
        #[cfg(test)]
        let db = graph.ownership.db.clone();
        #[cfg(test)]
        if let Err(error) =
            arm_worker_for_test(&db, graph.connection(), WorkerVmStage::LoaderLoad).await
        {
            graph.outcome = Some(Err(error));
            return;
        }
        // Split concrete fields: this is the unchanged full loader on the same
        // connection, with the actual single-cloned Caller, before any flush.
        let result = {
            let conn = graph.connection.as_mut().as_mut().unwrap();
            let load = kernel_v2::load_committed_on(
                conn,
                &graph.ownership.caller,
                &graph.ownership.room.record_id,
                PeerKind::Edit,
            );
            tokio::pin!(load);
            #[cfg(test)]
            let result = match futures::poll!(load.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    match test_checkpoint(&db, TestStage::LoaderLoadPending).await {
                        Ok(()) => load.await,
                        Err(error) => Err(error),
                    }
                }
            };
            #[cfg(not(test))]
            let result = load.await;
            result
        };
        graph.outcome = Some(result);
        #[cfg(test)]
        let _ = test_checkpoint(&db, TestStage::LoaderLoaded).await;
    }
    async fn settle(&mut self) -> Result<()> {
        use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
        let graph = self.graph.as_mut().unwrap();
        graph.phase = EarlierLoaderPhase::RollingBack;
        #[cfg(test)]
        let db = graph.ownership.db.clone();
        #[cfg(test)]
        arm_worker_for_test(&db, graph.connection(), WorkerVmStage::LoaderRollback).await?;
        #[cfg(test)]
        let inject_rollback = lock(&LOADER_ROLLBACK_DESYNC).remove(&session_key(&db));
        #[cfg(test)]
        if inject_rollback {
            // Invalid-driver failure injection only: actual SQL, no depth/ACK setter.
            sqlx::query("ROLLBACK")
                .execute(&mut *graph.connection())
                .await?;
        }
        {
            let rollback = Db::rollback_owned_kernel_connection(graph.connection());
            tokio::pin!(rollback);
            #[cfg(test)]
            let result = match futures::poll!(rollback.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    test_checkpoint(&db, TestStage::LoaderRollbackPending).await?;
                    rollback.await
                }
            };
            #[cfg(not(test))]
            let result = rollback.await;
            result?;
        }
        graph.phase = EarlierLoaderPhase::CheckingClean;
        if SqliteTransactionManager::get_transaction_depth(graph.connection()) != 0 {
            return Err(Error::engine("earlier loader rollback depth not settled"));
        }
        #[cfg(test)]
        let inject_dirty = lock(&LOADER_DIRTY_NATIVE).remove(&session_key(&db));
        #[cfg(test)]
        if inject_dirty {
            // Explicit invalid-driver injection, not a business write or authority.
            sqlx::query("BEGIN")
                .execute(&mut *graph.connection())
                .await?;
        }
        {
            let mut handle = graph.connection().lock_handle().await?;
            // SAFETY: same locked original native handle after worker rollback ACK.
            if unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) }
                == 0
            {
                return Err(Error::engine(
                    "earlier loader rollback native state not clean",
                ));
            }
        }
        graph.phase = EarlierLoaderPhase::Settled;
        #[cfg(test)]
        test_checkpoint(&db, TestStage::LoaderBeforeDisposal).await?;
        Ok(())
    }
    fn into_settled(mut self) -> Result<EarlierLoaderOwnership> {
        assert_eq!(
            self.graph.as_ref().unwrap().phase,
            EarlierLoaderPhase::Settled
        );
        let EarlierLoaderGraph {
            connection,
            outcome,
            ownership,
            ..
        } = *self.graph.take().unwrap();
        drop(connection);
        // Pool return is SQLx housekeeping, NOT physical close/drain ACK.
        match outcome.expect("actual loader outcome") {
            Ok(loaded) => {
                drop(loaded); // Full-body/discard cost deliberately preserved.
                let maps_match = existing_db_sessions(&ownership.db)
                    .is_some_and(|o| Arc::ptr_eq(&o, &ownership.owner))
                    && lock(&ownership.owner.records)
                        .get(&ownership.room.record_id)
                        .is_some_and(|r| Arc::ptr_eq(r, &ownership.room))
                    && ownership
                        .room
                        .kernel_origin
                        .as_ref()
                        .is_some_and(|d| d.same_handle(&ownership.db));
                let session_matches = {
                    let state = ownership.room.state();
                    state.session == ownership.session
                };
                if !maps_match || !session_matches {
                    return Err(Error::engine("earlier loader original target changed"));
                }
                Ok(ownership)
            }
            Err(error) => {
                drop(ownership); // ops/gate/lane/admission BEFORE final slot.
                Err(earlier_loader_error(error))
            }
        }
    }
    fn retain_unknown(&mut self) {
        let Some(graph) = self.graph.take() else {
            return;
        };
        let owner = Arc::clone(&graph.ownership.owner);
        let operation = graph.operation.clone();
        #[cfg(test)]
        let key = session_key(&graph.ownership.db);
        lock(&RETAINED_EARLIER_LOADERS).push(graph);
        // Retention precedes EVERY wake, including the quarantine watch.
        let panicking = std::thread::panicking();
        let notified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut identity = lock(&owner.kernel_quarantine_identity);
            if identity.is_none() {
                *identity = Some(operation);
            }
            drop(identity);
            owner.kernel_quarantine.send_replace(true);
            super::kernel_lifecycle::changed(&owner);
            #[cfg(test)]
            if let Some(gate) = lock(&TEST_GATES).remove(&(key, TestStage::LoaderNotifyPanic)) {
                if gate.fail {
                    panic!("earlier loader notification failure injection");
                }
            }
        }));
        if let Err(error) = notified {
            if !panicking {
                std::panic::resume_unwind(error);
            }
        }
    }
}
impl Drop for EarlierLoaderGuard {
    fn drop(&mut self) {
        self.retain_unknown();
    }
}

#[cfg(test)]
fn observe_earlier_loader_lease(graph: &mut EarlierLoaderGraph) {
    let observed = lock(&OBSERVED_TASKS)
        .get(&session_key(&graph.ownership.db))
        .cloned();
    if let Some(observed) = observed {
        let op = graph.operation.clone();
        if let Some(id) = tokio::task::try_id() {
            lock(&observed.operation_tasks).insert(op.clone(), id);
        }
        let same = OWNED_JOB_SLOT
            .try_with(|slot| Arc::ptr_eq(slot, &graph.ownership.slot))
            .unwrap_or(false);
        let mut slots = lock(&observed.loader_same_task_slot);
        assert!(slots.len() < 32, "bounded earlier-loader slot observation");
        slots.push(same);
        drop(slots);
        let address = connection_identity(graph.connection());
        let mut leases = lock(&observed.leases);
        assert!(
            leases.len() < 32,
            "bounded earlier-loader lease observation"
        );
        leases.push((op, address));
    }
}
#[cfg(test)]
static LOADER_NESTED_BEGIN: LazyLock<StdMutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum EarlierLoaderDropMode {
    Absent,
    Stopped,
    AliveUnpolled,
}
#[cfg(test)]
static LOADER_DROP_MODES: LazyLock<StdMutex<HashMap<PathBuf, EarlierLoaderDropMode>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(crate) fn earlier_loader_drop_mode_for_test(db: &Db, mode: EarlierLoaderDropMode) {
    let mut modes = lock(&LOADER_DROP_MODES);
    assert!(modes.len() < 64);
    assert!(modes.insert(session_key(db), mode).is_none());
}
#[cfg(test)]
fn loader_test_drop_mode(guard: EarlierLoaderGuard) -> Result<EarlierLoaderGuard> {
    let mode =
        lock(&LOADER_DROP_MODES).remove(&session_key(&guard.graph.as_ref().unwrap().ownership.db));
    let Some(mode) = mode else {
        return Ok(guard);
    };
    // The ACTUAL already-constructed read graph, not a supplied arbitrary
    // future/connection, crosses this fixed test-only destruction boundary.
    std::thread::spawn(move || match mode {
        EarlierLoaderDropMode::Absent => drop(guard),
        EarlierLoaderDropMode::Stopped => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let handle = runtime.handle().clone();
            drop(runtime);
            drop(handle.spawn(guard.admit()));
        }
        EarlierLoaderDropMode::AliveUnpolled => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            drop(runtime.spawn(guard.admit())); // Deliberately never drive it.
            drop(runtime);
        }
    })
    .join()
    .unwrap();
    Err(Error::engine("earlier loader fixed runtime-drop stimulus"))
}

#[cfg(test)]
static LOADER_ROLLBACK_DESYNC: LazyLock<StdMutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));
#[cfg(test)]
static LOADER_DIRTY_NATIVE: LazyLock<StdMutex<std::collections::HashSet<PathBuf>>> =
    LazyLock::new(|| StdMutex::new(std::collections::HashSet::new()));
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum EarlierLoaderFault {
    NestedBeforeBegin,
    RollbackDesync,
    DirtyAfterRollback,
}
#[cfg(test)]
pub(crate) fn earlier_loader_fault_for_test(db: &Db, fault: EarlierLoaderFault) {
    let set = match fault {
        EarlierLoaderFault::NestedBeforeBegin => &LOADER_NESTED_BEGIN,
        EarlierLoaderFault::DirtyAfterRollback => &LOADER_DIRTY_NATIVE,
        EarlierLoaderFault::RollbackDesync => &LOADER_ROLLBACK_DESYNC,
    };
    let mut set = lock(set);
    assert!(set.len() < 64);
    set.insert(session_key(db));
}
#[cfg(test)]
pub(crate) fn pause_earlier_loader_worker_for_test(db: &Db, stage: TestStage) -> PolicyWorkerPause {
    pause_worker_for_test(
        db,
        match stage {
            TestStage::LoaderBeginPending => WorkerVmStage::LoaderBegin,
            TestStage::LoaderLoadPending => WorkerVmStage::LoaderLoad,
            TestStage::LoaderRollbackPending => WorkerVmStage::LoaderRollback,
            _ => panic!("fixed loader worker stage required"),
        },
    )
}
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct EarlierLoaderObservation {
    pub(crate) operation: String,
    pub(crate) phase: String,
    pub(crate) connection_address: Option<usize>,
    pub(crate) exact_slot_owner: bool,
    pub(crate) exact_room_owner: bool,
    pub(crate) exact_seed_handle: bool,
    pub(crate) original_session_matches: bool,
    pub(crate) session: SessionId,
    pub(crate) original_body: String,
}
#[cfg(test)]
pub(crate) fn earlier_loader_retained_for_test(db: &Db) -> Vec<EarlierLoaderObservation> {
    lock(&RETAINED_EARLIER_LOADERS)
        .iter_mut()
        .filter(|g| g.ownership.db.same_handle(db))
        .map(|g| {
            let address = g
                .connection
                .as_mut()
                .as_mut()
                .map(|c| connection_identity(c.as_mut()));
            let state = g.ownership.room.state();
            EarlierLoaderObservation {
                operation: g.operation.clone(),
                phase: format!("{:?}", g.phase),
                connection_address: address,
                exact_slot_owner: Arc::ptr_eq(&g.ownership.slot.owner, &g.ownership.owner),
                exact_room_owner: g
                    .ownership
                    .room
                    .owner
                    .upgrade()
                    .is_some_and(|owner| Arc::ptr_eq(&owner, &g.ownership.owner)),
                exact_seed_handle: g
                    .ownership
                    .room
                    .kernel_origin
                    .as_ref()
                    .is_some_and(|origin| origin.same_handle(&g.ownership.db)),
                original_session_matches: state.session == g.ownership.session,
                session: g.ownership.session.clone(),
                original_body: state.registry.live_body(&state.session).unwrap(),
            }
        })
        .collect()
}
#[cfg(test)]
pub(crate) async fn dispose_earlier_loader_for_test(db: &Db) {
    struct Disposal(Option<Box<EarlierLoaderGraph>>);
    impl Drop for Disposal {
        fn drop(&mut self) {
            if let Some(g) = self.0.take() {
                lock(&RETAINED_EARLIER_LOADERS).push(g);
            }
        }
    }
    let graph = {
        let mut held = lock(&RETAINED_EARLIER_LOADERS);
        let i = held
            .iter()
            .position(|g| g.ownership.db.same_handle(db))
            .unwrap();
        held.remove(i)
    };
    let mut disposal = Disposal(Some(graph));
    if disposal.0.as_ref().unwrap().connection.is_some() {
        let g = disposal.0.as_mut().unwrap();
        // Explicitly repair invalid-driver injections only in this test cleanup.
        let conn = g.connection();
        let native_open = {
            let mut h = conn.lock_handle().await.unwrap();
            // SAFETY: exclusive actual retained SQLite handle, test cleanup only.
            unsafe { libsqlite3_sys::sqlite3_get_autocommit(h.as_raw_handle().as_ptr()) == 0 }
        };
        use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
        let depth = SqliteTransactionManager::get_transaction_depth(conn);
        assert!(depth <= 1);
        // Reconcile explicit invalid-driver injections with REAL SQL; then get
        // a real manager worker ACK/depth0. No depth setter or invented ACK.
        if depth == 1 && !native_open {
            sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
        } else if depth == 0 && native_open {
            sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
        }
        Db::rollback_owned_kernel_connection(conn).await.unwrap();
        let mut h = conn.lock_handle().await.unwrap();
        // SAFETY: exclusive actual retained handle after acknowledged cleanup.
        assert_ne!(
            unsafe { libsqlite3_sys::sqlite3_get_autocommit(h.as_raw_handle().as_ptr()) },
            0
        );
    }
    let g = disposal.0.take().unwrap();
    drop(g.connection);
    drop(g.outcome);
    drop(g.ownership); // Never unquarantine.
}

/// A phase is disposition, never authority or a durable receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriterPhase {
    PoolOwnedCheckout,
    PoolOwnedAcquisitionFailure,
    LeaseReady,
    BeginMayHaveRun,
    Open,
    CommitMayHaveRun,
    Settled,
}

// Preallocated before acquire: a returned lease is attached without allocating,
// and its Rust connection address stays stable through permit use/quarantine.
struct WriterGraph<O: Send + 'static> {
    db: Db,
    operation: String,
    owner: Arc<DbSessions>,
    connection: Box<Option<sqlx::pool::PoolConnection<Sqlite>>>,
    ownership: O,
    quarantine_owner: fn(&mut O, &str),
    job_slot: Option<Arc<OwnedJobSlot>>,
    phase: WriterPhase,
    diagnostic_key: Option<usize>,
}
impl<O: Send + 'static> WriterGraph<O> {
    fn connection(&mut self) -> &mut SqliteConnection {
        self.connection
            .as_mut()
            .as_mut()
            .expect("owned native lease")
            .as_mut()
    }
}

enum UnknownConnection {
    /// Native terminal fence ONLY; SQLx owns pre-checkout disposition.
    CheckoutNativeUnknown,
    OwnedConnectionUnknown {
        _connection: Box<Option<sqlx::pool::PoolConnection<Sqlite>>>,
        _phase: WriterPhase,
    },
}
/// One bounded representation. Never an automatically replayable/reaped queue.
struct QuarantinedTransaction {
    _operation: String,
    _database: PathBuf,
    _connection: UnknownConnection,
    _owner: Arc<DbSessions>,
    _ownership: Box<dyn Send>,
    _job_slot: Option<Arc<OwnedJobSlot>>,
}
static QUARANTINED: LazyLock<StdMutex<Vec<QuarantinedTransaction>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));

/// Already armed BEFORE runtime lookup/spawn. Its Drop never spawns again.
struct WriterDisposition<O: Send + 'static> {
    graph: Option<WriterGraph<O>>,
}
impl<O: Send + 'static> WriterDisposition<O> {
    fn quarantine(&mut self) {
        let Some(mut graph) = self.graph.take() else {
            return;
        };
        // Internal notifications run outside SERVICE/ledger/retention locks.
        // Catch their unwind only long enough to publish the SAME graph. An
        // original unwind continues; a new notification panic resumes afterward.
        let already_panicking = std::thread::panicking();
        let notified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            quarantine_storage(&graph.db, &graph.operation);
            (graph.quarantine_owner)(&mut graph.ownership, &graph.operation);
        }));
        let connection = if graph.connection.is_some() {
            UnknownConnection::OwnedConnectionUnknown {
                _connection: graph.connection,
                _phase: graph.phase,
            }
        } else {
            UnknownConnection::CheckoutNativeUnknown
        };
        let retained_owner = Arc::clone(&graph.owner);
        lock(&QUARANTINED).push(QuarantinedTransaction {
            _database: session_key(&graph.db),
            _operation: graph.operation,
            _connection: connection,
            _owner: graph.owner,
            _ownership: Box::new(graph.ownership),
            _job_slot: graph.job_slot,
        });
        // Separate lifecycle observers must also wake after concrete retention,
        // without waiting for this slot (which deliberately remains retained).
        super::kernel_lifecycle::changed(&retained_owner);
        if let Err(panic) = notified {
            if !already_panicking {
                std::panic::resume_unwind(panic);
            }
        }
    }
    async fn rollback(&mut self) -> Result<()> {
        let graph = self.graph.as_mut().expect("armed native disposition");
        #[cfg(test)]
        let db = graph.db.clone();
        let settled = {
            let rollback = Db::rollback_owned_kernel_connection(graph.connection());
            tokio::pin!(rollback);
            #[cfg(test)]
            match futures::poll!(rollback.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    test_checkpoint(&db, TestStage::CleanupRollbackPending).await?;
                    rollback.await
                }
            }
            #[cfg(not(test))]
            rollback.await
        };
        settled?;
        // The same lease is now known rolled back. No business SQL follows.
        graph.phase = WriterPhase::Settled;
        Ok(())
    }
    fn dispose_clean(&mut self) -> (O, Option<Arc<OwnedJobSlot>>) {
        assert_eq!(
            self.graph.as_ref().expect("settled native graph").phase,
            WriterPhase::Settled
        );
        let graph = self.graph.take().unwrap();
        let release = crate::write_diagnostics::Timer::new("lease_disposal_enqueue");
        drop(graph.connection);
        release.finish("enqueued");
        // SQLx may asynchronously return a clean lease. This is not physical
        // close ACK. Native guards precede final admitted-slot release.
        (graph.ownership, graph.job_slot)
    }
}
impl<O: Send + 'static> Drop for WriterDisposition<O> {
    fn drop(&mut self) {
        self.quarantine();
    }
}

/// Own constructor, actual returned connection, SQL and native custody together.
/// Earlier admission loader and prior flush effects remain separate boundaries.
pub(crate) struct KernelTransaction<O: Send + 'static> {
    disposition: WriterDisposition<O>,
}
impl<O: Send + 'static> KernelTransaction<O> {
    pub(crate) async fn begin(
        db: &Db,
        ownership: O,
        quarantine_owner: fn(&mut O, &str),
    ) -> Result<Self> {
        use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
        let started = Instant::now();
        let mut retry = crate::db::BeginWriteRetry::new(crate::db::WRITER_DEADLINE);
        let mut transaction = Self {
            disposition: WriterDisposition {
                graph: Some(WriterGraph {
                    db: db.clone(),
                    operation: uuid::Uuid::new_v4().to_string(),
                    owner: db_sessions(db),
                    connection: Box::new(None),
                    ownership,
                    quarantine_owner,
                    job_slot: OWNED_JOB_SLOT.try_with(Arc::clone).ok(),
                    phase: WriterPhase::PoolOwnedCheckout,
                    diagnostic_key: None,
                }),
            },
        };
        #[cfg(test)]
        test_checkpoint(db, TestStage::CheckoutBeforeAcquire).await?;
        // Explicit pool-owned boundary: normal Err is NOT physical disposal.
        let acquired = {
            let checkout = db.write_pool().acquire();
            tokio::pin!(checkout);
            #[cfg(test)]
            match futures::poll!(checkout.as_mut()) {
                std::task::Poll::Ready(result) => result,
                std::task::Poll::Pending => {
                    test_checkpoint(db, TestStage::CheckoutPending).await?;
                    checkout.await
                }
            }
            #[cfg(not(test))]
            checkout.await
        };
        match acquired {
            Ok(connection) => {
                let graph = transaction.disposition.graph.as_mut().unwrap();
                *graph.connection = Some(connection);
                graph.phase = WriterPhase::LeaseReady;
                #[cfg(test)]
                if let Some(observed) = lock(&OBSERVED_TASKS).get(&session_key(db)).cloned() {
                    let operation = graph.operation.clone();
                    if let Some(id) = tokio::task::try_id() {
                        lock(&observed.operation_tasks).insert(operation.clone(), id);
                    }
                    let address = connection_identity(graph.connection());
                    let mut leases = lock(&observed.leases);
                    assert!(leases.len() < 32);
                    leases.push((operation, address));
                }
            }
            Err(error) => {
                let graph = transaction.disposition.graph.as_mut().unwrap();
                graph.phase = WriterPhase::PoolOwnedAcquisitionFailure;
                // Deliberate synchronous disposition before error conversion.
                let graph = transaction.disposition.graph.take().unwrap();
                drop(graph.connection);
                drop(graph.ownership);
                drop(graph.job_slot);
                crate::db::record_owned_kernel_begin(retry.retries, started.elapsed(), true);
                return Err(error.into());
            }
        }
        #[cfg(test)]
        test_checkpoint(db, TestStage::LeaseAttached).await?;
        {
            let graph = transaction.disposition.graph.as_mut().unwrap();
            if SqliteTransactionManager::get_transaction_depth(graph.connection()) != 0 {
                transaction.disposition.quarantine();
                return Err(Error::engine(
                    "native BEGIN refuses a nested original connection",
                ));
            }
            let clean = {
                let mut handle = graph.connection().lock_handle().await?;
                // SAFETY: this original lease's handle is live and exclusively
                // locked; SQLx's worker cannot access it until the guard drops.
                unsafe {
                    libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) != 0
                }
            };
            if !clean {
                transaction.disposition.quarantine();
                return Err(Error::engine(
                    "native BEGIN original connection is not clean",
                ));
            }
        }
        loop {
            transaction.disposition.graph.as_mut().unwrap().phase = WriterPhase::BeginMayHaveRun;
            #[cfg(test)]
            test_checkpoint(db, TestStage::BeforeBorrowedBegin).await?;
            #[cfg(test)]
            arm_worker_for_test(
                db,
                transaction.disposition.graph.as_mut().unwrap().connection(),
                WorkerVmStage::Begin,
            )
            .await?;
            let outcome = {
                let conn = transaction.disposition.graph.as_mut().unwrap().connection();
                let begin = SqliteTransactionManager::begin(conn, Some("BEGIN IMMEDIATE".into()));
                tokio::pin!(begin);
                #[cfg(test)]
                match futures::poll!(begin.as_mut()) {
                    std::task::Poll::Ready(result) => result,
                    std::task::Poll::Pending => {
                        test_checkpoint(db, TestStage::BorrowedBeginPending).await?;
                        begin.await
                    }
                }
                #[cfg(not(test))]
                begin.await
            };
            match outcome {
                Ok(()) => break,
                Err(error) => {
                    let original = Error::from(error);
                    // Decide at the original acknowledgement, as the ordinary
                    // loop does; settlement must finish before that retry runs.
                    let retry_allowed = retry.should_retry(&original);
                    #[cfg(test)]
                    {
                        if let Some(observed) = lock(&OBSERVED_TASKS).get(&session_key(db)).cloned()
                        {
                            *lock(&observed.begin_failures) += 1;
                        }
                        test_checkpoint(db, TestStage::BorrowedBeginRefused).await?;
                    }
                    if let Err(settlement) = transaction.disposition.rollback().await {
                        transaction.disposition.quarantine();
                        crate::db::record_owned_kernel_begin(
                            retry.retries,
                            started.elapsed(),
                            true,
                        );
                        return Err(Error::engine(format!(
                            "native BEGIN settlement uncertain: {settlement}"
                        )));
                    }
                    if !retry_allowed {
                        crate::db::record_owned_kernel_begin(
                            retry.retries,
                            started.elapsed(),
                            true,
                        );
                        let (owner, slot) = transaction.disposition.dispose_clean();
                        drop(owner);
                        drop(slot);
                        return Err(original);
                    }
                    // Custody remains armed during the exact existing cadence.
                    transaction.disposition.graph.as_mut().unwrap().phase =
                        WriterPhase::BeginMayHaveRun;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    retry.record_retry(&original);
                }
            }
        }
        crate::db::record_owned_kernel_begin(retry.retries, started.elapsed(), false);
        #[cfg(test)]
        test_checkpoint(db, TestStage::BeginAcknowledged).await?;
        let graph = transaction.disposition.graph.as_mut().unwrap();
        if SqliteTransactionManager::get_transaction_depth(graph.connection()) != 1 {
            transaction.disposition.quarantine();
            return Err(Error::engine(
                "native BEGIN did not acknowledge top-level depth",
            ));
        }
        match crate::db::prepare_owned_kernel_begin(db, graph.connection()).await {
            Ok(key) => graph.diagnostic_key = key,
            Err(error) => return Err(transaction.rollback(error).await),
        }
        transaction.disposition.graph.as_mut().unwrap().phase = WriterPhase::Open;
        Ok(transaction)
    }
    pub(crate) fn parts(&mut self) -> (&mut SqliteConnection, &mut O) {
        let graph = self.disposition.graph.as_mut().unwrap();
        assert_eq!(graph.phase, WriterPhase::Open);
        let conn = graph.connection.as_mut().as_mut().unwrap().as_mut();
        (conn, &mut graph.ownership)
    }
    pub(crate) async fn rollback(mut self, original: Error) -> Error {
        let operation = self.disposition.graph.as_ref().unwrap().operation.clone();
        if self.disposition.graph.as_ref().unwrap().phase == WriterPhase::CommitMayHaveRun {
            self.disposition.quarantine();
            return Error::engine(format!(
                "kernel operation {operation} may have committed; do not retry"
            ));
        }
        match self.disposition.rollback().await {
            Ok(()) => {
                let (ownership, slot) = self.disposition.dispose_clean();
                drop(ownership);
                drop(slot);
                original
            }
            Err(error) => {
                self.disposition.quarantine();
                Error::engine(format!("kernel operation {operation} outcome uncertain: rollback settlement failed ({error})"))
            }
        }
    }
    async fn settle_read(mut self) -> Result<O> {
        if let Err(error) = self.disposition.rollback().await {
            self.disposition.quarantine();
            return Err(Error::engine(format!(
                "kernel seed settlement uncertain: {error}"
            )));
        }
        let (ownership, slot) = self.disposition.dispose_clean();
        // Successful native callers remain inside the SAME owned job scope;
        // its task-local Arc covers synchronous install/seed after this return.
        drop(slot);
        Ok(ownership)
    }
    pub(crate) async fn commit(mut self) -> Result<O> {
        use crate::db::KernelCommitOutcome;
        #[cfg(test)]
        {
            let db = self.disposition.graph.as_ref().unwrap().db.clone();
            if let Err(error) = test_checkpoint(&db, TestStage::BeforeCommit).await {
                return Err(self.rollback(error).await);
            }
        }
        let graph = self.disposition.graph.as_mut().unwrap();
        let db = graph.db.clone();
        graph.phase = WriterPhase::CommitMayHaveRun;
        let diagnostic_key = graph.diagnostic_key;
        let outcome = db
            .commit_owned_kernel_connection(graph.connection(), diagnostic_key)
            .await;
        match outcome {
            KernelCommitOutcome::Committed => {
                #[cfg(test)]
                if let Err(error) = test_checkpoint(&db, TestStage::AfterDurability).await {
                    self.disposition.quarantine();
                    return Err(Error::engine(format!(
                        "native operation committed; installation uncertain; do not retry: {error}"
                    )));
                }
                self.disposition.graph.as_mut().unwrap().phase = WriterPhase::Settled;
                let (ownership, slot) = self.disposition.dispose_clean();
                // The submitting owned job still retains its task-local slot
                // through the caller's immediate install/drain handoff.
                drop(slot);
                Ok(ownership)
            }
            KernelCommitOutcome::RolledBack(error) => {
                self.disposition.graph.as_mut().unwrap().phase = WriterPhase::Settled;
                let (ownership, slot) = self.disposition.dispose_clean();
                drop(ownership);
                drop(slot);
                Err(error)
            }
            KernelCommitOutcome::Refused(error) => {
                self.disposition.graph.as_mut().unwrap().phase = WriterPhase::Open;
                Err(self.rollback(error).await)
            }
            KernelCommitOutcome::Uncertain(error) => {
                self.disposition.quarantine();
                Err(Error::engine(format!(
                    "native commit outcome uncertain: {error}"
                )))
            }
        }
    }
}
impl<O: Send + 'static> Drop for KernelTransaction<O> {
    fn drop(&mut self) {
        let Some(graph) = self.disposition.graph.take() else {
            return;
        };
        let db = graph.db.clone();
        let phase = graph.phase;
        // Construct BEFORE Handle lookup/spawn, including its pre-poll drop.
        let mut cleanup = WriterDisposition { graph: Some(graph) };
        if matches!(
            phase,
            WriterPhase::PoolOwnedCheckout
                | WriterPhase::LeaseReady
                | WriterPhase::CommitMayHaveRun
        ) {
            cleanup.quarantine();
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            cleanup.quarantine();
            return;
        };
        #[cfg(test)]
        let observed_db = db.clone();
        let task = runtime.spawn(async move {
            #[cfg(test)]
            if test_checkpoint(&db, TestStage::CleanupStarted)
                .await
                .is_err()
            {
                return;
            }
            #[cfg(test)]
            if test_checkpoint(&db, TestStage::CleanupPanic).await.is_err() {
                return;
            }
            #[cfg(not(test))]
            let _ = db;
            if cleanup.rollback().await.is_ok() {
                #[cfg(test)]
                if test_checkpoint(&db, TestStage::CleanupBeforeDisposal)
                    .await
                    .is_err()
                {
                    return;
                }
                let (ownership, slot) = cleanup.dispose_clean();
                drop(ownership);
                drop(slot);
                #[cfg(test)]
                let _ = test_checkpoint(&db, TestStage::CleanupDisposed).await;
            }
            // Unsettled or interrupted cleanup Drop synchronously quarantines.
        });
        #[cfg(test)]
        observe_spawn(&observed_db, &task);
        #[cfg(not(test))]
        drop(task);
    }
}

struct SeedOwnership {
    db: Db,
    _owner: Arc<DbSessions>,
    _lane: OwnedMutexGuard<()>,
    _gate: tokio::sync::OwnedRwLockWriteGuard<()>,
    room: Option<Arc<LiveSession>>,
}
fn quarantine_seed(owner: &mut SeedOwnership, operation: &str) {
    quarantine_storage(&owner.db, operation);
    if let Some(room) = &owner.room {
        room.state().closed = true;
    }
}

pub(super) async fn seed_or_join(
    db: &Db,
    caller: &Caller,
    request: OpenRequest,
) -> std::result::Result<Option<(SessionPeer, Opened)>, Refused> {
    #[cfg(test)]
    test_checkpoint(db, TestStage::SeedBeforeLane)
        .await
        .map_err(unavailable)?;
    let owner = db_sessions(db);
    let lane = acquire_lane(db, &owner).await.map_err(unavailable)?;
    let gate = acquire_write_gate(db, &owner).await.map_err(unavailable)?;
    let OpenRequest {
        record_id,
        mode,
        resume_peer: _,
    } = request;
    let already_seeded = lock(&owner.records).contains_key(&record_id);
    if already_seeded {
        drop(gate);
        drop(lane);
        return Ok(None);
    }
    let ownership = SeedOwnership {
        db: db.clone(),
        _owner: Arc::clone(&owner),
        _lane: lane,
        _gate: gate,
        room: None,
    };
    #[cfg(test)]
    test_checkpoint(db, TestStage::SeedBeforeFence)
        .await
        .map_err(unavailable)?;
    ensure_available(db).map_err(unavailable)?;
    let mut transaction = KernelTransaction::begin(db, ownership, quarantine_seed)
        .await
        .map_err(unavailable)?;
    #[cfg(test)]
    if let Err(error) = test_checkpoint(db, TestStage::SeedAfterFence).await {
        return Err(unavailable(transaction.rollback(error).await));
    }
    let loaded = {
        let (tx, _) = transaction.parts();
        kernel_v2::load_committed_on(tx, caller, &record_id, mode).await
    };
    let LoadedBody {
        body,
        base,
        admitted_as_document,
    } = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(super::super::backend::kernel_refusal(
                transaction.rollback(error).await,
            ))
        }
    };
    let author = {
        let (tx, _) = transaction.parts();
        match kernel_v2::contributor_on(tx, caller).await {
            Ok(contributor) => Author {
                contributor,
                kind: author_for(caller).kind,
            },
            Err(error) => return Err(unavailable(transaction.rollback(error).await)),
        }
    };
    let mut registry = SessionRegistry::new();
    reserve_client_ids(&mut registry);
    let opened = registry.open(OpenParams {
        database_id: session_key(db).to_string_lossy().into_owned(),
        record_id: record_id.clone(),
        committed_body: body,
        kind: mode,
        record_supported: true,
    })?;
    // The seed doc's own snapshot, before any peer can apply: its
    // text must hash to the revision just read, or no proof.
    let base = match registry.version_snapshot(&opened.session_id) {
        Ok(seed) => BaseVersion {
            proof: base_proof(
                &seed,
                &base.body_sha256,
                BodyEvent::from_row(base.proof.body_event_id.clone(), base.proof.body_event_seq)
                    .as_ref(),
            ),
            ..base
        },
        Err(_) => base,
    };
    let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    let session = Arc::new(LiveSession {
        kernel_origin: Some(db.clone()),
        backend: SessionBackend::KernelV2,
        admitted_as_document,
        record_id: record_id.clone(),
        owner: Arc::downgrade(&owner),
        ops: Arc::new(AsyncMutex::new(())),
        state: StdMutex::new(State {
            db: db.clone(),
            registry,
            session: opened.session_id.clone(),
            closed: false,
            peers: HashMap::new(),
            departed: HashMap::new(),
            callers: HashMap::new(),
            versioned_epoch: 0,
            offline_merge: None,
            dirty_admission: None,
            last_op: Instant::now(),
            idle_after: IDLE_VERSION_AFTER,
            idle_timer: false,
            version_interval: REQUESTED_VERSION_INTERVAL,
            last_requested_cut: None,
            pending_request: None,
            request_timer: false,
            grace_until: None,
            grace_timer: false,
            failed_cuts: 0,
            transient_failures: 0,
            transient_since: None,
            transient_window: TRANSIENT_RETRY_WINDOW,
            absorbing: None,
            scope_change: false,
            pending_recheck: false,
            kernel_finalization_blocked: false,
            base: base.clone(),
            next_incarnation: 1,
        }),
        events,
    });
    let publication = {
        let _serial = lock(&owner.kernel_lifecycle.serial);
        ensure_available(db).map(|()| {
            let peer = attach(
                &session,
                &mut session.state(),
                caller,
                mode,
                &author,
                opened.peer_id,
                &opened.client_ids,
            );
            lock(&owner.records).insert(record_id.clone(), Arc::clone(&session));
            transaction.parts().1.room = Some(Arc::clone(&session));
            peer
        })
    };
    let peer = match publication {
        Ok(peer) => peer,
        Err(error) => return Err(unavailable(transaction.rollback(error).await)),
    };
    // The room reservation is visible before releasing the SQLite fence.
    // Earlier raw writers precede this snapshot; later inserts hit backstop.
    let ownership = transaction.settle_read().await.map_err(unavailable)?;
    drop(ownership);
    ensure_available(db).map_err(unavailable)?;
    let opened = Opened {
        session: opened.session_id,
        peer: peer.inner.peer.clone(),
        doc_client_ids: view_filtered(mode, opened.client_ids),
        sync: opened.sync_step2,
        base,
        limits: LIMITS,
        resumed: false,
    };
    Ok(Some((peer, opened)))
}

/// Explicit internal test entry only. No hosted route selects this backend.
#[cfg(test)]
pub(crate) async fn open_for_test(
    db: &Db,
    caller: &Caller,
    request: OpenRequest,
) -> std::result::Result<(SessionPeer, Opened), Refused> {
    super::open_kernel_inactive(db, caller, request).await
}

// Test-only directory custody, never app/actor admission. Capture BEFORE owned
// submission; fields in both concrete graphs keep the directory after slots.
#[cfg(test)]
type WriterFixtureOwnerMap = HashMap<
    uuid::Uuid,
    (
        uuid::Uuid,
        Arc<crate::v1_import::NativePeerAdoptedAppFixture>,
    ),
>;
#[cfg(test)]
static WRITER_FIXTURE_OWNERS: LazyLock<StdMutex<WriterFixtureOwnerMap>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));
#[cfg(test)]
pub(crate) fn register_writer_fixture_owner_for_test(
    db: &Db,
    owner: Arc<crate::v1_import::NativePeerAdoptedAppFixture>,
) -> impl Drop + Send + Sync {
    assert!(db.same_handle(&owner.db));
    struct Registration {
        handle: uuid::Uuid,
        token: uuid::Uuid,
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            let retired = {
                let mut entries = lock(&WRITER_FIXTURE_OWNERS);
                if entries
                    .get(&self.handle)
                    .is_some_and(|(token, _)| *token == self.token)
                {
                    entries.remove(&self.handle)
                } else {
                    None
                }
            };
            drop(retired);
        }
    }
    let handle = db.handle_id();
    let token = uuid::Uuid::new_v4();
    let mut entries = lock(&WRITER_FIXTURE_OWNERS);
    assert!(
        !entries.contains_key(&handle),
        "nested writer fixture owner"
    );
    entries.insert(handle, (token, owner));
    Registration { handle, token }
}
#[cfg(test)]
pub(crate) fn capture_writer_fixture_owner_for_test(
    db: &Db,
) -> Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>> {
    lock(&WRITER_FIXTURE_OWNERS)
        .get(&db.handle_id())
        .map(|(_, owner)| Arc::clone(owner))
}

#[cfg(test)]
pub(crate) async fn explicit_version_for_test(
    peer: &SessionPeer,
    caller: &Caller,
) -> std::result::Result<Option<Versioned>, Refused> {
    peer_reads::version_for_test(peer, caller).await
}
