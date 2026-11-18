//! Inactive, private native apply/sync. Only descendant tests can enter.
//! T2 authorizes a pinned native snapshot, not host freshness or queued output.
//! SQLx owns pre-checkout work; no result here certifies physical pool drain.
#![allow(dead_code)]

use super::*;
use crate::coedit::kernel_v2::NativePeerFacts;
use sqlx::{pool::PoolConnection, sqlite::SqliteTransactionManager, TransactionManager};

type PeerResult<T> = std::result::Result<T, Refused>;
const MAX_NATIVE_PEER_REQUEST_BYTES: usize = 128 * 1024;
tokio::task_local! { static N2_PEER_SCOPE: (); }

fn require_ingress() -> Result<()> {
    crate::mcp::kernel_v2::require_no_sql_session_for_native_peer_ingress()?;
    if OWNED_JOB_SLOT.try_with(|_| ()).is_ok()
        || kernel_lifecycle::current_cleanup().is_some()
        || N2_PEER_SCOPE.try_with(|_| ()).is_ok()
    {
        return Err(Error::engine(
            "native peer ingress rejects an inherited operation scope",
        ));
    }
    Ok(())
}

fn apply_bytes_fit(id: usize, update: usize) -> bool {
    update <= crate::coedit::registry::MAX_UPDATE_BYTES
        && id
            .checked_add(update)
            .is_some_and(|n| n <= MAX_NATIVE_PEER_REQUEST_BYTES)
}
fn too_large() -> Refused {
    Refused::new(
        RefusalCode::TooLarge,
        "native peer raw request exceeds private byte limit",
    )
}

enum PeerReadRequest {
    Apply { update_id: String, update: Vec<u8> },
    Sync { state_vector: Vec<u8> },
}
#[derive(Debug)]
enum PeerReadReply {
    Apply(PeerResult<PeerAck>),
    Sync(PeerResult<Vec<u8>>),
}

struct PeerOrigin {
    peer: Arc<PeerInner>,
    credential: String,
    principal: String,
    app: Option<AppAttribution>,
    mode: SessionMode,
}
impl PeerOrigin {
    fn capture(peer: &SessionPeer, caller: &Caller) -> PeerResult<(Self, Db, Arc<DbSessions>)> {
        let room = &peer.inner.session;
        if room.backend != SessionBackend::KernelV2 {
            return Err(unavailable("native peer backend mismatch"));
        }
        let db = room
            .kernel_origin
            .clone()
            .ok_or_else(|| unavailable("native seed handle absent"))?;
        let owner = room
            .owner
            .upgrade()
            .ok_or_else(|| unavailable("native owner absent"))?;
        let state = room.state();
        let entry = state.peer(&peer.inner.peer, peer.inner.incarnation)?;
        if peer.inner.left.load(Ordering::Acquire)
            || entry.caller.credential() != caller.credential()
            || entry.author.contributor.app != caller.host_asserted_app().map(AppAttribution::from)
        {
            return Err(Refused::new(
                RefusalCode::Forbidden,
                "native peer Caller identity changed",
            ));
        }
        Ok((
            Self {
                peer: Arc::clone(&peer.inner),
                credential: entry.caller.credential().to_owned(),
                principal: entry.author.contributor.principal.clone(),
                app: entry.author.contributor.app.clone(),
                mode: entry.mode,
            },
            db,
            owner,
        ))
    }
}
// No production caller or scheduler wiring. Caller is rooted only in this
// bounded owned job; no new persistent Caller/delegation cache exists.
pub(in crate::coedit) struct OwnedExplicitVersionRequest {
    origin: PeerOrigin,
    db: Db,
    owner: Arc<DbSessions>,
    caller: Caller,
    ambient: Option<(String, Arc<crate::mcp::app_attribution::AppAttribution>)>,
    basis: Option<(BaseVersion, u64, u64)>,
    #[cfg(test)]
    probe: Option<Arc<TestProbe>>,
    #[cfg(test)]
    fixture: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
}
impl OwnedExplicitVersionRequest {
    pub(in crate::coedit) fn caller(&self) -> &Caller {
        &self.caller
    }
    pub(in crate::coedit) fn record(&self) -> &str {
        &self.origin.peer.session.record_id
    }
    pub(super) fn db(&self) -> &Db {
        &self.db
    }
    pub(super) fn room(&self) -> &Arc<LiveSession> {
        &self.origin.peer.session
    }
    pub(super) fn owner(&self) -> &Arc<DbSessions> {
        &self.owner
    }
    #[cfg(test)]
    pub(super) fn fixture_owner(
        &self,
    ) -> Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>> {
        self.fixture
            .clone()
            .or_else(|| self.probe.as_ref().and_then(|p| p.fixture_owner.clone()))
    }
    pub(in crate::coedit) fn require_same_dispatch(&self) -> Result<()> {
        let ambient = crate::provenance::current_app_claim();
        if ambient != self.ambient
            || ambient
                .as_ref()
                .is_some_and(|(_, app)| Some(app.as_ref()) != self.caller.host_asserted_app())
        {
            return Err(Error::auth("explicit native dispatch/Caller mismatch"));
        }
        Ok(())
    }
    fn require_maps(&self, owner: &KernelBodyWrite) -> Result<()> {
        ensure_available(&self.db)?;
        if !Arc::ptr_eq(&owner._owner, &self.owner)
            || !owner.db.same_handle(&self.db)
            || !existing_db_sessions(&self.db).is_some_and(|o| Arc::ptr_eq(&o, &self.owner))
            || !lock(&self.owner.records)
                .get(self.record())
                .is_some_and(|r| Arc::ptr_eq(r, self.room()))
            || !self
                .room()
                .kernel_origin
                .as_ref()
                .is_some_and(|d| d.same_handle(&self.db))
        {
            return Err(Error::engine("explicit original owner/room/handle changed"));
        }
        Ok(())
    }
    fn require_state(&self, owner: &KernelBodyWrite, state: &State) -> Result<()> {
        let entry = state
            .peer(&self.origin.peer.peer, self.origin.peer.incarnation)
            .map_err(|e| Error::engine(e.to_string()))?;
        let live = owner
            .live
            .as_ref()
            .ok_or_else(|| Error::engine("explicit room missing"))?;
        if !Arc::ptr_eq(&live.room, self.room())
            || state.closed
            || state.session != self.origin.peer.session_id
            || live.session != state.session
            || self.origin.peer.left.load(Ordering::Acquire)
            || entry.mode != PeerKind::Edit
            || self.origin.mode != PeerKind::Edit
            || entry.caller.credential() != self.origin.credential
            || entry.author.contributor.principal != self.origin.principal
            || entry.author.contributor.app != self.origin.app
            || state.kernel_finalization_blocked
            || state.pending_recheck
            || state.scope_change
            || state.absorbing.is_some()
        {
            return Err(Error::engine("explicit original peer/basis unavailable"));
        }
        Ok(())
    }
    pub(super) fn require_owned_identity(&self, owner: &KernelBodyWrite) -> Result<()> {
        let _serial = lock(&self.owner.kernel_lifecycle.serial);
        self.require_maps(owner)?;
        let state = self.room().state();
        self.require_state(owner, &state)
    }
    pub(super) fn require_owned_basis(
        &self,
        owner: &KernelBodyWrite,
        facts: &NativePeerFacts,
        snapshot: &crate::coedit::VersionSnapshot,
    ) -> Result<()> {
        self.require_same_dispatch()?;
        let _serial = lock(&self.owner.kernel_lifecycle.serial);
        self.require_maps(owner)?;
        let state = self.room().state();
        self.require_state(owner, &state)?;
        let (base, epoch, versioned) = self
            .basis
            .as_ref()
            .ok_or_else(|| Error::engine("explicit basis absent"))?;
        if state.base != *base
            || state.epoch() != *epoch
            || state.versioned_epoch != *versioned
            || snapshot.session_id() != &state.session
            || state
                .registry
                .live_body(&state.session)
                .map_err(|e| Error::engine(e.to_string()))?
                != snapshot.body()
            || facts.principal() != self.origin.principal
            || facts.contributor().app != self.origin.app
        {
            return Err(Error::engine("explicit owned snapshot/identity changed"));
        }
        Ok(())
    }
}

// PRIVATE raw ingress. Do not export to a production caller/route.
async fn version_as(peer: &SessionPeer, caller: &Caller) -> PeerResult<Option<Versioned>> {
    require_ingress().map_err(unavailable)?;
    let (origin, db, owner) = PeerOrigin::capture(peer, caller)?;
    if origin.mode != PeerKind::Edit {
        return Err(Refused::new(
            RefusalCode::Forbidden,
            "view peer cannot version",
        ));
    }
    #[cfg(test)]
    let fixture = capture_writer_fixture_owner_for_test(&db);
    let request = OwnedExplicitVersionRequest {
        origin,
        owner,
        db,
        caller: caller.clone(),
        ambient: crate::provenance::current_app_claim(),
        basis: None,
        #[cfg(test)]
        probe: capture_probe(),
        #[cfg(test)]
        fixture,
    };
    request.require_same_dispatch().map_err(unavailable)?;
    let db = request.db.clone();
    let receiver = start_owned_with(db, move || {
        N2_PEER_SCOPE.scope((), run_explicit_version(request))
    })
    .map_err(unavailable)?;
    receiver
        .await
        .map_err(|_| unavailable("explicit native owner stopped; outcome uncertain"))?
        .map_err(unavailable)
}

// Known postcommit install mismatch retains actual native guards/slot and the
// dirty room, not a fictional still-open SQL lease. No recovery API exists.
struct RetainedExplicitInstall {
    owner: KernelBodyWrite,
    snapshot: crate::coedit::VersionSnapshot,
    base: BaseVersion,
}
static RETAINED_EXPLICIT_INSTALLS: LazyLock<StdMutex<Vec<RetainedExplicitInstall>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));

async fn run_explicit_version(
    mut request: OwnedExplicitVersionRequest,
) -> Result<Option<Versioned>> {
    let mut owner = KernelBodyWrite::acquire_explicit_version(&request).await?;
    let (snapshot, dirty, basis) = {
        let state = request.room().state();
        let snapshot = state
            .registry
            .version_snapshot(&state.session)
            .map_err(|e| Error::engine(e.to_string()))?;
        (
            snapshot,
            state.dirty(),
            (state.base.clone(), state.epoch(), state.versioned_epoch),
        )
    };
    request.basis = Some(basis);
    if dirty {
        owner.arm_finalization_failure();
    }
    let db = request.db.clone();
    let mut transaction = KernelTransaction::begin(&db, owner, KernelBodyWrite::quarantine).await?;
    let mut acts = crate::act::ActAllocation::new();
    let result = async {
        if !dirty {
            let (tx, owner) = transaction.parts();
            let facts =
                kernel_v2::peer_facts_on(tx, request.caller(), request.record(), PeerKind::Edit)
                    .await?;
            request.require_owned_basis(owner, &facts, &snapshot)?;
            let principal = crate::mcp::kernel_v2::principal_on(tx, request.caller()).await?;
            crate::kernel::app_installs::admit_dispatched_on(tx, &principal).await?;
            let loaded = kernel_v2::load_committed_on(
                tx,
                request.caller(),
                request.record(),
                PeerKind::Edit,
            )
            .await?;
            let state = request.room().state();
            if loaded.base.proof.body_event_id != state.base.proof.body_event_id
                || loaded.base.proof.body_event_seq != state.base.proof.body_event_seq
                || loaded.base.body_sha256 != state.base.body_sha256
            {
                return Err(Error::conflict("explicit clean body basis changed"));
            }
            return Ok(None);
        }
        let before = {
            let (tx, _) = transaction.parts();
            crate::kernel::record_metadata::updated_at_on(tx, request.record()).await?
        };
        let base = KernelBodyWrite::append_explicit_snapshot(
            &mut transaction,
            &request,
            &snapshot,
            &mut acts,
        )
        .await?;
        let after = {
            let (tx, owner) = transaction.parts();
            request.require_owned_identity(owner)?;
            owner.validate_precommit()?;
            crate::kernel::record_metadata::updated_at_on(tx, request.record()).await?
        };
        Ok::<_, Error>(Some((base, before, after)))
    }
    .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => return Err(transaction.rollback(error).await),
    };
    let Some((base, before, after)) = result else {
        let _owner = transaction.settle_read().await?;
        return Ok(None);
    };
    let mut owner = transaction.commit().await?;
    // No await between known durability and exact installation. Prepare owned
    // result before modifying registry; dirty lease drops after ALL locks.
    let installed = (|| {
        request.require_owned_identity(&owner)?;
        let event_id = base
            .proof
            .body_event_id
            .clone()
            .ok_or_else(|| Error::engine("explicit body proof absent"))?;
        if sha256_hex(snapshot.body()) != base.body_sha256 {
            return Err(Error::engine("explicit installed digest mismatch"));
        }
        let versioned = Versioned {
            session: snapshot.session_id().clone(),
            version: base.version.clone(),
            body_sha256: base.body_sha256.clone(),
            event_id,
            contributors: snapshot.contributors().to_vec(),
            reason: "Explicit native collaborative body version".into(),
            proof: base.proof.clone(),
            updated_at_around_cut: Some((before, after)),
        };
        let installed_body = snapshot.body().to_owned();
        let installed_base = base.clone();
        let retired_dirty;
        let _serial = lock(&request.owner.kernel_lifecycle.serial);
        request.require_maps(&owner)?;
        let mut state = request.room().state();
        request.require_state(&owner, &state)?;
        let (expected, epoch, versioned_epoch) = request.basis.as_ref().unwrap();
        if state.base != *expected
            || state.epoch() != *epoch
            || state.versioned_epoch != *versioned_epoch
            || state.closed
            || state.session != *snapshot.session_id()
            || state.registry.drain_version_snapshot(&snapshot)
                != Ok(crate::coedit::DrainOutcome::Drained)
        {
            return Err(Error::engine(
                "explicit committed snapshot installation mismatch",
            ));
        }
        let new_body = distinct_body_event(&state.base.proof, &base.proof);
        state.base = installed_base;
        state.versioned_epoch = state.epoch();
        retired_dirty = state.dirty_admission.take();
        if new_body {
            state.kernel_finalization_blocked = false;
            if let Some(mark) = owner.live.as_mut().unwrap().failure_mark.as_mut() {
                mark.disarm();
            }
        }
        let live = owner.live.as_mut().unwrap();
        live.body = installed_body;
        live.expected_body_seq = base.proof.body_event_seq;
        drop(state);
        drop(_serial);
        drop(retired_dirty);
        Ok::<_, Error>(versioned)
    })();
    match installed {
        Ok(versioned) => {
            request
                .room()
                .emit(SessionEvent::Versioned(versioned.clone()));
            Ok(Some(versioned))
        }
        Err(error) => {
            owner.quarantine(
                base.proof
                    .body_event_id
                    .as_deref()
                    .unwrap_or("explicit-install"),
            );
            let event = base.proof.body_event_id.clone().unwrap_or_default();
            lock(&RETAINED_EXPLICIT_INSTALLS).push(RetainedExplicitInstall {
                owner,
                snapshot,
                base,
            });
            Err(Error::engine(format!("explicit body event {event} committed but native installation is retained; do not retry: {error}")))
        }
    }
}
#[cfg(test)]
pub(super) async fn version_for_test(
    peer: &SessionPeer,
    caller: &Caller,
) -> PeerResult<Option<Versioned>> {
    version_as(peer, caller).await
}

struct OwnedPeerReadRequest {
    origin: PeerOrigin,
    db: Db,
    owner: Arc<DbSessions>,
    caller: Caller,
    request: PeerReadRequest,
    #[cfg(test)]
    probe: Option<Arc<TestProbe>>,
}

// Deliberately private: no production wrapper, method dispatch or pointer escape.
async fn apply_as(
    peer: &SessionPeer,
    caller: &Caller,
    update_id: &str,
    update: &[u8],
) -> PeerResult<PeerAck> {
    require_ingress().map_err(unavailable)?;
    if !apply_bytes_fit(update_id.len(), update.len()) {
        return Err(too_large());
    }
    let (origin, db, owner) = PeerOrigin::capture(peer, caller)?;
    if origin.mode != PeerKind::Edit {
        return Err(Refused::new(
            RefusalCode::Forbidden,
            "view-mode peers cannot author updates",
        ));
    }
    #[cfg(test)]
    let probe = capture_probe();
    let request = OwnedPeerReadRequest {
        origin,
        db,
        owner,
        caller: caller.clone(),
        request: PeerReadRequest::Apply {
            update_id: update_id.to_owned(),
            update: update.to_vec(),
        },
        #[cfg(test)]
        probe,
    };
    match submit(request).await? {
        PeerReadReply::Apply(answer) => answer,
        PeerReadReply::Sync(_) => Err(unavailable("native peer result kind mismatch")),
    }
}
async fn sync_as(peer: &SessionPeer, caller: &Caller, state_vector: &[u8]) -> PeerResult<Vec<u8>> {
    require_ingress().map_err(unavailable)?;
    if state_vector.len() > MAX_NATIVE_PEER_REQUEST_BYTES {
        return Err(too_large());
    }
    let (origin, db, owner) = PeerOrigin::capture(peer, caller)?;
    #[cfg(test)]
    let probe = capture_probe();
    let request = OwnedPeerReadRequest {
        origin,
        db,
        owner,
        caller: caller.clone(),
        request: PeerReadRequest::Sync {
            state_vector: state_vector.to_vec(),
        },
        #[cfg(test)]
        probe,
    };
    match submit(request).await? {
        PeerReadReply::Sync(answer) => answer,
        PeerReadReply::Apply(_) => Err(unavailable("native peer result kind mismatch")),
    }
}
async fn submit(request: OwnedPeerReadRequest) -> PeerResult<PeerReadReply> {
    let db = request.db.clone();
    let receiver = start_owned_with(db, move || N2_PEER_SCOPE.scope((), run_owned(request)))
        .map_err(unavailable)?;
    receiver
        .await
        .map_err(|_| unavailable("native peer owner stopped; outcome uncertain"))?
        .map_err(unavailable)
}

struct PeerReadOwnership {
    db: Db,
    owner: Arc<DbSessions>,
    room: Arc<LiveSession>,
    origin: PeerOrigin,
    request: PeerReadRequest,
    caller: Caller,
    // Actual ops/gate disposal precedes final slot release.
    _ops: OwnedMutexGuard<()>,
    _gate: OwnedRwLockReadGuard<()>,
    slot: Arc<OwnedJobSlot>,
    #[cfg(test)]
    probe: Option<Arc<TestProbe>>,
}
impl PeerReadOwnership {
    fn validate_maps(&self) -> PeerResult<()> {
        if !Arc::ptr_eq(&self.slot.owner, &self.owner)
            || !existing_db_sessions(&self.db).is_some_and(|o| Arc::ptr_eq(&o, &self.owner))
            || !lock(&self.owner.records)
                .get(&self.room.record_id)
                .is_some_and(|r| Arc::ptr_eq(r, &self.room))
            || self.room.backend != SessionBackend::KernelV2
            || !self
                .room
                .kernel_origin
                .as_ref()
                .is_some_and(|d| d.same_handle(&self.db))
        {
            return Err(unavailable("native peer owner/room/seed handle changed"));
        }
        Ok(())
    }
    fn validate_state(&self, state: &State) -> PeerResult<()> {
        let entry = state.peer(&self.origin.peer.peer, self.origin.peer.incarnation)?;
        if state.session != self.origin.peer.session_id
            || self.origin.peer.left.load(Ordering::Acquire)
            || entry.mode != self.origin.mode
            || entry.caller.credential() != self.origin.credential
            || entry.author.contributor.principal != self.origin.principal
            || entry.author.contributor.app != self.origin.app
            || state.kernel_finalization_blocked
            || state.pending_recheck
            || state.scope_change
            || state.absorbing.is_some()
        {
            return Err(unavailable("native peer origin or availability changed"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerReadPhase {
    PoolOwnedCheckout,
    LeaseReady,
    DriverPending,
    TransactionActive,
    Settling,
    Acknowledged,
    PoolOwnedAcquisitionFailure,
    Consumed,
}
struct PeerReadGuard {
    ownership: Option<PeerReadOwnership>,
    lease: Option<PoolConnection<Sqlite>>,
    phase: PeerReadPhase,
    facts: Option<NativePeerFacts>,
    refusal: Option<Refused>,
    operation_id: String,
}
// No production release path. Native uncertainty is not physical-drain proof.
enum RetainedPeerRead {
    CheckoutNativeUnknown {
        operation_id: String,
        ownership: PeerReadOwnership,
    },
    OwnedConnectionUnknown {
        operation_id: String,
        // Dispose the actual lease before ownership in any test reconciliation.
        lease: PoolConnection<Sqlite>,
        ownership: PeerReadOwnership,
        phase: PeerReadPhase,
    },
}
static RETAINED_PEER_READS: LazyLock<StdMutex<Vec<RetainedPeerRead>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));
impl Drop for PeerReadGuard {
    fn drop(&mut self) {
        if matches!(
            self.phase,
            PeerReadPhase::Acknowledged
                | PeerReadPhase::Consumed
                | PeerReadPhase::PoolOwnedAcquisitionFailure
        ) {
            debug_assert!(self.lease.is_none());
            return;
        }
        let Some(ownership) = self.ownership.take() else {
            return;
        };
        // Publish on the ORIGINAL owner, never remint one from a mutable key.
        // Same fields/watch as quarantine_storage; no lifecycle changed wake promised.
        let mut identity = lock(&ownership.owner.kernel_quarantine_identity);
        if identity.is_none() {
            *identity = Some(self.operation_id.clone());
        }
        ownership.owner.kernel_quarantine.send_replace(true);
        drop(identity);
        let operation_id = std::mem::take(&mut self.operation_id);
        let retained = match self.lease.take() {
            Some(lease) => RetainedPeerRead::OwnedConnectionUnknown {
                operation_id,
                lease,
                ownership,
                phase: self.phase,
            },
            None => RetainedPeerRead::CheckoutNativeUnknown {
                operation_id,
                ownership,
            },
        };
        lock(&RETAINED_PEER_READS).push(retained);
    }
}
impl PeerReadGuard {
    fn new(ownership: PeerReadOwnership) -> Self {
        Self {
            ownership: Some(ownership),
            lease: None,
            phase: PeerReadPhase::PoolOwnedCheckout,
            facts: None,
            refusal: None,
            operation_id: uuid::Uuid::new_v4().to_string(),
        }
    }
    async fn checkout(&mut self) -> Result<()> {
        #[cfg(test)]
        self.checkpoint(TestStage::Checkout).await;
        let pool = self.ownership.as_ref().unwrap().db.pool().clone();
        #[cfg(test)]
        let (answer, acquisitions) =
            crate::db::with_read_pool_acquisition_counter(pool.acquire()).await;
        #[cfg(not(test))]
        let answer = pool.acquire().await;
        let lease = match answer {
            Ok(lease) => lease,
            Err(error) => {
                self.phase = PeerReadPhase::PoolOwnedAcquisitionFailure;
                return Err(error.into());
            }
        };
        // No suspension/callback/allocation between returned lease and custody.
        self.lease = Some(lease);
        self.phase = PeerReadPhase::LeaseReady;
        #[cfg(test)]
        if let Some(probe) = &self.ownership.as_ref().unwrap().probe {
            probe.acquisitions.fetch_add(acquisitions, Ordering::SeqCst);
        }
        #[cfg(test)]
        self.checkpoint(TestStage::LeaseReady).await;
        Ok(())
    }
    async fn begin_deferred(&mut self) -> Result<()> {
        self.phase = PeerReadPhase::DriverPending;
        let conn: &mut SqliteConnection = self.lease.as_mut().unwrap();
        if SqliteTransactionManager::get_transaction_depth(conn) != 0 {
            return Err(Error::engine("native peer read refuses nested transaction"));
        }
        {
            let mut handle = conn.lock_handle().await?;
            // SAFETY: exclusive live SQLx SQLite handle, borrowed from owned lease.
            if unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) }
                == 0
            {
                return Err(Error::engine(
                    "native peer read found an active transaction",
                ));
            }
        }
        SqliteTransactionManager::begin(conn, None).await?;
        self.phase = PeerReadPhase::TransactionActive;
        #[cfg(test)]
        self.checkpoint(TestStage::Begun).await;
        Ok(())
    }
    async fn read_facts(&mut self) {
        let o = self.ownership.as_ref().unwrap();
        let result = kernel_v2::peer_facts_on(
            self.lease.as_mut().unwrap(),
            &o.caller,
            &o.room.record_id,
            o.origin.mode,
        )
        .await;
        match result {
            Ok(facts)
                if facts.principal() == o.origin.principal
                    && facts.contributor().app == o.origin.app
                    && o.caller.credential() == o.origin.credential =>
            {
                self.facts = Some(facts)
            }
            Ok(_) => {
                self.refusal = Some(Refused::new(
                    RefusalCode::Forbidden,
                    "native principal/app binding changed",
                ))
            }
            Err(error) => self.refusal = Some(crate::coedit::backend::kernel_refusal(error)),
        }
        #[cfg(test)]
        self.checkpoint(TestStage::Facts).await;
    }
    async fn settle(&mut self) -> Result<()> {
        self.phase = PeerReadPhase::Settling;
        #[cfg(test)]
        self.checkpoint(TestStage::Settling).await;
        let conn: &mut SqliteConnection = self.lease.as_mut().unwrap();
        SqliteTransactionManager::rollback(conn).await?;
        if SqliteTransactionManager::get_transaction_depth(conn) != 0 {
            return Err(Error::engine("native peer rollback depth did not settle"));
        }
        {
            let mut handle = conn.lock_handle().await?;
            // SAFETY: exclusive live SQLx handle after worker rollback ACK.
            if unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) }
                == 0
            {
                return Err(Error::engine("native peer rollback not in autocommit"));
            }
        }
        // No N2 SQL follows this observation. Pool housekeeping is SQLx-owned.
        drop(self.lease.take());
        self.phase = PeerReadPhase::Acknowledged;
        #[cfg(test)]
        self.checkpoint(TestStage::Settled).await;
        Ok(())
    }
    fn into_settled(mut self) -> PeerResult<SettledPeerRead> {
        if let Some(refusal) = self.refusal.take() {
            return Err(refusal);
        }
        let facts = self
            .facts
            .take()
            .ok_or_else(|| unavailable("native peer facts absent"))?;
        let ownership = self.ownership.take().unwrap();
        self.phase = PeerReadPhase::Consumed;
        Ok(SettledPeerRead { ownership, facts })
    }
    #[cfg(test)]
    async fn checkpoint(&mut self, stage: TestStage) {
        let probe = self.ownership.as_ref().unwrap().probe.clone();
        if let Some(probe) = probe {
            if let Some((at, worker)) = &probe.worker {
                if *at == stage {
                    // Test instrumentation also arms custody before lock_handle.
                    self.phase = PeerReadPhase::DriverPending;
                    worker.arm(self.lease.as_mut().unwrap()).await;
                }
            }
            probe.at(stage).await;
        }
    }
}
struct SettledPeerRead {
    ownership: PeerReadOwnership,
    facts: NativePeerFacts,
}
impl SettledPeerRead {
    fn consume(self) -> PeerResult<PeerReadReply> {
        let o = &self.ownership;
        // The configured admission and its returned lease have external code.
        // Snapshot the ops-protected basis, then release ALL synchronous locks
        // before invoking it. Facts still belong to this exact T2 operation.
        let basis = if matches!(&o.request, PeerReadRequest::Apply { .. }) {
            let _serial = lock(&o.owner.kernel_lifecycle.serial);
            o.validate_maps()?;
            ensure_available(&o.db).map_err(unavailable)?;
            let state = o.room.state();
            o.validate_state(&state)?;
            Some((state.base.clone(), state.epoch(), state.versioned_epoch))
        } else {
            None
        };
        // Declare BEFORE final locks: every early-return/unwind releases those
        // locks before an unused lease's potentially reentrant destructor.
        let mut dirty = if basis.is_some() {
            admit_dirty_write(&o.db)?
        } else {
            None
        };
        let _serial = lock(&o.owner.kernel_lifecycle.serial);
        o.validate_maps()?; // SERVICE/maps released before State; never reverse this order.
        ensure_available(&o.db).map_err(unavailable)?;
        let mut state = o.room.state();
        o.validate_state(&state)?;
        if let Some((base, epoch, versioned_epoch)) = &basis {
            if state.base != *base
                || state.epoch() != *epoch
                || state.versioned_epoch != *versioned_epoch
            {
                return Err(unavailable(
                    "native peer basis changed during dirty admission",
                ));
            }
        }
        // No external callback/await from this final validation to mutation.
        match &o.request {
            PeerReadRequest::Sync { state_vector } => {
                let empty = yrs::StateVector::default().encode_v1();
                let since = if state_vector.is_empty() {
                    &empty[..]
                } else {
                    state_vector
                };
                let answer = state.registry.encode_diff(&state.session, since);
                Ok(PeerReadReply::Sync(answer))
            }
            PeerReadRequest::Apply { update_id, update } => {
                if o.origin.mode != PeerKind::Edit {
                    return Err(Refused::new(
                        RefusalCode::Forbidden,
                        "view-mode peers cannot author updates",
                    ));
                }
                let before = state.epoch();
                let session = state.session.clone();
                let author = Author {
                    contributor: self.facts.contributor().clone(),
                    kind: author_for(&o.caller).kind,
                };
                let ack = state.registry.apply_update_attributed(
                    &session,
                    &o.origin.peer.peer,
                    update,
                    &author.contributor,
                )?;
                let advanced = state.epoch() != before;
                if advanced {
                    let entry = state.peers.get_mut(&o.origin.peer.peer).unwrap();
                    entry.caller = o.caller.clone();
                    entry.author = author.clone();
                    state
                        .callers
                        .insert(o.origin.credential.clone(), o.caller.clone());
                    if state.dirty() && state.dirty_admission.is_none() {
                        state.dirty_admission = dirty.take();
                    }
                }
                state.last_op = Instant::now();
                let start_timer = advanced && state.dirty() && !state.idle_timer;
                if start_timer {
                    state.idle_timer = true;
                }
                drop(state);
                drop(_serial);
                drop(dirty); // Unused/no-op lease destruction outside all locks.
                o.room.emit(SessionEvent::Remote {
                    update: Arc::new(ack.broadcast),
                    origin: Some(o.origin.peer.peer.clone()),
                    from: author,
                });
                if start_timer {
                    spawn_idle_loop(Arc::clone(&o.room));
                }
                Ok(PeerReadReply::Apply(Ok(PeerAck {
                    update_id: update_id.clone(),
                    clock: ack.state_vector,
                })))
            }
        }
    }
}
async fn run_owned(request: OwnedPeerReadRequest) -> Result<PeerReadReply> {
    let OwnedPeerReadRequest {
        origin,
        db,
        owner,
        caller,
        request,
        #[cfg(test)]
        probe,
    } = request;
    #[cfg(test)]
    if let Some(p) = &probe {
        p.launches.fetch_add(1, Ordering::SeqCst);
    }
    let room = Arc::clone(&origin.peer.session);
    let gate = acquire_read_gate(&db, &owner).await?;
    let ops = acquire_peer_ops(&room)
        .await
        .map_err(|e| Error::engine(e.to_string()))?;
    let slot = OWNED_JOB_SLOT.with(Arc::clone);
    let ownership = PeerReadOwnership {
        db,
        owner,
        room,
        origin,
        request,
        caller,
        _ops: ops,
        _gate: gate,
        slot,
        #[cfg(test)]
        probe,
    };
    ownership
        .validate_maps()
        .map_err(|e| Error::engine(e.to_string()))?;
    {
        let state = ownership.room.state();
        ownership
            .validate_state(&state)
            .map_err(|e| Error::engine(e.to_string()))?;
    }
    let mut read = PeerReadGuard::new(ownership);
    read.checkout().await?;
    read.begin_deferred().await?;
    read.read_facts().await;
    read.settle().await?;
    let is_apply = matches!(
        &read.ownership.as_ref().unwrap().request,
        PeerReadRequest::Apply { .. }
    );
    let answer = read.into_settled().and_then(SettledPeerRead::consume);
    Ok(match answer {
        Ok(reply) => reply,
        Err(e) if is_apply => PeerReadReply::Apply(Err(e)),
        Err(e) => PeerReadReply::Sync(Err(e)),
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestStage {
    Checkout,
    LeaseReady,
    Begun,
    Facts,
    Settling,
    Settled,
}
#[cfg(test)]
struct TestProbe {
    clones: std::sync::atomic::AtomicUsize,
    launches: std::sync::atomic::AtomicUsize,
    checkouts: std::sync::atomic::AtomicUsize,
    acquisitions: std::sync::atomic::AtomicU64,
    pause: Option<TestStage>,
    worker: Option<(TestStage, Arc<WorkerBarrier>)>,
    // Keeps the real directory alive through owned pending/quarantined reads.
    fixture_owner: Option<Arc<crate::v1_import::NativePeerAdoptedAppFixture>>,
    // New M1 fixture scopes also root inactive opener jobs before submission.
    fixture_registration: Option<Box<dyn Send + Sync>>,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
#[cfg(test)]
impl TestProbe {
    fn new(pause: Option<TestStage>) -> Arc<Self> {
        Arc::new(Self {
            clones: 0.into(),
            launches: 0.into(),
            checkouts: 0.into(),
            acquisitions: 0.into(),
            pause,
            worker: None,
            fixture_owner: None,
            fixture_registration: None,
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        })
    }
    async fn at(&self, stage: TestStage) {
        if stage == TestStage::Checkout {
            self.checkouts.fetch_add(1, Ordering::SeqCst);
        }
        if self.pause == Some(stage) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
    }
}
#[cfg(test)]
tokio::task_local! { static TEST_PROBE: Arc<TestProbe>; }
#[cfg(test)]
fn capture_probe() -> Option<Arc<TestProbe>> {
    TEST_PROBE
        .try_with(|p| {
            p.clones.fetch_add(1, Ordering::SeqCst);
            Arc::clone(p)
        })
        .ok()
}
#[cfg(test)]
#[path = "kernel_peer_reads_tests.rs"]
mod tests;

#[cfg(test)]
struct WorkerBarrier {
    released: Arc<(StdMutex<bool>, std::sync::Condvar)>,
    entered: Arc<tokio::sync::Notify>,
    handle: std::sync::atomic::AtomicUsize,
    interrupt: bool,
}
#[cfg(test)]
impl WorkerBarrier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            released: Arc::new((StdMutex::new(false), std::sync::Condvar::new())),
            entered: Arc::new(tokio::sync::Notify::new()),
            handle: 0.into(),
            interrupt: false,
        })
    }
    async fn arm(&self, conn: &mut SqliteConnection) {
        let mut handle = conn.lock_handle().await.unwrap();
        self.handle
            .store(handle.as_raw_handle().as_ptr() as usize, Ordering::SeqCst);
        let released = Arc::clone(&self.released);
        let entered = Arc::clone(&self.entered);
        let interrupt = self.interrupt;
        handle.set_progress_handler(1, move || {
            entered.notify_one();
            let (mutex, wake) = &*released;
            let mut done = lock(mutex);
            while !*done {
                done = wake
                    .wait(done)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            !interrupt
        });
    }
    fn release(&self) {
        let (mutex, wake) = &*self.released;
        *lock(mutex) = true;
        wake.notify_all();
    }
}
// A test must keep this external guard outside the owner it destroys.
#[cfg(test)]
struct ReleaseWorker(Arc<WorkerBarrier>);
#[cfg(test)]
impl Drop for ReleaseWorker {
    fn drop(&mut self) {
        self.0.release();
    }
}
