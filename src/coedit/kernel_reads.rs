//! Inactive snapshot-linearized current-body observation. No read authority.
use super::*;
use crate::coedit::backend::SessionBackend;
use crate::kernel::body_evidence::{BodyEventEvidence, NativeBodyBasis};
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CurrentReadRefusal {
    Deadline,
    ChangedBasis,
    ForeignHandle,
    ForeignOwner,
    ClosedOrRetained,
    Sealed,
    Quarantined,
    MissingEvidence,
    ResponseBudget,
}
impl From<CurrentReadRefusal> for crate::Error {
    fn from(value: CurrentReadRefusal) -> Self {
        crate::Error::engine(format!("current body read unavailable: {value:?}"))
    }
}
type ReadResult<T> = std::result::Result<T, CurrentReadRefusal>;

fn available(owner: &DbSessions) -> ReadResult<()> {
    if *owner.kernel_quarantine.borrow() {
        return Err(CurrentReadRefusal::Quarantined);
    }
    if *owner.kernel_lifecycle.sealed.borrow() {
        return Err(CurrentReadRefusal::Sealed);
    }
    Ok(())
}
async fn bounded<T>(
    owner: &DbSessions,
    deadline: Instant,
    work: impl Future<Output = T>,
    db: &Db,
    _stage: ReadStage,
) -> ReadResult<T> {
    let mut quarantine = owner.kernel_quarantine.subscribe();
    let mut sealed = owner.kernel_lifecycle.sealed.subscribe();
    available(owner)?;
    if Instant::now() >= deadline {
        return Err(CurrentReadRefusal::Deadline);
    }
    tokio::pin!(work);
    #[cfg(test)]
    match futures::poll!(work.as_mut()) {
        std::task::Poll::Ready(value) => {
            available(owner)?;
            if Instant::now() >= deadline {
                return Err(CurrentReadRefusal::Deadline);
            }
            return Ok(value);
        }
        std::task::Poll::Pending => checkpoint(db, _stage).await,
    }
    #[cfg(not(test))]
    let _ = db;
    let result = tokio::select! {
        biased;
        _ = quarantine.changed() => return Err(CurrentReadRefusal::Quarantined),
        _ = sealed.changed() => return Err(CurrentReadRefusal::Sealed),
        result = tokio::time::timeout_at(deadline, work.as_mut()) => result.map_err(|_| CurrentReadRefusal::Deadline)?,
    };
    available(owner)?;
    if Instant::now() >= deadline {
        return Err(CurrentReadRefusal::Deadline);
    }
    Ok(result)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Coordinates {
    session: SessionId,
    epoch: u64,
    versioned_epoch: u64,
    digest: String,
    committed_digest: String,
    committed_event: Option<BodyEventEvidence>,
}
fn coordinates(state: &State) -> ReadResult<(Coordinates, String)> {
    if state.closed
        || state.scope_change
        || state.pending_recheck
        || state.kernel_finalization_blocked
    {
        return Err(CurrentReadRefusal::ClosedOrRetained);
    }
    let (body, epoch) = state
        .registry
        .acknowledged_body(&state.session)
        .map_err(|_| CurrentReadRefusal::MissingEvidence)?;
    if state.versioned_epoch > epoch {
        return Err(CurrentReadRefusal::MissingEvidence);
    }
    let committed_event = match (
        &state.base.proof.body_event_id,
        state.base.proof.body_event_seq,
    ) {
        (None, None) => None,
        (Some(id), Some(seq)) if !id.is_empty() && seq > 0 => Some(BodyEventEvidence {
            id: id.clone(),
            seq,
        }),
        _ => return Err(CurrentReadRefusal::MissingEvidence),
    };
    Ok((
        Coordinates {
            session: state.session.clone(),
            epoch,
            versioned_epoch: state.versioned_epoch,
            digest: sha256_hex(&body),
            committed_digest: state.base.body_sha256.clone(),
            committed_event,
        },
        body,
    ))
}
struct CapturedRecord {
    id: String,
    room: Option<Arc<LiveSession>>,
    observation: ReadResult<Option<Coordinates>>,
}
pub(crate) struct CurrentBodyFence {
    db: Db,
    owner: Arc<DbSessions>,
    // ONE guard for the entire batch, held through acknowledged SQL close/T3.
    _publication: OwnedRwLockReadGuard<()>,
    records: Vec<CapturedRecord>,
    deadline: Instant,
}
#[derive(Debug)]
pub(crate) struct ValidatedBodyObservation {
    pub record_id: String,
    pub live: Option<ValidatedLiveBody>,
}
#[derive(Debug)]
pub(crate) struct ValidatedLiveBody {
    pub body: String,
    pub digest: String,
    pub session: String,
    pub epoch: u64,
    pub dirty: bool,
    /// T3 diagnostic only, never T2 native snapshot authority.
    pub room_state: &'static str,
}

pub(crate) async fn capture_current_bodies(
    db: &Db,
    ids: &[String],
    deadline: Instant,
) -> ReadResult<CurrentBodyFence> {
    let owner = db_sessions(db);
    let publication = bounded(
        &owner,
        deadline,
        Arc::clone(&owner.open_gate).read_owned(),
        db,
        ReadStage::Publication,
    )
    .await?;
    let mut records = Vec::with_capacity(ids.len());
    for id in ids {
        let room = lock(&owner.records).get(id).cloned();
        let observation = if let Some(room) = &room {
            if room.backend != SessionBackend::KernelV2 {
                Err(CurrentReadRefusal::ForeignOwner)
            } else if !room
                .kernel_origin
                .as_ref()
                .is_some_and(|origin| origin.same_handle(db))
            {
                Err(CurrentReadRefusal::ForeignHandle)
            } else {
                let _ops = bounded(
                    &owner,
                    deadline,
                    Arc::clone(&room.ops).lock_owned(),
                    db,
                    ReadStage::CaptureOps,
                )
                .await?;
                // Retain coordinates, not hidden live text. The T3 text is
                // extracted again under ops after T2 visibility admission.
                coordinates(&room.state()).map(|(coordinates, _)| Some(coordinates))
            }
        } else {
            Ok(None)
        };
        records.push(CapturedRecord {
            id: id.clone(),
            room,
            observation,
        });
        #[cfg(test)]
        checkpoint(db, ReadStage::RecordCaptured).await;
    }
    Ok(CurrentBodyFence {
        db: db.clone(),
        owner,
        _publication: publication,
        records,
        deadline,
    })
}
impl CurrentBodyFence {
    pub(crate) fn has_room(&self, id: &str) -> bool {
        self.records.iter().any(|r| r.id == id && r.room.is_some())
    }
    pub(crate) async fn validate(
        self,
        db: &Db,
        bases: &[NativeBodyBasis],
    ) -> ReadResult<Vec<ValidatedBodyObservation>> {
        if !self.db.same_handle(db) {
            return Err(CurrentReadRefusal::ForeignHandle);
        }
        if !existing_db_sessions(db).is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner)) {
            return Err(CurrentReadRefusal::ForeignOwner);
        }
        available(&self.owner)?;
        let mut validated = Vec::with_capacity(bases.len());
        let mut retained_live_bytes = 0usize;
        for basis in bases {
            let record = self
                .records
                .iter()
                .find(|r| r.id == basis.record_id)
                .ok_or(CurrentReadRefusal::MissingEvidence)?;
            let captured = record.observation.as_ref().map_err(|r| *r)?;
            let current_room = lock(&self.owner.records).get(&record.id).cloned();
            let live = match (&record.room, current_room, captured) {
                (None, None, None) => None,
                (Some(room), Some(current), Some(before)) if Arc::ptr_eq(room, &current) => {
                    if !room
                        .kernel_origin
                        .as_ref()
                        .is_some_and(|origin| origin.same_handle(db))
                    {
                        return Err(CurrentReadRefusal::ForeignHandle);
                    }
                    let _ops = bounded(
                        &self.owner,
                        self.deadline,
                        Arc::clone(&room.ops).lock_owned(),
                        db,
                        ReadStage::ValidateOps,
                    )
                    .await?;
                    available(&self.owner)?;
                    let state = room.state();
                    let (after, body) = coordinates(&state)?;
                    if &after != before
                        || after.committed_event != basis.event
                        || after.committed_digest != basis.digest
                        || after.committed_event.is_some() != basis.body.is_some()
                    {
                        return Err(CurrentReadRefusal::ChangedBasis);
                    }
                    retained_live_bytes = retained_live_bytes
                        .checked_add(body.len())
                        .ok_or(CurrentReadRefusal::ResponseBudget)?;
                    if retained_live_bytes > crate::query::sql_contract::MAX_RESULT_ENCODED_BYTES {
                        return Err(CurrentReadRefusal::ResponseBudget);
                    }
                    Some(ValidatedLiveBody {
                        body,
                        digest: after.digest,
                        session: after.session.0,
                        epoch: after.epoch,
                        dirty: after.epoch != after.versioned_epoch,
                        room_state: if state.peers.is_empty() {
                            "grace"
                        } else {
                            "active"
                        },
                    })
                }
                _ => return Err(CurrentReadRefusal::ChangedBasis),
            };
            validated.push(ValidatedBodyObservation {
                record_id: basis.record_id.clone(),
                live,
            });
        }
        available(&self.owner)?;
        Ok(validated)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReadStage {
    #[cfg(test)]
    RecordCaptured,
    Publication,
    CaptureOps,
    ValidateOps,
}
#[cfg(test)]
pub(crate) struct Gate {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}
#[cfg(test)]
type ReadGates = HashMap<(PathBuf, ReadStage), Arc<Gate>>;
#[cfg(test)]
static READ_GATES: std::sync::LazyLock<StdMutex<ReadGates>> =
    std::sync::LazyLock::new(|| StdMutex::new(ReadGates::new()));
#[cfg(test)]
pub(crate) fn gate(db: &Db, stage: ReadStage) -> Arc<Gate> {
    let gate = Arc::new(Gate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    lock(&READ_GATES).insert((session_key(db), stage), gate.clone());
    gate
}
#[cfg(test)]
async fn checkpoint(db: &Db, stage: ReadStage) {
    let gate = lock(&READ_GATES).remove(&(session_key(db), stage));
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
}

/// Read actual accepted/versioned coordinates through the same fallible State
/// observation as T1/T3. Test-only; no mutation, authority or wire fields.
#[cfg(test)]
pub(crate) fn observed_epochs_for_test(db: &Db, record: &str) -> ReadResult<(u64, u64)> {
    let room = existing_session(db, record).ok_or(CurrentReadRefusal::MissingEvidence)?;
    let state = room.state();
    let (observed, _) = coordinates(&state)?;
    Ok((observed.epoch, observed.versioned_epoch))
}

#[cfg(test)]
pub(crate) fn finalization_blocked_for_test(db: &Db, record: &str) -> Option<bool> {
    existing_session(db, record).map(|room| room.state().kernel_finalization_blocked)
}

#[cfg(test)]
pub(crate) async fn expire_clean_for_test(db: &Db, record: &str) {
    let room = existing_session(db, record).unwrap();
    {
        let mut state = room.state();
        assert!(state.peers.is_empty());
        assert!(!state.dirty());
        state.grace_until = Some(Instant::now());
    }
    let result = super::kernel_lifecycle::finalize(
        db.clone(),
        super::kernel_lifecycle::Target::new(db, room),
        super::kernel_lifecycle::Intent::GraceExpire,
        "explicit clean test expiry".into(),
        None,
    )
    .await;
    assert!(matches!(result, super::kernel_lifecycle::Outcome::Clean));
}

#[cfg(test)]
pub(crate) struct TestPublicationHold {
    _owner: Arc<DbSessions>,
    _gate: tokio::sync::OwnedRwLockWriteGuard<()>,
}
#[cfg(test)]
pub(crate) async fn hold_publication_for_test(db: &Db) -> TestPublicationHold {
    let owner = db_sessions(db);
    let gate = owner.open_gate.clone().write_owned().await;
    TestPublicationHold {
        _owner: owner,
        _gate: gate,
    }
}

/// FAILURE INJECTION ONLY: an actual separately seeded native Arc is placed in
/// a foreign V1 map. This is intentionally invalid custody, never valid seed,
/// owner, authority, migration or physical-generation evidence.
#[cfg(test)]
pub(crate) struct ForeignRoomInjection {
    destination: Arc<DbSessions>,
    key: String,
    room: Arc<LiveSession>,
    owner: Arc<DbSessions>,
    origin: Db,
    current_db: Db,
    session: SessionId,
}
#[cfg(test)]
pub(crate) fn inject_foreign_native_room_for_test(
    destination: &Db,
    key: &str,
    source: &Db,
    source_id: &str,
) -> ForeignRoomInjection {
    let room = existing_session(source, source_id).unwrap();
    assert_eq!(room.backend, SessionBackend::KernelV2);
    let owner = room.owner.upgrade().unwrap();
    let origin = room.kernel_origin.as_ref().unwrap().clone();
    assert!(origin.same_handle(source));
    let (current_db, session) = {
        let state = room.state();
        (state.db.clone(), state.session.clone())
    };
    let destination = db_sessions(destination);
    {
        let mut rooms = lock(&destination.records);
        assert!(!rooms.contains_key(key));
        rooms.insert(key.to_owned(), room.clone());
    }
    ForeignRoomInjection {
        destination,
        key: key.into(),
        room,
        owner,
        origin,
        current_db,
        session,
    }
}
#[cfg(test)]
impl ForeignRoomInjection {
    pub(crate) fn native_identity_unchanged(&self) -> bool {
        let registered = lock(&self.owner.records).get(&self.room.record_id).cloned();
        if !registered.is_some_and(|room| Arc::ptr_eq(&room, &self.room))
            || !self
                .room
                .owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, &self.owner))
            || !self
                .room
                .kernel_origin
                .as_ref()
                .is_some_and(|origin| origin.same_handle(&self.origin))
        {
            return false;
        }
        let state = self.room.state();
        state.db.same_handle(&self.current_db) && state.session == self.session
    }
}
#[cfg(test)]
impl Drop for ForeignRoomInjection {
    fn drop(&mut self) {
        let mut rooms = lock(&self.destination.records);
        if rooms
            .get(&self.key)
            .is_some_and(|room| Arc::ptr_eq(room, &self.room))
        {
            rooms.remove(&self.key);
        }
    }
}

#[cfg(test)]
pub(crate) async fn cut_for_test(db: &Db, record: &str, reason: &str) -> crate::Result<()> {
    let room = existing_session(db, record).unwrap();
    // Same native lifecycle entry as SessionPeer::version; actual stored
    // contributor Callers must still pass its ordinary current author checks.
    super::kernel_lifecycle::cut_room(db.clone(), room, reason.into(), None)
        .await
        .map(|_| ())
        .map_err(|error| crate::Error::engine(error.to_string()))
}
