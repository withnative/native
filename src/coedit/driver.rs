//! Inactive stage-1 engine consumer. No transport, app adoption or public ingress.
//!
//! Only enrolled physical-generation owners hold this state. Every command runs
//! in their retained Document lane, including auth, live mutation, commit and
//! ledger completion. IDs are provisional in-memory leases. Automatic cuts,
//! durable leases/hedge, requested-cut coalescing and adopted-app admission
//! remain release blockers. This is not the completed S2/S3-ready lifecycle.
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use super::{
    AcknowledgedContributor, DrainOutcome, OpenOk, OpenParams, PeerId, PeerKind, SessionId,
    SessionRegistry,
};
use crate::authorization::Capability;
use crate::db::{enrolled::ExecutionOwner, Db};
use crate::mcp::Caller;
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct PeerHandle {
    generation: String,
    record: String,
    session: SessionId,
    peer: PeerId,
}

/// No deserialization or public unrestricted submission. All fields are owned.
#[derive(Debug)]
pub(crate) enum Command {
    Open {
        record: String,
        mode: PeerKind,
    },
    Update {
        peer: PeerHandle,
        bytes: Vec<u8>,
    },
    Sync {
        peer: PeerHandle,
        vector: Vec<u8>,
    },
    Version {
        peer: PeerHandle,
        reason: String,
        request: Uuid,
    },
    Leave {
        peer: PeerHandle,
    },
}
impl Command {
    fn purpose(&self) -> (&'static str, Value) {
        match self {
            Self::Open { record, mode } => (
                "session.open",
                json!({"record_id": record, "mode": match mode { PeerKind::Edit => "edit", PeerKind::View => "view" }}),
            ),
            Self::Update { peer, bytes } => (
                "session.update",
                json!({"record_id": peer.record, "session":peer.session.0, "peer":peer.peer.0, "update":bytes}),
            ),
            Self::Sync { peer, vector } => (
                "session.sync",
                json!({"record_id":peer.record, "session":peer.session.0, "peer":peer.peer.0, "vector":vector}),
            ),
            Self::Version {
                peer,
                reason,
                request,
            } => (
                "session.version",
                json!({"record_id":peer.record, "session":peer.session.0, "peer":peer.peer.0, "reason":reason, "command_id":request.to_string()}),
            ),
            Self::Leave { peer } => (
                "session.close",
                json!({"record_id":peer.record, "session":peer.session.0, "peer":peer.peer.0}),
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Reply {
    Opened { peer: PeerHandle, state: OpenOk },
    Updated(super::Ack),
    Synced(Vec<u8>),
    Versioned(Value),
    Left,
}

/// Only submit can mint this after exact-purpose identity/storage admission.
/// The enrolled runner accepts this closed value rather than a Caller/future.
pub(crate) struct AdmittedCommand {
    owner: Arc<ExecutionOwner>,
    caller: Caller,
    command: Command,
}

/// Purpose-bound snapshot minted under the owner's lane after current Edit.
/// Other crate modules can inspect it but cannot substitute a record, identity,
/// reason or core snapshot at the private lifecycle consumer.
pub(crate) struct CutSnapshot {
    owner: Arc<ExecutionOwner>,
    record: String,
    principal: String,
    reason: String,
    snapshot: super::VersionSnapshot,
}
impl CutSnapshot {
    pub(crate) fn validate(&self, db: &Db, caller: &Caller) -> Result<()> {
        let owner = db.coedit_owner()?;
        if !Arc::ptr_eq(&owner, &self.owner) || caller.credential() != self.principal {
            return Err(Error::engine("session snapshot authority mismatch"));
        }
        let state = owner
            .sessions
            .lock()
            .map_err(|_| Error::engine("session state poisoned"))?;
        if !state
            .rooms
            .get(&self.record)
            .is_some_and(|room| room.session == *self.snapshot.session_id() && !room.unresolved)
        {
            return Err(Error::engine("session snapshot incarnation unavailable"));
        }
        Ok(())
    }
    pub(crate) fn record(&self) -> &str {
        &self.record
    }
    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
    pub(crate) fn snapshot(&self) -> &super::VersionSnapshot {
        &self.snapshot
    }
}

struct BoundPeer {
    principal: String,
    mode: PeerKind,
}
struct Completion {
    principal: String,
    peer: PeerId,
    reason: String,
    receipt: Value,
}
struct Room {
    session: SessionId,
    peers: HashMap<PeerId, BoundPeer>,
    dirty: bool,
    unresolved: bool,
    // Bounded immutable completions; a lost waiter can retry its exact ID.
    completion: HashMap<Uuid, Completion>,
}
#[derive(Default)]
pub(crate) struct DriverState {
    registry: SessionRegistry,
    rooms: HashMap<String, Room>,
}
impl std::fmt::Debug for DriverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverState")
            .field("rooms", &self.rooms.len())
            .field("unsaved", &self.has_unsaved())
            .finish()
    }
}
impl DriverState {
    pub(crate) fn has_unsaved(&self) -> bool {
        self.rooms.values().any(|r| r.dirty || r.unresolved)
    }
    fn bound(
        &self,
        owner: &ExecutionOwner,
        caller: &Caller,
        peer: &PeerHandle,
        edit: bool,
    ) -> Result<()> {
        let room = self
            .rooms
            .get(&peer.record)
            .ok_or_else(|| Error::engine("session peer unavailable"))?;
        let bound = room
            .peers
            .get(&peer.peer)
            .ok_or_else(|| Error::engine("session peer unavailable"))?;
        if peer.generation != owner.generation
            || room.session != peer.session
            || bound.principal != caller.credential()
            || (edit && bound.mode != PeerKind::Edit)
        {
            return Err(Error::engine("session peer authority mismatch"));
        }
        if room.unresolved {
            return Err(Error::engine(
                "session completion unresolved; reconciliation required",
            ));
        }
        Ok(())
    }
}

/// Make a new exact-purpose dispatch from the actual authenticated Caller.
/// Existing request annotations and storage/deployment admissions are retained
/// by session_job. A receipt for another action fails identity admission here.
pub(crate) async fn submit(db: Db, caller: Caller, command: Command) -> Result<Reply> {
    if caller.is_trusted_local() {
        return Err(Error::engine(
            "session driver requires an authenticated Caller",
        ));
    }
    let owner = db.coedit_owner()?;
    let (purpose, arguments) = command.purpose();
    let dispatch =
        crate::provenance::ProvenanceDispatch::from_caller(&caller, purpose, &arguments, None);
    let admission_db = db.clone();
    crate::storage_profile::with_operation(
        &admission_db,
        purpose,
        Some("native.domain-mcp.v1"),
        dispatch.scope(async move {
            crate::provenance::reserve_action_attestation()?.executor_identity_snapshot()?;
            crate::db::enrolled::session_job(
                db,
                AdmittedCommand {
                    owner,
                    caller,
                    command,
                },
            )
            .await
        }),
    )
    .await
}

/// Called only by the retained runner under the shared owner lane.
pub(crate) async fn execute(db: Db, admitted: AdmittedCommand) -> Result<Reply> {
    let AdmittedCommand {
        owner,
        caller,
        command,
    } = admitted;
    if !Arc::ptr_eq(&owner, &db.coedit_owner()?) || caller.is_trusted_local() {
        return Err(Error::engine("session command owner or Caller mismatch"));
    }
    let (purpose, _) = command.purpose();
    match command {
        Command::Open { record, mode } => {
            let mut tx = crate::db::enrolled::begin_document_write(&db).await?;
            let loaded =
                authorize_supported(&mut tx, &caller, purpose, &record, capability(mode)).await;
            tx.rollback().await?;
            let body = loaded?;
            let mut state = owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?;
            if state.rooms.get(&record).is_some_and(|room| room.unresolved) {
                return Err(Error::engine(
                    "session completion unresolved; cannot reopen",
                ));
            }
            let opened = state
                .registry
                .open(OpenParams {
                    database_id: owner.generation.clone(),
                    record_id: record.clone(),
                    committed_body: body,
                    kind: mode,
                    record_supported: true,
                })
                .map_err(refused)?;
            let room = state.rooms.entry(record.clone()).or_insert_with(|| Room {
                session: opened.session_id.clone(),
                peers: HashMap::new(),
                dirty: false,
                unresolved: false,
                completion: HashMap::new(),
            });
            room.peers.insert(
                opened.peer_id.clone(),
                BoundPeer {
                    principal: caller.credential().into(),
                    mode,
                },
            );
            Ok(Reply::Opened {
                peer: PeerHandle {
                    generation: owner.generation.clone(),
                    record,
                    session: opened.session_id.clone(),
                    peer: opened.peer_id.clone(),
                },
                state: opened,
            })
        }
        Command::Update { peer, bytes } => {
            authorize_peer(&db, &owner, &caller, purpose, &peer, true).await?;
            let identity =
                crate::provenance::reserve_action_attestation()?.executor_identity_snapshot()?;
            let contributor = AcknowledgedContributor {
                principal: identity.principal().into(),
                executor_kind: identity.executor_kind().into(),
            };
            let mut state = owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?;
            if state
                .rooms
                .get(&peer.record)
                .expect("bound room")
                .completion
                .len()
                >= 128
            {
                return Err(Error::engine(
                    "stage-1 session completion capacity exhausted; update refused",
                ));
            }
            let before = state
                .registry
                .mutation_epoch(&peer.session)
                .map_err(refused)?;
            let ack = state
                .registry
                .apply_update_attributed(&peer.session, &peer.peer, &bytes, &contributor)
                .map_err(refused)?;
            // State vectors omit delete-only changes; body text also omits
            // net-zero authored changes. The core epoch covers both exactly.
            if before
                != state
                    .registry
                    .mutation_epoch(&peer.session)
                    .map_err(refused)?
            {
                state.rooms.get_mut(&peer.record).expect("bound room").dirty = true;
            }
            Ok(Reply::Updated(ack))
        }
        Command::Sync { peer, vector } => {
            authorize_peer(&db, &owner, &caller, purpose, &peer, false).await?;
            let state = owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?;
            Ok(Reply::Synced(
                state
                    .registry
                    .encode_diff(&peer.session, &vector)
                    .map_err(refused)?,
            ))
        }
        Command::Version {
            peer,
            reason,
            request,
        } => {
            let mut tx = crate::db::enrolled::begin_document_write(&db).await?;
            let authorized =
                authorize_supported(&mut tx, &caller, purpose, &peer.record, Capability::Edit)
                    .await;
            if let Err(error) = authorized {
                tx.rollback().await?;
                return Err(error);
            }
            let snapshot_result = (|| -> Result<_> {
                let state = owner
                    .sessions
                    .lock()
                    .map_err(|_| Error::engine("session state poisoned"))?;
                state.bound(&owner, &caller, &peer, true)?;
                crate::mcp::tools::require_nonblank_reason(purpose, &reason)?;
                let room = state.rooms.get(&peer.record).expect("bound room");
                if let Some(completed) = room.completion.get(&request) {
                    if completed.reason != reason
                        || completed.principal != caller.credential()
                        || completed.peer != peer.peer
                    {
                        return Err(Error::engine(
                            "session command identity reused with different reason",
                        ));
                    }
                    return Ok(Err(completed.receipt.clone()));
                }
                if room.completion.len() >= 128 {
                    return Err(Error::engine(
                        "stage-1 session completion capacity exhausted",
                    ));
                }
                Ok(Ok(state
                    .registry
                    .version_snapshot(&peer.session)
                    .map_err(refused)?))
            })();
            let snapshot = match snapshot_result {
                Ok(Ok(snapshot)) => snapshot,
                Ok(Err(receipt)) => {
                    tx.rollback().await?;
                    return Ok(Reply::Versioned(receipt));
                }
                Err(error) => {
                    tx.rollback().await?;
                    return Err(error);
                }
            };
            let cut = CutSnapshot {
                owner: owner.clone(),
                record: peer.record.clone(),
                principal: caller.credential().into(),
                reason: reason.clone(),
                snapshot,
            };
            let prepared =
                crate::mcp::tools::lifecycle::prepare_session_version(&db, &caller, &cut, tx)
                    .await?;
            // No state mutation can interleave while the runner holds the lane.
            // Mark uncertainty BEFORE commit. Even a commit error must not allow
            // blind append retries. A known pre-commit failure rolled back above.
            owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?
                .rooms
                .get_mut(&peer.record)
                .expect("bound room")
                .unresolved = true;
            if let Err(error) = db.commit_content(prepared.tx).await {
                db.poison_enrolled_execution();
                return Err(error);
            }
            #[cfg(test)]
            if let Err(error) = fail_at(TestFault::AfterCommit) {
                db.poison_enrolled_execution();
                return Err(error);
            }
            let receipt = prepared.receipt;
            let mut state = owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?;
            if !matches!(
                state.registry.drain_version_snapshot(cut.snapshot()),
                Ok(DrainOutcome::Drained)
            ) {
                db.poison_enrolled_execution();
                return Err(Error::engine(
                    "committed session snapshot could not drain; do not retry",
                ));
            }
            let room = state.rooms.get_mut(&peer.record).expect("bound room");
            room.dirty = false;
            room.unresolved = false;
            room.completion.insert(
                request,
                Completion {
                    principal: caller.credential().into(),
                    peer: peer.peer.clone(),
                    reason,
                    receipt: receipt.clone(),
                },
            );
            Ok(Reply::Versioned(receipt))
        }
        Command::Leave { peer } => {
            // A caller may leave after access loss; identity binding still
            // applies, and this operation discloses no text or peer presence.
            let mut state = owner
                .sessions
                .lock()
                .map_err(|_| Error::engine("session state poisoned"))?;
            state.bound(&owner, &caller, &peer, false)?;
            let room = state.rooms.get(&peer.record).expect("bound room");
            let last_editor = room.peers[&peer.peer].mode == PeerKind::Edit
                && room
                    .peers
                    .values()
                    .filter(|p| p.mode == PeerKind::Edit)
                    .count()
                    == 1;
            if room.dirty && (last_editor || room.peers.len() == 1) {
                return Err(Error::engine(
                    "dirty session close requires explicit version; room retained",
                ));
            }
            state.registry.leave(&peer.session, &peer.peer);
            let room = state.rooms.get_mut(&peer.record).expect("bound room");
            room.peers.remove(&peer.peer);
            if room.peers.is_empty() {
                state.rooms.remove(&peer.record);
            }
            Ok(Reply::Left)
        }
    }
}
fn capability(mode: PeerKind) -> Capability {
    match mode {
        PeerKind::Edit => Capability::Edit,
        PeerKind::View => Capability::View,
    }
}
fn refused(error: super::Refused) -> Error {
    Error::engine(error.to_string())
}

async fn authorize_peer(
    db: &Db,
    owner: &Arc<ExecutionOwner>,
    caller: &Caller,
    purpose: &str,
    peer: &PeerHandle,
    edit: bool,
) -> Result<()> {
    let mut tx = crate::db::enrolled::begin_document_write(db).await?;
    let result = authorize_supported(
        &mut tx,
        caller,
        purpose,
        &peer.record,
        if edit {
            Capability::Edit
        } else {
            Capability::View
        },
    )
    .await;
    tx.rollback().await?;
    result?;
    owner
        .sessions
        .lock()
        .map_err(|_| Error::engine("session state poisoned"))?
        .bound(owner, caller, peer, edit)
}

/// Also consumed by the narrow lifecycle version wrapper. Exact enrolled
/// supported tuple, checked after actual record authorization in this tx.
pub(crate) async fn authorize_supported(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    purpose: &str,
    record: &str,
    required: Capability,
) -> Result<String> {
    crate::mcp::tools::require_record_in(tx, caller, purpose, record, required).await?;
    let row = sqlx::query("SELECT type,kind,body,deleted_at,EXISTS(SELECT 1 FROM facet_values WHERE record_id=records.id AND key='runtime') AS runtime_present FROM records WHERE id=?")
        .bind(record).fetch_one(&mut **tx).await?;
    let kind = row.try_get::<Option<String>, _>("kind")?;
    let (artifact, instruction) = if let Some(kind) = kind {
        let resolved = crate::meta::kind::resolve_on(tx, "Document", &kind).await?;
        (
            kind == "artifact"
                || crate::generated::kinds::CoreKind::DocumentArtifact.matches(&resolved),
            kind == "instruction" || resolved.canonical_kind.as_deref() == Some("instruction"),
        )
    } else {
        (false, false)
    };
    if row.try_get::<String, _>("type")? != "Document"
        || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        || row.try_get::<bool, _>("runtime_present")?
        || artifact
        || instruction
    {
        return Err(Error::engine(
            "session requires a live non-artifact, non-instruction Document without runtime",
        ));
    }
    Ok(row
        .try_get::<Option<String>, _>("body")?
        .unwrap_or_default())
}

/// Called ONLY after ordinary target authorization, inside its owned lane.
pub(crate) fn refuse_ordinary_write(db: &Db, record: &str) -> Result<()> {
    if !db.is_enrolled() {
        return Ok(());
    }
    let owner = db.coedit_owner()?;
    if owner
        .sessions
        .lock()
        .map_err(|_| Error::engine("session state poisoned"))?
        .rooms
        .contains_key(record)
    {
        return Err(Error::engine(
            "active session owns this body; ordinary body write refused",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum TestFault {
    AfterAppend,
    AfterCommit,
}
#[cfg(test)]
tokio::task_local! { pub(crate) static TEST_FAULT: TestFault; }
#[cfg(test)]
pub(crate) fn fail_at(fault: TestFault) -> Result<()> {
    if TEST_FAULT
        .try_with(|active| std::mem::discriminant(active) == std::mem::discriminant(&fault))
        .unwrap_or(false)
    {
        Err(Error::engine("injected session completion failure"))
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests;
