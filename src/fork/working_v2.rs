//! Off-default installed working manager internals. The bounded node append/Get
//! route uses this module. The original request identity provider owns admission;
//! this module never derives identity from ambient dispatch state.
#![allow(dead_code)]
pub(crate) mod manager;
pub(super) mod transaction;
use crate::kernel::working_undo_schema::{
    WORKING_APPLIED_DDL as APPLIED_DDL, WORKING_BASES_DDL as BASES_DDL,
    WORKING_PUBLICATION_DDL as PUBLICATION_DDL,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Stable portable namespace, not a bearer credential or browser window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkingBinding {
    pub account_id: String,
    pub database_id: String,
    pub origin_database_id: String,
    pub history_lineage: String,
    pub resource_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
}
impl WorkingBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        if [
            &self.account_id,
            &self.database_id,
            &self.origin_database_id,
            &self.history_lineage,
            &self.resource_origin,
        ]
        .into_iter()
        .any(|s| s.trim().is_empty())
        {
            return Err(Error::engine("working binding is incomplete"));
        }
        Ok(())
    }
}

/// Issued only by the bound owner. This does not discover authentication facts:
/// the existing verified auth/sign-out/account-switch owner supplies the signal.
#[derive(Clone)]
pub(crate) struct BindingControl(watch::Sender<bool>, std::sync::Arc<std::sync::Mutex<()>>);
#[derive(Clone)]
pub(crate) struct BindingGuard(watch::Receiver<bool>, std::sync::Arc<std::sync::Mutex<()>>);
#[derive(Clone, Copy, Debug)]
pub(crate) enum VerifiedCloseReason {
    Revocation,
    SignOut,
    AccountSwitch,
}
impl BindingControl {
    pub(crate) fn new() -> (Self, BindingGuard) {
        let (send, receive) = watch::channel(false);
        let close_fence = std::sync::Arc::new(std::sync::Mutex::new(()));
        (
            Self(send, close_fence.clone()),
            BindingGuard(receive, close_fence),
        )
    }
    pub(crate) fn close(&self, _reason: VerifiedCloseReason) {
        let _fence = self.1.lock().unwrap_or_else(|error| error.into_inner());
        self.0.send_replace(true);
    }
}
impl BindingGuard {
    /// ACK delivery and a confirmed close share one short synchronous fence.
    /// Never hold it across native work or an await; close cannot cancel COMMIT.
    pub(crate) fn while_open<T>(&self, action: impl FnOnce() -> T) -> Result<T> {
        let _fence = self.1.lock().unwrap_or_else(|error| error.into_inner());
        self.check()?;
        Ok(action())
    }

    pub(crate) fn check(&self) -> Result<()> {
        if *self.0.borrow() || self.0.has_changed().is_err() {
            return Err(Error::engine("working binding closed"));
        }
        Ok(())
    }
    pub(crate) async fn closed(&self) {
        let mut receive = self.0.clone();
        let _ = receive.wait_for(|closed| *closed).await;
    }
}

/// Immutable location evidence only. Native authority comes from the fresh
/// verified source and the retained-file audit, never these serialized bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkingLocation {
    pub version: u32,
    pub area: String,
    pub fork: String,
    pub file_identity: [u64; 2],
    pub reservation_bytes: u64,
    pub generation: String,
    pub original_anchor_sha256: String,
}
impl WorkingLocation {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.reservation_bytes == 0
            || [&self.area, &self.fork, &self.generation]
                .into_iter()
                .any(|id| uuid::Uuid::parse_str(id).is_err())
            || self.original_anchor_sha256.len() != 64
            || !self
                .original_anchor_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::engine("invalid retained working location"));
        }
        Ok(())
    }
}

/// Minted only after private resume admission and acknowledged rollback. Its
/// borrow keeps the exclusively owned file capability alive while RO pools open.
pub(crate) struct AuditedWorkingRead<'owner> {
    path: &'owner std::path::Path,
    identity: super::FileIdentity,
}
impl<'owner> AuditedWorkingRead<'owner> {
    fn new(path: &'owner std::path::Path, identity: super::FileIdentity) -> Self {
        Self { path, identity }
    }
    pub(crate) fn checked_path(&self) -> Result<&std::path::Path> {
        if super::identity(self.path, false).map_err(|e| Error::engine(e.to_string()))?
            != self.identity
        {
            return Err(Error::engine("audited working file identity changed"));
        }
        Ok(self.path)
    }
}

/// This metadata belongs only to W. It is never an accepted generation or a
/// projection/set proof, and publication cannot create journal authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkingPublication {
    pub binding: WorkingBinding,
    pub generation: String,
    pub publication: i64,
    pub accepted_frontier: i64,
    pub journal_revision: String,
}

/// Immutable provenance for ONE private publication, not a canonical receipt
/// ledger or an accepted-set certificate. Act and native Seq stay distinct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicationBase {
    publication: WorkingPublication,
    native: crate::standby::kernel_v2::KernelGeneration,
    origin: String,
    source_generation: Option<String>,
    genesis: String,
    principal: String,
    original_prefix: i64,
    pending_count: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recovery_dispositions: Vec<TerminalDraft>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalDraft {
    original_ordinal: i64,
    proposal_id: String,
    verified_answer_sha256: String,
}
impl PublicationBase {
    fn validate(&self) -> Result<()> {
        self.publication.validate()?;
        self.native.validate()?;
        if self.recovery_dispositions.len() > 1
            || self.recovery_dispositions.iter().any(|draft| {
                draft.original_ordinal.checked_add(1) != Some(self.original_prefix)
                    || draft.proposal_id.is_empty()
                    || draft.verified_answer_sha256.len() != 64
                    || !draft
                        .verified_answer_sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
            })
        {
            return Err(Error::engine("working terminal draft metadata invalid"));
        }
        if self.native.genesis_event_id != self.genesis
            || self.native.content_event_seq != self.publication.accepted_frontier
            || !crate::identity::is_database_id(&self.origin)
            || self
                .source_generation
                .as_ref()
                .is_some_and(|id| id.is_empty())
        {
            return Err(Error::engine("invalid native working base provenance"));
        }
        if self.native.head_act < 0
            || self.genesis.is_empty()
            || self.principal.is_empty()
            || self.original_prefix < 0
            || self.pending_count < 0
            || self.pending_count > self.original_prefix
        {
            return Err(Error::engine("invalid private working base provenance"));
        }
        Ok(())
    }
    fn read_binding(&self) -> WorkingReadBinding {
        WorkingReadBinding {
            binding: self.publication.binding.clone(),
            genesis: self.genesis.clone(),
            frontier: self.publication.accepted_frontier,
            principal: self.principal.clone(),
            published_base: Some(self.clone()),
            anchor_native: self.native.clone(),
            anchor_origin: self.origin.clone(),
        }
    }
    async fn insert_on(&self, tx: &mut sqlx::SqliteConnection) -> Result<()> {
        require_owned_transaction(tx)?;
        self.validate()?;
        sqlx::query("INSERT INTO main._native_working_bases(publication,state) VALUES(?,?)")
            .bind(self.publication.publication)
            .bind(serde_json::to_string(self)?)
            .execute(tx)
            .await?;
        Ok(())
    }
}
impl WorkingPublication {
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.generation.is_empty()
            || self.publication < 0
            || self.accepted_frontier < 0
            || self.journal_revision.len() != 64
            || !self
                .journal_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::engine("invalid private working publication"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkingState {
    Published,
    Applying,
    CommittedUnpublished,
    AwaitingQualifiedUndo,
    Quarantined,
    Closed,
}

fn require_owned_transaction(connection: &sqlx::SqliteConnection) -> Result<()> {
    use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
    if SqliteTransactionManager::get_transaction_depth(connection) != 1 {
        return Err(Error::engine(
            "working bookkeeping requires its top-level owned transaction",
        ));
    }
    Ok(())
}

/// Install private bookkeeping only on an exclusively owned disposable W.
/// These rows are not part of accepted generation verification or set proofs.
pub(super) async fn initialize_publication_on(
    tx: &mut sqlx::SqliteConnection,
    publication: &WorkingPublication,
) -> Result<()> {
    publication.validate()?;
    require_owned_transaction(tx)?;
    for ddl in [PUBLICATION_DDL, APPLIED_DDL] {
        sqlx::query(ddl).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO _native_working_publication(singleton,state) VALUES(1,?)")
        .bind(serde_json::to_string(publication)?)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// The caller must put the ordinary domain replay, this applied row and the
/// publication CAS on the SAME owned transaction before committing it once.
pub(super) async fn record_applied_on(
    tx: &mut sqlx::SqliteConnection,
    proposal: &crate::node::working_v2::DurableAppend,
    previous: &WorkingPublication,
    next: &WorkingPublication,
    fence: &crate::node::working_v2::JournalFence,
) -> Result<()> {
    next.validate()?;
    require_owned_transaction(tx)?;
    if next.binding != previous.binding
        || next.generation != previous.generation
        || next.accepted_frontier != previous.accepted_frontier
        || previous.publication.checked_add(1) != Some(next.publication)
        || proposal.binding() != &next.binding
        || fence.view().revision() != next.journal_revision
        || !fence.view().proposals().contains(proposal)
        || fence.view().requires_reconciliation()
    {
        return Err(Error::engine(
            "working publication changed pinned identity or base",
        ));
    }
    let ordinal = fence
        .view()
        .proposals()
        .iter()
        .position(|entry| entry == proposal)
        .and_then(|ordinal| i64::try_from(ordinal).ok())
        .ok_or_else(|| Error::engine("working proposal ordinal missing or too large"))?;
    sqlx::query("INSERT INTO _native_working_applied(proposal_id,request_fingerprint,actor,publication,original_ordinal) VALUES(?,?,?,?,?)")
        .bind(proposal.id()).bind(proposal.fingerprint()).bind(proposal.actor()).bind(next.publication)
        .bind(ordinal)
        .execute(&mut *tx).await?;
    let changed =
        sqlx::query("UPDATE _native_working_publication SET state=? WHERE singleton=1 AND state=?")
            .bind(serde_json::to_string(next)?)
            .bind(serde_json::to_string(previous)?)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if changed != 1 {
        return Err(Error::engine("working publication compare-and-set failed"));
    }
    Ok(())
}

/// Explicit trusted-owner boundary for this UNWIRED proof. The verified
/// failover/account/head owner supplies these coordinates, never tool args or
/// Caller credentials. This checks native facts, not transport authenticity.
/// Runtime integration must supply the existing verified owner capability.
pub(crate) struct OwnerPinnedBase {
    db: crate::db::Db,
    binding: WorkingBinding,
    genesis: String,
    frontier: i64,
    file: super::FileIdentity,
    principal: String,
    native: crate::standby::kernel_v2::KernelGeneration,
    origin: String,
    source_generation: Option<String>,
    _serving: Option<std::sync::Arc<crate::mcp::standby_stdio::WorkingBaseLease>>,
    // Present only until initial copy admission or retained-W grounding ends.
    source_snapshot: Option<sqlx::Transaction<'static, sqlx::Sqlite>>,
    source_checkpoint: Option<std::fs::File>,
}
impl OwnerPinnedBase {
    pub(super) async fn from_verified_owner(
        db: crate::db::Db,
        binding: WorkingBinding,
        confirmed_genesis: String,
        confirmed_frontier: i64,
        owner_caller: &crate::mcp::Caller,
    ) -> Result<Self> {
        binding.validate()?;
        if db.open_mode() != crate::db::DatabaseOpenMode::StandbyReadOnly
            || binding.history_lineage
                != format!("v2:{}:{}", binding.origin_database_id, confirmed_genesis)
            || confirmed_frontier < 0
            || owner_caller.host_asserted_app().is_some()
        {
            return Err(Error::engine(
                "working base owner coordinates are inconsistent",
            ));
        }
        let file =
            super::identity(db.path(), false).map_err(|error| Error::engine(error.to_string()))?;
        let mut snapshot = db.pool().begin().await?;
        let principal = crate::mcp::kernel_v2::principal_on(&mut snapshot, owner_caller).await?;
        let native = crate::standby::kernel_v2::coordinates(&mut snapshot).await?;
        let origin = crate::standby::kernel_v2::origin(&mut snapshot, &native).await?;
        let result = Self {
            db: db.clone(),
            binding,
            genesis: confirmed_genesis,
            frontier: confirmed_frontier,
            file,
            principal,
            native,
            origin,
            source_generation: None,
            _serving: None,
            source_snapshot: None,
            source_checkpoint: None,
        };
        result.check_file()?;
        result.check_native_on(&mut snapshot).await?;
        Ok(Self {
            source_snapshot: Some(snapshot),
            ..result
        })
    }
    pub(crate) async fn from_serving(
        lease: crate::mcp::standby_stdio::WorkingBaseLease,
        binding: WorkingBinding,
    ) -> Result<(Self, crate::mcp::Caller)> {
        binding.validate()?;
        if !lease.matches_binding(&binding) {
            return Err(Error::engine("verified working source binding changed"));
        }
        let (lease, mut snapshot, checkpoint, native, origin, caller, principal) =
            lease.pin_current_source().await?.into_parts();
        if binding.history_lineage != format!("v2:{}:{}", origin, native.genesis_event_id)
            || origin != binding.origin_database_id
        {
            return Err(Error::engine(
                "verified working base authority coordinates changed",
            ));
        }
        let db = lease.db();
        let file =
            super::identity(db.path(), false).map_err(|error| Error::engine(error.to_string()))?;
        let mut owner = Self {
            db,
            binding,
            genesis: native.genesis_event_id.clone(),
            frontier: native.content_event_seq,
            file,
            principal,
            native,
            origin,
            source_generation: Some(lease.generation_id().to_owned()),
            _serving: Some(std::sync::Arc::new(lease)),
            source_snapshot: None,
            source_checkpoint: None,
        };
        owner.check_file()?;
        owner.check_native_on(&mut snapshot).await?;
        owner.source_snapshot = Some(snapshot);
        owner.source_checkpoint = Some(checkpoint);
        Ok((owner, caller))
    }
    pub(crate) fn authority_act(&self) -> i64 {
        self.native.head_act
    }

    fn check_file(&self) -> Result<()> {
        let current = super::identity(self.db.path(), false)
            .map_err(|error| Error::engine(error.to_string()))?;
        if current != self.file {
            return Err(Error::engine("working base file identity changed"));
        }
        Ok(())
    }
    /// Check again on the completed private copy: an advance between an owner
    /// check and VACUUM must refuse, never silently choose a different base.
    pub(super) async fn check_native(&self, db: &crate::db::Db) -> Result<()> {
        self.check_file()?;
        let mut snapshot = db.pool().begin().await?;
        self.check_native_on(&mut snapshot).await?;
        snapshot.rollback().await?;
        Ok(())
    }
    async fn check_native_on(&self, conn: &mut sqlx::SqliteConnection) -> Result<()> {
        let (genesis, frontier) = native_base_coordinates(conn).await?;
        if genesis != self.genesis || frontier != self.frontier {
            return Err(Error::engine(
                "working base native genesis/frontier mismatch",
            ));
        }
        let native = crate::standby::kernel_v2::coordinates(conn).await?;
        if native != self.native
            || crate::standby::kernel_v2::origin(conn, &native).await? != self.origin
        {
            return Err(Error::engine(
                "working base full authority coordinates changed",
            ));
        }
        Ok(())
    }
    pub(super) fn read_binding(&self) -> WorkingReadBinding {
        WorkingReadBinding {
            binding: self.binding.clone(),
            genesis: self.genesis.clone(),
            frontier: self.frontier,
            principal: self.principal.clone(),
            published_base: None,
            anchor_native: self.native.clone(),
            anchor_origin: self.origin.clone(),
        }
    }
    #[cfg(test)]
    pub(in crate::fork) fn binding_for_test(&self) -> WorkingBinding {
        self.binding.clone()
    }
    fn stable_key(&self) -> super::ForkKey {
        use sha2::{Digest, Sha256};
        let namespace = hex::encode(Sha256::digest(
            serde_json::to_vec(&self.binding).expect("portable binding serialization"),
        ));
        super::ForkKey {
            window_id: format!("working:{namespace}"),
            workspace_id: self.binding.database_id.clone(),
        }
    }
}

/// Opaque resolved-principal capability from the trusted accepted-base owner.
/// The portable account namespace is NEVER compared to a kernel principal.
#[derive(Clone)]
pub(crate) struct WorkingReadBinding {
    binding: WorkingBinding,
    genesis: String,
    frontier: i64,
    principal: String,
    published_base: Option<PublicationBase>,
    anchor_native: crate::standby::kernel_v2::KernelGeneration,
    anchor_origin: String,
}
impl WorkingReadBinding {
    /// Immutable restart anchor from the accepted owner's opaque capability.
    /// This does not serialize bearer credentials or confer new authority.
    pub(crate) fn anchor_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "native.working.pinned-base.v2",
            &self.binding,
            &self.genesis,
            self.frontier,
            &self.principal,
            &self.anchor_origin,
            &self.anchor_native,
        ))?)
    }

    pub(crate) async fn validate_on(
        &self,
        conn: &mut sqlx::SqliteConnection,
        publication: &WorkingPublication,
        actual_principal: &str,
    ) -> Result<()> {
        if publication.binding != self.binding
            || publication.accepted_frontier != self.frontier
            || actual_principal != self.principal
        {
            return Err(Error::engine("working read owner binding mismatch"));
        }
        if let Some(base) = &self.published_base {
            if &base.publication != publication {
                return Err(Error::engine("working per-publication binding changed"));
            }
            let encoded: String = sqlx::query_scalar(
                "SELECT state FROM main._native_working_bases WHERE publication=?",
            )
            .bind(publication.publication)
            .fetch_one(&mut *conn)
            .await?;
            if encoded != serde_json::to_string(base)? {
                return Err(Error::engine("working immutable base provenance changed"));
            }
        }
        let (genesis, head) = native_base_coordinates(conn).await?;
        // Speculative writes advance W's head; the accepted-base anchor stays
        // pinned. Genesis must remain the native genesis verified by its owner.
        if genesis != self.genesis || head < self.frontier {
            return Err(Error::engine("working read native base mismatch"));
        }
        Ok(())
    }
}
async fn native_base_coordinates(conn: &mut sqlx::SqliteConnection) -> Result<(String, i64)> {
    let genesis: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM main.content_events WHERE type=? AND record_id=? AND actor=?",
    )
    .bind(crate::events::KERNEL_GENESIS_EVENT)
    .bind(crate::events::KERNEL_ROOT_ID)
    .bind(crate::events::KERNEL_GENESIS_ACTOR)
    .fetch_all(&mut *conn)
    .await?;
    if genesis.len() != 1 {
        return Err(Error::engine("working native base requires one genesis"));
    }
    let frontier: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
        .fetch_one(&mut *conn)
        .await?;
    Ok((genesis.into_iter().next().expect("one genesis"), frontier))
}
