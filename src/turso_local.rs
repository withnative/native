//! Local Turso runtime adapter for the canonical domain seam.
//!
//! The runtime owns one authoritative local Turso file per Native logical
//! database, guarded by a process-held file lock. It deliberately registers
//! only the domain operations which have crossed the local-Turso contract.
//! Cloud, sync, snapshot/export and backup/restore remain absent from the
//! engine registry and therefore fail closed. Caller SQL is
//! confined to the separately qualified isolated MemoryIO projection.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use fs2::FileExt;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::blob::{BlobMeta, BlobSlice};
use crate::domain_transaction::{
    AttachmentPhysicalPort, BindingAudit, BindingPhysicalPort, BindingRow, BindingSystemRule,
    ContentSemanticStatePort, EventCursorPort, FacetObservationPort, ProjectionPlan,
    ProjectorIntent, ProjectorPort, RecordFieldUpdate, RecordSemanticState, SpineFacet,
    TransactionLifecyclePort,
};
use crate::events::{CausalAdmission, CausalEnvelopeV1, CausalFrontierV1, EventRow};
use crate::mcp::fetch::FetchConfig;
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, ExecutionControl, ExecutionPhase, LogicalType,
    NormalizedRow, NormalizedValue, SqlError, SqlResult, StatementKind, StatementTemplate,
    TursoTransaction,
};
use crate::store::AppendSpec;
use crate::{Error, Result};

mod query_sql;
use query_sql::query_sql;

#[cfg(feature = "turso-tests")]
mod contract_harness;
mod policy;

const BACKEND: &str = "turso-local";
pub const TURSO_LOCAL_RUNTIME_CONFIG_FORMAT: &str = "native.turso-local-runtime.v1";
pub const TURSO_LOCAL_PROFILE_REVISION: u64 = 4;
const TURSO_RECORDS_FTS_DDL: &str =
    "CREATE INDEX records_turso_fts ON records USING fts (name, body)";
const TURSO_RECORDS_NAME_FTS_DDL: &str =
    "CREATE INDEX records_name_turso_fts ON records USING fts (name)";
const TURSO_DESCRIBE_SCHEMA_DDL_COUNT: usize = 87;
const TURSO_DESCRIBE_SCHEMA_DDL_FINGERPRINT: &str =
    "3b147534372585937388cc3868bce30d3b2bacf837d3378b5cc4792198a37dc9";
const TURSO_RUNTIME_TOPOLOGY_DDL_V2: &str = "CREATE TABLE _native_turso_runtime (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), logical_database_id TEXT NOT NULL UNIQUE, profile_revision INTEGER NOT NULL CHECK (profile_revision = 2))";
const TURSO_RUNTIME_TOPOLOGY_DDL_V3: &str = "CREATE TABLE _native_turso_runtime (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), logical_database_id TEXT NOT NULL UNIQUE, profile_revision INTEGER NOT NULL CHECK (profile_revision = 3))";
const TURSO_RUNTIME_TOPOLOGY_DDL: &str = "CREATE TABLE _native_turso_runtime (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), logical_database_id TEXT NOT NULL UNIQUE, profile_revision INTEGER NOT NULL CHECK (profile_revision = 4))";
const TURSO_FACET_VALUES_DDL: &str = "CREATE TABLE facet_values (id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records (id) ON DELETE CASCADE, \"key\" TEXT NOT NULL, value TEXT, value_num REAL, vocab_ref TEXT, created_at TEXT NOT NULL DEFAULT (strftime ('%Y-%m-%dT%H:%M:%fZ', 'now')), UNIQUE (record_id, \"key\"))";
const TURSO_RUN_CONTEXTS_DDL: &str = "CREATE TABLE run_contexts (run_key TEXT PRIMARY KEY, intent TEXT, agent_key TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime ('%Y-%m-%dT%H:%M:%fZ', 'now')), updated_at TEXT NOT NULL DEFAULT (strftime ('%Y-%m-%dT%H:%M:%fZ', 'now')))";
const TURSO_REQUIRED_RUNTIME_TABLES: [&str; 33] = [
    "content_events",
    "content_event_sources",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "records",
    "facet_values",
    "facet_observations",
    "links",
    "blobs",
    "bindings",
    "schema_config",
    "policy_events",
    "record_policies",
    "policy_entries",
    "meta_events",
    "vocabularies",
    "vocabulary_values",
    "database_identity",
    "database_identity_audit",
    "storage_portability_policy",
    "annotation_targets",
    "semantic_units",
    "message_audience_state",
    "message_mentions",
    "message_conversations",
    "run_contexts",
    "instruction_bindings",
    "onboarding_programmes",
    "onboarding_programme_sources",
    "notification_candidate_events",
    "notification_candidates",
    "canvas_objects",
    "canvas_batches",
];
const TURSO_REQUIRED_RUNTIME_INDEXES: [&str; 33] = [
    "idx_content_events_record",
    "idx_content_events_run",
    "idx_content_event_causal_frontier_parent",
    "idx_policy_events_record",
    "idx_records_type",
    "idx_records_kind",
    "idx_records_home",
    "idx_records_owner",
    "idx_records_policy_anchor",
    "idx_records_lifecycle",
    "idx_records_maturity",
    "idx_policy_entries_subject",
    "idx_links_source",
    "idx_links_target",
    "idx_message_audience_state_status",
    "idx_message_conversations_conversation",
    "idx_message_conversations_message",
    "idx_message_mentions_target",
    "idx_annotation_targets_target",
    "idx_facet_values_key",
    "idx_facet_values_num",
    "idx_facet_observations_series",
    "idx_facet_observations_key",
    "idx_bindings_external_identity",
    "idx_bindings_one_canonical_per_system",
    "idx_database_identity_audit_new",
    "idx_blobs_sha",
    "idx_meta_events_subject",
    "idx_semantic_units_bearer",
    "idx_instruction_bindings_source",
    "idx_notification_candidate_events_recipient",
    "idx_notification_candidates_recipient",
    "canvas_objects_live",
];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TursoLocalRuntimeConfig {
    pub format: String,
    pub logical_database_id: String,
    pub data_directory: PathBuf,
}

impl fmt::Debug for TursoLocalRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TursoLocalRuntimeConfig")
            .field("format", &self.format)
            .field("logical_database_id", &self.logical_database_id)
            .field("data_directory", &self.data_directory)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TursoLocalHealthReport {
    pub live: bool,
    pub ready: bool,
    pub write_ready: bool,
    pub schema_version: i64,
    pub expected_schema_version: i64,
    pub logical_database_id: String,
    pub profile_revision: u64,
    pub physical_overlays: Vec<&'static str>,
}

/// Verified evidence that a copied file is a usable Turso-local runtime.
///
/// Produced only by [`TursoLocalRuntimeConfig::verify_copy`], which reopens the
/// artifact through the same gates a real restore would. Every field is
/// measured on the copy itself, never inherited from the source it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TursoLocalCopyVerification {
    pub logical_database_id: String,
    pub schema_version: i64,
    pub profile_revision: u64,
    pub byte_len: u64,
    /// Digest of the exact bytes that were verified.
    ///
    /// Computed on the artifact, recomputed on the duplicate that was actually
    /// opened, and confirmed unchanged on the artifact afterwards — so a drill
    /// can record this and a later restore can prove it is restoring the same
    /// bytes that passed.
    pub sha256: String,
    /// Why this artifact must not be advertised as a stock SQLite ownership
    /// file, or `None` if stock SQLite can actually read it.
    ///
    /// This is measured by executing stock SQLite against the copy, not
    /// asserted from the profile text. See
    /// [`stock_sqlite_ownership_refusal`].
    pub stock_sqlite_ownership_refusal: Option<String>,
}

/// Receipt for a quiesced copy taken by [`TursoLocalDb::copy_quiesced_into`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TursoLocalQuiescedCopy {
    pub database_path: PathBuf,
    /// How many checkpoint attempts the quiescence needed. Always at least 1;
    /// more than 1 means readers were still draining under the write gate, and
    /// a rising value is worth alerting on in a drill.
    pub checkpoint_attempts: u32,
    pub verification: TursoLocalCopyVerification,
}

/// One durable-change notification from a local Turso runtime.
///
/// Generations are process-local, monotonically increasing, and emitted only
/// after a request's committed work has completed. They are a tailing signal,
/// not a replacement for reading authoritative database state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TursoLocalRealtimeEvent {
    pub generation: usize,
}

/// A bounded receiver for future durable-change notifications.
///
/// A receiver does not replay changes committed before subscription. Consumers
/// must re-read authoritative state after every event and resubscribe/reconcile
/// if `next()` reports lag or closure.
pub struct TursoLocalRealtimeTailer {
    receiver: tokio::sync::broadcast::Receiver<usize>,
}

impl TursoLocalRealtimeTailer {
    /// Wait for the next request-completion notification.
    pub async fn next(&mut self) -> Result<TursoLocalRealtimeEvent> {
        match self.receiver.recv().await {
            Ok(generation) => Ok(TursoLocalRealtimeEvent { generation }),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                Err(Error::engine(format!(
                    "Turso-local realtime tailer lagged by {missed} notifications; reconcile authoritative state"
                )))
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => Err(Error::engine(
                "Turso-local realtime tailer closed; resubscribe to a live runtime",
            )),
        }
    }

    /// Poll without waiting. `None` means no later commit is currently queued.
    pub fn try_next(&mut self) -> Result<Option<TursoLocalRealtimeEvent>> {
        match self.receiver.try_recv() {
            Ok(generation) => Ok(Some(TursoLocalRealtimeEvent { generation })),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(missed)) => {
                Err(Error::engine(format!(
                    "Turso-local realtime tailer lagged by {missed} notifications; reconcile authoritative state"
                )))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => Err(Error::engine(
                "Turso-local realtime tailer closed; resubscribe to a live runtime",
            )),
        }
    }
}

struct TursoLocalInner {
    database: turso::Database,
    logical_database_id: String,
    path: PathBuf,
    _ownership: File,
    write_gate: tokio::sync::Mutex<()>,
    /// Serializes portability-policy changes against admitted requests. An
    /// admitted request holds the read side for the whole of its governed
    /// future, so a stricter policy cannot commit between the admission
    /// decision and the execution that decision authorized.
    portability_policy_gate: tokio::sync::RwLock<()>,
    committed: Arc<AtomicUsize>,
    realtime: Arc<TursoLocalRealtimeHub>,
    #[cfg(feature = "turso-tests")]
    contract_faults: Arc<TursoContractFaults>,
}

#[cfg(feature = "turso-tests")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TursoContractFaultMode {
    Fail,
    Block,
}

#[cfg(feature = "turso-tests")]
#[derive(Default)]
struct TursoContractCheckpoint {
    armed: std::sync::Mutex<Option<(&'static str, TursoContractFaultMode)>>,
    entered: AtomicBool,
    released: AtomicBool,
    entered_notify: tokio::sync::Notify,
    release_notify: tokio::sync::Notify,
}

#[cfg(feature = "turso-tests")]
impl TursoContractCheckpoint {
    fn arm(&self, operation: &'static str, mode: TursoContractFaultMode) {
        *self.armed.lock().unwrap() = Some((operation, mode));
        self.entered.store(false, Ordering::Release);
        self.released.store(false, Ordering::Release);
    }

    async fn enter(&self, operation: &'static str) -> Result<()> {
        let mode = {
            let mut armed = self.armed.lock().unwrap();
            match *armed {
                Some((armed_operation, mode)) if armed_operation == operation => {
                    *armed = None;
                    Some(mode)
                }
                _ => None,
            }
        };
        match mode {
            None => Ok(()),
            Some(TursoContractFaultMode::Fail) => Err(Error::engine(format!(
                "contract forced {operation} failure after production handler work"
            ))),
            Some(TursoContractFaultMode::Block) => {
                self.entered.store(true, Ordering::Release);
                self.entered_notify.notify_waiters();
                loop {
                    let notified = self.release_notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.released.load(Ordering::Acquire) {
                        break;
                    }
                    notified.await;
                }
                Ok(())
            }
        }
    }

    async fn wait_until_entered(&self) {
        loop {
            let notified = self.entered_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release_notify.notify_waiters();
    }
}

#[cfg(feature = "turso-tests")]
#[derive(Default)]
struct TursoContractFaults {
    write: TursoContractCheckpoint,
    snapshot: TursoContractCheckpoint,
    intent: TursoContractCheckpoint,
    /// Run-key minting. Armed one-shot so a test can reach the mint-failure
    /// branch of the lifecycle port deterministically; unarmed it is inert and
    /// minting behaves exactly as it does in production.
    mint: TursoContractCheckpoint,
}

struct TursoLocalRealtimeHub {
    generation: AtomicUsize,
    sender: tokio::sync::broadcast::Sender<usize>,
}

impl TursoLocalRealtimeHub {
    fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(32);
        Self {
            generation: AtomicUsize::new(0),
            sender,
        }
    }

    fn wake(&self) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.sender.send(generation);
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<usize> {
        self.sender.subscribe()
    }
}

struct TursoRequestRealtimeCompletion {
    committed: AtomicBool,
    hub: Arc<TursoLocalRealtimeHub>,
}

impl TursoRequestRealtimeCompletion {
    fn finish(&self) {
        if self.committed.swap(false, Ordering::AcqRel) {
            self.hub.wake();
        }
    }
}

impl Drop for TursoRequestRealtimeCompletion {
    fn drop(&mut self) {
        self.finish();
    }
}

tokio::task_local! {
    static TURSO_REQUEST_REALTIME_COMPLETION: Arc<TursoRequestRealtimeCompletion>;
}

fn mark_turso_request_commit() -> bool {
    TURSO_REQUEST_REALTIME_COMPLETION
        .try_with(|completion| completion.committed.store(true, Ordering::Release))
        .is_ok()
}

/// One locally-owned Turso database. Clones share the driver, write gate and
/// process ownership lock; a second independent open of the same logical
/// database fails closed until every clone has been dropped.
#[derive(Clone)]
pub struct TursoLocalDb {
    inner: Arc<TursoLocalInner>,
}

impl fmt::Debug for TursoLocalDb {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TursoLocalDb")
            .field("logical_database_id", &self.inner.logical_database_id)
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

impl TursoLocalRuntimeConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes).map_err(|error| {
            Error::engine(format!("invalid Turso-local runtime config: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.format != TURSO_LOCAL_RUNTIME_CONFIG_FORMAT {
            return Err(Error::engine(format!(
                "unsupported Turso-local runtime config format {:?}",
                self.format
            )));
        }
        let id = self.logical_database_id.trim();
        if id.is_empty()
            || id != self.logical_database_id
            || id.len() > 255
            || id.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "Turso-local logical_database_id must contain 1..=255 non-control characters with no leading or trailing whitespace",
            ));
        }
        if !self.data_directory.is_absolute() {
            return Err(Error::engine(
                "Turso-local data_directory must be an absolute path",
            ));
        }
        Ok(())
    }

    pub fn database_path(&self) -> PathBuf {
        let digest = hex::encode(Sha256::digest(self.logical_database_id.as_bytes()));
        self.data_directory.join(format!("{digest}.turso"))
    }

    fn lock_path(&self) -> PathBuf {
        self.database_path().with_extension("turso.lock")
    }

    pub async fn open(&self) -> Result<TursoLocalDb> {
        self.open_with_database_id_minter(crate::identity::mint_database_id)
            .await
    }

    /// Verify that a copied artifact is a usable Turso-local runtime.
    ///
    /// This verifies the artifact, not the intent, and it does so **without
    /// touching the artifact**. The bytes are duplicated into a scratch
    /// directory and the duplicate is put through exactly the gates
    /// [`open`](Self::open) applies to any pre-existing file — the stock-SQLite
    /// read-only `user_version` preflight (`preflight_existing_runtime`), the
    /// exclusive ownership lock, `reconcile_runtime_profile`, and
    /// `validate_runtime`, which requires the `_native_turso_runtime` marker at
    /// profile revision 4 to carry a matching logical database identity, all
    /// three physical overlays, and complete content, policy and
    /// governed-vocabulary genesis. The scratch directory is then discarded.
    ///
    /// Nothing but a plain byte read ever touches the original. Every check
    /// that needs a database engine — the preflight, the stock-SQLite ownership
    /// probe, and the reopen — runs against the duplicate, because *any*
    /// engine-level open of a WAL-mode file, even a read-only one, materializes
    /// `-shm` and `-wal` sidecars beside it.
    ///
    /// Verifying a duplicate rather than the original is what makes the
    /// recorded [`sha256`](TursoLocalCopyVerification::sha256) mean something.
    /// Reopening a file necessarily writes to it — an ownership lock, a WAL and
    /// a shared-memory sidecar appear beside it, and a copy still at profile
    /// revision 3 is upgraded to 4 in place — so a drill that verified the
    /// artifact directly could only record a digest taken *before*
    /// verification, attesting bytes nothing had checked, or *after*, attesting
    /// bytes no restore would ever see. Here the digest is computed on the
    /// original, recomputed on the duplicate, and the two must match, so the
    /// claim "these exact bytes verified" is checkable rather than asserted.
    ///
    /// The pre-checks are not decoration. [`open`](Self::open) treats a missing
    /// or zero-length file as a *fresh* database and installs a new schema into
    /// it, so verification that skipped straight to reopening could fabricate
    /// the very artifact it claims to have verified. Refusing anything that is
    /// not already a non-empty regular file carrying the SQLite header is what
    /// makes a pass mean something.
    ///
    /// Cost: verification transiently needs room for one duplicate of the
    /// artifact. The scratch directory is preferentially created beside the
    /// artifact, so the duplicate lands on the same filesystem; if that
    /// directory is not writable — a read-only backup mount, for instance —
    /// it falls back to the system temporary directory.
    pub async fn verify_copy(&self) -> Result<TursoLocalCopyVerification> {
        self.validate()?;
        let path = self.database_path();
        reject_non_regular_target(&path, "copied database")?;
        let byte_len = std::fs::metadata(&path)
            .map_err(|_| Error::engine("copied Turso-local database is not readable"))?
            .len();
        if byte_len == 0 {
            return Err(Error::engine("copied Turso-local database is empty"));
        }
        if !has_sqlite_file_header(&path)? {
            return Err(Error::engine(
                "copied Turso-local database does not carry the SQLite file header",
            ));
        }
        let sha256 = file_sha256(&path)?;

        // Everything from here runs against a byte-duplicate. `scratch` is
        // declared before the handle that opens inside it so it is torn down
        // last, after the ownership lock has been released.
        let scratch = tempfile::Builder::new()
            .prefix(".native-turso-verify-")
            .tempdir_in(&self.data_directory)
            .or_else(|_| {
                tempfile::Builder::new()
                    .prefix(".native-turso-verify-")
                    .tempdir()
            })
            .map_err(|_| {
                Error::engine("cannot create a scratch directory to verify the copy in")
            })?;
        let duplicate_config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: self.logical_database_id.clone(),
            data_directory: scratch.path().to_path_buf(),
        };
        let duplicate = duplicate_config.database_path();
        std::fs::copy(&path, &duplicate)
            .map_err(|_| Error::engine("cannot duplicate the copy for verification"))?;
        if file_sha256(&duplicate)? != sha256 {
            return Err(Error::engine(
                "copied Turso-local database changed while it was being duplicated",
            ));
        }
        preflight_existing_runtime(&duplicate)?;
        let stock_sqlite_ownership_refusal = stock_sqlite_ownership_refusal(&duplicate);

        let restored = duplicate_config.open().await?;
        let health = restored.health().await?;
        drop(restored);
        if !health.ready {
            return Err(Error::engine(
                "copied Turso-local database reopened but is not ready",
            ));
        }

        // The artifact must be exactly what it was before verification ran.
        if file_sha256(&path)? != sha256 {
            return Err(Error::engine(
                "verification modified the copied Turso-local database",
            ));
        }
        drop(scratch);

        Ok(TursoLocalCopyVerification {
            logical_database_id: health.logical_database_id,
            schema_version: health.schema_version,
            // `validate_runtime` has already required the on-file marker to sit
            // at this revision, so reporting the constant is a statement about
            // the artifact, not a default.
            profile_revision: health.profile_revision,
            byte_len,
            sha256,
            stock_sqlite_ownership_refusal,
        })
    }

    async fn open_with_database_id_minter(
        &self,
        mint_database_id: impl FnOnce() -> String,
    ) -> Result<TursoLocalDb> {
        self.validate()?;
        ensure_runtime_directory(&self.data_directory)?;
        let path = self.database_path();
        reject_non_regular_target(&path, "database")?;
        let fresh = !path.exists() || path.metadata()?.len() == 0;
        if !fresh {
            preflight_existing_runtime(&path)?;
        }
        let ownership = acquire_ownership(&self.lock_path())?;
        let path_text = path.to_str().ok_or_else(|| {
            Error::engine("Turso-local database path is not valid UTF-8 for the selected driver")
        })?;
        let database = turso::Builder::new_local(path_text)
            .experimental_index_method(true)
            .build()
            .await
            .map_err(|_| Error::engine("cannot open Turso-local database"))?;
        let connection = database
            .connect()
            .map_err(|_| Error::engine("cannot connect to Turso-local database"))?;
        if fresh {
            install_schema(&connection, &self.logical_database_id).await?;
            seed_runtime(&database, mint_database_id()).await?;
        } else {
            migrate_existing_engine_schema(&connection).await?;
            reconcile_runtime_profile(&connection, &self.logical_database_id).await?;
        }
        validate_runtime(&connection, &self.logical_database_id).await?;
        Ok(TursoLocalDb {
            inner: Arc::new(TursoLocalInner {
                database,
                logical_database_id: self.logical_database_id.clone(),
                path,
                _ownership: ownership,
                write_gate: tokio::sync::Mutex::new(()),
                portability_policy_gate: tokio::sync::RwLock::new(()),
                committed: Arc::new(AtomicUsize::new(0)),
                realtime: Arc::new(TursoLocalRealtimeHub::new()),
                #[cfg(feature = "turso-tests")]
                contract_faults: Arc::new(TursoContractFaults::default()),
            }),
        })
    }
}

impl TursoLocalDb {
    pub fn logical_database_id(&self) -> &str {
        &self.inner.logical_database_id
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    #[cfg(feature = "turso-tests")]
    pub fn contract_commit_count_for_test(&self) -> usize {
        self.inner.committed.load(Ordering::Acquire)
    }

    #[cfg(feature = "turso-tests")]
    pub async fn contract_downgrade_shape_to_v38_for_test(&self) -> Result<()> {
        let connection = self.connect()?;
        connection
            .execute("DROP TRIGGER binding_audit_no_update", ())
            .await
            .map_err(|_| Error::engine("cannot remove binding audit update guard"))?;
        connection
            .execute("DROP TRIGGER binding_audit_no_delete", ())
            .await
            .map_err(|_| Error::engine("cannot remove binding audit delete guard"))?;
        connection
            .execute("PRAGMA user_version = 38", ())
            .await
            .map_err(|_| Error::engine("cannot install legacy Turso schema version"))?;
        Ok(())
    }

    /// Subscribe to future durable request-completion notifications.
    ///
    /// The tailer is intentionally scoped to this runtime handle and carries
    /// no record payloads or authorization-bearing data. On notification,
    /// consumers should query the database through qualified operations.
    pub fn subscribe_realtime(&self) -> TursoLocalRealtimeTailer {
        TursoLocalRealtimeTailer {
            receiver: self.inner.realtime.subscribe(),
        }
    }

    fn connect(&self) -> Result<turso::Connection> {
        self.inner
            .database
            .connect()
            .map_err(|_| Error::engine("cannot connect to Turso-local database"))
    }

    /// Take a byte copy of this database that a restore can trust.
    ///
    /// # Why a whole operation rather than a caller-held guard
    ///
    /// A `quiesce_for_copy()` guard would be more flexible, and it was the
    /// obvious alternative. It is rejected because it would make
    /// `TursoLocalInner::write_gate` — today a purely private serialization
    /// device — part of the public API surface. Every existing holder
    /// (`run_db_write`, `run_db_write_with_disposition`, `persist_intent`,
    /// `update_portability_policy`) acquires it, performs one bounded physical
    /// operation, and releases it inside the same function; none of them lets
    /// it escape. A guard would invert that: correctness would depend on the
    /// caller copying the right file, copying it at all, and not doing anything
    /// else meanwhile, and the failure mode of getting it wrong is a silently
    /// torn copy feeding a durability claim.
    ///
    /// What that costs: a caller cannot take one quiescence window across
    /// several artifacts, stream the bytes to a remote sink, or drive a
    /// filesystem-level snapshot. The sanctioned way to restore that
    /// flexibility later is a closure form that hands a callback the path of an
    /// already-quiesced file while the gate stays held *inside* this module —
    /// which keeps the property that makes this shape safe. It is deliberately
    /// not built yet.
    ///
    /// # What is proven, and what is not
    ///
    /// Under the write gate no write can begin, commit, or append a WAL frame
    /// between the checkpoint and the last byte read. The checkpoint is
    /// asserted with the Turso-specific quiescence test (see
    /// [`checkpoint_until_quiesced`]) and corroborated by the WAL sidecar
    /// being zero-length both before and after the copy. The artifact is then
    /// reopened and verified in its own right.
    ///
    /// Reads are deliberately *not* excluded: they take no gate, and a copy
    /// concurrent with a reader is still a copy of a fully checkpointed file. A
    /// reader can however make the checkpoint itself report `busy`, in which
    /// case this fails closed rather than copying.
    ///
    /// The result is a **Turso-local** restore artifact. It is not a stock
    /// SQLite file: see [`TursoLocalCopyVerification::stock_sqlite_ownership_refusal`].
    ///
    /// On success the destination directory holds exactly one file, the
    /// database itself, with the digest recorded on the receipt. Verification
    /// runs against a duplicate in a scratch directory that is discarded, so
    /// the artifact is never opened and never has sidecars written beside it.
    pub async fn copy_quiesced_into(
        &self,
        destination_directory: &Path,
    ) -> Result<TursoLocalQuiescedCopy> {
        let source = self.inner.path.clone();
        let source_directory = std::fs::canonicalize(
            source
                .parent()
                .ok_or_else(|| Error::engine("Turso-local database has no data directory"))?,
        )?;
        ensure_runtime_directory(destination_directory)?;
        let destination_directory = std::fs::canonicalize(destination_directory)?;
        if destination_directory.starts_with(&source_directory) {
            return Err(Error::engine(
                "Turso-local quiesced copy destination must be outside the live data directory",
            ));
        }
        let destination_config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: self.inner.logical_database_id.clone(),
            data_directory: destination_directory,
        };
        let destination = destination_config.database_path();
        if destination.exists() {
            return Err(Error::engine(format!(
                "refusing to overwrite {}",
                destination.display()
            )));
        }

        let checkpoint_attempts;
        {
            let _write = self.inner.write_gate.lock().await;
            let connection = self.connect()?;
            checkpoint_attempts = checkpoint_until_quiesced(&connection, &source).await?;

            let copy_source = source.clone();
            let copy_destination = destination.clone();
            // Off-thread: a multi-gigabyte copy would otherwise hold a runtime
            // worker as well as the write gate.
            tokio::task::spawn_blocking(move || copy_file_durably(&copy_source, &copy_destination))
                .await
                .map_err(|_| Error::engine("Turso-local quiesced copy did not complete"))??;

            // Under the write gate this cannot fail. It is asserted anyway
            // because the cost of a silently torn copy reaching a release gate
            // is unbounded, and this is the one check that would notice a
            // writer that reached the file without passing through the gate.
            let sidecar = wal_sidecar_path(&source);
            let residue = match std::fs::metadata(&sidecar) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
                Err(error) => return Err(error.into()),
            };
            if residue != 0 {
                let _ = std::fs::remove_file(&destination);
                return Err(Error::engine(
                    "Turso-local database was written during the quiesced copy",
                ));
            }
        }

        // The gate is released before verification. Verifying opens a second,
        // independent runtime on a different file, with its own ownership lock
        // and its own write gate, so it cannot deadlock against this one — and
        // it has no reason to keep excluding live writes while it runs.
        match destination_config.verify_copy().await {
            Ok(verification) => Ok(TursoLocalQuiescedCopy {
                database_path: destination,
                checkpoint_attempts,
                verification,
            }),
            Err(error) => {
                // Never leave an unverified artifact where a restore could find
                // it and assume it passed.
                let _ = std::fs::remove_file(&destination);
                let _ = std::fs::remove_file(wal_sidecar_path(&destination));
                Err(error)
            }
        }
    }

    pub async fn health(&self) -> Result<TursoLocalHealthReport> {
        let connection = self.connect()?;
        let schema_version = scalar_i64(&connection, "PRAGMA user_version").await?;
        let overlays = physical_overlay_names(&connection).await?;
        let ready = schema_version == crate::CURRENT_ENGINE_SCHEMA_VERSION
            && required_runtime_schema_ready(&connection).await?
            && runtime_genesis_ready(&connection).await?
            && seeded_runtime_vocabulary_ready(&connection).await?
            && seeded_runtime_schema_config_ready(&connection).await?
            && overlays
                == BTreeSet::from([
                    "projection.facet-value-number",
                    "search.turso-fts",
                    "topology.logical-database-identity",
                ]);
        Ok(TursoLocalHealthReport {
            live: true,
            ready,
            write_ready: ready,
            schema_version,
            expected_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            logical_database_id: self.logical_database_id().into(),
            profile_revision: TURSO_LOCAL_PROFILE_REVISION,
            physical_overlays: overlays.into_iter().collect(),
        })
    }
}

fn ensure_runtime_directory(directory: &Path) -> Result<()> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            Error::engine("Turso-local data_directory must be a non-symlink directory"),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory)?;
            let metadata = std::fs::symlink_metadata(directory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::engine(
                    "Turso-local data_directory must be a non-symlink directory",
                ));
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn reject_non_regular_target(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::engine(format!(
                "Turso-local {label} must be a regular non-symlink file"
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn acquire_ownership(path: &Path) -> Result<File> {
    reject_non_regular_target(path, "ownership lock")?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.try_lock_exclusive().map_err(|_| {
        Error::engine("Turso-local database is already owned by another runtime process")
    })?;
    Ok(file)
}

/// The WAL sidecar Turso keeps beside a local database file.
fn wal_sidecar_path(database_path: &Path) -> PathBuf {
    let mut sidecar = database_path.as_os_str().to_os_string();
    sidecar.push("-wal");
    PathBuf::from(sidecar)
}

/// True when `path` begins with the stock SQLite file header.
///
/// Cheap, header-only, and the one structural check that distinguishes an
/// unencrypted database file from an encrypted or truncated one without
/// parsing a schema.
fn has_sqlite_file_header(path: &Path) -> Result<bool> {
    use std::io::Read;

    let mut header = [0u8; 16];
    match File::open(path)?.read_exact(&mut header) {
        Ok(()) => Ok(&header == b"SQLite format 3\0"),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// How many attempts a quiesced checkpoint may make before failing closed.
///
/// Holding the write gate stops new writes from arriving but does not, on its
/// own, produce a clean checkpoint: see [`checkpoint_until_quiesced`].
const QUIESCE_CHECKPOINT_ATTEMPTS: u32 = 8;

/// Whether one checkpoint attempt actually folded the WAL away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointOutcome {
    Quiesced,
    /// The checkpoint declined to run. Retryable: nothing was changed.
    Contended,
}

/// SHA-256 of a file's contents, streamed so an artifact of any size is fine.
fn file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Issue `PRAGMA wal_checkpoint(TRUNCATE)` once and classify the result.
///
/// The assertion is deliberately **not** SQLite's.
/// `tests/turso/turso_checkpoint_semantics.rs` characterizes Turso 0.7.2: the
/// result row is `(busy, log, checkpointed)`, but `log` and `checkpointed` are
/// hardcoded zeros rather than frame counts, so SQLite's usual
/// `log_frames == checkpointed` test is vacuously true here and proves
/// nothing about checkpoint completion.
///
/// Only `busy` carries information. A contended checkpoint reports `busy = 1`
/// with **NULL** counters, so requiring all three columns to be integers is a
/// second, independent guard: a refused checkpoint fails to decode rather than
/// being read as a completed one.
///
/// `PRAGMA integrity_check` is deliberately absent. The same characterization
/// proves it unusable on a Turso runtime file in either engine.
async fn checkpoint_truncate_once(
    connection: &turso::Connection,
    database_path: &Path,
) -> Result<CheckpointOutcome> {
    let mut rows = connection
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await
        .map_err(|_| Error::engine("Turso-local checkpoint could not execute"))?;
    let columns = rows.column_names();
    if columns.len() != 3
        || columns[0] != "busy"
        || columns[1] != "log"
        || columns[2] != "checkpointed"
    {
        return Err(Error::engine(format!(
            "Turso-local checkpoint returned unexpected columns {columns:?}"
        )));
    }
    let mut triple: Option<Option<[i64; 3]>> = None;
    while let Some(row) = rows
        .next()
        .await
        .map_err(|_| Error::engine("Turso-local checkpoint result was unreadable"))?
    {
        if triple.is_some() || row.column_count() != 3 {
            return Err(Error::engine(
                "Turso-local checkpoint returned an unexpected result shape",
            ));
        }
        let mut values = [0i64; 3];
        let mut integers = true;
        for (index, slot) in values.iter_mut().enumerate() {
            match row.get_value(index) {
                Ok(turso::Value::Integer(observed)) => *slot = observed,
                // NULL counters are how Turso reports a checkpoint that
                // declined to run. Refusing to coerce them is the guard.
                _ => integers = false,
            }
        }
        triple = Some(integers.then_some(values));
    }
    let Some(triple) = triple else {
        return Err(Error::engine(
            "Turso-local checkpoint returned no result row",
        ));
    };
    let Some([busy, _log, _checkpointed]) = triple else {
        return Ok(CheckpointOutcome::Contended);
    };
    if busy != 0 {
        return Ok(CheckpointOutcome::Contended);
    }
    // Independent, engine-external evidence that the WAL really was folded into
    // the main file. The counters cannot supply this, so the filesystem does.
    // Reaching here with a non-empty WAL would mean the engine reported a clean
    // checkpoint that demonstrably did not happen, which is not retryable.
    let sidecar = wal_sidecar_path(database_path);
    match std::fs::metadata(&sidecar) {
        Ok(metadata) if metadata.len() != 0 => Err(Error::engine(format!(
            "Turso-local checkpoint reported success but left {} bytes in the WAL sidecar",
            metadata.len()
        ))),
        Ok(_) => Ok(CheckpointOutcome::Quiesced),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(CheckpointOutcome::Quiesced)
        }
        Err(error) => Err(error.into()),
    }
}

/// Drive `PRAGMA wal_checkpoint(TRUNCATE)` to a genuinely quiesced result.
///
/// **The write gate is necessary but not sufficient, and this is the seam's
/// most important caveat.** Holding it guarantees no domain write can begin,
/// commit, or append a WAL frame — every writer reaches the file through
/// `run_db_write`, `run_db_write_with_disposition`, `persist_intent`, or
/// `update_portability_policy`, all of which take the same gate. It does *not*
/// guarantee the checkpoint succeeds: measured on a loaded machine, roughly one
/// attempt in fifty still reported `busy` with the gate held, because reads take
/// no gate and a residual read snapshot from a just-finished operation can still
/// be draining when the checkpoint runs.
///
/// That contention is transient precisely *because* the gate is held: no new
/// writer can arrive, so the only thing the retry waits for is existing readers
/// to drain. Retrying affects liveness only — the success condition is
/// unchanged, and every attempt must still end at `busy == 0` with a
/// zero-length WAL sidecar or the whole operation fails closed with no artifact.
///
/// Returns the number of attempts used, which is worth recording in a drill: a
/// rising count is early warning that read load around backups is growing.
async fn checkpoint_until_quiesced(
    connection: &turso::Connection,
    database_path: &Path,
) -> Result<u32> {
    let mut backoff = std::time::Duration::from_millis(5);
    for attempt in 1..=QUIESCE_CHECKPOINT_ATTEMPTS {
        if checkpoint_truncate_once(connection, database_path).await? == CheckpointOutcome::Quiesced
        {
            return Ok(attempt);
        }
        if attempt < QUIESCE_CHECKPOINT_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    Err(Error::engine(format!(
        "Turso-local checkpoint stayed contended across {QUIESCE_CHECKPOINT_ATTEMPTS} attempts: the database is not quiesced"
    )))
}

/// Measure whether stock SQLite can own this file, and say why not if it cannot.
///
/// The `turso-local` profile classifies `native.sqlite-file-fast-path` as a
/// convertible fast path for "a quiesced, local, unencrypted file". Quiesced
/// and unencrypted is necessary but demonstrably **not** sufficient: a
/// Turso-local runtime file carries engine-native FTS objects whose
/// `sqlite_schema` entries stock SQLite cannot parse, so stock SQLite reports
/// `DatabaseCorrupt` when preparing *any* schema-touching statement against it.
/// This is the same class of refusal the portable [`crate::export`] artifact
/// boundary applies to libsql vector indexes.
///
/// The refusal is produced by running stock SQLite against the artifact rather
/// than by reading the profile text, so the claim stays honest — and would
/// automatically stop refusing — if the overlay ever changes.
fn stock_sqlite_ownership_refusal(path: &Path) -> Option<String> {
    let connection = match rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(connection) => connection,
        Err(error) => return Some(format!("stock sqlite cannot open the file: {error}")),
    };
    let refusal = match connection.prepare("SELECT name FROM sqlite_schema") {
        Ok(_) => None,
        Err(error) => Some(format!(
            "stock sqlite cannot read this file's schema: {error}"
        )),
    };
    refusal
}

/// Copy `source` to `destination` and make the new name durable.
fn copy_file_durably(source: &Path, destination: &Path) -> Result<()> {
    std::fs::copy(source, destination)?;
    File::open(destination)?.sync_all()?;
    if let Some(parent) = destination.parent() {
        // Fsync the directory too: without it the new name can survive as a
        // zero-length entry across a crash even though its contents are durable.
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn preflight_existing_runtime(path: &Path) -> Result<()> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| Error::engine("existing Turso-local file failed read-only preflight"))?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| Error::engine("existing Turso-local file failed read-only preflight"))?;
    if !matches!(version, 45..=49 | crate::CURRENT_ENGINE_SCHEMA_VERSION) {
        return Err(Error::engine(format!(
            "Turso-local schema version {version} is not supported (required current version {})",
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        )));
    }
    Ok(())
}

/// Error-label convention for the shared 45-to-46 and 46-to-47 edges: statement
/// failures use bare stable labels named for the target schema (`engine-46` and
/// `engine-47`), without driver detail or statement text. Keep those labels
/// byte-stable; change either only deliberately, with test cover asserting the
/// new text. Other migration rungs retain their own established error mapping.
async fn migrate_existing_engine_schema(connection: &turso::Connection) -> Result<()> {
    let version = scalar_i64(connection, "PRAGMA user_version").await?;
    if version == crate::CURRENT_ENGINE_SCHEMA_VERSION {
        return Ok(());
    }
    if !matches!(version, 45..=49) {
        return Err(Error::engine(format!(
            "Turso-local schema version {version} is not supported"
        )));
    }

    connection
        .execute("PRAGMA foreign_keys=OFF", ())
        .await
        .map_err(|_| Error::engine("cannot disable Turso-local migration foreign keys"))?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|_| Error::engine("cannot begin Turso-local engine migration"))?;
    let migration = async {
        if version == 45 {
            // Migration statement errors name the target schema reached by
            // this sequence.
            connection
                .execute("PRAGMA legacy_alter_table=ON", ())
                .await
                .map_err(|_| {
                    Error::engine("Turso-local engine-46 migration statement failed")
                })?;
            for statement in crate::migrations::ENGINE_45_TO_46_STATEMENTS {
                connection.execute(statement, ()).await.map_err(|_| {
                    Error::engine("Turso-local engine-46 migration statement failed")
                })?;
            }
            connection
                .execute("PRAGMA legacy_alter_table=OFF", ())
                .await
                .map_err(|_| {
                    Error::engine("Turso-local engine-46 migration statement failed")
                })?;
        }
        if version <= 48 {
            for statement in crate::migrations::ENGINE_46_TO_47_STATEMENTS {
                connection.execute(statement, ()).await.map_err(|_| {
                    Error::engine("Turso-local engine-47 migration statement failed")
                })?;
            }
            let manifest_ids = crate::migrations::dogfood_message_origin_repair_ids()
                .map(|id| format!("'{id}'"))
                .collect::<Vec<_>>()
                .join(",");
            let reviewed_rows = scalar_i64(
                connection,
                &format!("SELECT COUNT(*) FROM records WHERE id IN ({manifest_ids})"),
            )
            .await?;
            if reviewed_rows != 0 {
                return Err(Error::engine(
                    "Turso-local cannot apply the SQLite-qualified Native HQ dogfood Message-origin repair; migrate this database through the reference SQLite engine",
                ));
            }
            connection
                .execute("PRAGMA user_version=48", ())
                .await
                .map_err(|_| Error::engine("Turso-local engine-48 migration statement failed"))?;
            // Engine 49: the canvas scene projection and batch ledger, DDL-additive.
            for statement in crate::migrations::ENGINE_49_CANVAS_DDL {
                connection.execute(statement, ()).await.map_err(|error| {
                    // Name the statement and quote the engine's own reason. A bare
                    // "statement failed" sends the reader back through a rebuild to
                    // learn what the driver already said.
                    Error::engine(format!(
                        "Turso-local engine-49 migration statement failed: {error}; statement: {statement}"
                    ))
                })?;
            }
            connection
                .execute("PRAGMA user_version=49", ())
                .await
                .map_err(|_| Error::engine("Turso-local engine-49 migration statement failed"))?;
        }
        for statement in [
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE provenance_action_attestations RENAME TO provenance_action_attestations_v49",
            crate::schema::ddl::PROVENANCE_ACTION_ATTESTATIONS_DDL,
            r#"INSERT INTO provenance_action_attestations
                 (id,schema_version,principal,executor_kind,channel,executor_ref,
                  delegation_ref,interaction_receipt_id,operation,action_commitment,
                  action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                  issued_at,command_identity_digest,intent_digest)
               SELECT id,schema_version,principal,executor_kind,channel,executor_ref,
                      delegation_ref,interaction_receipt_id,operation,action_commitment,
                      action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                      issued_at,command_identity_digest,intent_digest
                 FROM provenance_action_attestations_v49"#,
            "DROP TABLE provenance_action_attestations_v49",
            "CREATE INDEX idx_provenance_action_principal ON provenance_action_attestations(principal, issued_at, id)",
            "CREATE INDEX idx_provenance_action_command ON provenance_action_attestations(principal, operation, command_identity_digest) WHERE command_identity_digest IS NOT NULL",
            r#"CREATE TRIGGER provenance_action_attestations_no_update
                 BEFORE UPDATE ON provenance_action_attestations
                 BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
            r#"CREATE TRIGGER provenance_action_attestations_no_delete
                 BEFORE DELETE ON provenance_action_attestations
                 BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
            "PRAGMA legacy_alter_table=OFF",
        ] {
            connection.execute(statement, ()).await.map_err(|error| {
                Error::engine(format!(
                    "Turso-local engine-50 attribution migration failed: {error}; statement: {statement}"
                ))
            })?;
        }
        for statement in crate::schema::ddl::ENGINE_50_WEBHOOK_DDL {
            connection.execute(statement, ()).await.map_err(|error| {
                Error::engine(format!(
                    "Turso-local engine-50 webhook migration failed: {error}; statement: {statement}"
                ))
            })?;
        }
        connection
            .execute("PRAGMA user_version=50", ())
            .await
            .map_err(|_| Error::engine("Turso-local engine-50 migration statement failed"))?;
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = migration {
        let _ = connection.execute("ROLLBACK", ()).await;
        let _ = connection.execute("PRAGMA foreign_keys=ON", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|_| Error::engine("cannot commit Turso-local engine migration"))?;
    connection
        .execute("PRAGMA foreign_keys=ON", ())
        .await
        .map_err(|_| Error::engine("cannot restore Turso-local migration foreign keys"))?;
    Ok(())
}

fn sqlite_fts_statement(statement: &str) -> bool {
    statement.contains("records_fts") || statement.contains("records_name_idx")
}

async fn install_schema(connection: &turso::Connection, logical_database_id: &str) -> Result<()> {
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(|_| Error::engine("cannot enable Turso-local foreign keys"))?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|_| Error::engine("cannot begin Turso-local schema installation"))?;
    let installation = async {
        for statement in crate::schema::DDL_STATEMENTS {
            if sqlite_fts_statement(statement) {
                continue;
            }
            let statement = if statement.contains("GENERATED ALWAYS AS") {
                TURSO_FACET_VALUES_DDL
            } else {
                statement
            };
            connection
                .execute(statement, ())
                .await
                .map_err(|_| Error::engine("Turso-local schema installation failed"))?;
        }
        connection
            .execute(
                TURSO_RECORDS_FTS_DDL,
                (),
            )
            .await
            .map_err(|_| Error::engine("Turso-local FTS overlay installation failed"))?;
        connection
            .execute(
                TURSO_RECORDS_NAME_FTS_DDL,
                (),
            )
            .await
            .map_err(|_| Error::engine("Turso-local name FTS overlay installation failed"))?;
        connection
            .execute(
                TURSO_RUNTIME_TOPOLOGY_DDL,
                (),
            )
            .await
            .map_err(|_| Error::engine("Turso-local topology overlay installation failed"))?;
        connection
            .execute(TURSO_RUN_CONTEXTS_DDL, ())
            .await
            .map_err(|_| Error::engine("Turso-local run-context overlay installation failed"))?;
        connection
            .execute(
                "INSERT INTO _native_turso_runtime(singleton, logical_database_id, profile_revision) VALUES(1, ?1, 4)",
                [logical_database_id],
            )
            .await
            .map_err(|_| Error::engine("Turso-local logical database identity installation failed"))?;
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = installation {
        let _ = connection.execute("ROLLBACK", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|_| Error::engine("cannot commit Turso-local schema installation"))?;
    Ok(())
}

async fn seed_runtime(database: &turso::Database, identity: String) -> Result<()> {
    let mut connection = database
        .connect()
        .map_err(|_| Error::engine("cannot connect for Turso-local genesis"))?;
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(|_| Error::engine("cannot enable Turso-local genesis foreign keys"))?;
    append_engine_seed_specs(
        &mut connection,
        Arc::new(AtomicUsize::new(0)),
        &ExecutionControl::default(),
        vec![
            AppendSpec {
                record_id: crate::schema::ROOT_RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    // Turso-local genesis has no account email in hand, so the
                    // workspace takes the neutral default name.
                    "type":"Collection", "kind":"folder",
                    "name": crate::schema::DEFAULT_WORKSPACE_NAME,
                    "home_id":null, "persistence":"enduring"
                }),
                actor: Some("engine:seed".into()),
            },
            AppendSpec {
                record_id: crate::schema::UNFILED_RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type":"Collection", "kind":"folder", "name":"Unfiled",
                    "home_id":crate::schema::ROOT_RECORD_ID, "persistence":"enduring"
                }),
                actor: Some("engine:seed".into()),
            },
        ],
    )
    .await?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|_| Error::engine("cannot begin Turso-local policy genesis"))?;
    let now = crate::store::now_iso();
    let policy_payload = serde_json::json!({
        "entries":[{"subject_kind":"members","subject_id":"native:members","effect":"allow","capability":"edit"}]
    })
    .to_string();
    let genesis = async {
        seed_runtime_vocabularies(&connection, &now).await?;
        connection.execute(
            "INSERT INTO policy_events(id,record_id,type,payload,actor,reason,created_at) VALUES(?1,'native:root','policy.replaced',?2,'engine:seed','canonical root policy genesis',?3)",
            (uuid::Uuid::new_v4().to_string(), policy_payload, now.clone()),
        ).await.map_err(|_| Error::engine("Turso-local policy event genesis failed"))?;
        // Explicit genesis-only write-funnel exception: materialize the canonical
        // root projection atomically with its authoritative policy event before the
        // handle is returned. Readiness verifies both rows and the event, and the
        // qualified Turso runtime exposes no direct policy-mutation route.
        connection.execute(
            "INSERT INTO record_policies(record_id,created_at) VALUES('native:root',?1)",
            [now.as_str()],
        ).await.map_err(|_| Error::engine("Turso-local policy projection genesis failed"))?;
        connection.execute(
            "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES('native:root','members','native:members','allow','edit')",
            (),
        ).await.map_err(|_| Error::engine("Turso-local policy entry genesis failed"))?;
        connection.execute(
            "INSERT INTO database_identity(singleton,origin_db_id,created_at) VALUES(1,?1,?2)",
            (identity.clone(), now.clone()),
        ).await.map_err(|_| Error::engine("Turso-local database identity genesis failed"))?;
        connection.execute(
            "INSERT INTO database_identity_audit(id,action,old_origin_db_id,new_origin_db_id,actor,reason,created_at) VALUES(?1,'mint',NULL,?2,'engine:seed','mint fresh database identity',?3)",
            (uuid::Uuid::new_v4().to_string(), identity, now),
        ).await.map_err(|_| Error::engine("Turso-local database identity audit genesis failed"))?;
        Ok::<_, Error>(())
    }.await;
    if let Err(error) = genesis {
        let _ = connection.execute("ROLLBACK", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|_| Error::engine("cannot commit Turso-local genesis"))?;
    Ok(())
}

async fn seed_runtime_vocabularies(connection: &turso::Connection, now: &str) -> Result<()> {
    async fn append_vocabulary(
        connection: &turso::Connection,
        id: &str,
        name: &str,
        now: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({"name": name}).to_string();
        connection
            .execute(
                "INSERT INTO meta_events(id,subject_id,type,payload,actor,created_at) VALUES(?1,?2,'vocabulary.created',?3,'engine:seed',?4)",
                (uuid::Uuid::new_v4().to_string(), id, payload, now),
            )
            .await
            .map_err(|_| Error::engine("Turso-local vocabulary genesis event failed"))?;
        connection
            .execute(
                "INSERT INTO vocabularies(id,name,created_at) VALUES(?1,?2,?3)",
                (id, name, now),
            )
            .await
            .map_err(|_| Error::engine("Turso-local vocabulary genesis projection failed"))?;
        Ok(())
    }

    async fn append_value(
        connection: &turso::Connection,
        id: &str,
        vocabulary_id: &str,
        value: &str,
        progression: (f64, &str),
        metadata: serde_json::Value,
        now: &str,
    ) -> Result<()> {
        let (ordinal, terminality) = progression;
        let metadata_text = serde_json::to_string(&metadata)?;
        let payload = serde_json::json!({
            "vocabulary_id": vocabulary_id,
            "value": value,
            "status": "active",
            "ordinal": ordinal,
            "terminality": terminality,
            "metadata": metadata,
        })
        .to_string();
        connection
            .execute(
                "INSERT INTO meta_events(id,subject_id,type,payload,actor,created_at) VALUES(?1,?2,'vocab_value.proposed',?3,'engine:seed',?4)",
                (uuid::Uuid::new_v4().to_string(), id, payload, now),
            )
            .await
            .map_err(|_| Error::engine("Turso-local vocabulary-value genesis event failed"))?;
        connection
            .execute(
                "INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES(?1,?2,?3,'active',?4,?5,?6)",
                (id, vocabulary_id, value, ordinal, terminality, metadata_text),
            )
            .await
            .map_err(|_| Error::engine("Turso-local vocabulary-value genesis projection failed"))?;
        Ok(())
    }

    for (name, values) in crate::meta::vocabulary::SEED_VOCABULARIES {
        let vocabulary_id = format!("voc:{name}");
        append_vocabulary(connection, &vocabulary_id, name, now).await?;
        for (value, ordinal, terminality) in values.seeded() {
            let value_id = format!("vv:{vocabulary_id}:{value}");
            append_value(
                connection,
                &value_id,
                &vocabulary_id,
                value,
                (ordinal, terminality.as_str()),
                serde_json::json!({}),
                now,
            )
            .await?;
        }
    }

    let manifest = crate::meta::kind::core_kind_manifest()?;
    for record_type in crate::schema::SPINE_TYPES {
        let vocabulary_id = crate::meta::kind::kind_vocabulary_id(record_type);
        let vocabulary_name = crate::meta::kind::kind_vocabulary_name(record_type);
        append_vocabulary(connection, &vocabulary_id, &vocabulary_name, now).await?;
        for kind in manifest
            .kinds
            .iter()
            .filter(|kind| kind.record_type == record_type)
        {
            append_value(
                connection,
                &kind.value_id,
                &vocabulary_id,
                &kind.token,
                (0.0, "open"),
                serde_json::to_value(&kind.metadata)?,
                now,
            )
            .await?;
        }
    }
    let pack_data = crate::meta::schema_config::recommended_pack_schema_config();
    let payload = serde_json::json!({
        "layer": "pack",
        "name": crate::meta::schema_config::RECOMMENDED_PACK_NAME,
        "data": pack_data.to_string(),
        "version_lineage": null,
        "applies_to_collection_id": null,
    })
    .to_string();
    connection
        .execute(
            "INSERT INTO meta_events(id,subject_id,type,payload,actor,created_at) VALUES(?1,'pack:@native/recommended','schema_config.set',?2,'engine:seed',?3)",
            (uuid::Uuid::new_v4().to_string(), payload, now),
        )
        .await
        .map_err(|_| Error::engine("Turso-local schema-config genesis event failed"))?;
    connection
        .execute(
            "INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('pack:@native/recommended','pack',?1,?2,?3)",
            (
                crate::meta::schema_config::RECOMMENDED_PACK_NAME,
                pack_data.to_string(),
                now,
            ),
        )
        .await
        .map_err(|_| Error::engine("Turso-local schema-config genesis projection failed"))?;
    Ok(())
}

async fn scalar_i64(connection: &turso::Connection, sql: &str) -> Result<i64> {
    let mut rows = connection
        .query(sql, ())
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local runtime"))?;
    let row = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local runtime"))?
        .ok_or_else(|| Error::engine("Turso-local runtime inspection returned no row"))?;
    row.get(0)
        .map_err(|_| Error::engine("Turso-local runtime inspection returned an invalid value"))
}

async fn scalar_text(connection: &turso::Connection, sql: &str) -> Result<String> {
    let mut rows = connection
        .query(sql, ())
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local runtime"))?;
    let row = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local runtime"))?
        .ok_or_else(|| Error::engine("Turso-local runtime inspection returned no row"))?;
    row.get(0)
        .map_err(|_| Error::engine("Turso-local runtime inspection returned an invalid value"))
}

async fn reconcile_runtime_profile(
    connection: &turso::Connection,
    logical_database_id: &str,
) -> Result<()> {
    let topology_sql = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='table' AND name='_native_turso_runtime'),'')",
    )
    .await?;
    if topology_sql == TURSO_RUNTIME_TOPOLOGY_DDL {
        return reconcile_run_context_overlay(connection).await;
    }
    if topology_sql == TURSO_RUNTIME_TOPOLOGY_DDL_V3 {
        let stored = scalar_text(
            connection,
            "SELECT logical_database_id FROM _native_turso_runtime WHERE singleton=1 AND profile_revision=3",
        )
        .await?;
        if stored != logical_database_id {
            return Err(Error::engine(
                "Turso-local database belongs to a different logical database",
            ));
        }
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|_| Error::engine("cannot begin Turso-local profile upgrade"))?;
        let upgrade = async {
            connection
                .execute(
                    "ALTER TABLE _native_turso_runtime RENAME TO _native_turso_runtime_v3",
                    (),
                )
                .await
                .map_err(|_| {
                    Error::engine("Turso-local profile upgrade could not preserve v3 marker")
                })?;
            connection
                .execute(TURSO_RUNTIME_TOPOLOGY_DDL, ())
                .await
                .map_err(|_| {
                    Error::engine("Turso-local profile upgrade could not install v4 marker")
                })?;
            let inserted = connection
                .execute(
                    "INSERT INTO _native_turso_runtime(singleton,logical_database_id,profile_revision) SELECT singleton,logical_database_id,4 FROM _native_turso_runtime_v3 WHERE singleton=1 AND profile_revision=3",
                    (),
                )
                .await
                .map_err(|_| {
                    Error::engine("Turso-local profile upgrade could not copy v3 identity")
                })?;
            if inserted != 1 {
                return Err(Error::engine(
                    "Turso-local profile upgrade found an invalid v3 identity",
                ));
            }
            connection
                .execute("DROP TABLE _native_turso_runtime_v3", ())
                .await
                .map_err(|_| {
                    Error::engine("Turso-local profile upgrade could not retire v3 marker")
                })?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = upgrade {
            let _ = connection.execute("ROLLBACK", ()).await;
            return Err(error);
        }
        connection
            .execute("COMMIT", ())
            .await
            .map_err(|_| Error::engine("cannot commit Turso-local profile upgrade"))?;
        return reconcile_run_context_overlay(connection).await;
    }
    if topology_sql != TURSO_RUNTIME_TOPOLOGY_DDL_V2 {
        return Err(Error::engine(
            "Turso-local database has an unsupported runtime profile marker",
        ));
    }
    let stored = scalar_text(
        connection,
        "SELECT logical_database_id FROM _native_turso_runtime WHERE singleton=1 AND profile_revision=2",
    )
    .await?;
    if stored != logical_database_id {
        return Err(Error::engine(
            "Turso-local database belongs to a different logical database",
        ));
    }

    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|_| Error::engine("cannot begin Turso-local profile upgrade"))?;
    let upgrade = async {
        connection
            .execute(
                "ALTER TABLE _native_turso_runtime RENAME TO _native_turso_runtime_v2",
                (),
            )
            .await
            .map_err(|_| Error::engine("Turso-local profile upgrade could not preserve v2 marker"))?;
        connection
            .execute(TURSO_RUNTIME_TOPOLOGY_DDL_V3, ())
            .await
            .map_err(|_| Error::engine("Turso-local profile upgrade could not install v3 marker"))?;
        let inserted = connection
            .execute(
                "INSERT INTO _native_turso_runtime(singleton,logical_database_id,profile_revision) SELECT singleton,logical_database_id,3 FROM _native_turso_runtime_v2 WHERE singleton=1 AND profile_revision=2",
                (),
            )
            .await
            .map_err(|_| Error::engine("Turso-local profile upgrade could not copy v2 identity"))?;
        if inserted != 1 {
            return Err(Error::engine(
                "Turso-local profile upgrade found an invalid v2 identity",
            ));
        }
        connection
            .execute("DROP TABLE _native_turso_runtime_v2", ())
            .await
            .map_err(|_| Error::engine("Turso-local profile upgrade could not retire v2 marker"))?;
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = upgrade {
        let _ = connection.execute("ROLLBACK", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|_| Error::engine("cannot commit Turso-local profile upgrade"))?;
    Box::pin(reconcile_runtime_profile(connection, logical_database_id)).await
}

async fn reconcile_run_context_overlay(connection: &turso::Connection) -> Result<()> {
    let stored = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='table' AND name='run_contexts'),'')",
    )
    .await?;
    if stored == TURSO_RUN_CONTEXTS_DDL {
        return Ok(());
    }
    if !stored.is_empty() {
        return Err(Error::engine(
            "Turso-local database has an incompatible run-context overlay",
        ));
    }
    connection
        .execute(TURSO_RUN_CONTEXTS_DDL, ())
        .await
        .map_err(|_| Error::engine("Turso-local run-context overlay upgrade failed"))?;
    Ok(())
}

async fn physical_overlay_names(connection: &turso::Connection) -> Result<BTreeSet<&'static str>> {
    let mut overlays = BTreeSet::new();
    let facet_sql = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='table' AND name='facet_values'),'')",
    )
    .await?;
    if facet_sql == TURSO_FACET_VALUES_DDL {
        overlays.insert("projection.facet-value-number");
    }
    let records_fts = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='index' AND name='records_turso_fts'),'')",
    )
    .await?;
    let records_name_fts = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='index' AND name='records_name_turso_fts'),'')",
    )
    .await?;
    if records_fts == TURSO_RECORDS_FTS_DDL && records_name_fts == TURSO_RECORDS_NAME_FTS_DDL {
        overlays.insert("search.turso-fts");
    }
    let topology_sql = scalar_text(
        connection,
        "SELECT COALESCE((SELECT sql FROM sqlite_schema WHERE type='table' AND name='_native_turso_runtime'),'')",
    )
    .await?;
    if topology_sql == TURSO_RUNTIME_TOPOLOGY_DDL {
        overlays.insert("topology.logical-database-identity");
    }
    Ok(overlays)
}

async fn validate_runtime(connection: &turso::Connection, logical_database_id: &str) -> Result<()> {
    let version = scalar_i64(connection, "PRAGMA user_version").await?;
    if version != crate::CURRENT_ENGINE_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "Turso-local schema version {version} is not the required version {}",
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        )));
    }
    let stored = scalar_text(
        connection,
        "SELECT logical_database_id FROM _native_turso_runtime WHERE singleton=1 AND profile_revision=4",
    )
    .await?;
    if stored != logical_database_id {
        return Err(Error::engine(
            "Turso-local database belongs to a different logical database",
        ));
    }
    if physical_overlay_names(connection).await?.len() != 3 {
        return Err(Error::engine(
            "Turso-local database is missing a required physical overlay",
        ));
    }
    if !required_runtime_schema_ready(connection).await? {
        return Err(Error::engine("Turso-local required schema is incomplete"));
    }
    if !runtime_genesis_ready(connection).await? {
        return Err(Error::engine(
            "Turso-local content/policy genesis is incomplete",
        ));
    }
    if !seeded_runtime_vocabulary_ready(connection).await? {
        return Err(Error::engine(
            "Turso-local governed vocabulary genesis is incomplete",
        ));
    }
    Ok(())
}

fn ddl_names_object(statement: &str, prefix: &str, name: &str) -> bool {
    statement
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(name))
        .and_then(|rest| rest.chars().next())
        .is_some_and(|next| next.is_whitespace() || next == '(')
}

fn ddl_trigger_name(statement: &str) -> Option<&str> {
    let mut words = statement.split_whitespace();
    if words.next()? != "CREATE" || words.next()? != "TRIGGER" {
        return None;
    }
    let next = words.next()?;
    if next == "IF" {
        (words.next()? == "NOT" && words.next()? == "EXISTS").then(|| words.next())?
    } else {
        Some(next)
    }
}

fn ddl_trigger_targets_required_table(statement: &str) -> bool {
    TURSO_REQUIRED_RUNTIME_TABLES
        .iter()
        .any(|table| statement.contains(&format!(" ON {table}")))
}

fn compiled_runtime_schema_definition(object_type: &str, name: &str) -> Result<&'static str> {
    if object_type == "table" && name == "facet_values" {
        return Ok(TURSO_FACET_VALUES_DDL);
    }
    if object_type == "table" && name == "run_contexts" {
        return Ok(TURSO_RUN_CONTEXTS_DDL);
    }
    crate::schema::DDL_STATEMENTS
        .iter()
        .copied()
        .find(|statement| match object_type {
            "table" => ddl_names_object(statement, "CREATE TABLE ", name),
            "index" => {
                ddl_names_object(statement, "CREATE INDEX ", name)
                    || ddl_names_object(statement, "CREATE UNIQUE INDEX ", name)
            }
            "trigger" => ddl_trigger_name(statement) == Some(name),
            _ => false,
        })
        .ok_or_else(|| {
            Error::engine(format!(
                "compiled Turso-local schema contract is missing {object_type} {name}"
            ))
        })
}

fn normalized_runtime_schema_sql(sql: String) -> String {
    // Turso 0.7.2 quotes its two reserved identifiers and rewrites SQLite's
    // equivalent `<>` comparison spelling to `!=`. Canonicalize only those
    // pinned-driver equivalences; columns, constraints, defaults, predicates
    // and index properties remain load-bearing.
    crate::db::normalized_schema_sql(Some(sql))
        .replace("\"key\"", "key")
        .replace("\"action\"", "action")
        .replace("<>", "!=")
}

fn compiled_required_runtime_schema() -> Result<BTreeMap<(String, String), String>> {
    let mut contract = TURSO_REQUIRED_RUNTIME_TABLES
        .iter()
        .map(|name| ("table", *name))
        .chain(
            TURSO_REQUIRED_RUNTIME_INDEXES
                .iter()
                .map(|name| ("index", *name)),
        )
        .map(|(object_type, name)| {
            Ok((
                (object_type.into(), name.into()),
                normalized_runtime_schema_sql(
                    compiled_runtime_schema_definition(object_type, name)?.into(),
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for statement in crate::schema::DDL_STATEMENTS {
        let Some(name) = ddl_trigger_name(statement) else {
            continue;
        };
        if !sqlite_fts_statement(statement) && ddl_trigger_targets_required_table(statement) {
            contract.insert(
                ("trigger".into(), name.into()),
                normalized_runtime_schema_sql(
                    compiled_runtime_schema_definition("trigger", name)?.into(),
                ),
            );
        }
    }
    Ok(contract)
}

async fn installed_required_runtime_schema(
    connection: &turso::Connection,
    expected: &BTreeMap<(String, String), String>,
) -> Result<BTreeMap<(String, String), String>> {
    let names = expected
        .keys()
        .map(|(_, name)| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(",");
    let mut rows = connection
        .query(
            &format!(
                "SELECT type,name,sql FROM sqlite_schema WHERE name IN ({names}) ORDER BY type,name"
            ),
            (),
        )
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local required schema"))?;
    let mut actual = BTreeMap::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local required schema"))?
    {
        let object_type: String = row
            .get(0)
            .map_err(|_| Error::engine("invalid Turso-local required schema object type"))?;
        let name: String = row
            .get(1)
            .map_err(|_| Error::engine("invalid Turso-local required schema object name"))?;
        let sql: Option<String> = row
            .get(2)
            .map_err(|_| Error::engine("invalid Turso-local required schema definition"))?;
        let Some(sql) = sql else {
            return Err(Error::engine(
                "Turso-local required schema object has no installed definition",
            ));
        };
        actual.insert((object_type, name), normalized_runtime_schema_sql(sql));
    }
    Ok(actual)
}

async fn required_runtime_schema_ready(connection: &turso::Connection) -> Result<bool> {
    let expected = compiled_required_runtime_schema()?;
    Ok(installed_required_runtime_schema(connection, &expected).await? == expected)
}

async fn runtime_genesis_ready(connection: &turso::Connection) -> Result<bool> {
    Ok(scalar_i64(
        connection,
        "SELECT COUNT(*) FROM records WHERE (id='native:root' AND type='Collection' AND kind='folder' AND policy_anchor_id='native:root' AND deleted_at IS NULL) OR (id='native:unfiled' AND type='Collection' AND kind='folder' AND home_id='native:root' AND policy_anchor_id='native:root' AND deleted_at IS NULL)",
    )
    .await?
        == 2
        && scalar_i64(connection, "SELECT COUNT(*) FROM record_policies WHERE record_id='native:root'").await? == 1
        && scalar_i64(connection, "SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='members' AND subject_id='native:members' AND effect='allow' AND capability='edit'").await? == 1
        && scalar_i64(connection, "SELECT COUNT(*) FROM policy_events WHERE record_id='native:root' AND type='policy.replaced'").await? == 1
        && scalar_i64(connection, "SELECT COUNT(*) FROM database_identity WHERE singleton=1 AND origin_db_id<>''").await? == 1
        && scalar_i64(connection, "SELECT COUNT(*) FROM database_identity_audit WHERE action='mint' AND new_origin_db_id IS NOT NULL").await? == 1)
}

async fn vocabulary_row_ready(
    connection: &turso::Connection,
    id: &str,
    vocabulary_id: &str,
    value: &str,
    ordinal: f64,
    terminality: &str,
    metadata: &Value,
) -> Result<bool> {
    let mut rows = connection
        .query(
            "SELECT vocabulary_id,value,status,ordinal,terminality,metadata FROM vocabulary_values WHERE id=?1",
            [id],
        )
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local governed vocabulary"))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local governed vocabulary"))?
    else {
        return Ok(false);
    };
    let stored_vocabulary: String = row
        .get(0)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    let stored_value: String = row
        .get(1)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    let status: String = row
        .get(2)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    let stored_ordinal: f64 = row
        .get(3)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    let stored_terminality: String = row
        .get(4)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    let stored_metadata: String = row
        .get(5)
        .map_err(|_| Error::engine("invalid Turso-local governed vocabulary"))?;
    Ok(stored_vocabulary == vocabulary_id
        && stored_value == value
        && matches!(status.as_str(), "active" | "deprecated")
        && stored_ordinal == ordinal
        && stored_terminality == terminality
        && serde_json::from_str::<Value>(&stored_metadata)? == *metadata)
}

async fn seeded_runtime_vocabulary_ready(connection: &turso::Connection) -> Result<bool> {
    for (name, values) in crate::meta::vocabulary::SEED_VOCABULARIES {
        let vocabulary_id = format!("voc:{name}");
        if scalar_i64(
            connection,
            &format!(
                "SELECT COUNT(*) FROM vocabularies WHERE id='{}' AND name='{}'",
                vocabulary_id.replace('\'', "''"),
                name.replace('\'', "''")
            ),
        )
        .await?
            != 1
        {
            return Ok(false);
        }
        for (value, ordinal, terminality) in values.seeded() {
            let value_id = format!("vv:{vocabulary_id}:{value}");
            if !vocabulary_row_ready(
                connection,
                &value_id,
                &vocabulary_id,
                value,
                ordinal,
                terminality.as_str(),
                &serde_json::json!({}),
            )
            .await?
            {
                return Ok(false);
            }
        }
    }
    let manifest = crate::meta::kind::core_kind_manifest()?;
    for record_type in crate::schema::SPINE_TYPES {
        let vocabulary_id = crate::meta::kind::kind_vocabulary_id(record_type);
        let vocabulary_name = crate::meta::kind::kind_vocabulary_name(record_type);
        if scalar_i64(
            connection,
            &format!(
                "SELECT COUNT(*) FROM vocabularies WHERE id='{}' AND name='{}'",
                vocabulary_id.replace('\'', "''"),
                vocabulary_name.replace('\'', "''")
            ),
        )
        .await?
            != 1
        {
            return Ok(false);
        }
        for kind in manifest
            .kinds
            .iter()
            .filter(|kind| kind.record_type == record_type)
        {
            if !vocabulary_row_ready(
                connection,
                &kind.value_id,
                &vocabulary_id,
                &kind.token,
                0.0,
                "open",
                &serde_json::to_value(&kind.metadata)?,
            )
            .await?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn seeded_runtime_schema_config_ready(connection: &turso::Connection) -> Result<bool> {
    let expected = crate::meta::schema_config::recommended_pack_schema_config().to_string();
    let mut rows = connection
        .query(
            "SELECT layer,name,data FROM schema_config WHERE id='pack:@native/recommended'",
            (),
        )
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local schema-config genesis"))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local schema-config genesis"))?
    else {
        return Ok(false);
    };
    let layer: String = row
        .get(0)
        .map_err(|_| Error::engine("invalid Turso-local schema-config genesis"))?;
    let name: String = row
        .get(1)
        .map_err(|_| Error::engine("invalid Turso-local schema-config genesis"))?;
    let data: String = row
        .get(2)
        .map_err(|_| Error::engine("invalid Turso-local schema-config genesis"))?;
    Ok(layer == "pack"
        && name == crate::meta::schema_config::RECOMMENDED_PACK_NAME
        && data == expected)
}

fn statement(
    kind: StatementKind,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> SqlResult<StatementTemplate> {
    StatementTemplate::new(kind, relation, fragments)
}

fn stable(operation: &str, error: SqlError) -> Error {
    crate::domain_transaction::stable_storage_error(operation, &error)
}

fn text(row: &NormalizedRow, column: &str, context: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn optional_text(row: &NormalizedRow, column: &str, context: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn integer(row: &NormalizedRow, column: &str, context: &str) -> Result<i64> {
    match row.get(column) {
        Some(NormalizedValue::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn boolean(row: &NormalizedRow, column: &str, context: &str) -> Result<bool> {
    match row.get(column) {
        Some(NormalizedValue::Bool(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn json_binding(value: &Value) -> BindValue {
    match value {
        Value::Null => BindValue::Null(LogicalType::Text),
        Value::Bool(value) => BindValue::Bool(*value),
        Value::Number(value) if value.is_i64() => BindValue::Integer(value.as_i64().unwrap()),
        Value::Number(value) => BindValue::Real(value.as_f64().unwrap_or(f64::NAN)),
        Value::String(value) => BindValue::Text(value.clone()),
        value => BindValue::Json(value.clone()),
    }
}

fn optional_binding(value: Option<&str>) -> BindValue {
    value
        .map(|value| BindValue::Text(value.to_string()))
        .unwrap_or(BindValue::Null(LogicalType::Text))
}

#[derive(Debug)]
struct TursoCommentRecord {
    record_type: String,
    kind: Option<String>,
    body: Option<String>,
    lifecycle: Option<String>,
    summary: Option<String>,
    deleted_at: Option<String>,
}

async fn governed_comment_in(
    transaction: &mut TursoDomainTransaction<'_>,
    record_type: &str,
    kind: Option<&str>,
) -> Result<bool> {
    let Some(kind) = kind else { return Ok(false) };
    let resolution = crate::meta::kind::resolve_with(transaction, record_type, kind).await?;
    Ok(crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution))
}

async fn comment_record_in(
    transaction: &mut TursoDomainTransaction<'_>,
    id: &str,
) -> Result<Option<TursoCommentRecord>> {
    let select = statement(
        StatementKind::Select,
        "records",
        &[
            "SELECT type,kind,body,lifecycle,summary,deleted_at FROM {{relation}} WHERE id=",
            "",
        ],
    )
    .map_err(|error| stable("read comment record", error))?;
    let rows = transaction
        .rows(
            "read comment record",
            &select,
            &[BindValue::Text(id.into())],
            &[
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("kind", LogicalType::Text),
                ColumnSpec::nullable("body", LogicalType::Text),
                ColumnSpec::nullable("lifecycle", LogicalType::Text),
                ColumnSpec::nullable("summary", LogicalType::Text),
                ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ],
        )
        .await?;
    rows.first()
        .map(|row| {
            Ok(TursoCommentRecord {
                record_type: text(row, "type", "comment record")?,
                kind: optional_text(row, "kind", "comment record")?,
                body: optional_text(row, "body", "comment record")?,
                lifecycle: optional_text(row, "lifecycle", "comment record")?,
                summary: optional_text(row, "summary", "comment record")?,
                deleted_at: optional_text(row, "deleted_at", "comment record")?,
            })
        })
        .transpose()
}

async fn comment_bearers_in(
    transaction: &mut TursoDomainTransaction<'_>,
    id: &str,
) -> Result<Vec<String>> {
    let select = statement(
        StatementKind::Select,
        "links",
        &[
            "SELECT target_id FROM {{relation}} WHERE source_id=",
            " AND relationship='part_of' ORDER BY target_id",
        ],
    )
    .map_err(|error| stable("read comment bearer", error))?;
    transaction
        .rows(
            "read comment bearer",
            &select,
            &[BindValue::Text(id.into())],
            &[ColumnSpec::required("target_id", LogicalType::Text)],
        )
        .await?
        .iter()
        .map(|row| text(row, "target_id", "comment bearer"))
        .collect()
}

async fn comment_position_for_bearer_in(
    transaction: &mut TursoDomainTransaction<'_>,
    tool: &str,
    bearer_id: &str,
) -> Result<crate::comments::Position> {
    let bearer = comment_record_in(transaction, bearer_id)
        .await?
        .ok_or_else(|| Error::engine(format!("{tool}: comment bearer does not exist")))?;
    if bearer.deleted_at.is_some() {
        return Err(Error::engine(format!(
            "{tool}: comment bearer is deleted (tombstoned)"
        )));
    }
    if !governed_comment_in(transaction, &bearer.record_type, bearer.kind.as_deref()).await? {
        return Ok(crate::comments::Position::Root);
    }
    crate::comments::validate_prospective(
        tool,
        crate::comments::Position::Root,
        bearer.body.as_deref(),
        bearer.lifecycle.as_deref(),
        bearer.summary.as_deref(),
    )?;
    let root_bearers = comment_bearers_in(transaction, bearer_id).await?;
    if root_bearers.len() != 1 {
        return Err(Error::engine(format!(
            "{tool}: reply bearer must be a valid root comment"
        )));
    }
    let root_target = comment_record_in(transaction, &root_bearers[0])
        .await?
        .ok_or_else(|| Error::engine(format!("{tool}: reply bearer has a dead bearer")))?;
    if root_target.deleted_at.is_some() {
        return Err(Error::engine(format!(
            "{tool}: reply bearer has a dead bearer"
        )));
    }
    if governed_comment_in(
        transaction,
        &root_target.record_type,
        root_target.kind.as_deref(),
    )
    .await?
    {
        return Err(Error::engine(format!(
            "{tool}: replies must bear directly on a root comment; reply-to-reply nesting is not supported"
        )));
    }
    Ok(crate::comments::Position::Reply)
}

fn optional_string_field<'a>(tool: &str, name: &str, value: &'a Value) -> Result<Option<&'a str>> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value)),
        _ => Err(Error::engine(format!(
            "{tool}: '{name}' must be a string or null"
        ))),
    }
}

/// One admitted local-Turso transaction. The control token is stored beside
/// the maintained portable executor so every shared relational read and every
/// named physical write has the same cancellation/poisoning semantics.
struct TursoDomainTransaction<'connection> {
    inner: TursoTransaction<'connection>,
    control: ExecutionControl,
}

impl TursoDomainTransaction<'_> {
    async fn execute(
        &mut self,
        operation: &str,
        statement: &StatementTemplate,
        bindings: &[BindValue],
    ) -> Result<u64> {
        self.inner
            .execute(statement, bindings, &self.control)
            .await
            .map_err(|error| stable(operation, error))
    }

    async fn rows(
        &mut self,
        operation: &str,
        statement: &StatementTemplate,
        bindings: &[BindValue],
        columns: &[ColumnSpec],
    ) -> Result<Vec<NormalizedRow>> {
        self.inner
            .fetch_all(statement, bindings, columns, &self.control)
            .await
            .map_err(|error| stable(operation, error))
    }

    async fn next_record_updated_at(&mut self, record_id: &str, at: &str) -> Result<String> {
        let select = statement(
            StatementKind::Select,
            "records",
            &["SELECT updated_at FROM {{relation}} WHERE id = ", ""],
        )
        .map_err(|error| stable("advance record updated_at", error))?;
        let rows = self
            .rows(
                "advance record updated_at",
                &select,
                &[BindValue::Text(record_id.into())],
                &[ColumnSpec::required("updated_at", LogicalType::Text)],
            )
            .await?;
        let current_raw = rows
            .first()
            .map(|row| text(row, "updated_at", "record"))
            .transpose()?
            .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
        let current = DateTime::parse_from_rfc3339(&current_raw)
            .map_err(|_| {
                Error::engine(format!(
                    "record '{record_id}' has an invalid stored updated_at timestamp"
                ))
            })?
            .with_timezone(&Utc);
        let candidate = DateTime::parse_from_rfc3339(at)
            .map_err(|_| Error::engine("event has an invalid created_at timestamp"))?
            .with_timezone(&Utc);
        let next = if candidate > current {
            candidate
        } else {
            current + Duration::milliseconds(1)
        };
        Ok(next.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    async fn touch(&mut self, record_id: &str, at: &str) -> Result<()> {
        let updated_at = self.next_record_updated_at(record_id, at).await?;
        let statement = statement(
            StatementKind::Update,
            "records",
            &[
                "UPDATE {{relation}} SET updated_at = ",
                ", last_activity_at = ",
                " WHERE id = ",
                "",
            ],
        )
        .map_err(|error| stable("touch record", error))?;
        self.execute(
            "touch record",
            &statement,
            &[
                BindValue::Text(updated_at),
                BindValue::Text(at.into()),
                BindValue::Text(record_id.into()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn refresh_policy_anchor_subtree(&mut self, record_id: &str) -> Result<()> {
        // Recursive SQL is intentionally outside StatementTemplate. The named
        // adapter performs the same fold with bounded relational steps.
        let parent_statement = statement(
            StatementKind::Select,
            "records",
            &[
                "SELECT r.home_id, r.policy_anchor_id AS current_anchor, parent.policy_anchor_id, EXISTS(SELECT 1 FROM record_policies p WHERE p.record_id = r.id) AS explicit FROM {{relation}} r LEFT JOIN records parent ON parent.id = r.home_id WHERE r.id = ",
                "",
            ],
        )
        .map_err(|error| stable("refresh policy anchor", error))?;
        let children_statement = statement(
            StatementKind::Select,
            "records",
            &[
                "SELECT id FROM {{relation}} WHERE home_id = ",
                " ORDER BY id",
            ],
        )
        .map_err(|error| stable("refresh policy anchor", error))?;
        let update_statement = statement(
            StatementKind::Update,
            "records",
            &[
                "UPDATE {{relation}} SET policy_anchor_id = ",
                " WHERE id = ",
                "",
            ],
        )
        .map_err(|error| stable("refresh policy anchor", error))?;
        let mut queue = VecDeque::from([record_id.to_string()]);
        let mut inherited: BTreeMap<String, String> = BTreeMap::new();
        while let Some(id) = queue.pop_front() {
            let rows = self
                .rows(
                    "refresh policy anchor",
                    &parent_statement,
                    &[BindValue::Text(id.clone())],
                    &[
                        ColumnSpec::nullable("home_id", LogicalType::Text),
                        ColumnSpec::nullable("current_anchor", LogicalType::Text),
                        ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
                        ColumnSpec::required("explicit", LogicalType::Bool),
                    ],
                )
                .await?;
            let Some(row) = rows.first() else {
                return Err(Error::engine(format!("record '{id}' not found")));
            };
            let anchor = if boolean(row, "explicit", "policy anchor")? {
                id.clone()
            } else if let Some(anchor) = inherited.get(&id) {
                anchor.clone()
            } else {
                optional_text(row, "policy_anchor_id", "policy anchor")?.ok_or_else(|| {
                    Error::engine(format!(
                        "policy inheritance from '{record_id}' does not terminate at an explicit boundary"
                    ))
                })?
            };
            // Skip a row whose anchor is already what the fold computed.
            // Rewriting an unchanged `policy_anchor_id` is invisible to
            // readers but not to the engine: it advanced the database-wide
            // authorization epoch once per subtree row, so re-anchoring a
            // large folder told every subscriber to re-read for a change that
            // had not happened.
            if optional_text(row, "current_anchor", "policy anchor")?.as_deref() != Some(&anchor) {
                self.execute(
                    "refresh policy anchor",
                    &update_statement,
                    &[BindValue::Text(anchor.clone()), BindValue::Text(id.clone())],
                )
                .await?;
            }
            let children = self
                .rows(
                    "refresh policy anchor",
                    &children_statement,
                    &[BindValue::Text(id)],
                    &[ColumnSpec::required("id", LogicalType::Text)],
                )
                .await?;
            for child in children {
                let child = text(&child, "id", "policy child")?;
                inherited.insert(child.clone(), anchor.clone());
                queue.push_back(child);
            }
        }
        Ok(())
    }
}

impl DomainStatementExecutor for TursoDomainTransaction<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            self.inner
                .fetch_all(statement, bindings, columns, &self.control)
                .await
        })
    }
}

impl crate::domain_transaction::search::SearchPhysicalPort for TursoDomainTransaction<'_> {
    fn native_lexical_candidates<'a>(
        &'a mut self,
        terms: &'a [String],
        eligible_ids: &'a HashSet<String>,
        cap: i64,
    ) -> BoxFuture<'a, Result<Vec<crate::domain_transaction::search::NativeSearchCandidate>>> {
        Box::pin(async move {
            if eligible_ids.is_empty() {
                return Ok(Vec::new());
            }
            let transaction = self
                .inner
                .native_search_transaction()
                .map_err(|error| stable("search turso native FTS", error))?;
            let mut intersection: Option<
                HashMap<String, crate::domain_transaction::search::NativeSearchCandidate>,
            > = None;
            for term in terms {
                // Terms come from the shared alphanumeric tokenizer. Quoting
                // still matters because words such as OR are FTS grammar in
                // their unquoted form even when supplied as a bound value.
                let match_term = format!("\"{term}\"");
                let mut term_hits = HashMap::new();
                for column in ["name", "body"] {
                    let sql = format!(
                        "SELECT id,substr(coalesce(name,''),1,512) AS name,\
                                substr(body,1,4096) AS body \
                         FROM records WHERE {column} MATCH ?1 ORDER BY id"
                    );
                    let mut rows = transaction
                        .query(&sql, turso::params![match_term.as_str()])
                        .await
                        .map_err(|_| {
                            Error::engine("search: turso-local native FTS execution failed")
                        })?;
                    while let Some(row) = rows.next().await.map_err(|_| {
                        Error::engine("search: turso-local native FTS execution failed")
                    })? {
                        let candidate = crate::domain_transaction::search::NativeSearchCandidate {
                            id: row.get(0).map_err(|_| {
                                Error::engine("search: turso-local native FTS returned invalid id")
                            })?,
                            name: row.get(1).map_err(|_| {
                                Error::engine(
                                    "search: turso-local native FTS returned invalid name",
                                )
                            })?,
                            body: row.get(2).map_err(|_| {
                                Error::engine(
                                    "search: turso-local native FTS returned invalid body",
                                )
                            })?,
                        };
                        if !eligible_ids.contains(&candidate.id) {
                            continue;
                        }
                        term_hits.insert(candidate.id.clone(), candidate);
                    }
                }
                intersection = Some(match intersection.take() {
                    None => term_hits,
                    Some(mut current) => {
                        current.retain(|id, _| term_hits.contains_key(id));
                        current
                    }
                });
                if intersection.as_ref().is_some_and(HashMap::is_empty) {
                    break;
                }
            }
            let mut candidates = intersection
                .unwrap_or_default()
                .into_values()
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| left.id.cmp(&right.id));
            candidates.truncate(cap as usize);
            Ok(candidates)
        })
    }
}

impl ContentSemanticStatePort for TursoDomainTransaction<'_> {
    fn record_state<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<RecordSemanticState>>> {
        Box::pin(async move {
            let statement = statement(
                StatementKind::Select,
                "records",
                &[
                    "SELECT r.type, r.kind, r.persistence, r.deleted_at, r.policy_anchor_id, EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id = r.id AND f.key = ",
                    ") AS archived, EXISTS(SELECT 1 FROM annotation_targets t WHERE t.annotation_id = r.id) AS targeted, EXISTS(SELECT 1 FROM attribution_targets a WHERE a.annotation_id = r.id) AS attributed, EXISTS(SELECT 1 FROM semantic_units u WHERE u.unit_id = r.id) AS semantic_unit, (SELECT status FROM message_audience_state m WHERE m.message_id = r.id) AS message_status FROM {{relation}} r WHERE r.id = ",
                    "",
                ],
            )
            .map_err(|error| stable("read projector state", error))?;
            let rows = self
                .rows(
                    "read projector state",
                    &statement,
                    &[
                        BindValue::Text(crate::schema::ARCHIVED_FACET_KEY.into()),
                        BindValue::Text(record_id.into()),
                    ],
                    &[
                        ColumnSpec::required("type", LogicalType::Text),
                        ColumnSpec::nullable("kind", LogicalType::Text),
                        ColumnSpec::required("persistence", LogicalType::Text),
                        ColumnSpec::nullable("deleted_at", LogicalType::Text),
                        ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
                        ColumnSpec::required("archived", LogicalType::Bool),
                        ColumnSpec::required("targeted", LogicalType::Bool),
                        ColumnSpec::required("attributed", LogicalType::Bool),
                        ColumnSpec::required("semantic_unit", LogicalType::Bool),
                        ColumnSpec::nullable("message_status", LogicalType::Text),
                    ],
                )
                .await?;
            rows.first()
                .map(|row| {
                    Ok(RecordSemanticState {
                        record_type: text(row, "type", "projector record")?,
                        kind: optional_text(row, "kind", "projector record")?,
                        persistence: text(row, "persistence", "projector record")?,
                        deleted: optional_text(row, "deleted_at", "projector record")?.is_some(),
                        policy_anchor_id: optional_text(
                            row,
                            "policy_anchor_id",
                            "projector record",
                        )?,
                        archived: boolean(row, "archived", "projector record")?,
                        targeted: boolean(row, "targeted", "projector record")?,
                        attributed: boolean(row, "attributed", "projector record")?,
                        semantic_unit: boolean(row, "semantic_unit", "projector record")?,
                        message_status: optional_text(row, "message_status", "projector record")?,
                    })
                })
                .transpose()
        })
    }

    fn home_would_cycle<'a>(
        &'a mut self,
        record_id: &'a str,
        home_id: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let statement = statement(
                StatementKind::Select,
                "records",
                &["SELECT home_id FROM {{relation}} WHERE id = ", ""],
            )
            .map_err(|error| stable("check home cycle", error))?;
            let mut cursor = Some(home_id.to_string());
            let mut seen = std::collections::BTreeSet::new();
            while let Some(id) = cursor {
                if id == record_id {
                    return Ok(true);
                }
                if !seen.insert(id.clone()) {
                    return Ok(true);
                }
                let rows = self
                    .rows(
                        "check home cycle",
                        &statement,
                        &[BindValue::Text(id)],
                        &[ColumnSpec::nullable("home_id", LogicalType::Text)],
                    )
                    .await?;
                cursor = rows
                    .first()
                    .map(|row| optional_text(row, "home_id", "home cycle"))
                    .transpose()?
                    .flatten();
            }
            Ok(false)
        })
    }

    fn first_live_child<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let statement = statement(
                StatementKind::Select,
                "records",
                &[
                    "SELECT id FROM {{relation}} WHERE home_id = ",
                    " AND deleted_at IS NULL ORDER BY id LIMIT 1",
                ],
            )
            .map_err(|error| stable("read live child", error))?;
            self.rows(
                "read live child",
                &statement,
                &[BindValue::Text(record_id.into())],
                &[ColumnSpec::required("id", LogicalType::Text)],
            )
            .await?
            .first()
            .map(|row| text(row, "id", "live child"))
            .transpose()
        })
    }

    fn link_identity<'a>(
        &'a mut self,
        source_id: &'a str,
        target_id: &'a str,
        relationship: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let statement = statement(
                StatementKind::Select,
                "links",
                &[
                    "SELECT id FROM {{relation}} WHERE source_id = ",
                    " AND target_id = ",
                    " AND relationship = ",
                    " LIMIT 1",
                ],
            )
            .map_err(|error| stable("read link identity", error))?;
            self.rows(
                "read link identity",
                &statement,
                &[
                    BindValue::Text(source_id.into()),
                    BindValue::Text(target_id.into()),
                    BindValue::Text(relationship.into()),
                ],
                &[ColumnSpec::required("id", LogicalType::Text)],
            )
            .await?
            .first()
            .map(|row| text(row, "id", "link identity"))
            .transpose()
        })
    }
}

impl EventCursorPort for TursoDomainTransaction<'_> {
    fn append_event<'a>(
        &'a mut self,
        event: &'a mut EventRow,
        causal_admission: &'a CausalAdmission,
        _control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let causal_envelope = match causal_admission {
                CausalAdmission::LocalComputed => {
                    let heads = self
                        .rows(
                            "read causal heads",
                            &statement(
                                StatementKind::Select,
                                "content_events",
                                &["SELECT event.id FROM {{relation}} event WHERE NOT EXISTS (SELECT 1 FROM content_event_causal_frontier frontier WHERE frontier.parent_event_id=event.id) ORDER BY event.id"],
                            )
                            .map_err(|error| stable("read causal heads", error))?,
                            &[],
                            &[ColumnSpec::required("id", LogicalType::Text)],
                        )
                        .await?
                        .iter()
                        .map(|row| text(row, "id", "causal head"))
                        .collect::<Result<Vec<_>>>()?;
                    if heads.is_empty() {
                        let count = self
                            .rows(
                                "read content event count",
                                &statement(
                                    StatementKind::Select,
                                    "content_events",
                                    &["SELECT COUNT(*) AS count FROM {{relation}}"],
                                )
                                .map_err(|error| stable("read content event count", error))?,
                                &[],
                                &[ColumnSpec::required("count", LogicalType::Integer)],
                            )
                            .await?;
                        if integer(&count[0], "count", "content event count")? != 0 {
                            return Err(Error::engine(
                                "content event causal state has no heads for a nonempty log",
                            ));
                        }
                    }
                    CausalEnvelopeV1::complete(CausalFrontierV1::new(heads)?)
                }
                CausalAdmission::GovernedImport(_) => {
                    return Err(Error::engine(
                        "Turso-local governed causal import is not supported",
                    ));
                }
            };
            causal_envelope.validate_for_event(&event.id)?;
            let parent_statement = statement(
                StatementKind::Select,
                "content_event_causal_frontier",
                &[
                    "SELECT parent_event_id FROM {{relation}} WHERE event_id = ",
                    "",
                ],
            )
            .map_err(|error| stable("validate causal frontier", error))?;
            for parent_event_id in causal_envelope.frontier().as_slice() {
                let mut pending = vec![parent_event_id.clone()];
                let mut seen = std::collections::BTreeSet::new();
                while let Some(ancestor) = pending.pop() {
                    if ancestor == event.id {
                        return Err(Error::engine("causal frontier would create a cycle"));
                    }
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    let rows = self
                        .rows(
                            "validate causal frontier",
                            &parent_statement,
                            &[BindValue::Text(ancestor)],
                            &[ColumnSpec::required("parent_event_id", LogicalType::Text)],
                        )
                        .await?;
                    pending.extend(
                        rows.iter()
                            .map(|row| text(row, "parent_event_id", "causal frontier"))
                            .collect::<Result<Vec<_>>>()?,
                    );
                }
            }
            event.causal_envelope = causal_envelope;
            let insert = statement(
                StatementKind::Insert,
                "content_events",
                &[
                    "INSERT INTO {{relation}} (id, record_id, type, payload, actor, run_key, parent_key, intent, created_at, causal_envelope_version, causal_status) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("append event", error))?;
            self.execute(
                "append event",
                &insert,
                &[
                    BindValue::Text(event.id.clone()),
                    BindValue::Text(event.record_id.clone()),
                    BindValue::Text(event.event_type.clone()),
                    optional_binding(event.payload.as_deref()),
                    optional_binding(event.actor.as_deref()),
                    optional_binding(event.run_key.as_deref()),
                    optional_binding(event.parent_key.as_deref()),
                    optional_binding(event.intent.as_deref()),
                    BindValue::Text(event.created_at.clone()),
                    BindValue::Integer(event.causal_envelope.version().as_i64()),
                    BindValue::Text(event.causal_envelope.status().as_str().into()),
                ],
            )
            .await?;
            let insert_frontier = statement(
                StatementKind::Insert,
                "content_event_causal_frontier",
                &[
                    "INSERT INTO {{relation}} (event_id,parent_event_id) VALUES (",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("append causal frontier", error))?;
            for parent_event_id in event.causal_envelope.frontier().as_slice() {
                self.execute(
                    "append causal frontier",
                    &insert_frontier,
                    &[
                        BindValue::Text(event.id.clone()),
                        BindValue::Text(parent_event_id.clone()),
                    ],
                )
                .await?;
            }
            let select = statement(
                StatementKind::Select,
                "content_events",
                &["SELECT seq FROM {{relation}} WHERE id = ", ""],
            )
            .map_err(|error| stable("append event", error))?;
            let rows = self
                .rows(
                    "append event",
                    &select,
                    &[BindValue::Text(event.id.clone())],
                    &[ColumnSpec::required("seq", LogicalType::Integer)],
                )
                .await?;
            integer(&rows[0], "seq", "content event")
        })
    }
}

impl FacetObservationPort for TursoDomainTransaction<'_> {
    fn append_facet_observation<'a>(
        &'a mut self,
        spec: AppendSpec,
        control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let payload = crate::domain_transaction::normalize_event_payload(
                &spec.record_id,
                &spec.event_type,
                spec.payload,
            );
            let annotations = crate::store::current_event_annotations();
            let mut event = EventRow {
                local_seq: -1,
                id: uuid::Uuid::new_v4().to_string(),
                record_id: spec.record_id,
                event_type: spec.event_type,
                payload: Some(serde_json::to_string(&payload)?),
                actor: spec.actor,
                run_key: annotations.run_key,
                parent_key: annotations.parent_key,
                intent: annotations.intent,
                created_at: crate::store::now_iso(),
                causal_envelope: CausalEnvelopeV1::complete(CausalFrontierV1::empty()),
            };
            crate::domain_transaction::append_and_project(self, &mut event, control).await?;
            Ok(event.local_seq)
        })
    }
}

impl ProjectorPort for TursoDomainTransaction<'_> {
    fn apply_projector<'a>(
        &'a mut self,
        intent: &'a ProjectorIntent,
        event: &'a EventRow,
        _control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let plan = crate::domain_transaction::plan_projection(self, event, intent).await?;
            self.apply_projection_plan(event, plan).await
        })
    }
}

impl TursoDomainTransaction<'_> {
    async fn apply_projection_plan(
        &mut self,
        event: &EventRow,
        plan: ProjectionPlan,
    ) -> Result<()> {
        match plan {
            ProjectionPlan::RecordCreated {
                fields,
                kind,
                policy_anchor_id,
                message_mentions,
            } => {
                self.apply_record_created(event, fields, &kind, &policy_anchor_id, message_mentions)
                    .await
            }
            ProjectionPlan::RecordUpdated {
                fields,
                refresh_policy_anchor,
            } => {
                self.apply_record_updated(event, &fields, refresh_policy_anchor)
                    .await
            }
            ProjectionPlan::RecordTypeCorrected { record_type, kind } => {
                self.apply_record_type_corrected(event, &record_type, &kind)
                    .await
            }
            ProjectionPlan::RecordDeleted => self.apply_record_deleted(event).await,
            ProjectionPlan::FacetSet { payload, spine } => {
                self.apply_facet_set(event, payload, spine).await
            }
            ProjectionPlan::FacetUnset { payload, spine } => {
                self.apply_facet_unset(event, payload, spine).await
            }
            ProjectionPlan::LinkAdded {
                payload,
                link_id,
                relationship_owned,
            } => {
                if relationship_owned {
                    return Err(crate::domain_transaction::unsupported_backend_operation(
                        "turso-local",
                        "relationship-owned link mutation",
                    ));
                }
                self.apply_link_added(event, payload, link_id).await
            }
            ProjectionPlan::LinkRemoved {
                payload,
                relationship_owned,
            } => {
                if relationship_owned {
                    return Err(crate::domain_transaction::unsupported_backend_operation(
                        "turso-local",
                        "relationship-owned link mutation",
                    ));
                }
                self.apply_link_removed(event, payload).await
            }
        }
    }

    async fn apply_record_created(
        &mut self,
        event: &EventRow,
        fields: Map<String, Value>,
        kind: &str,
        policy_anchor_id: &str,
        message_mentions: Option<Vec<crate::domain_transaction::MessageMention>>,
    ) -> Result<()> {
        let insert = statement(
            StatementKind::Insert,
            "records",
                &[
                    "INSERT INTO {{relation}} (id, type, kind, name, body, home_id, lifecycle, owner_id, policy_anchor_id, persistence, maturity, summary, last_activity_at, created_at, updated_at) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ")",
            ],
        )
        .map_err(|error| stable("create_record", error))?;
        let name = fields
            .get("name")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        let persistence = fields
            .get("persistence")
            .cloned()
            .unwrap_or_else(|| Value::String("enduring".into()));
        self.execute(
            "create_record",
            &insert,
            &[
                BindValue::Text(event.record_id.clone()),
                json_binding(fields.get("type").unwrap_or(&Value::Null)),
                BindValue::Text(kind.into()),
                json_binding(&name),
                json_binding(fields.get("body").unwrap_or(&Value::Null)),
                json_binding(fields.get("home_id").unwrap_or(&Value::Null)),
                json_binding(fields.get("lifecycle").unwrap_or(&Value::Null)),
                json_binding(fields.get("owner_id").unwrap_or(&Value::Null)),
                BindValue::Text(policy_anchor_id.into()),
                json_binding(&persistence),
                json_binding(fields.get("maturity").unwrap_or(&Value::Null)),
                json_binding(fields.get("summary").unwrap_or(&Value::Null)),
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(event.created_at.clone()),
            ],
        )
        .await?;
        if let Some(mentions) = message_mentions {
            let audience = statement(
                StatementKind::Insert,
                "message_audience_state",
                &[
                    "INSERT INTO {{relation}} (message_id, status, declaration_event_seq, updated_at) VALUES (",
                    ", 'pending_local', NULL, ",
                    ")",
                ],
            )
            .map_err(|error| stable("apply message create", error))?;
            self.execute(
                "apply message create",
                &audience,
                &[
                    BindValue::Text(event.record_id.clone()),
                    BindValue::Text(event.created_at.clone()),
                ],
            )
            .await?;
            let mention_statement = statement(
                StatementKind::Insert,
                "message_mentions",
                &[
                    "INSERT INTO {{relation}} (message_id, mention_id, target_kind, target_binding, target_record_id, span_start, span_end, authored_label, source_event_seq, effective) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", 1)",
                ],
            )
            .map_err(|error| stable("apply message mention", error))?;
            for mention in mentions {
                self.execute(
                    "apply message mention",
                    &mention_statement,
                    &[
                        BindValue::Text(event.record_id.clone()),
                        BindValue::Text(mention.mention_id),
                        BindValue::Text(mention.target_kind),
                        BindValue::Text(mention.target_binding),
                        BindValue::Text(mention.target_record_id),
                        BindValue::Integer(mention.span_start),
                        BindValue::Integer(mention.span_end),
                        BindValue::Text(mention.authored_label),
                        BindValue::Integer(event.local_seq),
                    ],
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn apply_record_updated(
        &mut self,
        event: &EventRow,
        fields: &[RecordFieldUpdate],
        refresh_policy_anchor: bool,
    ) -> Result<()> {
        let updated_at = self
            .next_record_updated_at(&event.record_id, &event.created_at)
            .await?;
        // One statement per column the event actually carries, then the
        // timestamps. The previous single statement named all twelve columns
        // as `CASE WHEN ? THEN ? ELSE col END`; SQLite-family
        // `AFTER UPDATE OF ...` triggers fire on the columns a statement
        // NAMES, so an ordinary body edit advanced the database-wide
        // authorization epoch. The portable template contract requires
        // `&'static` fragments, so the named adapter narrows by issuing the
        // per-column statements `RecordFieldUpdate::write` supplies rather
        // than by assembling text — the same bounded-relational-steps shape
        // this adapter already uses for the anchor fold.
        for field in fields {
            let write = field.write();
            let update = statement(StatementKind::Update, "records", write.portable_update)
                .map_err(|error| stable("apply record update", error))?;
            self.execute(
                "apply record update",
                &update,
                &[
                    json_binding(write.value),
                    BindValue::Text(event.record_id.clone()),
                ],
            )
            .await?;
        }
        let touch = statement(
            StatementKind::Update,
            "records",
            &[
                "UPDATE {{relation}} SET updated_at=",
                ", last_activity_at=",
                " WHERE id=",
                "",
            ],
        )
        .map_err(|error| stable("apply record update", error))?;
        self.execute(
            "apply record update",
            &touch,
            &[
                BindValue::Text(updated_at),
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(event.record_id.clone()),
            ],
        )
        .await?;
        if refresh_policy_anchor {
            self.refresh_policy_anchor_subtree(&event.record_id).await?;
        }
        Ok(())
    }

    async fn apply_record_type_corrected(
        &mut self,
        event: &EventRow,
        record_type: &str,
        kind: &str,
    ) -> Result<()> {
        let updated_at = self
            .next_record_updated_at(&event.record_id, &event.created_at)
            .await?;
        let update = statement(
            StatementKind::Update,
            "records",
            &[
                "UPDATE {{relation}} SET type=",
                ", kind=",
                ", updated_at=",
                ", last_activity_at=",
                " WHERE id=",
                "",
            ],
        )
        .map_err(|error| stable("apply record type correction", error))?;
        self.execute(
            "apply record type correction",
            &update,
            &[
                BindValue::Text(record_type.into()),
                BindValue::Text(kind.into()),
                BindValue::Text(updated_at),
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(event.record_id.clone()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn apply_record_deleted(&mut self, event: &EventRow) -> Result<()> {
        let updated_at = self
            .next_record_updated_at(&event.record_id, &event.created_at)
            .await?;
        let update = statement(
            StatementKind::Update,
            "records",
            &[
                "UPDATE {{relation}} SET deleted_at = ",
                ", updated_at = ",
                ", last_activity_at = ",
                " WHERE id = ",
                "",
            ],
        )
        .map_err(|error| stable("apply record delete", error))?;
        self.execute(
            "apply record delete",
            &update,
            &[
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(updated_at),
                BindValue::Text(event.created_at.clone()),
                BindValue::Text(event.record_id.clone()),
            ],
        )
        .await?;
        let mentions = statement(
            StatementKind::Update,
            "message_mentions",
            &[
                "UPDATE {{relation}} SET effective = 0 WHERE message_id = ",
                "",
            ],
        )
        .map_err(|error| stable("apply record delete", error))?;
        self.execute(
            "apply record delete",
            &mentions,
            &[BindValue::Text(event.record_id.clone())],
        )
        .await?;
        Ok(())
    }

    async fn apply_facet_set(
        &mut self,
        event: &EventRow,
        payload: crate::events::FacetSetPayload,
        spine: Option<SpineFacet>,
    ) -> Result<()> {
        if let Some(spine) = spine {
            let updated_at = self
                .next_record_updated_at(&event.record_id, &event.created_at)
                .await?;
            let (column, operation) = match spine {
                SpineFacet::Lifecycle => ("lifecycle", "apply lifecycle facet"),
                SpineFacet::Owner => ("owner_id", "apply owner facet"),
                SpineFacet::Persistence => ("persistence", "apply persistence facet"),
                SpineFacet::Maturity => ("maturity", "apply maturity facet"),
            };
            let fragments: &'static [&'static str] = match column {
                "lifecycle" => &[
                    "UPDATE {{relation}} SET lifecycle = ",
                    ", updated_at = ",
                    ", last_activity_at = ",
                    " WHERE id = ",
                    "",
                ],
                "owner_id" => &[
                    "UPDATE {{relation}} SET owner_id = ",
                    ", updated_at = ",
                    ", last_activity_at = ",
                    " WHERE id = ",
                    "",
                ],
                "persistence" => &[
                    "UPDATE {{relation}} SET persistence = ",
                    ", updated_at = ",
                    ", last_activity_at = ",
                    " WHERE id = ",
                    "",
                ],
                "maturity" => &[
                    "UPDATE {{relation}} SET maturity = ",
                    ", updated_at = ",
                    ", last_activity_at = ",
                    " WHERE id = ",
                    "",
                ],
                _ => unreachable!(),
            };
            let update = statement(StatementKind::Update, "records", fragments)
                .map_err(|error| stable(operation, error))?;
            self.execute(
                operation,
                &update,
                &[
                    optional_binding(payload.value.as_deref()),
                    BindValue::Text(updated_at),
                    BindValue::Text(event.created_at.clone()),
                    BindValue::Text(event.record_id.clone()),
                ],
            )
            .await?;
            return Ok(());
        }
        if !payload.observation_only {
            let value_num = payload
                .value
                .as_deref()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .and_then(|value| value.as_f64())
                .map(BindValue::Real)
                .unwrap_or(BindValue::Null(LogicalType::Real));
            let current = statement(
                StatementKind::Insert,
                "facet_values",
                &[
                    "INSERT INTO {{relation}} (id, record_id, key, value, value_num, vocab_ref, created_at) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ") ON CONFLICT (record_id, key) DO UPDATE SET value=excluded.value, value_num=excluded.value_num, vocab_ref=excluded.vocab_ref",
                ],
            )
            .map_err(|error| stable("apply facet set", error))?;
            self.execute(
                "apply facet set",
                &current,
                &[
                    BindValue::Text(format!("fv:{}:{}", event.record_id, payload.key)),
                    BindValue::Text(event.record_id.clone()),
                    BindValue::Text(payload.key.clone()),
                    optional_binding(payload.value.as_deref()),
                    value_num,
                    optional_binding(payload.vocab_ref.as_deref()),
                    BindValue::Text(event.created_at.clone()),
                ],
            )
            .await?;
        }
        let as_of = payload.as_of.as_deref().unwrap_or(&event.created_at);
        let observation = statement(
            StatementKind::Insert,
            "facet_observations",
            &[
                "INSERT INTO {{relation}} (id, record_id, key, value, op, vocab_ref, as_of, observed_at, event_seq) VALUES (",
                ", ",
                ", ",
                ", ",
                ", 'set', ",
                ", ",
                ", ",
                ", ",
                ") ON CONFLICT (record_id, key, as_of) DO UPDATE SET value=excluded.value, op=excluded.op, vocab_ref=excluded.vocab_ref, observed_at=excluded.observed_at, event_seq=excluded.event_seq",
            ],
        )
        .map_err(|error| stable("apply facet observation", error))?;
        self.execute(
            "apply facet observation",
            &observation,
            &[
                BindValue::Text(format!("fo:{}:{}:{as_of}", event.record_id, payload.key)),
                BindValue::Text(event.record_id.clone()),
                BindValue::Text(payload.key),
                optional_binding(payload.value.as_deref()),
                optional_binding(payload.vocab_ref.as_deref()),
                BindValue::Text(as_of.into()),
                BindValue::Text(event.created_at.clone()),
                BindValue::Integer(event.local_seq),
            ],
        )
        .await?;
        self.touch(&event.record_id, &event.created_at).await
    }

    async fn apply_facet_unset(
        &mut self,
        event: &EventRow,
        payload: crate::events::FacetUnsetPayload,
        spine: Option<SpineFacet>,
    ) -> Result<()> {
        if let Some(spine) = spine {
            let updated_at = self
                .next_record_updated_at(&event.record_id, &event.created_at)
                .await?;
            let fragments: &'static [&'static str] = match spine {
                SpineFacet::Lifecycle => &[
                    "UPDATE {{relation}} SET lifecycle=NULL, updated_at=",
                    ", last_activity_at=",
                    " WHERE id=",
                    "",
                ],
                SpineFacet::Owner => &[
                    "UPDATE {{relation}} SET owner_id=NULL, updated_at=",
                    ", last_activity_at=",
                    " WHERE id=",
                    "",
                ],
                SpineFacet::Persistence => unreachable!("shared planner rejects persistence unset"),
                SpineFacet::Maturity => &[
                    "UPDATE {{relation}} SET maturity=NULL, updated_at=",
                    ", last_activity_at=",
                    " WHERE id=",
                    "",
                ],
            };
            let update = statement(StatementKind::Update, "records", fragments)
                .map_err(|error| stable("apply facet unset", error))?;
            self.execute(
                "apply facet unset",
                &update,
                &[
                    BindValue::Text(updated_at),
                    BindValue::Text(event.created_at.clone()),
                    BindValue::Text(event.record_id.clone()),
                ],
            )
            .await?;
            return Ok(());
        }
        if !payload.observation_only {
            let delete = statement(
                StatementKind::Delete,
                "facet_values",
                &[
                    "DELETE FROM {{relation}} WHERE record_id = ",
                    " AND key = ",
                    "",
                ],
            )
            .map_err(|error| stable("apply facet unset", error))?;
            self.execute(
                "apply facet unset",
                &delete,
                &[
                    BindValue::Text(event.record_id.clone()),
                    BindValue::Text(payload.key.clone()),
                ],
            )
            .await?;
        }
        let as_of = payload.as_of.as_deref().unwrap_or(&event.created_at);
        let observation = statement(
            StatementKind::Insert,
            "facet_observations",
            &[
                "INSERT INTO {{relation}} (id, record_id, key, value, op, vocab_ref, as_of, observed_at, event_seq) VALUES (",
                ", ",
                ", ",
                ", NULL, 'unset', NULL, ",
                ", ",
                ", ",
                ") ON CONFLICT (record_id, key, as_of) DO UPDATE SET value=excluded.value, op=excluded.op, vocab_ref=excluded.vocab_ref, observed_at=excluded.observed_at, event_seq=excluded.event_seq",
            ],
        )
        .map_err(|error| stable("apply facet observation", error))?;
        self.execute(
            "apply facet observation",
            &observation,
            &[
                BindValue::Text(format!("fo:{}:{}:{as_of}", event.record_id, payload.key)),
                BindValue::Text(event.record_id.clone()),
                BindValue::Text(payload.key),
                BindValue::Text(as_of.into()),
                BindValue::Text(event.created_at.clone()),
                BindValue::Integer(event.local_seq),
            ],
        )
        .await?;
        self.touch(&event.record_id, &event.created_at).await
    }

    async fn apply_link_added(
        &mut self,
        event: &EventRow,
        payload: crate::events::LinkAddedPayload,
        link_id: String,
    ) -> Result<()> {
        let insert = statement(
            StatementKind::Insert,
            "links",
            &[
                "INSERT INTO {{relation}} (id, source_id, target_id, relationship, note, created_at) VALUES (",
                ", ",
                ", ",
                ", ",
                ", ",
                ", ",
                ") ON CONFLICT (source_id, target_id, relationship) DO UPDATE SET note=excluded.note",
            ],
        )
        .map_err(|error| stable("apply link add", error))?;
        self.execute(
            "apply link add",
            &insert,
            &[
                BindValue::Text(link_id),
                BindValue::Text(payload.source_id.clone()),
                BindValue::Text(payload.target_id.clone()),
                BindValue::Text(payload.relationship.clone()),
                optional_binding(payload.note.as_deref()),
                BindValue::Text(event.created_at.clone()),
            ],
        )
        .await?;
        if payload.relationship == "participates_in" {
            let classify = statement(
                StatementKind::Insert,
                "message_conversations",
                &[
                    "INSERT INTO {{relation}} (message_id, conversation_id, event_seq, classified_at) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ") ON CONFLICT (message_id, conversation_id) DO UPDATE SET event_seq=excluded.event_seq, classified_at=excluded.classified_at",
                ],
            )
            .map_err(|error| stable("apply conversation link", error))?;
            self.execute(
                "apply conversation link",
                &classify,
                &[
                    BindValue::Text(payload.source_id.clone()),
                    BindValue::Text(payload.target_id),
                    BindValue::Integer(event.local_seq),
                    BindValue::Text(event.created_at.clone()),
                ],
            )
            .await?;
        }
        self.touch(&payload.source_id, &event.created_at).await
    }

    async fn apply_link_removed(
        &mut self,
        event: &EventRow,
        payload: crate::events::LinkRemovedPayload,
    ) -> Result<()> {
        let delete = statement(
            StatementKind::Delete,
            "links",
            &[
                "DELETE FROM {{relation}} WHERE source_id = ",
                " AND target_id = ",
                " AND relationship = ",
                "",
            ],
        )
        .map_err(|error| stable("apply link remove", error))?;
        let affected = self
            .execute(
                "apply link remove",
                &delete,
                &[
                    BindValue::Text(payload.source_id.clone()),
                    BindValue::Text(payload.target_id.clone()),
                    BindValue::Text(payload.relationship.clone()),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(Error::engine(format!(
                "cannot remove link: no '{}' link from {} to {}",
                payload.relationship, payload.source_id, payload.target_id
            )));
        }
        if payload.relationship == "participates_in" {
            let classified = statement(
                StatementKind::Delete,
                "message_conversations",
                &[
                    "DELETE FROM {{relation}} WHERE message_id = ",
                    " AND conversation_id = ",
                    "",
                ],
            )
            .map_err(|error| stable("apply conversation unlink", error))?;
            self.execute(
                "apply conversation unlink",
                &classified,
                &[
                    BindValue::Text(payload.source_id.clone()),
                    BindValue::Text(payload.target_id),
                ],
            )
            .await?;
        }
        self.touch(&payload.source_id, &event.created_at).await
    }
}

impl AttachmentPhysicalPort for TursoDomainTransaction<'_> {
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn insert_blob<'a>(
        &'a mut self,
        bytes: &'a [u8],
        mime: Option<&'a str>,
        original_filename: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlobMeta>> {
        Box::pin(async move {
            let meta = crate::blob::new_blob_meta(bytes, mime, original_filename);
            let insert = statement(
                StatementKind::Insert,
                "blobs",
                &[
                    "INSERT INTO {{relation}} (id, bytes, mime, size_bytes, sha256, original_filename, storage_tier, created_at) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("insert attachment blob", error))?;
            self.execute(
                "insert attachment blob",
                &insert,
                &[
                    BindValue::Text(meta.id.clone()),
                    BindValue::Bytes(bytes.to_vec()),
                    optional_binding(meta.mime.as_deref()),
                    BindValue::Integer(meta.size_bytes),
                    BindValue::Text(meta.sha256.clone()),
                    optional_binding(meta.original_filename.as_deref()),
                    BindValue::Text(meta.storage_tier.clone()),
                    BindValue::Text(meta.created_at.clone()),
                ],
            )
            .await?;
            Ok(meta)
        })
    }

    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> BoxFuture<'a, Result<Option<BlobSlice>>> {
        Box::pin(async move {
            if offset > i64::MAX as u64 || length > i64::MAX as u64 {
                return Err(Error::engine(format!(
                    "blob range out of bounds: offset {offset}, length {length}"
                )));
            }
            let select = statement(
                StatementKind::Select,
                "blobs",
                &[
                    "SELECT substr(bytes, ",
                    ", ",
                    ") AS chunk, size_bytes, storage_tier, (bytes IS NULL) AS no_bytes FROM {{relation}} WHERE id = ",
                    "",
                ],
            )
            .map_err(|error| stable("read attachment blob", error))?;
            let rows = self
                .rows(
                    "read attachment blob",
                    &select,
                    &[
                        BindValue::Integer((offset + 1) as i64),
                        BindValue::Integer(length as i64),
                        BindValue::Text(blob_id.into()),
                    ],
                    &[
                        ColumnSpec::nullable("chunk", LogicalType::Bytes),
                        ColumnSpec::required("size_bytes", LogicalType::Integer),
                        ColumnSpec::required("storage_tier", LogicalType::Text),
                        ColumnSpec::required("no_bytes", LogicalType::Bool),
                    ],
                )
                .await?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            let tier = text(row, "storage_tier", "attachment blob")?;
            if tier != "inline" {
                return Err(Error::engine(format!(
                    "blob {blob_id} is stored externally (storage_tier '{tier}') — external blobs are not readable in v1"
                )));
            }
            if boolean(row, "no_bytes", "attachment blob")? {
                return Err(Error::engine(format!("blob {blob_id} has no inline bytes")));
            }
            let bytes = match row.get("chunk") {
                Some(NormalizedValue::Bytes(bytes)) => bytes.clone(),
                _ => Vec::new(),
            };
            let total_size = integer(row, "size_bytes", "attachment blob")?.max(0) as u64;
            Ok(Some(BlobSlice {
                eof: offset + bytes.len() as u64 >= total_size,
                bytes,
                offset,
                total_size,
            }))
        })
    }

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<()>> {
        self.append_content_admitted(spec, false)
    }
}

impl crate::domain_transaction::RecordLifecyclePhysicalPort for TursoDomainTransaction<'_> {
    fn lock_live_record<'a>(&'a mut self, _record_id: &'a str) -> BoxFuture<'a, Result<()>> {
        // `run_db_write` holds this logical database's exclusive writer gate
        // for the complete transaction, so no second writer can pass the
        // target-state read before this transaction commits or rolls back.
        Box::pin(async { Ok(()) })
    }

    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        // The same writer gate serializes cursor allocation and the CAS read.
        Box::pin(async { Ok(()) })
    }

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<String>> {
        self.append_content_event_admitted(spec, false)
    }
}

impl BindingPhysicalPort for TursoDomainTransaction<'_> {
    fn lock_bindings<'a>(
        &'a mut self,
        _claims: &'a [crate::identity::BindingClaim],
    ) -> BoxFuture<'a, Result<()>> {
        // The adapter write gate plus BEGIN IMMEDIATE is the one local-Turso
        // binding lock. There is no weaker per-row lock to acquire here.
        Box::pin(async { Ok(()) })
    }

    fn system_rule<'a>(
        &'a mut self,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingSystemRule>>> {
        Box::pin(async move {
            let select = statement(StatementKind::Select, "binding_systems", &[
                "SELECT compatible_type,compatible_kind,visibility,add_policy,remove_policy,canonicalize_policy,transfer_policy,reconciliation_rule,stub_allowed,required_durable FROM {{relation}} WHERE system=", "",
            ]).map_err(|error| stable("read binding system", error))?;
            let rows = self
                .rows(
                    "read binding system",
                    &select,
                    &[BindValue::Text(system.into())],
                    &[
                        ColumnSpec::nullable("compatible_type", LogicalType::Text),
                        ColumnSpec::nullable("compatible_kind", LogicalType::Text),
                        ColumnSpec::required("visibility", LogicalType::Text),
                        ColumnSpec::required("add_policy", LogicalType::Text),
                        ColumnSpec::required("remove_policy", LogicalType::Text),
                        ColumnSpec::required("canonicalize_policy", LogicalType::Text),
                        ColumnSpec::required("transfer_policy", LogicalType::Text),
                        ColumnSpec::required("reconciliation_rule", LogicalType::Text),
                        ColumnSpec::required("stub_allowed", LogicalType::Bool),
                        ColumnSpec::required("required_durable", LogicalType::Bool),
                    ],
                )
                .await?;
            rows.first()
                .map(|row| {
                    Ok(BindingSystemRule {
                        system: system.into(),
                        compatible_type: optional_text(row, "compatible_type", "binding system")?,
                        compatible_kind: optional_text(row, "compatible_kind", "binding system")?,
                        visibility: text(row, "visibility", "binding system")?,
                        add_policy: text(row, "add_policy", "binding system")?,
                        remove_policy: text(row, "remove_policy", "binding system")?,
                        canonicalize_policy: text(row, "canonicalize_policy", "binding system")?,
                        transfer_policy: text(row, "transfer_policy", "binding system")?,
                        reconciliation_rule: text(row, "reconciliation_rule", "binding system")?,
                        stub_allowed: boolean(row, "stub_allowed", "binding system")?,
                        required_durable: boolean(row, "required_durable", "binding system")?,
                    })
                })
                .transpose()
        })
    }

    fn binding<'a>(
        &'a mut self,
        system: &'a str,
        identifier: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingRow>>> {
        Box::pin(async move {
            let select = statement(StatementKind::Select, "bindings", &[
                "SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {{relation}} WHERE system=", " AND identifier=", "",
            ]).map_err(|error| stable("read external binding", error))?;
            let rows = self
                .rows(
                    "read external binding",
                    &select,
                    &[
                        BindValue::Text(system.into()),
                        BindValue::Text(identifier.into()),
                    ],
                    &binding_columns(),
                )
                .await?;
            rows.first().map(turso_binding_row).transpose()
        })
    }

    fn record_shape<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, Option<String>, bool)>>> {
        Box::pin(async move {
            let select = statement(StatementKind::Select, "records", &["SELECT type,kind,(deleted_at IS NOT NULL) AS deleted FROM {{relation}} WHERE id=", ""])
                .map_err(|error| stable("read binding record shape", error))?;
            let rows = self
                .rows(
                    "read binding record shape",
                    &select,
                    &[BindValue::Text(record_id.into())],
                    &[
                        ColumnSpec::required("type", LogicalType::Text),
                        ColumnSpec::nullable("kind", LogicalType::Text),
                        ColumnSpec::required("deleted", LogicalType::Bool),
                    ],
                )
                .await?;
            rows.first()
                .map(|row| {
                    Ok((
                        text(row, "type", "binding record")?,
                        optional_text(row, "kind", "binding record")?,
                        boolean(row, "deleted", "binding record")?,
                    ))
                })
                .transpose()
        })
    }

    fn canonical_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let select = statement(
                StatementKind::Select,
                "bindings",
                &[
                    "SELECT identifier FROM {{relation}} WHERE record_id=",
                    " AND system=",
                    " AND is_canonical=1",
                ],
            )
            .map_err(|error| stable("read canonical binding", error))?;
            let rows = self
                .rows(
                    "read canonical binding",
                    &select,
                    &[
                        BindValue::Text(record_id.into()),
                        BindValue::Text(system.into()),
                    ],
                    &[ColumnSpec::required("identifier", LogicalType::Text)],
                )
                .await?;
            rows.first()
                .map(|row| text(row, "identifier", "canonical binding"))
                .transpose()
        })
    }

    fn binding_count<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let select = statement(
                StatementKind::Select,
                "bindings",
                &[
                    "SELECT COUNT(*) AS count FROM {{relation}} WHERE record_id=",
                    " AND system=",
                    "",
                ],
            )
            .map_err(|error| stable("count bindings", error))?;
            let rows = self
                .rows(
                    "count bindings",
                    &select,
                    &[
                        BindValue::Text(record_id.into()),
                        BindValue::Text(system.into()),
                    ],
                    &[ColumnSpec::required("count", LogicalType::Integer)],
                )
                .await?;
            integer(&rows[0], "count", "binding count")
        })
    }

    fn account_owner<'a>(&'a mut self, actor: &'a str) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let select = statement(
                StatementKind::Select,
                "bindings",
                &[
                    "SELECT record_id FROM {{relation}} WHERE system='account' AND identifier=",
                    " AND is_canonical=1",
                ],
            )
            .map_err(|error| stable("resolve binding owner", error))?;
            let rows = self
                .rows(
                    "resolve binding owner",
                    &select,
                    &[BindValue::Text(actor.into())],
                    &[ColumnSpec::required("record_id", LogicalType::Text)],
                )
                .await?;
            rows.first()
                .map(|row| text(row, "record_id", "binding owner"))
                .transpose()
        })
    }

    fn public_bindings<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<BindingRow>>> {
        Box::pin(async move {
            let select = statement(StatementKind::Select,"bindings",&[
                "SELECT b.record_id,b.system,b.identifier,b.is_canonical,b.url,b.etag,b.last_seen_at FROM {{relation}} b JOIN binding_systems s ON s.system=b.system WHERE b.record_id="," AND s.visibility='public' ORDER BY b.system,b.is_canonical DESC,b.identifier",
            ]).map_err(|error| stable("list public bindings",error))?;
            self.rows(
                "list public bindings",
                &select,
                &[BindValue::Text(record_id.into())],
                &binding_columns(),
            )
            .await?
            .iter()
            .map(turso_binding_row)
            .collect()
        })
    }

    fn set_canonical<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
        identifier: &'a str,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let update = statement(
                StatementKind::Update,
                "bindings",
                &[
                    "UPDATE {{relation}} SET is_canonical=",
                    " WHERE record_id=",
                    " AND system=",
                    " AND identifier=",
                    "",
                ],
            )
            .map_err(|error| stable("update canonical binding", error))?;
            self.execute(
                "update canonical binding",
                &update,
                &[
                    BindValue::Bool(canonical),
                    BindValue::Text(record_id.into()),
                    BindValue::Text(system.into()),
                    BindValue::Text(identifier.into()),
                ],
            )
            .await?;
            Ok(())
        })
    }

    fn insert_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let insert = statement(
                StatementKind::Insert,
                "bindings",
                &[
                    "INSERT INTO {{relation}}(record_id,system,identifier,is_canonical) VALUES(",
                    ",",
                    ",",
                    ",",
                    ")",
                ],
            )
            .map_err(|error| stable("insert external binding", error))?;
            self.execute(
                "insert external binding",
                &insert,
                &[
                    BindValue::Text(record_id.into()),
                    BindValue::Text(claim.system.clone()),
                    BindValue::Text(claim.identifier.clone()),
                    BindValue::Bool(canonical),
                ],
            )
            .await?;
            Ok(())
        })
    }

    fn delete_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let delete = statement(
                StatementKind::Delete,
                "bindings",
                &[
                    "DELETE FROM {{relation}} WHERE record_id=",
                    " AND system=",
                    " AND identifier=",
                    "",
                ],
            )
            .map_err(|error| stable("delete external binding", error))?;
            self.execute(
                "delete external binding",
                &delete,
                &[
                    BindValue::Text(record_id.into()),
                    BindValue::Text(claim.system.clone()),
                    BindValue::Text(claim.identifier.clone()),
                ],
            )
            .await?;
            Ok(())
        })
    }

    fn transfer_binding<'a>(
        &'a mut self,
        source_record_id: &'a str,
        target_record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let update = statement(
                StatementKind::Update,
                "bindings",
                &[
                    "UPDATE {{relation}} SET record_id=",
                    " WHERE record_id=",
                    " AND system=",
                    " AND identifier=",
                    "",
                ],
            )
            .map_err(|error| stable("transfer external binding", error))?;
            self.execute(
                "transfer external binding",
                &update,
                &[
                    BindValue::Text(target_record_id.into()),
                    BindValue::Text(source_record_id.into()),
                    BindValue::Text(claim.system.clone()),
                    BindValue::Text(claim.identifier.clone()),
                ],
            )
            .await?;
            Ok(())
        })
    }

    fn append_binding_audit<'a>(
        &'a mut self,
        audit: BindingAudit<'a>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let insert = statement(
                StatementKind::Insert,
                "binding_audit",
                &[
                    "INSERT INTO {{relation}}(id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at) VALUES(",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ",",
                    ")",
                ],
            )
            .map_err(|error| stable("append binding audit", error))?;
            self.execute(
                "append binding audit",
                &insert,
                &[
                    BindValue::Text(uuid::Uuid::new_v4().to_string()),
                    BindValue::Text(audit.action.into()),
                    BindValue::Text(audit.claim.system.clone()),
                    BindValue::Text(audit.claim.identifier.clone()),
                    optional_binding(audit.old_record_id),
                    optional_binding(audit.new_record_id),
                    audit
                        .old_canonical
                        .map(BindValue::Bool)
                        .unwrap_or(BindValue::Null(LogicalType::Bool)),
                    audit
                        .new_canonical
                        .map(BindValue::Bool)
                        .unwrap_or(BindValue::Null(LogicalType::Bool)),
                    BindValue::Text(audit.actor.into()),
                    BindValue::Text(audit.reason.into()),
                    optional_binding(audit.run_key),
                    optional_binding(audit.parent_key),
                    optional_binding(audit.intent),
                    BindValue::Text(crate::store::now_iso()),
                ],
            )
            .await?;
            Ok(())
        })
    }
}

fn binding_columns() -> [ColumnSpec; 7] {
    [
        ColumnSpec::required("record_id", LogicalType::Text),
        ColumnSpec::required("system", LogicalType::Text),
        ColumnSpec::required("identifier", LogicalType::Text),
        ColumnSpec::required("is_canonical", LogicalType::Bool),
        ColumnSpec::nullable("url", LogicalType::Text),
        ColumnSpec::nullable("etag", LogicalType::Text),
        ColumnSpec::nullable("last_seen_at", LogicalType::Text),
    ]
}

fn turso_binding_row(row: &NormalizedRow) -> Result<BindingRow> {
    Ok(BindingRow {
        record_id: text(row, "record_id", "external binding")?,
        system: text(row, "system", "external binding")?,
        identifier: text(row, "identifier", "external binding")?,
        canonical: boolean(row, "is_canonical", "external binding")?,
        url: optional_text(row, "url", "external binding")?,
        etag: optional_text(row, "etag", "external binding")?,
        last_seen_at: optional_text(row, "last_seen_at", "external binding")?,
    })
}

impl TursoDomainTransaction<'_> {
    fn append_engine_seed_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<()>> {
        self.append_content_admitted(spec, true)
    }

    fn append_content_admitted<'a>(
        &'a mut self,
        spec: AppendSpec,
        engine_seed: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.append_content_event_admitted(spec, engine_seed)
                .await
                .map(|_| ())
        })
    }

    fn append_content_event_admitted<'a>(
        &'a mut self,
        spec: AppendSpec,
        engine_seed: bool,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let payload = crate::domain_transaction::normalize_event_payload(
                &spec.record_id,
                &spec.event_type,
                spec.payload,
            );
            let annotations = crate::store::current_event_annotations();
            let event_id = uuid::Uuid::new_v4().to_string();
            let mut event = EventRow {
                local_seq: -1,
                id: event_id.clone(),
                record_id: spec.record_id,
                event_type: spec.event_type,
                payload: Some(serde_json::to_string(&payload)?),
                actor: spec.actor,
                run_key: annotations.run_key,
                parent_key: annotations.parent_key,
                intent: annotations.intent,
                created_at: crate::store::now_iso(),
                causal_envelope: CausalEnvelopeV1::complete(CausalFrontierV1::empty()),
            };
            let control = self.control.clone();
            if engine_seed {
                crate::domain_transaction::append_and_project_engine_seed(
                    self, &mut event, &control,
                )
                .await?;
            } else {
                crate::domain_transaction::append_and_project(self, &mut event, &control).await?;
            }
            Ok(event_id)
        })
    }
}

impl crate::awareness::CandidateWithdrawalPhysicalPort for TursoDomainTransaction<'_> {
    fn append_candidate_withdrawal<'a>(
        &'a mut self,
        withdrawal_event_id: &'a str,
        candidate: &'a crate::awareness::CandidateWithdrawal,
        message_id: &'a str,
        source_event_type: &'a str,
        source_event_id: &'a str,
        created_at: &'a str,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let insert = statement(
                StatementKind::Insert,
                "notification_candidate_events",
                &[
                    "INSERT INTO {{relation}} (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES (",
                    ", ",
                    ",'withdrawn',",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("append notification candidate withdrawal", error))?;
            self.execute(
                "append notification candidate withdrawal",
                &insert,
                &[
                    BindValue::Text(withdrawal_event_id.into()),
                    BindValue::Text(candidate.candidate_key.clone()),
                    BindValue::Text(candidate.recipient_account_id.clone()),
                    BindValue::Text(message_id.into()),
                    BindValue::Text(candidate.reason.clone()),
                    BindValue::Text(candidate.priority.clone()),
                    optional_binding(candidate.not_before.as_deref()),
                    BindValue::Text(candidate.redaction_class.clone()),
                    BindValue::Text(candidate.evaluator_kind.clone()),
                    BindValue::Text(candidate.policy_version.clone()),
                    BindValue::Text(source_event_type.into()),
                    BindValue::Text(source_event_id.into()),
                    BindValue::Text("{\"schema\":\"native.notification-candidate.v1\"}".into()),
                    BindValue::Text(created_at.into()),
                ],
            )
            .await?;
            let select = statement(
                StatementKind::Select,
                "notification_candidate_events",
                &["SELECT seq FROM {{relation}} WHERE id = ", ""],
            )
            .map_err(|error| stable("read notification candidate withdrawal", error))?;
            let rows = self
                .rows(
                    "read notification candidate withdrawal",
                    &select,
                    &[BindValue::Text(withdrawal_event_id.into())],
                    &[ColumnSpec::required("seq", LogicalType::Integer)],
                )
                .await?;
            let row = rows.first().ok_or_else(|| {
                Error::engine("notification candidate withdrawal event was not persisted")
            })?;
            integer(row, "seq", "notification candidate withdrawal")
        })
    }

    fn project_candidate_withdrawal<'a>(
        &'a mut self,
        candidate_id: &'a str,
        event_seq: i64,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let update = statement(
                StatementKind::Update,
                "notification_candidates",
                &[
                    "UPDATE {{relation}} SET status='withdrawn', candidate_event_seq=",
                    " WHERE candidate_id=",
                    "",
                ],
            )
            .map_err(|error| stable("project notification candidate withdrawal", error))?;
            self.execute(
                "project notification candidate withdrawal",
                &update,
                &[
                    BindValue::Integer(event_seq),
                    BindValue::Text(candidate_id.into()),
                ],
            )
            .await?;
            Ok(())
        })
    }
}

/// Transaction lifecycle over a transaction admitted by the local Turso
/// connection factory. Keeping admission outside the shared runner avoids a
/// self-referential connection/transaction object while the adapter still owns
/// the physical BEGIN choice.
struct TursoTransactionLifecycle<'connection> {
    transaction: Option<TursoDomainTransaction<'connection>>,
    committed_realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl<'connection> TursoTransactionLifecycle<'connection> {
    async fn admit(
        connection: &'connection mut turso::Connection,
        control: ExecutionControl,
        committed_realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Result<Self> {
        let admitted = connection
            .transaction_with_behavior(turso::transaction::TransactionBehavior::Immediate)
            .await
            .map_err(|error| {
                stable(
                    "begin Turso transaction",
                    crate::portable_sql::normalize_turso_error(ExecutionPhase::Begin, &error),
                )
            })?;
        Ok(Self {
            transaction: Some(TursoDomainTransaction {
                inner: TursoTransaction::from_admitted(admitted),
                control,
            }),
            committed_realtime,
        })
    }
}

impl<'connection> TransactionLifecyclePort for TursoTransactionLifecycle<'connection> {
    type Transaction = TursoDomainTransaction<'connection>;

    fn begin<'a>(&'a mut self) -> BoxFuture<'a, Result<Self::Transaction>> {
        let transaction = self.transaction.take();
        Box::pin(async move {
            transaction.ok_or_else(|| Error::engine("Turso transaction was already admitted"))
        })
    }

    fn commit<'a>(&'a mut self, transaction: Self::Transaction) -> BoxFuture<'a, SqlResult<()>> {
        let realtime = self.committed_realtime.clone();
        Box::pin(async move {
            let admitted = transaction.inner.into_admitted()?;
            admitted.commit().await.map_err(|error| {
                crate::portable_sql::normalize_turso_error(ExecutionPhase::Commit, &error)
            })?;
            realtime.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            mark_turso_request_commit();
            Ok(())
        })
    }

    fn rollback<'a>(&'a mut self, transaction: Self::Transaction) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let admitted = transaction
                .inner
                .into_admitted()
                .map_err(|error| stable("rollback Turso transaction", error))?;
            admitted.rollback().await.map_err(|error| {
                stable(
                    "rollback Turso transaction",
                    crate::portable_sql::normalize_turso_error(ExecutionPhase::Rollback, &error),
                )
            })
        })
    }
}

/// Internal request wrapper adapter. Run-key reads are intentionally bounded to
/// the fresh/conformance case here; production persistence and routing belong
/// to the later runtime-promotion task. Every physical stage is nevertheless
/// explicit and executable, so the canonical wrapper cannot infer support from
/// an optional SQLite handle.
#[cfg(test)]
#[derive(Default)]
struct TursoRequestLifecycle {
    committed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    wakeups: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[cfg(test)]
impl crate::domain_transaction::request::RequestLifecyclePort for TursoRequestLifecycle {
    fn backend_label(&self) -> &'static str {
        BACKEND
    }

    fn capability(
        &self,
        _operation: crate::domain_transaction::request::GovernedRequestOperation,
    ) -> crate::domain_transaction::request::RequestStageCapability {
        crate::domain_transaction::request::RequestStageCapability::Applied
    }

    fn mint_run_key<'a>(&'a self, _agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Ok("scout-chair-a748b2".into()) })
    }

    fn intent_at<'a>(&'a self, _run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }

    fn persist_intent<'a>(
        &'a self,
        _run_key: &'a str,
        _intent: &'a str,
        _authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn displaced_key_note<'a>(
        &'a self,
        _caller: &'a crate::mcp::Caller,
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }

    fn with_operation_admission<'a>(
        &'a self,
        _operation: &'a str,
        _capability: Option<&'a str>,
        future: BoxFuture<'a, Result<crate::mcp::ToolResult>>,
    ) -> BoxFuture<'a, Result<crate::mcp::ToolResult>> {
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push("strict.enter");
            let result = future.await;
            events.lock().unwrap().push("strict.exit");
            result
        })
    }

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<crate::mcp::ToolResult>>,
    ) -> BoxFuture<'a, Result<crate::mcp::ToolResult>> {
        let committed = self.committed.clone();
        let wakeups = self.wakeups.clone();
        let events = self.events.clone();
        Box::pin(async move {
            let before = committed.load(std::sync::atomic::Ordering::SeqCst);
            events.lock().unwrap().push("realtime.enter");
            let result = future.await;
            if committed.load(std::sync::atomic::Ordering::SeqCst) > before {
                wakeups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            events.lock().unwrap().push("realtime.exit");
            result
        })
    }

    fn capture_interaction<'a>(
        &'a self,
        capture: crate::domain_transaction::request::InteractionCapture<'a>,
    ) -> BoxFuture<'a, ()> {
        let events = self.events.clone();
        let no_record_interactions = matches!(
            capture.extractor,
            crate::mcp::interactions::Extractor::Custom(
                crate::mcp::CustomInteractionPolicy::NoRecordInteractions
            )
        );
        Box::pin(async move {
            assert!(no_record_interactions);
            events.lock().unwrap().push("interaction");
        })
    }
}

impl TursoLocalDb {
    /// Durable run-key evidence, for minting only.
    ///
    /// Content annotations and explicit run-context declarations are both
    /// durable evidence. The optional interaction tap remains absent.
    async fn persisted_run_keys(&self, agent_pattern: Option<&str>) -> Result<HashSet<String>> {
        let connection = self.connect()?;
        let mut rows = match agent_pattern {
            Some(pattern) => {
                connection
                    .query(
                        "SELECT run_key FROM content_events WHERE run_key IS NOT NULL AND run_key LIKE ?1 UNION SELECT run_key FROM run_contexts WHERE run_key LIKE ?1",
                        [pattern],
                    )
                    .await
            }
            None => {
                connection
                    .query(
                        "SELECT run_key FROM content_events WHERE run_key IS NOT NULL UNION SELECT run_key FROM run_contexts",
                        (),
                    )
                    .await
            }
        }
        .map_err(|_| Error::engine("cannot inspect Turso-local run-key evidence"))?;
        let mut taken = HashSet::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|_| Error::engine("cannot inspect Turso-local run-key evidence"))?
        {
            let run_key: Option<String> = row
                .get(0)
                .map_err(|_| Error::engine("invalid Turso-local run-key evidence"))?;
            taken.extend(run_key);
        }
        Ok(taken)
    }

    async fn intent_at(&self, run_key: Option<&str>) -> Option<String> {
        let run_key = run_key?;
        let connection = self.connect().ok()?;
        let mut rows = connection
            .query(
                "SELECT intent FROM run_contexts WHERE run_key=?1 AND intent IS NOT NULL",
                [run_key],
            )
            .await
            .ok()?;
        rows.next()
            .await
            .ok()
            .flatten()
            .and_then(|row| row.get::<String>(0).ok())
    }

    async fn persist_intent(&self, run_key: &str, intent: &str) -> Result<()> {
        let crate::runkey::KeyOutcome::Valid(valid) = crate::runkey::validate_full(Some(run_key))
        else {
            return Err(Error::engine(
                "set_intent requires a valid full run key for persistence",
            ));
        };
        // Intent declarations participate in the same physical write order as
        // content events. Besides avoiding transient busy failures, this makes
        // concurrent redeclarations deterministic at the statement boundary.
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|_| Error::engine("cannot persist run intent"))?;
        let outcome = async {
            connection
            .execute(
                "INSERT INTO run_contexts(run_key,intent,agent_key) VALUES(?1,?2,?3) ON CONFLICT(run_key) DO UPDATE SET intent=excluded.intent,agent_key=excluded.agent_key,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                (valid.clone(), intent, crate::runkey::agent_key_of(&valid)),
            )
            .await
            .map_err(|_| Error::engine("cannot persist run intent"))?;
            #[cfg(feature = "turso-tests")]
            self.inner.contract_faults.intent.enter("persist_intent").await?;
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => connection
                .execute("COMMIT", ())
                .await
                .map(|_| ())
                .map_err(|_| Error::engine("cannot persist run intent")),
            Err(error) => {
                connection
                    .execute("ROLLBACK", ())
                    .await
                    .map_err(|_| Error::engine("cannot persist run intent"))?;
                Err(error)
            }
        }
    }

    /// Persist an exact, monotonic portability policy for this database.
    ///
    /// This profile declares no canonical-interchange import, so this runtime
    /// API is how a policy reaches a Turso-local database. The decision is the
    /// shared one — compare-and-set on the policy revision, monotonic revision
    /// floors, the target capability intersection and the catalog pin all come
    /// from `storage_profile`; only the transaction and the physical row codec
    /// are owned here.
    ///
    /// The policy gate's write side excludes every admitted request for the
    /// whole update, so a stricter policy cannot land between an admission
    /// decision and the execution it authorized. The immediate transaction
    /// supplies the durable compare-and-set boundary, so a rejected policy
    /// leaves the previous one exactly as it was.
    ///
    /// The write gate is taken second and only around the physical write: the
    /// policy gate is what orders this against admission, and taking the write
    /// gate for the whole call would instead order it against unrelated domain
    /// writes.
    pub async fn update_portability_policy(
        &self,
        update: crate::storage_profile::PortabilityPolicyUpdate,
    ) -> Result<Value> {
        let _policy = self.inner.portability_policy_gate.write().await;
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|_| Error::engine("cannot begin Turso-local portability policy update"))?;
        let outcome = self.write_portability_policy(&connection, update).await;
        match &outcome {
            Ok(_) => connection.execute("COMMIT", ()).await.map_err(|_| {
                Error::engine("cannot commit Turso-local portability policy update")
            })?,
            Err(_) => connection.execute("ROLLBACK", ()).await.map_err(|_| {
                Error::engine("cannot roll back Turso-local portability policy update")
            })?,
        };
        outcome
    }

    async fn write_portability_policy(
        &self,
        connection: &turso::Connection,
        update: crate::storage_profile::PortabilityPolicyUpdate,
    ) -> Result<Value> {
        let current = read_portability_policy(connection).await?;
        let planned = crate::storage_profile::plan_portability_policy_update(
            current.as_ref(),
            &turso_local_policy_authority(),
            &update,
        )?;
        let columns = planned.columns;
        connection
            .execute(
                "INSERT INTO storage_portability_policy(singleton,policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256,updated_at) \
                 VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) \
                 ON CONFLICT(singleton) DO UPDATE SET policy_revision=excluded.policy_revision,enforcement=excluded.enforcement,source_profile_id=excluded.source_profile_id,source_profile_revision=excluded.source_profile_revision,source_mode=excluded.source_mode,targets=excluded.targets,revision_floors=excluded.revision_floors,allow_conversions=excluded.allow_conversions,catalog_sha256=excluded.catalog_sha256,updated_at=excluded.updated_at",
                turso::params![
                    columns.policy_revision,
                    columns.enforcement.as_str(),
                    columns.source_profile_id.as_str(),
                    columns.source_profile_revision,
                    columns.source_mode.as_str(),
                    columns.targets.as_str(),
                    columns.revision_floors.as_str(),
                    columns.allow_conversions.as_str(),
                    columns.catalog_sha256.as_str(),
                    crate::store::now_iso().as_str(),
                ],
            )
            .await
            .map_err(|_| Error::engine("cannot persist the Turso-local portability policy"))?;
        Ok(planned.report)
    }

    /// The persisted portability policy, if this database carries one.
    ///
    /// The physical column set is identical on every backend, so the row is
    /// handed straight to the shared decoder rather than being reinterpreted
    /// here. A row that cannot be decoded is an error, never an absent policy:
    /// a database whose policy is unreadable must not silently become
    /// unenforced.
    async fn persisted_portability_policy(
        &self,
    ) -> Result<Option<crate::storage_profile::PersistedPolicy>> {
        read_portability_policy(&self.connect()?).await
    }
}

/// This runtime authors its own portability policies, so the intersection is
/// computed from this profile's own capability set — not the compiled active
/// profile, which belongs to SQLite. Everything this backend admits or denies
/// under strict enforcement follows from these declared capabilities.
pub(crate) fn turso_local_policy_authority() -> crate::storage_profile::StorageTarget {
    crate::storage_profile::StorageTarget {
        id: "turso-local".into(),
        revision: TURSO_LOCAL_PROFILE_REVISION,
        mode: "embedded".into(),
    }
}

/// Decode the persisted policy through the shared decoder.
///
/// A row that cannot be decoded is an error, never an absent policy: a database
/// whose policy is unreadable must not silently become unenforced.
async fn read_portability_policy(
    connection: &turso::Connection,
) -> Result<Option<crate::storage_profile::PersistedPolicy>> {
    let mut rows = connection
        .query(
            "SELECT policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256 FROM storage_portability_policy WHERE singleton=1",
            (),
        )
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local portability policy"))?;
    let Some(row) = rows
        .next()
        .await
        .map_err(|_| Error::engine("cannot inspect Turso-local portability policy"))?
    else {
        return Ok(None);
    };
    let invalid = || Error::engine("invalid Turso-local portability policy row");
    let integer = |index: usize| row.get::<i64>(index).map_err(|_| invalid());
    let string = |index: usize| row.get::<String>(index).map_err(|_| invalid());
    crate::storage_profile::decode_policy_columns(
        crate::storage_profile::PortabilityPolicyColumns {
            policy_revision: integer(0)?,
            enforcement: string(1)?,
            source_profile_id: string(2)?,
            source_profile_revision: integer(3)?,
            source_mode: string(4)?,
            targets: string(5)?,
            revision_floors: string(6)?,
            allow_conversions: string(7)?,
            catalog_sha256: string(8)?,
        },
    )
    .map(Some)
}

/// Runtime request capabilities for the promoted handle. Interaction capture
/// stays explicitly suppressed because `native.interaction-log.v1` is not
/// qualified for this profile; run context, fixed-profile admission and
/// post-commit wakeup retain the shared wrapper order.
pub(crate) struct TursoRuntimeRequestLifecycle {
    db: TursoLocalDb,
}

impl TursoRuntimeRequestLifecycle {
    pub(crate) fn new(db: TursoLocalDb) -> Self {
        Self { db }
    }
}

impl crate::domain_transaction::request::RequestLifecyclePort for TursoRuntimeRequestLifecycle {
    fn backend_label(&self) -> &'static str {
        BACKEND
    }

    fn capability(
        &self,
        operation: crate::domain_transaction::request::GovernedRequestOperation,
    ) -> crate::domain_transaction::request::RequestStageCapability {
        use crate::domain_transaction::request::{
            GovernedRequestOperation as Operation, RequestStageCapability as Capability,
        };
        match operation {
            Operation::InteractionCapture => Capability::Suppressed,
            Operation::RunContext
            | Operation::Authorization
            | Operation::StrictPortability
            | Operation::RealtimeWakeup
            | Operation::TransientEvidence
            | Operation::StableErrors => Capability::Applied,
        }
    }

    /// Mint against persisted evidence, using the shared selection rule.
    ///
    /// A key that has actually been used must never be minted again while its
    /// evidence exists, so the candidate walk is checked against durable
    /// content annotations and explicit run-context declarations rather than
    /// trusting randomness. This profile still materializes no disposable
    /// interaction/read-log tier.
    ///
    /// An unusable agent key now returns a mint error instead of minting under
    /// `scout-chair`, which had handed the caller a different agent's
    /// namespace. This changes only what the mint returns, not what the request
    /// does: the shared fold turns any mint error into `KeyOutcome::Absent`, so
    /// the call still runs, uncorrelated, and reports that it is not attached
    /// to a run. It is deliberately not an operation rejection.
    fn mint_run_key<'a>(&'a self, agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            #[cfg(feature = "turso-tests")]
            self.db
                .inner
                .contract_faults
                .mint
                .enter("mint_run_key")
                .await?;
            match agent_key {
                Some(agent_key) => {
                    let agent_key = match crate::runkey::validate(Some(&format!(
                        "{}{agent_key}",
                        crate::runkey::AGENT_KEY_SENTINEL_PREFIX
                    ))) {
                        crate::runkey::KeyOutcome::Requested {
                            agent_key: Some(valid),
                        } => valid,
                        _ => return Err(Error::engine("invalid agent key")),
                    };
                    let taken = self
                        .db
                        .persisted_run_keys(Some(&format!("{agent_key}-%")))
                        .await?;
                    crate::runkey::mint_run_for_agent(&agent_key, &taken)
                }
                None => {
                    let taken = self.db.persisted_run_keys(None).await?;
                    crate::runkey::mint_fresh_agent_run(&taken)
                }
            }
        })
    }

    fn intent_at<'a>(&'a self, run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
        Box::pin(self.db.intent_at(run_key))
    }

    fn persist_intent<'a>(
        &'a self,
        run_key: &'a str,
        intent: &'a str,
        _authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.db.persist_intent(run_key, intent))
    }

    fn displaced_key_note<'a>(
        &'a self,
        _caller: &'a crate::mcp::Caller,
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }

    fn with_operation_admission<'a>(
        &'a self,
        operation: &'a str,
        capability: Option<&'a str>,
        future: BoxFuture<'a, Result<crate::mcp::ToolResult>>,
    ) -> BoxFuture<'a, Result<crate::mcp::ToolResult>> {
        Box::pin(async move {
            let admitted = matches!(
                (operation, capability),
                ("ping" | "engine_info" | "set_intent", None)
                    | (
                        "create_record"
                            | "get_record"
                            | "get_structure"
                            | "get_dashboard"
                            | "render_record"
                            | "update_record"
                            | "delete_record"
                            | "archive_record"
                            | "get_history"
                            | "manage_links"
                            | "attach_text"
                            | "attach_from_url"
                            | "read_attachment"
                            | "manage_attachments"
                            | "query_record"
                            | "resolve_rollup"
                            | "search"
                            | "scan"
                            | "resolve_external"
                            | "manage_bindings"
                            | "manage_facet_observations"
                            | "preview_record_shape"
                            | "resolve_facets"
                            | "suggest_facet_values",
                        Some("native.domain-mcp.v1"),
                    )
                    | ("get_record", Some("native.operation.record-read.v1"))
                    | ("get_history", Some("native.operation.record-history.v1"))
                    | ("manage_links", Some("native.operation.link-add.v1"))
                    | ("search", Some("native.search.lexical.v1"))
                    | ("query_sql", Some("native.raw-sql"))
                    | ("describe_schema", Some("native.describe-physical-schema"),)
            );
            if !admitted {
                return Err(Error::engine(format!(
                    "turso-local fixed-profile admission rejected operation '{operation}' with capability '{}'",
                    capability.unwrap_or("none")
                )));
            }
            // The fixed profile says what this backend implements; the
            // persisted policy says what this database is allowed to remain
            // portable to. Both must admit the request, and an unreadable
            // policy fails closed.
            //
            // The read lease is taken before the policy is read and held for
            // the whole governed future, so the decision and the execution it
            // authorized cannot be split by a concurrent stricter update.
            let _policy_lease = self.db.inner.portability_policy_gate.read().await;
            let policy = self.db.persisted_portability_policy().await?;
            crate::storage_profile::admit_request_operation(
                policy.as_ref(),
                &turso_local_policy_authority(),
                operation,
                capability,
            )?;
            future.await
        })
    }

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<crate::mcp::ToolResult>>,
    ) -> BoxFuture<'a, Result<crate::mcp::ToolResult>> {
        let completion = Arc::new(TursoRequestRealtimeCompletion {
            committed: AtomicBool::new(false),
            hub: self.db.inner.realtime.clone(),
        });
        Box::pin(async move {
            let outcome = TURSO_REQUEST_REALTIME_COMPLETION
                .scope(Arc::clone(&completion), future)
                .await;
            completion.finish();
            outcome
        })
    }

    fn capture_interaction<'a>(
        &'a self,
        _capture: crate::domain_transaction::request::InteractionCapture<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

fn unsupported(operation: &str) -> Error {
    crate::domain_transaction::unsupported_backend_operation(BACKEND, operation)
}

async fn run_write<'connection, T, H>(
    connection: &'connection mut turso::Connection,
    realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    H: for<'transaction> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let mut lifecycle =
        TursoTransactionLifecycle::admit(connection, control.clone(), realtime).await?;
    crate::domain_transaction::run_backend_transaction(
        &mut lifecycle,
        control,
        &mut (),
        |transaction, _| handler(transaction),
    )
    .await
    .map_err(|error| error.stable("execute Turso domain transaction"))
}

async fn run_write_with_disposition<'connection, T, H>(
    connection: &'connection mut turso::Connection,
    realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    H: for<'transaction> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<
        'transaction,
        Result<crate::domain_transaction::TransactionDisposition<T>>,
    >,
{
    let mut lifecycle =
        TursoTransactionLifecycle::admit(connection, control.clone(), realtime).await?;
    crate::domain_transaction::run_backend_transaction_with_disposition(
        &mut lifecycle,
        control,
        &mut (),
        |transaction, _| handler(transaction),
    )
    .await
    .map_err(|error| error.stable("execute Turso domain transaction"))
}

async fn run_snapshot<'connection, T, H>(
    connection: &'connection mut turso::Connection,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    H: for<'transaction> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let mut lifecycle = TursoTransactionLifecycle::admit(
        connection,
        control.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .await?;
    crate::domain_transaction::run_backend_snapshot(
        &mut lifecycle,
        control,
        &mut (),
        |transaction, _| handler(transaction),
    )
    .await
    .map_err(|error| error.stable("execute Turso domain snapshot"))
}

#[cfg(test)]
async fn append_specs(
    connection: &mut turso::Connection,
    realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    control: &ExecutionControl,
    specs: Vec<AppendSpec>,
) -> Result<()> {
    run_write(connection, realtime, control, move |transaction| {
        Box::pin(async move {
            for spec in specs {
                transaction.append_content(spec).await?;
            }
            Ok(())
        })
    })
    .await
}

async fn append_engine_seed_specs(
    connection: &mut turso::Connection,
    realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    control: &ExecutionControl,
    specs: Vec<AppendSpec>,
) -> Result<()> {
    run_write(connection, realtime, control, move |transaction| {
        Box::pin(async move {
            for spec in specs {
                transaction.append_engine_seed_content(spec).await?;
            }
            Ok(())
        })
    })
    .await
}

/// Narrow conformance operation for the guarded-write lifecycle. The expected
/// body is re-read inside the admitted immediate transaction, so a stale
/// contender cannot append an event after another writer commits.
#[cfg(test)]
async fn guarded_record_update(
    connection: &mut turso::Connection,
    realtime: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    control: &ExecutionControl,
    record_id: String,
    expected_body: String,
    replacement_body: String,
) -> Result<()> {
    run_write(connection, realtime, control, move |transaction| {
        Box::pin(async move {
            let current = statement(
                StatementKind::Select,
                "records",
                &["SELECT body FROM {{relation}} WHERE id = ", ""],
            )
            .map_err(|error| stable("guard record update", error))?;
            let rows = transaction
                .rows(
                    "guard record update",
                    &current,
                    &[BindValue::Text(record_id.clone())],
                    &[ColumnSpec::nullable("body", LogicalType::Text)],
                )
                .await?;
            let body = rows
                .first()
                .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))
                .and_then(|row| optional_text(row, "body", "guarded record"))?;
            if body.as_deref() != Some(expected_body.as_str()) {
                return Err(Error::engine(format!(
                    "guarded record update conflict for '{record_id}'"
                )));
            }
            transaction
                .append_content(AppendSpec {
                    record_id,
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({"body": replacement_body}),
                    actor: Some("agent:race".into()),
                })
                .await
        })
    })
    .await
}

#[cfg(test)]
async fn record_snapshot(
    connection: &mut turso::Connection,
    control: &ExecutionControl,
    record_id: &str,
) -> Result<Option<Value>> {
    let record_id = record_id.to_string();
    run_snapshot(connection, control, move |transaction| {
        Box::pin(async move {
            let select = statement(
                StatementKind::Select,
                "records",
                &[
                    "SELECT id, type, kind, name, body, home_id, lifecycle, owner_id, claimed_by_account, claimed_run_key, claimed_at, policy_anchor_id, persistence, maturity, summary, created_at, updated_at, deleted_at FROM {{relation}} WHERE id = ",
                    "",
                ],
            )
            .map_err(|error| stable("read record", error))?;
            let rows = transaction
                .rows(
                    "read record",
                    &select,
                    &[BindValue::Text(record_id)],
                    &[
                        ColumnSpec::required("id", LogicalType::Text),
                        ColumnSpec::required("type", LogicalType::Text),
                        ColumnSpec::nullable("kind", LogicalType::Text),
                        ColumnSpec::required("name", LogicalType::Text),
                        ColumnSpec::nullable("body", LogicalType::Text),
                        ColumnSpec::nullable("home_id", LogicalType::Text),
                        ColumnSpec::nullable("lifecycle", LogicalType::Text),
                        ColumnSpec::nullable("owner_id", LogicalType::Text),
                        ColumnSpec::nullable("claimed_by_account", LogicalType::Text),
                        ColumnSpec::nullable("claimed_run_key", LogicalType::Text),
                        ColumnSpec::nullable("claimed_at", LogicalType::Text),
                        ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
                        ColumnSpec::required("persistence", LogicalType::Text),
                        ColumnSpec::nullable("maturity", LogicalType::Text),
                        ColumnSpec::nullable("summary", LogicalType::Text),
                        ColumnSpec::required("created_at", LogicalType::Text),
                        ColumnSpec::required("updated_at", LogicalType::Text),
                        ColumnSpec::nullable("deleted_at", LogicalType::Text),
                    ],
                )
                .await?;
            rows.first().map(normalized_record).transpose()
        })
    })
    .await
}

#[cfg(test)]
fn normalized_record(row: &NormalizedRow) -> Result<Value> {
    let mut record = serde_json::Map::new();
    for column in [
        "id",
        "type",
        "kind",
        "name",
        "body",
        "home_id",
        "lifecycle",
        "owner_id",
        "claimed_by_account",
        "claimed_run_key",
        "claimed_at",
        "policy_anchor_id",
        "persistence",
        "maturity",
        "summary",
        "created_at",
        "updated_at",
        "deleted_at",
    ] {
        let value = match row.get(column) {
            Some(NormalizedValue::Text(value)) => Value::String(value.clone()),
            Some(NormalizedValue::Null) => Value::Null,
            _ => {
                return Err(Error::engine(format!(
                    "record snapshot column '{column}' is invalid"
                )))
            }
        };
        record.insert(column.into(), value);
    }
    Ok(Value::Object(record))
}

fn principal(caller: &crate::mcp::Caller) -> crate::authorization::Principal<'_> {
    if caller.is_trusted_local() && caller.hosting_database().is_none() {
        crate::authorization::Principal::trusted_local()
    } else {
        // Routed hosted callers have already crossed the catalog membership
        // boundary before an EngineHandle is selected.
        crate::authorization::Principal::bound(caller.credential(), true)
    }
}

async fn run_db_write<T, H>(db: &TursoLocalDb, control: &ExecutionControl, handler: H) -> Result<T>
where
    H: for<'transaction, 'connection> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let _write = db.inner.write_gate.lock().await;
    let mut connection = db.connect()?;
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(|_| Error::engine("cannot enable Turso-local foreign keys"))?;
    let before = db.inner.committed.load(Ordering::Acquire);
    let outcome = run_write(
        &mut connection,
        db.inner.committed.clone(),
        control,
        handler,
    )
    .await;
    if db.inner.committed.load(Ordering::Acquire) > before
        && TURSO_REQUEST_REALTIME_COMPLETION.try_with(|_| ()).is_err()
    {
        db.inner.realtime.wake();
    }
    outcome
}

async fn run_db_write_with_disposition<T, H>(
    db: &TursoLocalDb,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    H: for<'transaction, 'connection> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<
        'transaction,
        Result<crate::domain_transaction::TransactionDisposition<T>>,
    >,
{
    let _write = db.inner.write_gate.lock().await;
    let mut connection = db.connect()?;
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .map_err(|_| Error::engine("cannot enable Turso-local foreign keys"))?;
    let before = db.inner.committed.load(Ordering::Acquire);
    let outcome = run_write_with_disposition(
        &mut connection,
        db.inner.committed.clone(),
        control,
        handler,
    )
    .await;
    if db.inner.committed.load(Ordering::Acquire) > before
        && TURSO_REQUEST_REALTIME_COMPLETION.try_with(|_| ()).is_err()
    {
        db.inner.realtime.wake();
    }
    outcome
}

async fn run_db_operation_write<T, H>(
    db: &TursoLocalDb,
    operation: &'static str,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    T: Send + 'static,
    H: for<'transaction, 'connection> FnOnce(
            &'transaction mut TursoDomainTransaction<'connection>,
        ) -> BoxFuture<'transaction, Result<T>>
        + Send
        + 'static,
{
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    run_db_write(db, control, move |transaction| {
        Box::pin(async move {
            let result = handler(transaction).await?;
            #[cfg(feature = "turso-tests")]
            faults.write.enter(operation).await?;
            Ok(result)
        })
    })
    .await
}

async fn run_db_operation_write_with_disposition<T, H>(
    db: &TursoLocalDb,
    operation: &'static str,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    T: Send + 'static,
    H: for<'transaction, 'connection> FnOnce(
            &'transaction mut TursoDomainTransaction<'connection>,
        ) -> BoxFuture<
            'transaction,
            Result<crate::domain_transaction::TransactionDisposition<T>>,
        > + Send
        + 'static,
{
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    run_db_write_with_disposition(db, control, move |transaction| {
        Box::pin(async move {
            let result = handler(transaction).await?;
            #[cfg(feature = "turso-tests")]
            faults.write.enter(operation).await?;
            Ok(result)
        })
    })
    .await
}

async fn run_db_snapshot<T, H>(
    db: &TursoLocalDb,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    H: for<'transaction, 'connection> FnOnce(
        &'transaction mut TursoDomainTransaction<'connection>,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    let mut connection = db.connect()?;
    run_snapshot(&mut connection, control, handler).await
}

async fn run_db_operation_snapshot<T, H>(
    db: &TursoLocalDb,
    operation: &'static str,
    control: &ExecutionControl,
    handler: H,
) -> Result<T>
where
    T: Send + 'static,
    H: for<'transaction, 'connection> FnOnce(
            &'transaction mut TursoDomainTransaction<'connection>,
        ) -> BoxFuture<'transaction, Result<T>>
        + Send
        + 'static,
{
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    run_db_snapshot(db, control, move |transaction| {
        Box::pin(async move {
            let result = handler(transaction).await?;
            #[cfg(feature = "turso-tests")]
            faults.snapshot.enter(operation).await?;
            Ok(result)
        })
    })
    .await
}

/// Resolve abbreviated record arguments through the same admitted portable
/// snapshot used by bounded Turso-local reads. The snapshot rolls back before
/// dispatch enters the selected handler, so no transaction is nested or held
/// across the tool's own work.
pub(crate) async fn resolve_record_ids(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    tool: &str,
    arguments: Value,
    abbreviations: Vec<(String, String)>,
) -> Result<Value> {
    let caller = caller.clone();
    let tool = tool.to_string();
    run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            crate::mcp::record_ref::resolve_record_ids_with(
                transaction,
                &caller,
                &tool,
                arguments,
                abbreviations,
            )
            .await
        })
    })
    .await
}

async fn require_capability(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    tool: &str,
    record_id: &str,
    capability: crate::authorization::Capability,
) -> Result<()> {
    if crate::authorization::allows_record_with(
        transaction,
        principal(caller),
        record_id,
        capability,
    )
    .await?
    {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{tool}: record {record_id} does not exist"
        )))
    }
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(tool: &str, value: Value) -> Result<T> {
    serde_json::from_value(value)
        .map_err(|error| Error::engine(format!("invalid arguments for {tool}: {error}")))
}

fn require_reason(tool: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        Err(Error::engine(format!("{tool}: 'reason' must not be blank")))
    } else {
        Ok(())
    }
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrectRecordTypeArguments {
    record_id: String,
    target_type: String,
    target_kind: String,
    reason: String,
    #[serde(default)]
    if_content_seq: Option<i64>,
    #[serde(default)]
    if_schema_state_revision: Option<String>,
    #[serde(default)]
    if_dependency_digest: Option<String>,
    #[serde(default)]
    plan_id: Option<String>,
    #[serde(default)]
    effect_digest: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    confirmation_required: Option<bool>,
}

#[cfg(feature = "mcp-executor-prototype")]
async fn correction_rows(
    transaction: &mut TursoDomainTransaction<'_>,
    relation: &'static str,
    fragments: &'static [&'static str],
    record_id: &str,
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    let query = statement(StatementKind::Select, relation, fragments)
        .map_err(|error| stable("prepare record type correction", error))?;
    transaction
        .rows(
            "prepare record type correction",
            &query,
            &[BindValue::Text(record_id.into())],
            columns,
        )
        .await
}

#[cfg(feature = "mcp-executor-prototype")]
async fn correction_snapshot(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    args: &CorrectRecordTypeArguments,
    capability: crate::authorization::Capability,
) -> Result<crate::record_type_correction::CorrectionPlan> {
    const TOOL: &str = "correct_record_type";
    require_capability(transaction, caller, TOOL, &args.record_id, capability).await?;
    require_reason(TOOL, &args.reason)?;
    if !crate::schema::SPINE_TYPES.contains(&args.target_type.as_str())
        || args.target_kind.trim().is_empty()
    {
        return Err(Error::engine(
            "correct_record_type: target_type must be a closed spine type and target_kind must be non-empty",
        ));
    }
    let rows = correction_rows(
        transaction,
        "records",
        &["SELECT type,kind,name,body,home_id,updated_at,deleted_at,lifecycle,owner_id,persistence,maturity FROM {{relation}} WHERE id=", ""],
        &args.record_id,
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::required("name", LogicalType::Text),
            ColumnSpec::nullable("body", LogicalType::Text),
            ColumnSpec::nullable("home_id", LogicalType::Text),
            ColumnSpec::required("updated_at", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ColumnSpec::nullable("lifecycle", LogicalType::Text),
            ColumnSpec::nullable("owner_id", LogicalType::Text),
            ColumnSpec::required("persistence", LogicalType::Text),
            ColumnSpec::nullable("maturity", LogicalType::Text),
        ],
    ).await?;
    let row = rows.first().ok_or_else(|| {
        Error::engine(format!("{TOOL}: record {} does not exist", args.record_id))
    })?;
    if optional_text(row, "deleted_at", "record type correction")?.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.record_id
        )));
    }
    let current_type = text(row, "type", "record type correction")?;
    let current_kind = optional_text(row, "kind", "record type correction")?.ok_or_else(|| {
        Error::engine(
            "correct_record_type: current record has no kind and cannot preserve identity",
        )
    })?;
    let name = text(row, "name", "record type correction")?;
    let body = optional_text(row, "body", "record type correction")?;
    let home_id = optional_text(row, "home_id", "record type correction")?;
    let updated_at = text(row, "updated_at", "record type correction")?;

    let seq = correction_rows(
        transaction,
        "content_events",
        &[
            "SELECT COALESCE(MAX(seq),0) AS seq FROM {{relation}} WHERE record_id=",
            "",
        ],
        &args.record_id,
        &[ColumnSpec::required("seq", LogicalType::Integer)],
    )
    .await?;
    let previous_seq = integer(&seq[0], "seq", "record type correction")?;
    if args
        .if_content_seq
        .is_some_and(|expected| expected != previous_seq)
    {
        return Err(Error::engine(
            "correct_record_type: content revision conflict; prepare again",
        ));
    }

    let target_resolution =
        crate::meta::kind::resolve_with(transaction, &args.target_type, &args.target_kind).await?;
    let target_active = !target_resolution.quarantined;
    let canonical_target_kind = target_resolution
        .canonical_kind
        .clone()
        .unwrap_or_else(|| args.target_kind.clone());
    let current_resolution =
        crate::meta::kind::resolve_with(transaction, &current_type, &current_kind).await?;
    let mut matching_types = Vec::new();
    for record_type in crate::schema::SPINE_TYPES {
        if !crate::meta::kind::resolve_with(transaction, record_type, &current_kind)
            .await?
            .quarantined
        {
            matching_types.push(record_type);
        }
    }
    let unique_wrong_type_match = current_resolution.quarantined
        && matching_types.as_slice() == [args.target_type.as_str()]
        && target_active
        && canonical_target_kind == current_kind;

    let runtime = correction_rows(
        transaction,
        "facet_values",
        &[
            "SELECT value FROM {{relation}} WHERE record_id=",
            " AND key='runtime'",
        ],
        &args.record_id,
        &[ColumnSpec::nullable("value", LogicalType::Text)],
    )
    .await?
    .first()
    .map(|row| optional_text(row, "value", "record type correction runtime"))
    .transpose()?
    .flatten();

    let dependent_queries: [(&str, &'static str, &'static [&'static str]); 10] = [
        ("incoming_links", "links", &["SELECT source_id AS id FROM {{relation}} WHERE target_id=", " ORDER BY source_id LIMIT 20"]),
        ("outgoing_links", "links", &["SELECT target_id AS id FROM {{relation}} WHERE source_id=", " ORDER BY target_id LIMIT 20"]),
        ("children", "records", &["SELECT id FROM {{relation}} WHERE home_id=", " AND deleted_at IS NULL ORDER BY id LIMIT 20"]),
        ("comments", "links", &["SELECT r.id AS id FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"]),
        ("citations", "links", &["SELECT r.id AS id FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"]),
        ("attachments", "links", &["SELECT r.id AS id FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"]),
        ("targeted_annotations", "annotation_targets", &["SELECT annotation_id AS id FROM {{relation}} WHERE target_record_id=", " ORDER BY annotation_id LIMIT 20"]),
        ("attributions", "attribution_targets", &["SELECT annotation_id AS id FROM {{relation}} WHERE target_record_id=", " ORDER BY annotation_id LIMIT 20"]),
        ("relationships", "relationship_endpoints", &["SELECT relationship_origin_db_id || ':' || relationship_id AS id FROM {{relation}} WHERE record_id=", " ORDER BY relationship_origin_db_id,relationship_id LIMIT 20"]),
        ("bindings", "bindings", &["SELECT system || ':' || identifier || ':' || is_canonical AS id FROM {{relation}} WHERE record_id=", " ORDER BY system,identifier LIMIT 20"]),
    ];
    let mut bounded_ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for (key, relation, fragments) in dependent_queries {
        let ids = correction_rows(
            transaction,
            relation,
            fragments,
            &args.record_id,
            &[ColumnSpec::required("id", LogicalType::Text)],
        )
        .await?
        .iter()
        .map(|row| text(row, "id", "record type correction dependency"))
        .collect::<Result<Vec<_>>>()?;
        let count_fragments: &'static [&'static str] = match key {
            "incoming_links" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE target_id=", ""],
            "outgoing_links" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE source_id=", ""],
            "children" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE home_id=", " AND deleted_at IS NULL"],
            "comments" => &["SELECT COUNT(*) AS count FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL"],
            "citations" => &["SELECT COUNT(*) AS count FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL"],
            "attachments" => &["SELECT COUNT(*) AS count FROM {{relation}} l JOIN records r ON r.id=l.source_id WHERE l.target_id=", " AND l.relationship='part_of' AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL"],
            "targeted_annotations" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE target_record_id=", ""],
            "attributions" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE target_record_id=", ""],
            "relationships" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE record_id=", ""],
            "bindings" => &["SELECT COUNT(*) AS count FROM {{relation}} WHERE record_id=", ""],
            _ => unreachable!(),
        };
        let count_rows = correction_rows(
            transaction,
            relation,
            count_fragments,
            &args.record_id,
            &[ColumnSpec::required("count", LogicalType::Integer)],
        )
        .await?;
        counts.insert(
            key.into(),
            integer(&count_rows[0], "count", "record type correction dependency")?,
        );
        bounded_ids.insert(key.into(), ids);
    }
    let facet_count = correction_rows(
        transaction,
        "facet_values",
        &[
            "SELECT COUNT(*) AS count FROM {{relation}} WHERE record_id=",
            "",
        ],
        &args.record_id,
        &[ColumnSpec::required("count", LogicalType::Integer)],
    )
    .await?;
    counts.insert(
        "facets".into(),
        integer(&facet_count[0], "count", "record type correction facets")?,
    );
    let binding_head = statement(
        StatementKind::Select,
        "binding_audit",
        &["SELECT COALESCE(MAX(seq),0) AS count FROM {{relation}}"],
    )
    .map_err(|error| stable("prepare record type correction", error))?;
    let binding_head = transaction
        .rows(
            "prepare record type correction",
            &binding_head,
            &[],
            &[ColumnSpec::required("count", LogicalType::Integer)],
        )
        .await?;
    let binding_audit_head = integer(
        &binding_head[0],
        "count",
        "record type correction binding audit",
    )?;
    let relationship_head = statement(
        StatementKind::Select,
        "relationship_events",
        &["SELECT COALESCE(MAX(seq),0) AS count FROM {{relation}}"],
    )
    .map_err(|error| stable("prepare record type correction", error))?;
    let relationship_head = transaction
        .rows(
            "prepare record type correction",
            &relationship_head,
            &[],
            &[ColumnSpec::required("count", LogicalType::Integer)],
        )
        .await?;
    let relationship_event_head = integer(
        &relationship_head[0],
        "count",
        "record type correction relationship audit",
    )?;

    let mut relevant_ids = BTreeSet::from([args.record_id.clone()]);
    for (category, ids) in &bounded_ids {
        if !matches!(category.as_str(), "relationships" | "bindings") {
            relevant_ids.extend(ids.iter().cloned());
        }
    }
    let caller_run = caller.run_key();
    let mut same_run_provenance = caller_run.is_some();
    let mut creation_matches = false;
    for id in &relevant_ids {
        let events = correction_rows(
            transaction,
            "content_events",
            &[
                "SELECT type,actor,run_key FROM {{relation}} WHERE record_id=",
                " ORDER BY seq",
            ],
            id,
            &[
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("actor", LogicalType::Text),
                ColumnSpec::nullable("run_key", LogicalType::Text),
            ],
        )
        .await?;
        for event in events {
            let event_type = text(&event, "type", "record type correction provenance")?;
            let matches = optional_text(&event, "actor", "record type correction provenance")?
                .as_deref()
                == Some(caller.actor())
                && optional_text(&event, "run_key", "record type correction provenance")?
                    .as_deref()
                    == caller_run;
            same_run_provenance &= matches;
            if id == &args.record_id && event_type == "record.created" {
                creation_matches = matches;
            }
        }
    }
    same_run_provenance &= creation_matches;
    let replicated = correction_rows(transaction, "content_events", &["SELECT EXISTS(SELECT 1 FROM {{relation}} e JOIN content_event_sources s ON s.event_id=e.id WHERE e.record_id=", ") AS present"], &args.record_id, &[ColumnSpec::required("present", LogicalType::Bool)]).await?;
    same_run_provenance &= !boolean(
        &replicated[0],
        "present",
        "record type correction replication",
    )?;

    let mut blockers = Vec::new();
    {
        let mut block = |blocker: crate::record_type_correction::Blocker| blockers.push(blocker);
        if crate::schema::ENGINE_PROVISIONED_RECORD_IDS.contains(&args.record_id.as_str()) {
            block(crate::record_type_correction::Blocker::EngineFilingRecord);
        }
        if args.target_type == "Message"
            || (args.target_type == "Annotation"
                && matches!(
                    canonical_target_kind.as_str(),
                    "attribution" | "citation" | "comment"
                ))
        {
            // This adapter does not distinguish the two specialised target
            // shapes the SQLite adapter names separately; the combined wording
            // is preserved rather than silently aligned.
            block(crate::record_type_correction::Blocker::SpecialisedTargetShape);
        }
        if let Err(error) = crate::mcp::tools::lifecycle::validate_prospective_program(
            TOOL,
            &args.target_type,
            Some(&canonical_target_kind),
            runtime.as_deref(),
        ) {
            block(
                crate::record_type_correction::Blocker::ProspectiveProgramShape {
                    detail: error.to_string(),
                },
            );
        }
        // Focused queries keep every governed blocker tied to one explicit bound
        // bearer rather than depending on backend-specific multi-parameter SQL.
        for (blocker, relation, fragments) in [
            (
                crate::record_type_correction::Blocker::SemanticUnit,
                "semantic_units",
                &[
                    "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE unit_id=",
                    ") AS present",
                ] as &'static [&'static str],
            ),
            (
                crate::record_type_correction::Blocker::TargetedAnnotation,
                "annotation_targets",
                &[
                    "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE annotation_id=",
                    ") AS present",
                ],
            ),
            (
                crate::record_type_correction::Blocker::GovernedAttribution,
                "attribution_assertions",
                &[
                    "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE annotation_id=",
                    ") AS present",
                ],
            ),
        ] {
            let found = correction_rows(
                transaction,
                relation,
                fragments,
                &args.record_id,
                &[ColumnSpec::required("present", LogicalType::Bool)],
            )
            .await?;
            if boolean(&found[0], "present", "record type correction blocker")? {
                block(blocker);
            }
        }
        if current_type == "Annotation" && current_kind == "attribution" {
            block(crate::record_type_correction::Blocker::GovernedAttribution);
        }
        if current_type == "Message" {
            let status = correction_rows(
                transaction,
                "message_audience_state",
                &["SELECT status FROM {{relation}} WHERE message_id=", ""],
                &args.record_id,
                &[ColumnSpec::required("status", LogicalType::Text)],
            )
            .await?;
            if status
                .first()
                .map(|row| text(row, "status", "message state"))
                .transpose()?
                .as_deref()
                != Some("pending_local")
            {
                block(crate::record_type_correction::Blocker::MessageDeliveryState);
            }
        }
        for (relation, fragments) in [
        ("module_releases", &["SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE module_record_id=", ") AS present"] as &'static [&'static str]),
        ("recipe_releases", &["SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE program_id=", ") AS present"]),
        ("artifact_source_attestations", &["SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE artifact_id=", ") AS present"]),
        ("derivation_target_heads", &["SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE target_kind='record' AND target_record_id=", ") AS present"]),
        ("derivation_artifact_role_heads", &["SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE target_kind='record' AND target_record_id=", ") AS present"]),
    ] {
        let found = correction_rows(transaction, relation, fragments, &args.record_id, &[ColumnSpec::required("present", LogicalType::Bool)]).await?;
        if boolean(&found[0], "present", "record type correction aggregate")? {
            block(crate::record_type_correction::Blocker::SpecialisedAggregate);
        }
    }
        let incompatible = statement(StatementKind::Select, "bindings", &[
        "SELECT EXISTS(SELECT 1 FROM {{relation}} b JOIN binding_systems s ON s.system=b.system WHERE b.record_id=", " AND ((s.compatible_type IS NOT NULL AND s.compatible_type<>", ") OR (s.compatible_kind IS NOT NULL AND s.compatible_kind<>", "))) AS present"
    ]).map_err(|error| stable("prepare record type correction", error))?;
        let incompatible = transaction
            .rows(
                "prepare record type correction",
                &incompatible,
                &[
                    BindValue::Text(args.record_id.clone()),
                    BindValue::Text(args.target_type.clone()),
                    BindValue::Text(canonical_target_kind.clone()),
                ],
                &[ColumnSpec::required("present", LogicalType::Bool)],
            )
            .await?;
        if boolean(
            &incompatible[0],
            "present",
            "record type correction binding",
        )? {
            block(crate::record_type_correction::Blocker::IncompatibleIdentityBinding);
        }
    }

    let schema_rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
    let target_facets = crate::query::cascade::facets_for_record_context(
        &schema_rows,
        &args.target_type,
        Some(&canonical_target_kind),
        home_id.as_deref(),
    );
    let open = correction_rows(
        transaction,
        "facet_values",
        &[
            "SELECT key FROM {{relation}} WHERE record_id=",
            " AND value IS NOT NULL ORDER BY key",
        ],
        &args.record_id,
        &[ColumnSpec::required("key", LogicalType::Text)],
    )
    .await?;
    let present_open = open
        .iter()
        .map(|row| text(row, "key", "record type correction facet"))
        .collect::<Result<BTreeSet<_>>>()?;
    for (key, shape) in target_facets {
        if shape.get("required") != Some(&Value::Bool(true)) {
            continue;
        }
        let present = match crate::schema::spine_facet_column(&key) {
            Some(column) => optional_text(row, column, "record type correction")?.is_some(),
            None => present_open.contains(&key),
        };
        if !present {
            blockers
                .push(crate::record_type_correction::Blocker::RequiredFacetMissing { facet: key });
        }
    }
    let facet_rows = correction_rows(
        transaction,
        "facet_values",
        &[
            "SELECT key,value,value_num,vocab_ref FROM {{relation}} WHERE record_id=",
            " AND value IS NOT NULL ORDER BY key",
        ],
        &args.record_id,
        &[
            ColumnSpec::required("key", LogicalType::Text),
            ColumnSpec::required("value", LogicalType::Text),
            ColumnSpec::nullable("value_num", LogicalType::Real),
            ColumnSpec::nullable("vocab_ref", LogicalType::Text),
        ],
    )
    .await?;
    let mut facets = facet_rows
        .iter()
        .map(|row| {
            let key = text(row, "key", "record type correction facet")?;
            let stored = text(row, "value", "record type correction facet")?;
            let value = match row.get("value_num") {
                Some(NormalizedValue::Real(_)) | Some(NormalizedValue::Integer(_)) => {
                    serde_json::from_str(&stored).map_err(|_| {
                        Error::engine(format!(
                            "correct_record_type: stored numeric facet '{key}' is not valid JSON"
                        ))
                    })?
                }
                _ => Value::String(stored),
            };
            Ok(crate::domain_transaction::FacetWrite {
                key,
                value,
                vocab_ref: optional_text(row, "vocab_ref", "record type correction facet")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Err(error) = crate::domain_transaction::govern_facet_writes(
        transaction,
        &schema_rows,
        TOOL,
        &args.target_type,
        Some(&canonical_target_kind),
        &mut facets,
    )
    .await
    {
        blockers.push(
            crate::record_type_correction::Blocker::IncompatibleFacetValue {
                detail: error.to_string(),
            },
        );
    }

    let revision = statement(StatementKind::Select, "meta_events", &["SELECT COALESCE((SELECT MAX(seq) FROM {{relation}}),0) AS meta, COALESCE((SELECT MAX(seq) FROM content_events),0) AS content"])
        .map_err(|error| stable("prepare record type correction", error))?;
    let revisions = transaction
        .rows(
            "prepare record type correction",
            &revision,
            &[],
            &[
                ColumnSpec::required("meta", LogicalType::Integer),
                ColumnSpec::required("content", LogicalType::Integer),
            ],
        )
        .await?;
    let schema_state_revision = format!(
        "schema-state-v1:meta:{}:content:{}",
        integer(&revisions[0], "meta", "schema revision")?,
        integer(&revisions[0], "content", "schema revision")?
    );
    if args
        .if_schema_state_revision
        .as_deref()
        .is_some_and(|expected| expected != schema_state_revision)
    {
        return Err(Error::engine(
            "correct_record_type: schema state revision conflict; prepare again",
        ));
    }
    // This adapter fences on the same two append-only domain logs as SQLite,
    // under its own established key names. Renaming either would move every
    // dependency digest this backend has ever issued, so the names stay.
    let plan = crate::record_type_correction::CorrectionPlan::new(
        crate::record_type_correction::CorrectionFacts {
            record_id: args.record_id.clone(),
            reason: args.reason.clone(),
            name,
            body_digest: crate::mcp::tools::lifecycle::body_digest(body.as_deref()),
            updated_at,
            previous_seq,
            schema_state_revision,
            current: crate::record_type_correction::Identity {
                record_type: current_type,
                kind: current_kind,
            },
            target: crate::record_type_correction::Identity {
                record_type: args.target_type.clone(),
                kind: canonical_target_kind,
            },
            target_active,
            unique_wrong_type_match,
            same_run_provenance,
            preserved_state_counts: counts,
            bounded_identifiers: bounded_ids,
            dependency_fences: BTreeMap::from([
                (
                    "binding_audit_head".to_string(),
                    serde_json::json!(binding_audit_head),
                ),
                (
                    "relationship_event_head".to_string(),
                    serde_json::json!(relationship_event_head),
                ),
            ]),
            blockers,
        },
    )?;
    if args
        .if_dependency_digest
        .as_deref()
        .is_some_and(|expected| expected != plan.dependency_digest())
    {
        return Err(Error::engine(
            "correct_record_type: dependent state changed; prepare again",
        ));
    }
    Ok(plan)
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_correct_record_type(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<crate::mcp::tools::lifecycle::CorrectRecordTypePreparation> {
    let args: CorrectRecordTypeArguments = parse_arguments("correct_record_type", arguments)?;
    if args.if_content_seq.is_some()
        || args.if_schema_state_revision.is_some()
        || args.if_dependency_digest.is_some()
        || args.plan_id.is_some()
        || args.effect_digest.is_some()
        || args.mode.is_some()
        || args.confirmation_required.is_some()
    {
        return Err(Error::engine(
            "correct_record_type: preparation does not accept executor-owned fields",
        ));
    }
    let caller = caller.clone();
    let plan = run_db_operation_snapshot(
        db,
        "prepare_correct_record_type",
        &ExecutionControl::default(),
        {
            let args = args.clone();
            move |transaction| {
                Box::pin(async move {
                    correction_snapshot(
                        transaction,
                        &caller,
                        &args,
                        crate::authorization::Capability::Edit,
                    )
                    .await
                })
            }
        },
    )
    .await?;
    Ok(plan.prepared()?.into())
}

#[cfg(feature = "mcp-executor-prototype")]
async fn correct_record_type(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: CorrectRecordTypeArguments = parse_arguments("correct_record_type", arguments)?;
    let execution = caller.write_plan_execution().ok_or_else(|| {
        Error::engine(
            "correct_record_type: execute only through a claimed records_write.correct_record_type plan",
        )
    })?;
    if execution.executor != "records_write"
        || execution.operation != "correct_record_type"
        || args.plan_id.as_deref() != Some(execution.plan_id.as_str())
        || args.effect_digest.as_deref() != Some(execution.effect_digest.as_str())
    {
        return Err(Error::engine(
            "correct_record_type: executor plan binding does not match the claimed plan",
        ));
    }
    let mode = args.mode.clone().ok_or_else(|| {
        Error::engine(
        "correct_record_type: execute only through records_write.correct_record_type preparation",
    )
    })?;
    if mode == "ineligible" {
        return Err(Error::engine("correct_record_type: prepared effect is ineligible; create a new bearer when appropriate"));
    }
    let confirmation_required = args.confirmation_required.unwrap_or(false);
    if (mode == "confirmed") != confirmation_required
        || !matches!(mode.as_str(), "autonomous" | "confirmed")
    {
        return Err(Error::engine(
            "correct_record_type: invalid prepared correction mode",
        ));
    }
    let plan_id = args
        .plan_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::engine("correct_record_type: executor plan_id is required"))?;
    let effect_digest = args
        .effect_digest
        .clone()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| Error::engine("correct_record_type: executor effect_digest is required"))?;
    let caller = caller.clone();
    run_db_operation_write(
        db,
        "correct_record_type",
        &ExecutionControl::default(),
        move |transaction| {
            Box::pin(async move {
                let plan = correction_snapshot(
                    transaction,
                    &caller,
                    &args,
                    if confirmation_required {
                        crate::authorization::Capability::Manage
                    } else {
                        crate::authorization::Capability::Edit
                    },
                )
                .await?;
                let classification = plan.classification();
                let expected_mode = plan.execution_mode();
                if mode.as_str() != expected_mode {
                    return Err(Error::engine(
                        "correct_record_type: eligibility changed; prepare again",
                    ));
                }
                let event_id = transaction
                    .append_content_event_admitted(
                        AppendSpec {
                            record_id: args.record_id.clone(),
                            event_type: "record.type_corrected.v1".into(),
                            payload: serde_json::json!({
                                "from": classification.current,
                                "to": classification.target,
                                "mode": mode,
                                "reason": args.reason,
                                "plan_id": plan_id,
                                "effect_digest": format!("sha256:{effect_digest}"),
                                "schema_state_revision": plan.schema_state_revision(),
                                "confirmation_required": confirmation_required,
                            }),
                            actor: Some(caller.actor().into()),
                        },
                        false,
                    )
                    .await?;
                let event = correction_rows(
                    transaction,
                    "content_events",
                    &["SELECT seq FROM {{relation}} WHERE id=", ""],
                    &event_id,
                    &[ColumnSpec::required("seq", LogicalType::Integer)],
                )
                .await?;
                Ok(serde_json::json!({
                    "record_id": args.record_id,
                    "type": classification.target.record_type,
                    "kind": classification.target.kind,
                    "mode": mode,
                    "event_id": event_id,
                    "event_seq": integer(&event[0], "seq", "record type correction event")?,
                    "previous_seq": plan.previous_seq(),
                    "body_digest": plan.body_digest(),
                }))
            })
        },
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewLink {
    target_id: String,
    relationship: String,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecordArguments {
    id: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    kind: String,
    name: Option<String>,
    body: Option<String>,
    home_id: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    summary: Option<String>,
    facets: Option<Map<String, Value>>,
    links: Option<Vec<NewLink>>,
    addressed_to: Option<Vec<String>>,
    reason: String,
}

fn facet_write(key: String, value: Value) -> Result<crate::domain_transaction::FacetWrite> {
    crate::mcp::tools::lifecycle::parse_facet_entry("create_record", &key, &value, false)?
        .ok_or_else(|| Error::engine("create_record: facet value must not be null"))
}

async fn create_record(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "create_record";
    let mut args: CreateRecordArguments = parse_arguments(TOOL, arguments)?;
    require_reason(TOOL, &args.reason)?;
    let normalized_lifecycle = args.lifecycle.take();
    if args.kind.is_empty() {
        return Err(Error::engine("create_record: 'kind' must not be empty"));
    }
    if args.record_type == "Message" || args.addressed_to.is_some() {
        return Err(unsupported("create_record Message delivery"));
    }
    let id = crate::domain_transaction::record_id_for_create(args.id)?;
    let home_id = args
        .home_id
        .unwrap_or_else(|| crate::schema::UNFILED_RECORD_ID.into());
    let actor = caller.actor().to_string();
    let record_type = args.record_type;
    let raw_kind = args.kind;
    let name = args.name;
    let body = args.body;
    let mut lifecycle = normalized_lifecycle;
    let owner_id = args.owner_id;
    let persistence = args.persistence.unwrap_or_else(|| "enduring".into());
    let maturity = args.maturity;
    let summary = args.summary;
    let reason = args.reason;
    let facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| facet_write(key, value))
        .collect::<Result<Vec<_>>>()?;
    let links = args.links.unwrap_or_default();
    let id_for_write = id.clone();
    let caller = caller.clone();
    run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            let mut facets = facets;
            let mut owner_id = owner_id;
            require_capability(
                transaction,
                &caller,
                TOOL,
                &home_id,
                crate::authorization::Capability::Edit,
            )
            .await?;
            let trusted_local = caller.is_trusted_local() && caller.hosting_database().is_none();
            if !trusted_local {
                let binding_select = statement(
                    StatementKind::Select,
                    "bindings",
                    &[
                        "SELECT record_id FROM {{relation}} WHERE system='account' AND identifier=",
                        " AND is_canonical=1 ORDER BY record_id",
                    ],
                )
                .map_err(|error| stable("authorize record owner", error))?;
                let bindings = transaction
                    .rows(
                        "authorize record owner",
                        &binding_select,
                        &[BindValue::Text(caller.credential().into())],
                        &[ColumnSpec::required("record_id", LogicalType::Text)],
                    )
                    .await?;
                if bindings.len() != 1 {
                    return Err(Error::engine(format!(
                        "{TOOL}: caller has no unique portable account binding"
                    )));
                }
                let bound_owner = text(&bindings[0], "record_id", "owner binding")?;
                if owner_id.as_deref().is_some_and(|owner| owner != bound_owner) {
                    return Err(Error::engine(format!(
                        "{TOOL}: owner_id must name the caller's verified portable identity"
                    )));
                }
                owner_id = Some(bound_owner);
            }
            for link in &links {
                if link.relationship.is_empty() {
                    return Err(Error::engine("link relationship must not be empty"));
                }
                require_capability(
                    transaction,
                    &caller,
                    TOOL,
                    &link.target_id,
                    crate::authorization::Capability::View,
                )
                .await?;
            }
            let resolution = crate::meta::kind::resolve_with(transaction, &record_type, &raw_kind)
                .await?;
            if crate::generated::kinds::CoreKind::AnnotationAttribution.matches(&resolution) {
                return Err(Error::engine(
                    "create_record: governed Annotation kind:attribution must be created with create_attribution so bearer, exact target, assertion, evidence, and action attestation commit atomically",
                ));
            }
            let is_comment =
                crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution);
            let is_suggestion =
                crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution);
            let kind = resolution
                .canonical_kind_for_write()
                .unwrap_or(&raw_kind)
                .to_string();
            let schema_rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
            crate::domain_transaction::govern_facet_writes(
                transaction,
                &schema_rows,
                TOOL,
                &record_type,
                Some(&kind),
                &mut facets,
            )
            .await?;
            // Only the two governed core work kinds receive an ordinary-create
            // default. Future WorkItem kinds must declare their own lifecycle
            // shape and still do not inherit a default from the type.
            if record_type == "WorkItem" && matches!(kind.as_str(), "task" | "epic") {
                lifecycle.get_or_insert_with(|| "open".into());
            }
            if !is_comment {
                if let Some(value) = lifecycle.as_deref() {
                    let mut lifecycle_write = [crate::domain_transaction::FacetWrite {
                        key: "lifecycle".into(),
                        value: Value::String(value.into()),
                        vocab_ref: None,
                    }];
                    crate::domain_transaction::govern_facet_writes(
                        transaction,
                        &schema_rows,
                        TOOL,
                        &record_type,
                        Some(&kind),
                        &mut lifecycle_write,
                    )
                    .await?;
                }
            }
            if is_suggestion {
                crate::suggestion_lifecycle::validate_create(TOOL, lifecycle.as_deref())?;
            }
            if is_comment {
                let bearers = links
                    .iter()
                    .filter(|link| link.relationship == "part_of")
                    .map(|link| link.target_id.clone())
                    .collect::<Vec<_>>();
                if bearers.len() != 1 {
                    return Err(Error::engine(format!(
                        "{TOOL}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"
                    )));
                }
                let position =
                    comment_position_for_bearer_in(transaction, TOOL, &bearers[0]).await?;
                if lifecycle.as_deref() == Some("resolved") {
                    return Err(Error::engine(format!(
                        "{TOOL}: comment roots cannot be created resolved; create open, then resolve with update_record"
                    )));
                }
                crate::comments::validate_prospective(
                    TOOL,
                    position,
                    body.as_deref(),
                    lifecycle.as_deref(),
                    summary.as_deref(),
                )?;
                // Name the state instead of leaving it to absence: a root
                // created with no lifecycle is an FYI, so it stores
                // `informational` rather than null. Replies keep their null.
                lifecycle = crate::comments::created_lifecycle(position, lifecycle.as_deref());
                if let Some(value) = lifecycle.as_deref() {
                    let mut lifecycle_write = [crate::domain_transaction::FacetWrite {
                        key: "lifecycle".into(),
                        value: Value::String(value.into()),
                        vocab_ref: None,
                    }];
                    crate::domain_transaction::govern_facet_writes(
                        transaction,
                        &schema_rows,
                        TOOL,
                        &record_type,
                        Some(&kind),
                        &mut lifecycle_write,
                    )
                    .await?;
                }
            }
            let record_payload = serde_json::json!({
                "type": record_type,
                "kind": kind,
                "name": name,
                "body": body,
                "home_id": home_id,
                "lifecycle": lifecycle,
                "owner_id": owner_id,
                "persistence": persistence,
                "maturity": maturity,
                "summary": summary,
                "reason": reason,
            });
            transaction
                .append_content(AppendSpec {
                    record_id: id_for_write.clone(),
                    event_type: "record.created".into(),
                    payload: record_payload,
                    actor: Some(actor.clone()),
                })
                .await?;
            for facet in facets {
                transaction
                    .append_content(crate::domain_transaction::facet_set_spec(
                        &id_for_write,
                        &facet,
                        &actor,
                    ))
                    .await?;
            }
            let after = crate::domain_transaction::required_violations(
                transaction,
                &schema_rows,
                &[id_for_write.as_str()],
            )
            .await?;
            crate::domain_transaction::assert_required_not_worsened(
                TOOL,
                &Default::default(),
                &after,
            )?;
            for link in links {
                transaction
                    .append_content(AppendSpec {
                        record_id: id_for_write.clone(),
                        event_type: "link.added".into(),
                        payload: serde_json::to_value(crate::events::LinkAddedPayload {
                            id: None,
                            source_id: id_for_write.clone(),
                            target_id: link.target_id,
                            relationship: link.relationship,
                            note: link.note,
                        })?,
                        actor: Some(actor.clone()),
                    })
                    .await?;
            }
            read_record_in(transaction, &caller, &id_for_write)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "create_record: record {id_for_write} not readable after write"
                    ))
                })
        })
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRecordArguments {
    ids: Vec<String>,
    include_interpretation: Option<bool>,
    resolve: Option<bool>,
    children_limit: Option<i64>,
    children_offset: Option<i64>,
    links_limit: Option<i64>,
    links_offset: Option<i64>,
    include_suggestions: Option<bool>,
    suggestions_limit: Option<i64>,
    suggestions_offset: Option<i64>,
    include_citations: Option<bool>,
    citations_limit: Option<i64>,
    citations_offset: Option<i64>,
    include_comments: Option<bool>,
    comments_limit: Option<i64>,
    comments_offset: Option<i64>,
}

impl GetRecordArguments {
    fn validate_registered_slice(&self) -> Result<()> {
        let neutral_empty_window = |limit: Option<i64>, offset: Option<i64>| {
            matches!(limit, None | Some(0)) && matches!(offset, None | Some(0))
        };
        if self.include_interpretation.unwrap_or(false) {
            return Err(unsupported("get_record interpretation projection"));
        }
        if self.resolve.is_some()
            || !neutral_empty_window(self.children_limit, self.children_offset)
            || !neutral_empty_window(self.links_limit, self.links_offset)
            || self.include_suggestions.is_some()
            || self.suggestions_limit.is_some()
            || self.suggestions_offset.is_some()
            || self.include_citations.is_some()
            || self.citations_limit.is_some()
            || self.citations_offset.is_some()
        {
            return Err(unsupported("get_record enrichment selectors"));
        }
        if self.ids.len() > 100 {
            return Err(Error::engine("get_record: ids exceeds the 100-record cap"));
        }
        let limit = self
            .comments_limit
            .unwrap_or(crate::query::read::DEFAULT_COMMENTS_LIMIT);
        let offset = self.comments_offset.unwrap_or(0);
        if !(0..=crate::query::read::MAX_COMMENTS_LIMIT).contains(&limit) {
            return Err(Error::engine(format!(
                "comments limit must be between 0 and {}",
                crate::query::read::MAX_COMMENTS_LIMIT
            )));
        }
        if offset < 0 {
            return Err(Error::engine("comments offset must be >= 0"));
        }
        Ok(())
    }
}

async fn get_record(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: GetRecordArguments = parse_arguments("get_record", arguments)?;
    args.validate_registered_slice()?;
    let include_comments = args.include_comments.unwrap_or(false);
    let comments_limit = args
        .comments_limit
        .unwrap_or(crate::query::read::DEFAULT_COMMENTS_LIMIT);
    let comments_offset = args.comments_offset.unwrap_or(0);
    let caller = caller.clone();
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            let lifecycle_interpreter =
                crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
                    transaction,
                    principal(&caller),
                )
                .await?;
            let mut records = Vec::with_capacity(args.ids.len());
            for (index, id) in args.ids.into_iter().enumerate() {
                #[cfg(feature = "turso-tests")]
                if index == 1 {
                    faults.snapshot.enter("get_record").await?;
                }
                let Some(mut record) = read_record_with_lifecycle_in(
                    transaction,
                    &caller,
                    &id,
                    &lifecycle_interpreter,
                )
                .await?
                else {
                    records.push(serde_json::json!({"id":id,"status":"not_found"}));
                    continue;
                };
                crate::mcp::tools::lifecycle::annotate_full_record_path_for_item(&mut record, &id)?;
                let candidates =
                    comment_summaries_in(transaction, &caller, &id, &lifecycle_interpreter).await?;
                let count = candidates.len();
                let object = record
                    .as_object_mut()
                    .expect("read_record_in returns an object");
                object.insert("comment_count".into(), serde_json::json!(count));
                if include_comments {
                    object.insert(
                        "comments".into(),
                        Value::Array(
                            candidates
                                .into_iter()
                                .skip(comments_offset as usize)
                                .take(comments_limit as usize)
                                .collect(),
                        ),
                    );
                }
                records.push(record);
            }
            Ok(serde_json::json!({"records":records}))
        })
    })
    .await
}

async fn read_record_in(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    record_id: &str,
) -> Result<Option<Value>> {
    let lifecycle_interpreter = crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
        transaction,
        principal(caller),
    )
    .await?;
    read_record_with_lifecycle_in(transaction, caller, record_id, &lifecycle_interpreter).await
}

async fn read_record_with_lifecycle_in(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    record_id: &str,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
) -> Result<Option<Value>> {
    if !crate::authorization::allows_record_with(
        transaction,
        principal(caller),
        record_id,
        crate::authorization::Capability::View,
    )
    .await?
    {
        return Ok(None);
    }
    let select = statement(
        StatementKind::Select,
        "records",
        &[
            "SELECT id,type,kind,name,body,home_id,lifecycle,owner_id,persistence,maturity,summary,created_at,updated_at,deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=records.id AND f.key='archived') AS archived FROM {{relation}} WHERE id=",
            "",
        ],
    )
    .map_err(|error| stable("read record", error))?;
    let rows = transaction
        .rows(
            "read record",
            &select,
            &[BindValue::Text(record_id.into())],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("kind", LogicalType::Text),
                ColumnSpec::required("name", LogicalType::Text),
                ColumnSpec::nullable("body", LogicalType::Text),
                ColumnSpec::nullable("home_id", LogicalType::Text),
                ColumnSpec::nullable("lifecycle", LogicalType::Text),
                ColumnSpec::nullable("owner_id", LogicalType::Text),
                ColumnSpec::required("persistence", LogicalType::Text),
                ColumnSpec::nullable("maturity", LogicalType::Text),
                ColumnSpec::nullable("summary", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
                ColumnSpec::required("updated_at", LogicalType::Text),
                ColumnSpec::nullable("deleted_at", LogicalType::Text),
                ColumnSpec::required("archived", LogicalType::Bool),
            ],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let facets = statement(
        StatementKind::Select,
        "facet_values",
        &[
            "SELECT key,value,vocab_ref FROM {{relation}} WHERE record_id=",
            " AND key<>",
            " ORDER BY key",
        ],
    )
    .map_err(|error| stable("read record facets", error))?;
    let facets = transaction
        .rows(
            "read record facets",
            &facets,
            &[
                BindValue::Text(record_id.into()),
                BindValue::Text(crate::schema::ARCHIVED_FACET_KEY.into()),
            ],
            &[
                ColumnSpec::required("key", LogicalType::Text),
                ColumnSpec::nullable("value", LogicalType::Text),
                ColumnSpec::nullable("vocab_ref", LogicalType::Text),
            ],
        )
        .await?;
    let facets = facets
        .into_iter()
        .map(|facet| {
            let value = optional_text(&facet, "value", "record facet")?
                .map(|stored| {
                    serde_json::from_str::<Value>(&stored).unwrap_or(Value::String(stored))
                })
                .unwrap_or(Value::Null);
            Ok(serde_json::json!({
                "key": text(&facet,"key","record facet")?,
                "value": value,
                "vocab_ref": optional_text(&facet,"vocab_ref","record facet")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let record_type = text(row, "type", "record")?;
    let kind = optional_text(row, "kind", "record")?;
    let home_id = optional_text(row, "home_id", "record")?;
    let lifecycle = optional_text(row, "lifecycle", "record")?;
    let lifecycle_interpretation = lifecycle_interpreter.interpret(
        &record_type,
        kind.as_deref(),
        home_id.as_deref(),
        lifecycle.as_deref(),
    );
    let mut record = serde_json::json!({
        "status":"found",
        "id":text(row,"id","record")?,
        "type":record_type,
        "kind":kind,
        "name":text(row,"name","record")?,
        "body":optional_text(row,"body","record")?,
        "home_id":home_id,
        "lifecycle_interpretation":lifecycle_interpretation,
        "owner_id":optional_text(row,"owner_id","record")?,
        "persistence":text(row,"persistence","record")?,
        "maturity":optional_text(row,"maturity","record")?,
        "summary":optional_text(row,"summary","record")?,
        "created_at":text(row,"created_at","record")?,
        "updated_at":text(row,"updated_at","record")?,
        "deleted_at":optional_text(row,"deleted_at","record")?,
        "archived":boolean(row,"archived","record")?,
        "facets":facets,
    });
    crate::mcp::tools::lifecycle::annotate_body_digest(&mut record);
    Ok(Some(record))
}

async fn valid_comment_in(transaction: &mut TursoDomainTransaction<'_>, id: &str) -> Result<bool> {
    let Some(comment) = comment_record_in(transaction, id).await? else {
        return Ok(false);
    };
    if comment.deleted_at.is_some()
        || !governed_comment_in(transaction, &comment.record_type, comment.kind.as_deref()).await?
    {
        return Ok(false);
    }
    let bearers = comment_bearers_in(transaction, id).await?;
    if bearers.len() != 1 {
        return Ok(false);
    }
    let Some(bearer) = comment_record_in(transaction, &bearers[0]).await? else {
        return Ok(false);
    };
    if bearer.deleted_at.is_some() {
        return Ok(false);
    }
    let position =
        if governed_comment_in(transaction, &bearer.record_type, bearer.kind.as_deref()).await? {
            if crate::comments::validate_prospective(
                "get_record",
                crate::comments::Position::Root,
                bearer.body.as_deref(),
                bearer.lifecycle.as_deref(),
                bearer.summary.as_deref(),
            )
            .is_err()
            {
                return Ok(false);
            }
            let root_bearers = comment_bearers_in(transaction, &bearers[0]).await?;
            if root_bearers.len() != 1 {
                return Ok(false);
            }
            let Some(root_target) = comment_record_in(transaction, &root_bearers[0]).await? else {
                return Ok(false);
            };
            if root_target.deleted_at.is_some()
                || governed_comment_in(
                    transaction,
                    &root_target.record_type,
                    root_target.kind.as_deref(),
                )
                .await?
            {
                return Ok(false);
            }
            crate::comments::Position::Reply
        } else {
            crate::comments::Position::Root
        };
    Ok(crate::comments::validate_prospective(
        "get_record",
        position,
        comment.body.as_deref(),
        comment.lifecycle.as_deref(),
        comment.summary.as_deref(),
    )
    .is_ok())
}

async fn comment_summaries_in(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    bearer_id: &str,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
) -> Result<Vec<Value>> {
    let bearer = comment_record_in(transaction, bearer_id).await?;
    let replies = if let Some(bearer) = bearer {
        governed_comment_in(transaction, &bearer.record_type, bearer.kind.as_deref()).await?
    } else {
        false
    };
    let select = if replies {
        statement(
            StatementKind::Select,
            "records",
            &[
                "SELECT r.id,r.type,r.kind,r.name,r.body,r.home_id,r.lifecycle,r.summary,r.owner_id,r.created_at,r.updated_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.deleted_at IS NULL AND r.type='Annotation' AND EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='part_of' AND l.target_id=",
                ") ORDER BY r.created_at ASC,r.id ASC",
            ],
        )
    } else {
        statement(
            StatementKind::Select,
            "records",
            &[
                "SELECT r.id,r.type,r.kind,r.name,r.body,r.home_id,r.lifecycle,r.summary,r.owner_id,r.created_at,r.updated_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.deleted_at IS NULL AND r.type='Annotation' AND EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='part_of' AND l.target_id=",
                ") ORDER BY r.created_at DESC,r.id DESC",
            ],
        )
    }
    .map_err(|error| stable("read comment summaries", error))?;
    let rows = transaction
        .rows(
            "read comment summaries",
            &select,
            &[BindValue::Text(bearer_id.into())],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("kind", LogicalType::Text),
                ColumnSpec::required("name", LogicalType::Text),
                ColumnSpec::nullable("body", LogicalType::Text),
                ColumnSpec::nullable("home_id", LogicalType::Text),
                ColumnSpec::nullable("lifecycle", LogicalType::Text),
                ColumnSpec::nullable("summary", LogicalType::Text),
                ColumnSpec::nullable("owner_id", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
                ColumnSpec::required("updated_at", LogicalType::Text),
                ColumnSpec::required("archived", LogicalType::Bool),
            ],
        )
        .await?;
    let mut comments = Vec::with_capacity(rows.len());
    for row in rows {
        let id = text(&row, "id", "comment summary")?;
        if !valid_comment_in(transaction, &id).await?
            || !crate::authorization::allows_record_with(
                transaction,
                principal(caller),
                &id,
                crate::authorization::Capability::View,
            )
            .await?
        {
            continue;
        }
        let mut owner_id = optional_text(&row, "owner_id", "comment summary")?;
        if let Some(owner) = owner_id.as_deref() {
            if !crate::authorization::allows_record_with(
                transaction,
                principal(caller),
                owner,
                crate::authorization::Capability::View,
            )
            .await?
            {
                owner_id = None;
            }
        }
        let record_type = text(&row, "type", "comment summary")?;
        let kind = optional_text(&row, "kind", "comment summary")?;
        let home_id = optional_text(&row, "home_id", "comment summary")?;
        let lifecycle = optional_text(&row, "lifecycle", "comment summary")?;
        let lifecycle_interpretation = lifecycle_interpreter.interpret(
            &record_type,
            kind.as_deref(),
            home_id.as_deref(),
            lifecycle.as_deref(),
        );
        comments.push(serde_json::json!({
            "id": id,
            "type": record_type,
            "kind": kind,
            "name": text(&row,"name","comment summary")?,
            "body": optional_text(&row,"body","comment summary")?.unwrap_or_default(),
            "lifecycle_interpretation": lifecycle_interpretation,
            "summary": optional_text(&row,"summary","comment summary")?,
            "owner_id": owner_id,
            "created_at": text(&row,"created_at","comment summary")?,
            "updated_at": text(&row,"updated_at","comment summary")?,
            "archived": boolean(&row,"archived","comment summary")?,
        }));
    }
    Ok(comments)
}

fn present<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRecordArguments {
    id: String,
    reason: String,
    #[serde(default, deserialize_with = "present")]
    kind: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    name: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    body: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    home_id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    lifecycle: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    owner_id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    persistence: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    maturity: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    summary: Option<Value>,
    facets: Option<Map<String, Value>>,
    if_body_digest: Option<String>,
    if_unmodified_since: Option<String>,
}

const MAX_MULTI_UPDATE: usize = 100;
const MAX_MULTI_UPDATE_FAILURE_DETAILS: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiUpdateRecordArguments {
    ids: Vec<String>,
    reason: String,
    facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    maturity: Option<Value>,
    home_id: Option<String>,
    if_facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    if_maturity: Option<Value>,
    if_home_id: Option<String>,
}

#[derive(Clone)]
struct PreparedMultiUpdate {
    index: usize,
    id: String,
    fields: Map<String, Value>,
    facet_sets: Vec<crate::domain_transaction::FacetWrite>,
    facet_unsets: Vec<String>,
}

impl PreparedMultiUpdate {
    fn changed(&self) -> bool {
        !self.fields.is_empty() || !self.facet_sets.is_empty() || !self.facet_unsets.is_empty()
    }
}

#[derive(Serialize)]
struct MultiUpdateIssue {
    index: usize,
    id: String,
    classification: &'static str,
    message: String,
}

fn validate_multi_maturity(tool: &str, field: &str, value: &Option<Value>) -> Result<()> {
    if let Some(value) = value {
        if !matches!(value, Value::String(_) | Value::Null) {
            return Err(Error::engine(format!(
                "{tool}: '{field}' must be a string or null"
            )));
        }
    }
    Ok(())
}

fn multi_update_rejection(
    requested: usize,
    unchanged: usize,
    issues: Vec<MultiUpdateIssue>,
) -> Error {
    let conflicted = issues
        .iter()
        .filter(|issue| issue.classification == "conflict")
        .count();
    let failed = issues.len() - conflicted;
    let omitted = issues
        .len()
        .saturating_sub(MAX_MULTI_UPDATE_FAILURE_DETAILS);
    let details = issues
        .into_iter()
        .take(MAX_MULTI_UPDATE_FAILURE_DETAILS)
        .collect::<Vec<_>>();
    let receipt = serde_json::json!({
        "requested": requested,
        "changed": 0,
        "unchanged": unchanged,
        "conflicted": conflicted,
        "failed": failed,
        "details": details,
        "details_truncated": omitted > 0,
        "omitted_detail_count": omitted,
    });
    let message = format!(
        "update_record: multi-target preflight rejected the atomic request; nothing was written; receipt={receipt}"
    );
    if failed == 0 {
        Error::conflict(message)
    } else {
        Error::engine(message)
    }
}

async fn current_facet_state(
    transaction: &mut TursoDomainTransaction<'_>,
    record_id: &str,
    key: &str,
) -> Result<Option<(String, Option<String>)>> {
    let select = statement(
        StatementKind::Select,
        "facet_values",
        &[
            "SELECT value,vocab_ref FROM {{relation}} WHERE record_id=",
            " AND key=",
            "",
        ],
    )
    .map_err(|error| stable("read current facet", error))?;
    transaction
        .rows(
            "read current facet",
            &select,
            &[
                BindValue::Text(record_id.into()),
                BindValue::Text(key.into()),
            ],
            &[
                ColumnSpec::required("value", LogicalType::Text),
                ColumnSpec::nullable("vocab_ref", LogicalType::Text),
            ],
        )
        .await?
        .first()
        .map(|row| {
            Ok((
                text(row, "value", "current facet")?,
                optional_text(row, "vocab_ref", "current facet")?,
            ))
        })
        .transpose()
}

async fn collection_message_origin(
    transaction: &mut TursoDomainTransaction<'_>,
    record_id: &str,
) -> Result<Option<String>> {
    let select = statement(
        StatementKind::Select,
        "content_events",
        &[
            "SELECT payload FROM {{relation}} WHERE record_id=",
            " AND type='message.origin.declared.v1' ORDER BY seq DESC LIMIT 1",
        ],
    )
    .map_err(|error| stable("read Message collection origin", error))?;
    let rows = transaction
        .rows(
            "read Message collection origin",
            &select,
            &[BindValue::Text(record_id.into())],
            &[ColumnSpec::required("payload", LogicalType::Text)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let payload: Value =
        serde_json::from_str(&text(row, "payload", "Message collection origin payload")?)?;
    Ok(payload
        .get("collection_id")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

async fn update_record(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    if arguments.get("ids").is_some() {
        Box::pin(update_record_multi(db, caller, arguments)).await
    } else {
        Box::pin(update_record_singular(db, caller, arguments)).await
    }
}

async fn update_record_multi(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "update_record";
    let args: MultiUpdateRecordArguments = parse_arguments(TOOL, arguments)?;
    require_reason(TOOL, &args.reason)?;
    if args.ids.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'ids' must contain at least one record id"
        )));
    }
    if args.ids.len() > MAX_MULTI_UPDATE {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_MULTI_UPDATE} ids may be updated per call"
        )));
    }
    let mut positions = BTreeMap::new();
    for (index, id) in args.ids.iter().enumerate() {
        if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
            return Err(Error::engine(format!(
                "{TOOL}: ids[{index}] must be an exact canonical lowercase UUID of version 4 or 7"
            )));
        }
        if let Some(first) = positions.insert(id.as_str(), index) {
            return Err(Error::engine(format!(
                "{TOOL}: ids[{index}] duplicates ids[{first}]; multi-target ids must be unique"
            )));
        }
    }
    validate_multi_maturity(TOOL, "maturity", &args.maturity)?;
    validate_multi_maturity(TOOL, "if_maturity", &args.if_maturity)?;

    let facet_inputs = args.facets.as_ref().cloned().unwrap_or_default();
    if facet_inputs.is_empty() && args.maturity.is_none() && args.home_id.is_none() {
        return Err(Error::engine(format!(
            "{TOOL}: multi-target mode requires at least one non-empty facets patch, maturity, or home_id"
        )));
    }
    let mut facet_sets = Vec::new();
    let mut facet_unsets = Vec::new();
    for (key, value) in &facet_inputs {
        match crate::mcp::tools::lifecycle::parse_facet_entry(TOOL, key, value, true)? {
            Some(facet) => facet_sets.push(facet),
            None => facet_unsets.push(key.clone()),
        }
    }
    let expected_inputs = args.if_facets.as_ref().cloned().unwrap_or_default();
    if args.if_facets.is_some() && expected_inputs.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'if_facets' must not be empty when supplied"
        )));
    }
    let mut expected_sets = Vec::new();
    let mut expected_absent = Vec::new();
    for (key, value) in &expected_inputs {
        match crate::mcp::tools::lifecycle::parse_facet_entry(TOOL, key, value, true)? {
            Some(facet) => expected_sets.push(facet),
            None => expected_absent.push(key.clone()),
        }
    }

    let caller = caller.clone();
    run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            if let Some(new_home) = args.home_id.as_deref() {
                require_capability(
                    transaction,
                    &caller,
                    TOOL,
                    new_home,
                    crate::authorization::Capability::Edit,
                )
                .await
                .map_err(|_| {
                    Error::engine(format!(
                        "{TOOL}: multi-target relocation home {new_home} is unavailable; nothing was written"
                    ))
                })?;
                let home = transaction.record_state(new_home).await?.ok_or_else(|| {
                    Error::engine(format!(
                        "{TOOL}: multi-target relocation home {new_home} is unavailable; nothing was written"
                    ))
                })?;
                if home.record_type != "Collection"
                    || home.kind.as_deref() != Some("folder")
                    || home.persistence != "enduring"
                    || home.deleted
                    || home.archived
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: multi-target relocation home must be a live, unarchived, enduring Collection kind:folder; nothing was written"
                    )));
                }
            }

            // Complete source authorization against the pre-request snapshot.
            // In particular, no relocation event is appended until every
            // source and the shared destination have passed authorization.
            let current_select = statement(
                StatementKind::Select,
                "records",
                &[
                    "SELECT type,kind,maturity,home_id FROM {{relation}} WHERE id=",
                    " AND deleted_at IS NULL",
                ],
            )
            .map_err(|error| stable("preflight multi record update", error))?;
            let mut current_rows = Vec::with_capacity(args.ids.len());
            let mut authorized = vec![false; args.ids.len()];
            let mut issues = Vec::new();
            for (index, id) in args.ids.iter().enumerate() {
                let rows = transaction
                    .rows(
                        "preflight multi record update",
                        &current_select,
                        &[BindValue::Text(id.clone())],
                        &[
                            ColumnSpec::required("type", LogicalType::Text),
                            ColumnSpec::nullable("kind", LogicalType::Text),
                            ColumnSpec::nullable("maturity", LogicalType::Text),
                            ColumnSpec::nullable("home_id", LogicalType::Text),
                        ],
                    )
                    .await?;
                let row = rows.first().cloned();
                let current_home = row
                    .as_ref()
                    .map(|row| optional_text(row, "home_id", "multi record update"))
                    .transpose()?
                    .flatten();
                let relocates = args
                    .home_id
                    .as_deref()
                    .is_some_and(|desired| current_home.as_deref() != Some(desired));
                let capability = if relocates {
                    crate::authorization::Capability::Manage
                } else {
                    crate::authorization::Capability::Edit
                };
                match require_capability(transaction, &caller, TOOL, id, capability).await {
                    Ok(()) if row.is_some() => authorized[index] = true,
                    _ => issues.push(MultiUpdateIssue {
                        index,
                        id: id.clone(),
                        classification: "unavailable",
                        message: "record is unavailable".into(),
                    }),
                }
                current_rows.push(row);
            }

            let schema_rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
            let touches_message_expectation = facet_inputs
                .contains_key(crate::message_expectation::EXPECTATION_FACET_KEY);
            let mut prepared = Vec::with_capacity(args.ids.len());
            let mut unchanged = 0usize;
            for (index, id) in args.ids.iter().enumerate() {
                if !authorized[index] {
                    continue;
                }
                let row = current_rows[index]
                    .as_ref()
                    .expect("authorized live record has a preflight row");
                let record_type = text(row, "type", "multi record update")?;
                let kind = optional_text(row, "kind", "multi record update")?;
                let current_maturity = optional_text(row, "maturity", "multi record update")?;
                let current_home = optional_text(row, "home_id", "multi record update")?;

                if touches_message_expectation {
                    let state = transaction
                        .record_state(id)
                        .await?
                        .expect("authorized live record has semantic state");
                    if state.record_type == "Message" {
                        issues.push(MultiUpdateIssue {
                            index,
                            id: id.clone(),
                            classification: "invalid",
                            message: "Message expectation is immutable sender-authored content"
                                .into(),
                        });
                        continue;
                    }
                }

                let mut governed_sets = facet_sets.clone();
                if let Err(error) = crate::domain_transaction::govern_facet_writes(
                    transaction,
                    &schema_rows,
                    TOOL,
                    &record_type,
                    kind.as_deref(),
                    &mut governed_sets,
                )
                .await
                {
                    issues.push(MultiUpdateIssue {
                        index,
                        id: id.clone(),
                        classification: "invalid",
                        message: error.to_string(),
                    });
                    continue;
                }
                let mut governed_expected = expected_sets.clone();
                if let Err(error) = crate::domain_transaction::govern_facet_writes(
                    transaction,
                    &schema_rows,
                    TOOL,
                    &record_type,
                    kind.as_deref(),
                    &mut governed_expected,
                )
                .await
                {
                    issues.push(MultiUpdateIssue {
                        index,
                        id: id.clone(),
                        classification: "invalid",
                        message: error.to_string(),
                    });
                    continue;
                }

                let mut conflict = None;
                for expected in &governed_expected {
                    let current = current_facet_state(transaction, id, &expected.key).await?;
                    let desired = (expected.stored_value(), expected.vocab_ref.clone());
                    if current.as_ref() != Some(&desired) {
                        conflict = Some(format!(
                            "facet '{}' no longer has the expected current value",
                            expected.key
                        ));
                        break;
                    }
                }
                if conflict.is_none() {
                    for key in &expected_absent {
                        if current_facet_state(transaction, id, key).await?.is_some() {
                            conflict = Some(format!("facet '{key}' is no longer absent"));
                            break;
                        }
                    }
                }
                if conflict.is_none() {
                    if let Some(expected) = args.if_maturity.as_ref() {
                        let matches = match expected {
                            Value::String(expected) => {
                                current_maturity.as_deref() == Some(expected)
                            }
                            Value::Null => current_maturity.is_none(),
                            _ => unreachable!("multi maturity was validated before admission"),
                        };
                        if !matches {
                            conflict =
                                Some("maturity no longer has the expected current value".into());
                        }
                    }
                }
                if conflict.is_none() {
                    if let Some(expected) = args.if_home_id.as_deref() {
                        if current_home.as_deref() != Some(expected) {
                            conflict = Some("home_id no longer has the expected current value".into());
                        }
                    }
                }
                if let Some(message) = conflict {
                    issues.push(MultiUpdateIssue {
                        index,
                        id: id.clone(),
                        classification: "conflict",
                        message,
                    });
                    continue;
                }

                if let Some(new_home) = args.home_id.as_deref() {
                    if record_type == "Message"
                        && collection_message_origin(transaction, id)
                            .await?
                            .is_some_and(|collection_id| collection_id != new_home)
                    {
                        issues.push(MultiUpdateIssue {
                            index,
                            id: id.clone(),
                            classification: "invalid",
                            message: "a Collection-origin Message must remain filed in its authored Collection".into(),
                        });
                        continue;
                    }
                    if transaction.home_would_cycle(id, new_home).await? {
                        issues.push(MultiUpdateIssue {
                            index,
                            id: id.clone(),
                            classification: "invalid",
                            message: "relocation would create a containment cycle".into(),
                        });
                        continue;
                    }
                }

                let mut changed_sets = Vec::new();
                for facet in governed_sets {
                    let current = current_facet_state(transaction, id, &facet.key).await?;
                    let desired = (facet.stored_value(), facet.vocab_ref.clone());
                    if current.as_ref() != Some(&desired) {
                        changed_sets.push(facet);
                    }
                }
                let mut changed_unsets = Vec::new();
                for key in &facet_unsets {
                    if current_facet_state(transaction, id, key).await?.is_some() {
                        changed_unsets.push(key.clone());
                    }
                }
                let mut fields = Map::new();
                if let Some(desired) = args.maturity.as_ref() {
                    let changed = match desired {
                        Value::String(desired) => current_maturity.as_deref() != Some(desired),
                        Value::Null => current_maturity.is_some(),
                        _ => unreachable!("multi maturity was validated before admission"),
                    };
                    if changed {
                        fields.insert("maturity".into(), desired.clone());
                    }
                }
                if let Some(desired) = args.home_id.as_deref() {
                    if current_home.as_deref() != Some(desired) {
                        fields.insert("home_id".into(), Value::String(desired.into()));
                    }
                }
                let target = PreparedMultiUpdate {
                    index,
                    id: id.clone(),
                    fields,
                    facet_sets: changed_sets,
                    facet_unsets: changed_unsets,
                };
                if !target.changed() {
                    unchanged += 1;
                }
                prepared.push(target);
            }

            if !issues.is_empty() {
                return Err(multi_update_rejection(args.ids.len(), unchanged, issues));
            }

            let id_refs = args.ids.iter().map(String::as_str).collect::<Vec<_>>();
            let before_required = crate::domain_transaction::required_violations(
                transaction,
                &schema_rows,
                &id_refs,
            )
            .await?;
            let changed = prepared.iter().filter(|target| target.changed()).count();
            for mut target in prepared.iter().filter(|target| target.changed()).cloned() {
                let field_event = !target.fields.is_empty();
                if field_event {
                    target
                        .fields
                        .insert("reason".into(), Value::String(args.reason.clone()));
                    transaction
                        .append_content(AppendSpec {
                            record_id: target.id.clone(),
                            event_type: "record.updated".into(),
                            payload: Value::Object(target.fields),
                            actor: Some(caller.actor().into()),
                        })
                        .await?;
                }
                let mut first_facet = true;
                for facet in target.facet_sets {
                    let mut spec = crate::domain_transaction::facet_set_spec(
                        &target.id,
                        &facet,
                        caller.actor(),
                    );
                    if !field_event && first_facet {
                        spec.payload["reason"] = Value::String(args.reason.clone());
                    }
                    first_facet = false;
                    transaction.append_content(spec).await?;
                }
                for key in target.facet_unsets {
                    let mut payload = serde_json::json!({ "key": key });
                    if !field_event && first_facet {
                        payload["reason"] = Value::String(args.reason.clone());
                    }
                    first_facet = false;
                    transaction
                        .append_content(AppendSpec {
                            record_id: target.id.clone(),
                            event_type: "facet.unset".into(),
                            payload,
                            actor: Some(caller.actor().into()),
                        })
                        .await?;
                }
            }
            // Individual home events refresh immediately. Repeating the fold
            // after the complete cohort reaches its final graph makes derived
            // anchors independent of input/event order for related targets.
            for target in prepared
                .iter()
                .filter(|target| target.fields.contains_key("home_id"))
            {
                transaction.refresh_policy_anchor_subtree(&target.id).await?;
            }
            let after_required = crate::domain_transaction::required_violations(
                transaction,
                &schema_rows,
                &id_refs,
            )
            .await?;
            crate::domain_transaction::assert_required_not_worsened(
                TOOL,
                &before_required,
                &after_required,
            )?;

            let results = prepared
                .into_iter()
                .map(|target| {
                    serde_json::json!({
                        "index": target.index,
                        "id": target.id,
                        "status": if target.changed() { "changed" } else { "unchanged" },
                    })
                })
                .collect::<Vec<_>>();
            Ok(serde_json::json!({
                "requested": args.ids.len(),
                "changed": changed,
                "unchanged": args.ids.len() - changed,
                "results": results,
            }))
        })
    })
    .await
}

async fn update_record_singular(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "update_record";
    let args: UpdateRecordArguments = parse_arguments(TOOL, arguments)?;
    require_reason(TOOL, &args.reason)?;
    crate::mcp::tools::require_workspace_rename_authority(
        TOOL,
        caller,
        &args.id,
        args.name.as_ref(),
    )?;
    let structural = args.home_id.is_some();
    let new_home = args
        .home_id
        .as_ref()
        .and_then(Value::as_str)
        .map(str::to_owned);
    let new_owner = args.owner_id.clone();
    let kind_touched = args.kind.is_some();
    let lifecycle_touched = args.lifecycle.is_some();
    let summary_touched = args.summary.is_some();
    // Captured before `args.body` is folded into the field map: "present"
    // (string or explicit null) is what the whole-body guard keys on, and an
    // explicit null must stay distinguishable from an absent field.
    let body_touched = args.body.is_some();
    let mut fields = Map::new();
    for (name, value) in [
        ("kind", args.kind),
        ("name", args.name),
        ("body", args.body),
        ("home_id", args.home_id),
        ("lifecycle", args.lifecycle),
        ("owner_id", args.owner_id),
        ("persistence", args.persistence),
        ("maturity", args.maturity),
        ("summary", args.summary),
    ] {
        if let Some(value) = value {
            fields.insert(name.into(), value);
        }
    }
    fields.insert("reason".into(), Value::String(args.reason));
    let facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| {
            crate::mcp::tools::lifecycle::parse_facet_entry(TOOL, &key, &value, true)
                .map(|facet| (key, facet))
        })
        .collect::<Result<Vec<_>>>()?;
    let id = args.id;
    let caller = caller.clone();
    run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            let mut fields = fields;
            let mut facets = facets;
            require_capability(
                transaction,
                &caller,
                TOOL,
                &id,
                if structural {
                    crate::authorization::Capability::Manage
                } else {
                    crate::authorization::Capability::Edit
                },
            )
            .await?;
            if let Some(owner_value) = new_owner.as_ref() {
                let new_owner = owner_value.as_str().ok_or_else(|| {
                    Error::engine(format!(
                        "{TOOL}: owner_id must be a portable identity id"
                    ))
                })?;
                let legacy_local = caller.is_trusted_local()
                    && caller.hosting_database().is_none();
                if !legacy_local {
                    let owner_select = statement(
                        StatementKind::Select,
                        "records",
                        &[
                            "SELECT owner_id FROM {{relation}} WHERE id = ",
                            " AND deleted_at IS NULL",
                        ],
                    )
                    .map_err(|error| stable("authorize owner transfer", error))?;
                    let owner_rows = transaction
                        .rows(
                            "authorize owner transfer",
                            &owner_select,
                            &[BindValue::Text(id.clone())],
                            &[ColumnSpec::nullable("owner_id", LogicalType::Text)],
                        )
                        .await?;
                    let current_owner = owner_rows
                        .first()
                        .map(|row| optional_text(row, "owner_id", "record"))
                        .transpose()?
                        .flatten();
                    let binding_select = statement(
                        StatementKind::Select,
                        "bindings",
                        &[
                            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id = ",
                            " AND system = 'account' AND identifier = ",
                            " AND is_canonical = 1) AS bound",
                        ],
                    )
                    .map_err(|error| stable("authorize owner transfer", error))?;
                    let owns = if let Some(current_owner) = current_owner {
                        transaction
                            .rows(
                                "authorize owner transfer",
                                &binding_select,
                                &[
                                    BindValue::Text(current_owner),
                                    BindValue::Text(caller.credential().into()),
                                ],
                                &[ColumnSpec::required("bound", LogicalType::Bool)],
                            )
                            .await?
                            .first()
                            .map(|row| boolean(row, "bound", "owner binding"))
                            .transpose()?
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    if !owns {
                        return Err(Error::engine(format!(
                            "{TOOL}: record {id} does not exist"
                        )));
                    }
                    let target_select = statement(
                        StatementKind::Select,
                        "bindings",
                        &[
                            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id = ",
                            " AND system = 'account' AND is_canonical = 1) AS bound",
                        ],
                    )
                    .map_err(|error| stable("authorize owner transfer", error))?;
                    let target_bound = transaction
                        .rows(
                            "authorize owner transfer",
                            &target_select,
                            &[BindValue::Text(new_owner.into())],
                            &[ColumnSpec::required("bound", LogicalType::Bool)],
                        )
                        .await?
                        .first()
                        .map(|row| boolean(row, "bound", "owner binding"))
                        .transpose()?
                        .unwrap_or(false);
                    if !target_bound {
                        return Err(Error::engine(format!(
                            "{TOOL}: owner_id must name a verified portable identity"
                        )));
                    }
                }
            }
            if let Some(new_home) = new_home.as_deref() {
                require_capability(
                    transaction,
                    &caller,
                    TOOL,
                    new_home,
                    crate::authorization::Capability::Edit,
                )
                .await?;
            }
            if let Some(expected_raw) = args.if_unmodified_since.as_deref() {
                let expected = DateTime::parse_from_rfc3339(expected_raw).map_err(|_| {
                    Error::engine(format!(
                        "{TOOL}: 'if_unmodified_since' must be an RFC3339 timestamp"
                    ))
                })?;
                let current = statement(
                    StatementKind::Select,
                    "records",
                    &[
                        "SELECT updated_at,name,body FROM {{relation}} WHERE id = ",
                        " AND deleted_at IS NULL",
                    ],
                )
                .map_err(|error| stable("guard record update", error))?;
                let rows = transaction
                    .rows(
                        "guard record update",
                        &current,
                        &[BindValue::Text(id.clone())],
                        &[
                            ColumnSpec::required("updated_at", LogicalType::Text),
                            ColumnSpec::nullable("name", LogicalType::Text),
                            ColumnSpec::nullable("body", LogicalType::Text),
                        ],
                    )
                    .await?;
                let row = rows.first().ok_or_else(|| {
                    Error::engine(format!("{TOOL}: record {id} does not exist"))
                })?;
                let current_raw = text(row, "updated_at", "record")?;
                let current = DateTime::parse_from_rfc3339(&current_raw).map_err(|_| {
                    Error::engine(format!(
                        "{TOOL}: record {id} has an invalid stored updated_at timestamp"
                    ))
                })?;
                if expected != current {
                    // Same legible content as the other two refusals; Turso
                    // mints no display reference, so the record is named by
                    // title and id.
                    return Err(
                        crate::mcp::tools::lifecycle::stale_unmodified_since_error(
                            TOOL,
                            &crate::mcp::tools::lifecycle::BodyGuardTarget {
                                id: id.clone(),
                                name: optional_text(row, "name", "record")?,
                                display_reference: None,
                                body_digest: crate::mcp::tools::lifecycle::body_digest(
                                    optional_text(row, "body", "record")?.as_deref(),
                                ),
                                updated_at: current_raw,
                            },
                        ),
                    );
                }
            }
            // Whole-body replacement and the digest precondition are resolved
            // from current state inside the same write transaction, so a
            // concurrent writer cannot establish non-empty content between the
            // check and the append. Turso mints no display reference, so the
            // refusal identifies the record by title and id.
            if body_touched || args.if_body_digest.is_some() {
                let current = statement(
                    StatementKind::Select,
                    "records",
                    &["SELECT body,name,updated_at FROM {{relation}} WHERE id=", ""],
                )
                .map_err(|error| stable("guard record update", error))?;
                let rows = transaction
                    .rows(
                        "guard record update",
                        &current,
                        &[BindValue::Text(id.clone())],
                        &[
                            ColumnSpec::nullable("body", LogicalType::Text),
                            ColumnSpec::nullable("name", LogicalType::Text),
                            ColumnSpec::nullable("updated_at", LogicalType::Text),
                        ],
                    )
                    .await?;
                let row = rows.first();
                let current_body = row
                    .map(|row| optional_text(row, "body", "record"))
                    .transpose()?
                    .flatten();
                let guard_target = || {
                    Ok::<_, Error>(crate::mcp::tools::lifecycle::BodyGuardTarget {
                        id: id.clone(),
                        name: row
                            .map(|row| optional_text(row, "name", "record"))
                            .transpose()?
                            .flatten(),
                        display_reference: None,
                        body_digest: crate::mcp::tools::lifecycle::body_digest(
                            current_body.as_deref(),
                        ),
                        updated_at: row
                            .map(|row| optional_text(row, "updated_at", "record"))
                            .transpose()?
                            .flatten()
                            .unwrap_or_default(),
                    })
                };
                if crate::mcp::tools::lifecycle::whole_body_write_needs_guard(
                    body_touched,
                    current_body.as_deref(),
                    args.if_body_digest.as_deref(),
                    args.if_unmodified_since.as_deref(),
                ) {
                    return Err(crate::mcp::tools::lifecycle::unguarded_body_write_error(
                        TOOL,
                        &guard_target()?,
                    ));
                }
                if let Some(expected) = args.if_body_digest.as_deref() {
                    let actual =
                        crate::mcp::tools::lifecycle::body_digest(current_body.as_deref());
                    if !expected.eq_ignore_ascii_case(&actual) {
                        return Err(crate::mcp::tools::lifecycle::stale_body_digest_error(
                            TOOL,
                            &guard_target()?,
                        ));
                    }
                }
            }
            let current_select = statement(
                StatementKind::Select,
                "records",
                &["SELECT type,kind,body,lifecycle,summary FROM {{relation}} WHERE id=", " AND deleted_at IS NULL"],
            )
            .map_err(|error| stable("validate comment update", error))?;
            let current_rows = transaction
                .rows(
                    "validate comment update",
                    &current_select,
                    &[BindValue::Text(id.clone())],
                    &[
                        ColumnSpec::required("type", LogicalType::Text),
                        ColumnSpec::nullable("kind", LogicalType::Text),
                        ColumnSpec::nullable("body", LogicalType::Text),
                        ColumnSpec::nullable("lifecycle", LogicalType::Text),
                        ColumnSpec::nullable("summary", LogicalType::Text),
                    ],
                )
                .await?;
            let current = current_rows.first().ok_or_else(|| {
                Error::engine(format!("{TOOL}: record {id} does not exist"))
            })?;
            let record_type = text(current, "type", "comment update")?;
            let current_kind = optional_text(current, "kind", "comment update")?;
            let current_body = optional_text(current, "body", "comment update")?;
            let current_lifecycle = optional_text(current, "lifecycle", "comment update")?;
            let current_summary = optional_text(current, "summary", "comment update")?;
            let mut resulting_kind = match fields.get("kind") {
                Some(value) => optional_string_field(TOOL, "kind", value)?.map(str::to_owned),
                None => current_kind.clone(),
            };
            let resulting_resolution = if let Some(kind) = resulting_kind.as_deref() {
                Some(crate::meta::kind::resolve_with(transaction, &record_type, kind).await?)
            } else {
                None
            };
            let current_effective_kind = if let Some(kind) = current_kind.as_deref() {
                let resolution =
                    crate::meta::kind::resolve_with(transaction, &record_type, kind).await?;
                Some(
                    resolution
                        .canonical_kind_for_write()
                        .unwrap_or(kind)
                        .to_string(),
                )
            } else {
                None
            };
            let resulting_effective_kind = resulting_kind.as_deref().map(|kind| {
                resulting_resolution
                    .as_ref()
                    .and_then(|resolution| resolution.canonical_kind_for_write())
                    .unwrap_or(kind)
                    .to_string()
            });
            if fields.contains_key("kind") {
                if let Some(canonical) = resulting_resolution
                    .as_ref()
                    .and_then(|resolution| resolution.canonical_kind_for_write())
                {
                    resulting_kind = Some(canonical.to_string());
                    fields.insert("kind".into(), Value::String(canonical.into()));
                }
            }
            let resulting_body = match fields.get("body") {
                Some(value) => optional_string_field(TOOL, "body", value)?.map(str::to_owned),
                None => current_body,
            };
            let resulting_lifecycle = match fields.get("lifecycle") {
                Some(value) => optional_string_field(TOOL, "lifecycle", value)?.map(str::to_owned),
                None => current_lifecycle.clone(),
            };
            let resulting_summary = match fields.get("summary") {
                Some(value) => optional_string_field(TOOL, "summary", value)?.map(str::to_owned),
                None => current_summary,
            };
            let schema_rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
            let before_required = crate::domain_transaction::required_violations(
                transaction,
                &schema_rows,
                &[id.as_str()],
            )
            .await?;
            let mut governed = facets
                .iter()
                .filter_map(|(_, facet)| facet.clone())
                .collect::<Vec<_>>();
            crate::domain_transaction::govern_facet_writes(
                transaction,
                &schema_rows,
                TOOL,
                &record_type,
                resulting_kind.as_deref(),
                &mut governed,
            )
            .await?;
            for (_, facet) in &mut facets {
                if let Some(facet) = facet {
                    facet.vocab_ref = governed
                        .iter()
                        .find(|checked| checked.key == facet.key)
                        .and_then(|checked| checked.vocab_ref.clone());
                }
            }
            let lifecycle_facet = facets
                .iter()
                .find(|(key, _)| key == "lifecycle")
                .map(|(_, facet)| facet.as_ref().map(|facet| facet.stored_value()));
            let prospective_lifecycle = match &lifecycle_facet {
                Some(lifecycle) => lifecycle.clone(),
                None => resulting_lifecycle.clone(),
            };
            let shape_context_changed = resulting_effective_kind != current_effective_kind;
            let resulting_is_comment = resulting_resolution.as_ref().is_some_and(|resolution| {
                crate::generated::kinds::CoreKind::AnnotationComment.matches(resolution)
            });
            let current_is_comment = governed_comment_in(
                transaction,
                &record_type,
                current_kind.as_deref(),
            )
            .await?;
            if !current_is_comment
                && (shape_context_changed || lifecycle_touched || lifecycle_facet.is_some())
                && prospective_lifecycle.is_some()
            {
                let mut lifecycle_write = [crate::domain_transaction::FacetWrite {
                    key: "lifecycle".into(),
                    value: Value::String(
                        prospective_lifecycle
                            .clone()
                            .expect("checked as present above"),
                    ),
                    vocab_ref: None,
                }];
                crate::domain_transaction::govern_facet_writes(
                    transaction,
                    &schema_rows,
                    TOOL,
                    &record_type,
                    resulting_effective_kind.as_deref(),
                    &mut lifecycle_write,
                )
                .await?;
            }
            let current_is_suggestion = if let Some(kind) = current_kind.as_deref() {
                let resolution =
                    crate::meta::kind::resolve_with(transaction, &record_type, kind).await?;
                crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution)
            } else {
                false
            };
            let resulting_is_suggestion = resulting_resolution.as_ref().is_some_and(|resolution| {
                crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(resolution)
            });
            let current_lifecycle_is_active = if current_is_suggestion {
                if let Some(current_lifecycle) = current_lifecycle.as_deref() {
                    crate::domain_transaction::active_vocabulary_value(
                        transaction,
                        crate::meta::vocabulary::SUGGESTION_LIFECYCLE_VOCABULARY_ID,
                        current_lifecycle,
                    )
                    .await?
                } else {
                    false
                }
            } else {
                false
            };
            crate::suggestion_lifecycle::validate_update(
                TOOL,
                current_is_suggestion,
                resulting_is_suggestion,
                current_lifecycle.as_deref(),
                resulting_lifecycle.as_deref(),
                lifecycle_touched,
                current_lifecycle_is_active,
            )?;
            let resulting_is_attribution =
                resulting_resolution.as_ref().is_some_and(|resolution| {
                    crate::generated::kinds::CoreKind::AnnotationAttribution.matches(resolution)
                });
            if resulting_is_attribution {
                let current_is_attribution = if let Some(kind) = current_kind.as_deref() {
                    let resolution =
                        crate::meta::kind::resolve_with(transaction, &record_type, kind).await?;
                    crate::generated::kinds::CoreKind::AnnotationAttribution.matches(&resolution)
                } else {
                    false
                };
                if !current_is_attribution {
                    return Err(Error::engine(
                        "update_record: governed attribution identity cannot be added in place; use create_attribution",
                    ));
                }
            }
            if !current_is_comment && resulting_is_comment {
                return Err(Error::engine(format!(
                    "{TOOL}: governed comment identity cannot be added by updating kind; create a comment with its bearer atomically"
                )));
            }
            if current_is_comment {
                if !resulting_is_comment {
                    return Err(Error::engine(format!(
                        "{TOOL}: governed comment identity cannot be removed by updating kind"
                    )));
                }
                if kind_touched {
                    let canonical = resulting_resolution
                        .as_ref()
                        .and_then(|resolution| resolution.canonical_kind_for_write())
                        .expect("governed comment resolution has a writable canonical token");
                    fields.insert("kind".into(), Value::String(canonical.into()));
                }
                let bearers = comment_bearers_in(transaction, &id).await?;
                if bearers.len() != 1 {
                    return Err(Error::engine(format!(
                        "{TOOL}: Annotation kind:comment requires exactly one outgoing part_of link to its bearer"
                    )));
                }
                let position =
                    comment_position_for_bearer_in(transaction, TOOL, &bearers[0]).await?;
                crate::comments::validate_prospective(
                    TOOL,
                    position,
                    resulting_body.as_deref(),
                    resulting_lifecycle.as_deref(),
                    resulting_summary.as_deref(),
                )?;
                crate::comments::assert_resolution_transition(
                    TOOL,
                    position,
                    current_lifecycle.as_deref(),
                    resulting_lifecycle.as_deref(),
                    resulting_summary.as_deref(),
                    lifecycle_touched,
                    summary_touched,
                )?;
                if (shape_context_changed || lifecycle_touched || lifecycle_facet.is_some())
                    && prospective_lifecycle.is_some()
                {
                    let mut lifecycle_write = [crate::domain_transaction::FacetWrite {
                        key: "lifecycle".into(),
                        value: Value::String(
                            prospective_lifecycle
                                .clone()
                                .expect("checked as present above"),
                        ),
                        vocab_ref: None,
                    }];
                    crate::domain_transaction::govern_facet_writes(
                        transaction,
                        &schema_rows,
                        TOOL,
                        &record_type,
                        resulting_effective_kind.as_deref(),
                        &mut lifecycle_write,
                    )
                    .await?;
                }
            }
            transaction
                .append_content(AppendSpec {
                    record_id: id.clone(),
                    event_type: "record.updated".into(),
                    payload: Value::Object(fields),
                    actor: Some(caller.actor().into()),
                })
                .await?;
            for (key, facet) in facets {
                let spec = match facet {
                    Some(facet) => {
                        crate::domain_transaction::facet_set_spec(&id, &facet, caller.actor())
                    }
                    None => AppendSpec {
                        record_id: id.clone(),
                        event_type: "facet.unset".into(),
                        payload: serde_json::json!({"key":key}),
                        actor: Some(caller.actor().into()),
                    },
                };
                transaction.append_content(spec).await?;
            }
            let after_required = crate::domain_transaction::required_violations(
                transaction,
                &schema_rows,
                &[id.as_str()],
            )
            .await?;
            crate::domain_transaction::assert_required_not_worsened(
                TOOL,
                &before_required,
                &after_required,
            )?;
            read_record_in(transaction, &caller, &id)
                .await?
                .ok_or_else(|| Error::engine(format!("update_record: record {id} disappeared")))
        })
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveRecordArguments {
    id: String,
    archived: Option<bool>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRecordArguments {
    id: String,
    reason: String,
    #[serde(default)]
    if_content_seq: Option<i64>,
}

async fn delete_record(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: DeleteRecordArguments = parse_arguments("delete_record", arguments)?;
    let caller = caller.clone();
    run_db_operation_write(
        db,
        "delete_record",
        &ExecutionControl::default(),
        move |transaction| {
            Box::pin(async move {
                crate::domain_transaction::delete_record(
                    transaction,
                    principal(&caller),
                    &args.id,
                    &args.reason,
                    caller.actor(),
                    args.if_content_seq,
                )
                .await
            })
        },
    )
    .await
}

async fn archive_record(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "archive_record";
    let args: ArchiveRecordArguments = parse_arguments(TOOL, arguments)?;
    require_reason(TOOL, &args.reason)?;
    let want = args.archived.unwrap_or(true);
    let id = args.id;
    let caller = caller.clone();
    run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            require_capability(
                transaction,
                &caller,
                TOOL,
                &id,
                crate::authorization::Capability::Edit,
            )
            .await?;
            let state = transaction.record_state(&id).await?.ok_or_else(|| {
                Error::engine(format!("archive_record: record {id} does not exist"))
            })?;
            if state.archived == want {
                return Ok(serde_json::json!({"id":id,"archived":want,"changed":false}));
            }
            transaction
                .append_content(AppendSpec {
                    record_id: id.clone(),
                    event_type: if want { "facet.set" } else { "facet.unset" }.into(),
                    payload: if want {
                        serde_json::json!({"key":"archived","value":"true"})
                    } else {
                        serde_json::json!({"key":"archived"})
                    },
                    actor: Some(caller.actor().into()),
                })
                .await?;
            Ok(serde_json::json!({"id":id,"archived":want,"changed":true}))
        })
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageLinksArguments {
    Add {
        source_id: String,
        target_id: String,
        relationship: String,
        note: Option<String>,
    },
    Remove {
        source_id: String,
        target_id: String,
        relationship: String,
    },
    List {
        record_id: String,
    },
}

async fn manage_links(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: ManageLinksArguments = parse_arguments("manage_links", arguments)?;
    match args {
        ManageLinksArguments::List { record_id } => {
            let caller = caller.clone();
            run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
                Box::pin(async move {
                    require_capability(
                        transaction,
                        &caller,
                        "manage_links",
                        &record_id,
                        crate::authorization::Capability::View,
                    )
                    .await?;
                    list_links_in(transaction, &caller, &record_id).await
                })
            })
            .await
        }
        ManageLinksArguments::Add {
            source_id,
            target_id,
            relationship,
            note,
        } => mutate_link(db, caller, true, source_id, target_id, relationship, note).await,
        ManageLinksArguments::Remove {
            source_id,
            target_id,
            relationship,
        } => mutate_link(db, caller, false, source_id, target_id, relationship, None).await,
    }
}

async fn mutate_link(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    add: bool,
    source_id: String,
    target_id: String,
    relationship: String,
    note: Option<String>,
) -> Result<Value> {
    if relationship.is_empty() || (add && relationship.trim().is_empty()) {
        return Err(Error::engine(
            "link relationship must contain non-whitespace text",
        ));
    }
    let caller = caller.clone();
    run_db_write(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            require_capability(
                transaction,
                &caller,
                "manage_links",
                &source_id,
                crate::authorization::Capability::Edit,
            )
            .await?;
            if relationship == "part_of" {
                if let Some(source) = comment_record_in(transaction, &source_id).await? {
                    if source.deleted_at.is_none()
                        && governed_comment_in(
                            transaction,
                            &source.record_type,
                            source.kind.as_deref(),
                        )
                        .await?
                    {
                        return Err(Error::engine(
                            "manage_links: a governed comment's part_of bearer is immutable; create a new comment instead",
                        ));
                    }
                }
            }
            require_capability(
                transaction,
                &caller,
                "manage_links",
                &target_id,
                crate::authorization::Capability::View,
            )
            .await?;
            transaction
                .append_content(AppendSpec {
                    record_id: source_id.clone(),
                    event_type: if add { "link.added" } else { "link.removed" }.into(),
                    payload: if add {
                        serde_json::to_value(crate::events::LinkAddedPayload {
                            id: None,
                            source_id: source_id.clone(),
                            target_id: target_id.clone(),
                            relationship: relationship.clone(),
                            note,
                        })?
                    } else {
                        serde_json::to_value(crate::events::LinkRemovedPayload {
                            source_id: source_id.clone(),
                            target_id: target_id.clone(),
                            relationship: relationship.clone(),
                        })?
                    },
                    actor: Some(caller.actor().into()),
                })
                .await?;
            Ok(serde_json::json!({
                "status":if add{"added"}else{"removed"},
                "source_id":source_id,
                "target_id":target_id,
                "relationship":relationship,
            }))
        })
    })
    .await
}

async fn list_links_in(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    record_id: &str,
) -> Result<Value> {
    let query = statement(
        StatementKind::Select,
        "links",
        &[
            "SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} WHERE source_id=",
            " OR target_id=",
            " ORDER BY id",
        ],
    )
    .map_err(|error| stable("list links", error))?;
    let rows = transaction
        .rows(
            "list links",
            &query,
            &[
                BindValue::Text(record_id.into()),
                BindValue::Text(record_id.into()),
            ],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("source_id", LogicalType::Text),
                ColumnSpec::required("target_id", LogicalType::Text),
                ColumnSpec::required("relationship", LogicalType::Text),
                ColumnSpec::nullable("note", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
            ],
        )
        .await?;
    let mut outbound = Vec::new();
    let mut inbound = Vec::new();
    for row in rows {
        let source = text(&row, "source_id", "link")?;
        let target = text(&row, "target_id", "link")?;
        let other = if source == record_id {
            &target
        } else {
            &source
        };
        if !crate::authorization::allows_record_with(
            transaction,
            principal(caller),
            other,
            crate::authorization::Capability::View,
        )
        .await?
        {
            continue;
        }
        let value = serde_json::json!({
            "id":text(&row,"id","link")?,
            "source_id":source,
            "target_id":target,
            "relationship":text(&row,"relationship","link")?,
            "note":optional_text(&row,"note","link")?,
            "created_at":text(&row,"created_at","link")?,
        });
        if value["source_id"] == record_id {
            outbound.push(value);
        } else {
            inbound.push(value);
        }
    }
    Ok(serde_json::json!({
        "record_id":record_id,
        "links_out":outbound,
        "links_in":inbound,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArguments {
    record_id: Option<String>,
    for_run: Option<String>,
    #[serde(default)]
    include_child_runs: bool,
    #[serde(rename = "after_local_seq", alias = "after_seq")]
    after_seq: Option<i64>,
    limit: Option<i64>,
    order: Option<String>,
    #[serde(default)]
    detail: crate::mcp::tools::history::HistoryDetail,
}

async fn get_history(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: HistoryArguments = parse_arguments("get_history", arguments)?;
    if args.for_run.is_some()
        || args.include_child_runs
        || args.order.as_deref().is_some_and(|v| v != "oldest_first")
    {
        return Err(unsupported("get_history run/order selectors"));
    }
    let record_id = args.record_id.ok_or_else(|| {
        Error::engine(
            "get_history: Turso-local requires record_id; whole-log history is not qualified",
        )
    })?;
    let caller = caller.clone();
    let local_database_id = db.logical_database_id().to_owned();
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            require_capability(
                transaction,
                &caller,
                "get_history",
                &record_id,
                crate::authorization::Capability::View,
            )
            .await?;
            #[cfg(feature = "turso-tests")]
            faults.snapshot.enter("get_history").await?;
            let query = statement(
                StatementKind::Select,
                "content_events",
                &["SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status,(SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier frontier WHERE frontier.event_id=content_events.id) AS causal_frontier FROM {{relation}} WHERE record_id=", " AND seq>", " ORDER BY seq LIMIT ", ""],
            ).map_err(|error| stable("get history",error))?;
            let columns = [
                ColumnSpec::required("seq",LogicalType::Integer),
                ColumnSpec::required("id",LogicalType::Text),
                ColumnSpec::required("record_id",LogicalType::Text),
                ColumnSpec::required("type",LogicalType::Text),
                ColumnSpec::nullable("payload",LogicalType::Text),
                ColumnSpec::nullable("actor",LogicalType::Text),
                ColumnSpec::nullable("run_key",LogicalType::Text),
                ColumnSpec::nullable("parent_key",LogicalType::Text),
                ColumnSpec::nullable("intent",LogicalType::Text),
                ColumnSpec::required("created_at",LogicalType::Text),
                ColumnSpec::required("causal_envelope_version",LogicalType::Integer),
                ColumnSpec::required("causal_status",LogicalType::Text),
                ColumnSpec::required("causal_frontier",LogicalType::Text),
            ];
            let limit = args.limit.unwrap_or(100).clamp(1,1000) as usize;
            // Attribution follows `View` of the actor's person record, decided by
            // the one shared rule in `authorization` rather than a copy local to
            // this engine. Resolved once per distinct actor: a page holds many
            // events but few actors.
            let mut disclosable: std::collections::HashMap<String, bool> =
                std::collections::HashMap::new();
            let mut events = Vec::new();
            let mut scan_after = args.after_seq.unwrap_or(0);
            let mut exhausted = false;
            while events.len() <= limit && !exhausted {
                let rows = transaction.rows(
                    "get history",
                    &query,
                    &[
                        BindValue::Text(record_id.clone()),
                        BindValue::Integer(scan_after),
                        BindValue::Integer(1001),
                    ],
                    &columns,
                ).await?;
                exhausted = rows.len() < 1001;
                for row in rows {
                    scan_after = integer(&row,"seq","history")?;
                    let event_type = text(&row,"type","history")?;
                    if integer(&row,"causal_envelope_version","history")? != 1 {
                        return Err(Error::engine("unsupported stored causal envelope version"));
                    }
                    let causal_status = text(&row,"causal_status","history")?;
                    let causal_frontier: Value = serde_json::from_str(
                        &text(&row,"causal_frontier","history")?
                    )?;
                    let mut payload: Option<Value> = optional_text(&row,"payload","history")?
                        .map(|value| serde_json::from_str::<Value>(&value))
                        .transpose()?;
                    if !turso_history_event_visible(
                        transaction,
                        &caller,
                        &event_type,
                        payload.as_ref(),
                    ).await? {
                        continue;
                    }
                let mut actor = optional_text(&row,"actor","history")?;
                let mut run_key = optional_text(&row,"run_key","history")?;
                let mut parent_key = optional_text(&row,"parent_key","history")?;
                let mut intent = optional_text(&row,"intent","history")?;
                if !caller.is_trusted_local() {
                    if let Some(payload) = payload.as_mut() {
                        crate::domain_transaction::redact_history_payload_for_member(
                            payload,
                            caller.credential(),
                        );
                    }
                    let disclose = match actor.as_deref() {
                        Some(actor) => {
                            if let Some(decided) = disclosable.get(actor) {
                                *decided
                            } else {
                                let decided = crate::authorization::actor_disclosable_with(
                                    transaction,
                                    principal(&caller),
                                    actor,
                                ).await?;
                                disclosable.insert(actor.to_owned(), decided);
                                decided
                            }
                        }
                        None => false,
                    };
                    if !disclose {
                        actor = None;
                        run_key = None;
                        parent_key = None;
                        intent = None;
                    }
                }
                events.push(crate::mcp::tools::history::shape_history_event(serde_json::json!({
                    "local_seq":scan_after,
                    "id":text(&row,"id","history")?,
                    "record_id":text(&row,"record_id","history")?,
                    "type":event_type,
                    "payload":payload,
                    "actor":actor,
                    "run_key":run_key,
                    "parent_key":parent_key,
                    "intent":intent,
                    "created_at":text(&row,"created_at","history")?,
                    "causal_envelope":{
                        "version":"v1",
                        "status":causal_status,
                        "frontier":causal_frontier,
                    },
                }), args.detail));
                    if events.len() > limit {
                        break;
                    }
                }
            }
            let has_more = events.len() > limit;
            if has_more {
                events.pop();
            }
            let next_after_seq = has_more
                .then(|| events.last().and_then(|event| event.get("local_seq")).and_then(Value::as_i64))
                .flatten();
            Ok(serde_json::json!({
                "local_database_id":local_database_id,
                "events":events,
                "next_after_local_seq":next_after_seq,
                "order":"oldest_first",
                "representation":crate::mcp::tools::history::history_representation(args.detail),
            }))
        })
    }).await
}

async fn turso_history_event_visible(
    transaction: &mut TursoDomainTransaction<'_>,
    caller: &crate::mcp::Caller,
    event_type: &str,
    payload: Option<&Value>,
) -> Result<bool> {
    if matches!(
        event_type,
        "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
    ) {
        return Ok(false);
    }
    if event_type != "occurrence.bound.v1" {
        return Ok(true);
    }
    let Some(payload) = payload else {
        return Ok(false);
    };
    let Ok(payload) =
        serde_json::from_value::<crate::events::OccurrenceBoundPayload>(payload.clone())
    else {
        return Ok(false);
    };
    crate::authorization::allows_record_with(
        transaction,
        principal(caller),
        &payload.artefact_revision.subject_id,
        crate::authorization::Capability::View,
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachTextArguments {
    record_id: String,
    text: String,
    filename: Option<String>,
    mime: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: Option<Map<String, Value>>,
}

async fn attach_text(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "attach_text";
    const MAX_BYTES: usize = crate::mcp::fetch::MAX_FETCH_BYTES as usize;
    let args: AttachTextArguments = parse_arguments(TOOL, arguments)?;
    if args.text.len() > MAX_BYTES {
        return Err(Error::engine(format!(
            "attach_text: text exceeds the {MAX_BYTES} byte cap"
        )));
    }
    let facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| facet_write(key, value))
        .collect::<Result<Vec<_>>>()?;
    let mime = args
        .mime
        .unwrap_or_else(|| "text/plain; charset=utf-8".into());
    let name = args
        .name
        .or_else(|| args.filename.clone())
        .unwrap_or_else(|| "attachment".into());
    let caller = caller.clone();
    run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            crate::domain_transaction::create_attachment(
                transaction,
                crate::domain_transaction::AttachmentCreate {
                    tool: TOOL,
                    bearer_id: &args.record_id,
                    bytes: args.text.as_bytes(),
                    mime: Some(&mime),
                    filename: args.filename.as_deref(),
                    name: &name,
                    lifecycle: args.lifecycle.as_deref(),
                    owner_id: args.owner_id.as_deref(),
                    persistence: args.persistence.as_deref(),
                    maturity: args.maturity.as_deref(),
                    extra_facets: facets,
                    actor: caller.actor(),
                    credential: caller.credential(),
                    principal: principal(&caller),
                    attachment_id: None,
                    image_insert: None,
                },
            )
            .await
        })
    })
    .await
}

async fn preflight_attach_target(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    tool: &'static str,
    record_id: &str,
) -> Result<()> {
    let caller = caller.clone();
    let record_id = record_id.to_string();
    run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            require_capability(
                transaction,
                &caller,
                tool,
                &record_id,
                crate::authorization::Capability::Edit,
            )
            .await?;
            crate::domain_transaction::require_live_attachment_bearer(transaction, tool, &record_id)
                .await
        })
    })
    .await
}

/// `attach_from_url` parses and authorizes before network I/O, then enters the
/// same transactional create fold as `attach_text`. The fold repeats the
/// bearer checks after the fetch.
async fn attach_from_url(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
    config: FetchConfig,
) -> Result<Value> {
    const TOOL: &str = "attach_from_url";
    let (request, config) =
        crate::mcp::tools::attachments::parse_attachment_from_url(TOOL, arguments, config)?;
    preflight_attach_target(db, caller, TOOL, &request.record_id).await?;
    let prepared =
        crate::mcp::tools::attachments::fetch_attachment_from_url(request, &config).await?;
    let crate::mcp::tools::attachments::PreparedAttachmentFromUrl {
        record_id,
        bytes,
        mime,
        filename,
        name,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        facets,
        url,
        final_url,
        redirects,
    } = prepared;
    let caller = caller.clone();
    let result =
        run_db_operation_write(db, TOOL, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                crate::domain_transaction::create_attachment(
                    transaction,
                    crate::domain_transaction::AttachmentCreate {
                        tool: TOOL,
                        bearer_id: &record_id,
                        bytes: &bytes,
                        mime: Some(&mime),
                        filename: filename.as_deref(),
                        name: &name,
                        lifecycle: lifecycle.as_deref(),
                        owner_id: owner_id.as_deref(),
                        persistence: persistence.as_deref(),
                        maturity: maturity.as_deref(),
                        extra_facets: facets,
                        actor: caller.actor(),
                        credential: caller.credential(),
                        principal: principal(&caller),
                        attachment_id: None,
                        image_insert: None,
                    },
                )
                .await
            })
        })
        .await?;
    let mut result = result;
    let object = result.as_object_mut().expect("create_attachment payload");
    object.insert("url".into(), serde_json::json!(url));
    object.insert("final_url".into(), serde_json::json!(final_url));
    object.insert("redirects".into(), serde_json::json!(redirects));
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAttachmentArguments {
    attachment_id: String,
    offset: Option<u64>,
    length: Option<u64>,
}

async fn read_attachment(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: ReadAttachmentArguments = parse_arguments("read_attachment", arguments)?;
    let caller = caller.clone();
    run_db_operation_snapshot(
        db,
        "read_attachment",
        &ExecutionControl::default(),
        move |transaction| {
            Box::pin(async move {
                crate::domain_transaction::read_attachment(
                    transaction,
                    principal(&caller),
                    "read_attachment",
                    &args.attachment_id,
                    args.offset.unwrap_or(0),
                    args.length.unwrap_or(64 * 1024),
                    512 * 1024,
                )
                .await
            })
        },
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageAttachmentsArguments {
    List {
        record_id: String,
    },
    Inspect {
        attachment_id: String,
    },
    Detach {
        attachment_id: String,
        #[serde(default)]
        if_content_seq: Option<i64>,
    },
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_manage_attachments_detach(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<crate::domain_transaction::AttachmentDetachPreparation> {
    let ManageAttachmentsArguments::Detach {
        attachment_id,
        if_content_seq: None,
    } = parse_arguments("manage_attachments", arguments)?
    else {
        return Err(Error::engine(
            "manage_attachments: executor preparation only supports action detach without an internal revision",
        ));
    };
    let caller = caller.clone();
    run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            crate::domain_transaction::prepare_attachment_detach(
                transaction,
                principal(&caller),
                "manage_attachments",
                &attachment_id,
            )
            .await
        })
    })
    .await
}

async fn manage_attachments(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: ManageAttachmentsArguments = parse_arguments("manage_attachments", arguments)?;
    let caller = caller.clone();
    match args {
        ManageAttachmentsArguments::List { record_id } => {
            run_db_operation_snapshot(
                db,
                "manage_attachments",
                &ExecutionControl::default(),
                move |transaction| {
                    Box::pin(async move {
                        crate::domain_transaction::list_attachments(
                            transaction,
                            principal(&caller),
                            "manage_attachments",
                            &record_id,
                        )
                        .await
                    })
                },
            )
            .await
        }
        ManageAttachmentsArguments::Inspect { attachment_id } => {
            run_db_operation_snapshot(
                db,
                "manage_attachments",
                &ExecutionControl::default(),
                move |transaction| {
                    Box::pin(async move {
                        crate::domain_transaction::inspect_attachment(
                            transaction,
                            principal(&caller),
                            "manage_attachments",
                            &attachment_id,
                        )
                        .await
                    })
                },
            )
            .await
        }
        ManageAttachmentsArguments::Detach {
            attachment_id,
            if_content_seq,
        } => {
            run_db_operation_write(
                db,
                "manage_attachments",
                &ExecutionControl::default(),
                move |transaction| {
                    Box::pin(async move {
                        crate::domain_transaction::detach_attachment(
                            transaction,
                            principal(&caller),
                            "manage_attachments",
                            &attachment_id,
                            caller.actor(),
                            if_content_seq,
                        )
                        .await
                    })
                },
            )
            .await
        }
    }
}

async fn manage_facet_observations(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let action = arguments
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let caller = caller.clone();
    let control = ExecutionControl::default();
    let fold_control = control.clone();
    if action == "list" {
        return run_db_operation_snapshot(
            db,
            "manage_facet_observations",
            &control,
            move |transaction| {
                Box::pin(async move {
                    crate::domain_transaction::execute_manage_facet_observations(
                        transaction,
                        &caller,
                        arguments,
                        &fold_control,
                    )
                    .await
                })
            },
        )
        .await;
    }
    run_db_operation_write(
        db,
        "manage_facet_observations",
        &control,
        move |transaction| {
            Box::pin(async move {
                crate::domain_transaction::execute_manage_facet_observations(
                    transaction,
                    &caller,
                    arguments,
                    &fold_control,
                )
                .await
            })
        },
    )
    .await
}

async fn engine_info(db: &TursoLocalDb, arguments: Value) -> Result<Value> {
    let object = arguments
        .as_object()
        .ok_or_else(|| Error::engine("invalid arguments: expected an object"))?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "target_profiles" | "required_capabilities"))
    {
        return Err(Error::engine("invalid arguments for engine_info"));
    }
    if object.get("required_capabilities").is_some()
        || object
            .get("target_profiles")
            .is_some_and(|value| value.as_array().is_some_and(|values| !values.is_empty()))
    {
        return Err(unsupported("engine_info portability audit"));
    }
    Ok(serde_json::json!({
        "engine":crate::ENGINE_NAME,
        "engine_version":crate::ENGINE_VERSION,
        "git_sha":crate::GIT_SHA,
        "schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,
        "storage_profile":{
            "format":"native.storage-runtime.v1",
            "id":"turso-local",
            "revision":TURSO_LOCAL_PROFILE_REVISION,
            "mode":"embedded",
            "status":"spike",
            "topology":"authoritative-local-file-per-logical-database",
            "logical_database_id":db.logical_database_id(),
            "driver":"turso 0.7.2",
            "enforcement":"fixed-profile"
        },
        "health":db.health().await?,
        "query_sql":crate::query::sql_contract::capability(
            crate::query::sql_contract::QuerySqlProfile::TursoLocal
        ),
    }))
}

async fn run_portable_view(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
    operation: &'static str,
) -> Result<Value> {
    let caller = caller.clone();
    run_db_operation_snapshot(
        db,
        operation,
        &ExecutionControl::default(),
        move |transaction| {
            Box::pin(async move {
                match operation {
                    "get_structure" => {
                        crate::domain_transaction::views_history::get_structure(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "get_dashboard" => {
                        crate::domain_transaction::views_history::get_dashboard(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "render_record" => {
                        crate::domain_transaction::views_history::render_record(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "query_record" => {
                        crate::mcp::tools::querying::execute_portable_live_query_record(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "resolve_rollup" => {
                        crate::mcp::tools::querying::execute_portable_live_rollup(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "search" => {
                        crate::domain_transaction::search::execute(transaction, &caller, arguments)
                            .await
                    }
                    "scan" => {
                        crate::mcp::tools::querying::execute_portable_nonlexical_scan(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "preview_record_shape" => {
                        crate::domain_transaction::execute_preview_record_shape(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "resolve_facets" => {
                        crate::domain_transaction::execute_resolve_facets(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    "suggest_facet_values" => {
                        crate::domain_transaction::execute_suggest_facet_values(
                            transaction,
                            &caller,
                            arguments,
                        )
                        .await
                    }
                    _ => unreachable!("registered portable view operation"),
                }
            })
        },
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeSchemaArguments {
    include_ddl: Option<bool>,
}

fn turso_schema_table_visible(table: &str, caller: &crate::mcp::Caller) -> bool {
    caller.is_host_owner()
        || !matches!(
            table,
            "meta_events"
                | "policy_events"
                | "record_policies"
                | "policy_entries"
                | "bindings"
                | "database_identity"
                | "database_identity_audit"
                | "storage_portability_policy"
        )
}

async fn describe_schema(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    let args: DescribeSchemaArguments = parse_arguments("describe_schema", arguments)?;
    if args.include_ddl.unwrap_or(false) && !caller.is_host_owner() {
        return Err(Error::auth(
            "describe_schema: database owner host role required for physical DDL",
        ));
    }

    let connection = db.connect()?;
    let mut by_table: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for table in TURSO_REQUIRED_RUNTIME_TABLES {
        let mut rows = connection
            .query(&format!("PRAGMA table_xinfo('{table}')"), ())
            .await
            .map_err(|_| Error::engine("cannot inspect Turso-local schema columns"))?;
        let mut columns = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|_| Error::engine("cannot inspect Turso-local schema columns"))?
        {
            let name: String = row
                .get(1)
                .map_err(|_| Error::engine("invalid Turso-local schema column name"))?;
            let physical_type: String = row
                .get(2)
                .map_err(|_| Error::engine("invalid Turso-local schema column type"))?;
            let notnull: i64 = row
                .get(3)
                .map_err(|_| Error::engine("invalid Turso-local schema nullability"))?;
            let pk: i64 = row
                .get(5)
                .map_err(|_| Error::engine("invalid Turso-local schema primary key"))?;
            columns.push(crate::schema::discovery::column(
                table,
                name,
                physical_type,
                notnull != 0,
                pk != 0,
            ));
        }
        if columns.is_empty() {
            return Err(Error::engine(format!(
                "describe_schema: required Turso-local relation '{table}' is absent"
            )));
        }
        by_table.insert(table.into(), columns);
    }
    if !crate::schema::discovery::shared_logical_contract_holds(&by_table) {
        return Err(Error::engine(format!(
            "describe_schema: Turso-local logical column contract is incomplete: {}",
            crate::schema::discovery::shared_logical_contract_mismatches(&by_table).join(", ")
        )));
    }
    let user_version = scalar_i64(&connection, "PRAGMA user_version").await?;
    let expected_schema = compiled_required_runtime_schema()?;
    let installed_schema = installed_required_runtime_schema(&connection, &expected_schema).await?;
    if installed_schema != expected_schema {
        return Err(Error::engine(
            "describe_schema: installed Turso-local DDL differs from the frozen compiled contract",
        ));
    }
    let overlays = physical_overlay_names(&connection).await?;
    if overlays
        != BTreeSet::from([
            "projection.facet-value-number",
            "search.turso-fts",
            "topology.logical-database-identity",
        ])
    {
        return Err(Error::engine(
            "describe_schema: installed Turso-local physical overlays differ from the frozen contract",
        ));
    }
    drop(connection);

    let caller_for_snapshot = caller.clone();
    #[cfg(feature = "turso-tests")]
    let faults = Arc::clone(&db.inner.contract_faults);
    let (mut resolved, kind_registry) =
        run_db_snapshot(db, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                let rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
                #[cfg(feature = "turso-tests")]
                faults.snapshot.enter("describe_schema").await?;
                let mut visible = Vec::with_capacity(rows.len());
                for row in rows {
                    let allowed = match row.applies_to_collection_id.as_deref() {
                        None => true,
                        Some(bearer) => {
                            crate::authorization::allows_record_with(
                                transaction,
                                principal(&caller_for_snapshot),
                                bearer,
                                crate::authorization::Capability::View,
                            )
                            .await?
                        }
                    };
                    if allowed {
                        visible.push(row);
                    }
                }
                let resolved = crate::query::cascade::resolve_from_rows(&visible).resolved;
                let mut kind_registry = Map::new();
                for record_type in crate::schema::SPINE_TYPES {
                    let kinds =
                        crate::meta::kind::list_active_with(transaction, record_type).await?;
                    kind_registry.insert(record_type.into(), serde_json::to_value(kinds)?);
                }
                Ok((resolved, kind_registry))
            })
        })
        .await?;
    for record_type in crate::schema::SPINE_TYPES {
        let tokens = kind_registry[record_type]
            .as_array()
            .expect("kind registry values are arrays")
            .iter()
            .filter_map(|kind| kind.get("token").cloned())
            .collect();
        resolved["shapes"][record_type]["kinds"] = Value::Array(tokens);
    }

    let tables = TURSO_REQUIRED_RUNTIME_TABLES
        .iter()
        .filter(|table| turso_schema_table_visible(table, caller))
        .map(|table| {
            serde_json::json!({
                "name":table,
                "role":crate::schema::discovery::table_role(table),
                "columns":by_table.get(*table).expect("required table checked"),
            })
        })
        .collect::<Vec<_>>();
    // These are the normalized definitions read from the installed catalog,
    // after byte-for-byte comparison with the frozen compiled contract above.
    let complete_ddl = installed_schema
        .values()
        .cloned()
        .chain([
            TURSO_RECORDS_FTS_DDL.into(),
            TURSO_RECORDS_NAME_FTS_DDL.into(),
        ])
        .collect::<Vec<_>>();
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&complete_ddl)?));
    if complete_ddl.len() != TURSO_DESCRIBE_SCHEMA_DDL_COUNT
        || fingerprint != TURSO_DESCRIBE_SCHEMA_DDL_FINGERPRINT
    {
        return Err(Error::engine(format!(
            "describe_schema: installed Turso-local DDL differs from the frozen allowlisted contract (count={}, fingerprint={fingerprint})",
            complete_ddl.len()
        )));
    }
    let ddl_statements = args.include_ddl.unwrap_or(false).then_some(complete_ddl);
    let mut out = serde_json::json!({
        "engine":{
            "name":crate::ENGINE_NAME,
            "version":crate::ENGINE_VERSION,
            "git_sha":crate::GIT_SHA,
            "schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,
            "supported_schema_baseline":crate::SUPPORTED_ENGINE_SCHEMA_BASELINE,
            "user_version":user_version,
            "ddl_fingerprint":fingerprint,
            "storage_profile":"turso-local",
            "storage_profile_revision":TURSO_LOCAL_PROFILE_REVISION,
        },
        "model":crate::schema::discovery::AUTHORITY_MODEL,
        "physical_differences":{
            "catalog":"allowlisted runtime schema only",
            "json":"canonical JSON text",
            "timestamps":"RFC3339 text",
            "physical_overlays":overlays,
            "runtime_topology_table_exposed":false,
        },
        "tables":tables,
        "resolved_schema_config":resolved,
        "kind_registry":kind_registry,
    });
    if let Some(ddl_statements) = ddl_statements {
        out["ddl_statements"] = serde_json::to_value(ddl_statements)?;
        out["ddl_representation"] = Value::String(
            "exact compiled allowlisted Turso-local tables with keys, defaults, foreign keys and checks, plus their indexes, triggers, and public physical FTS overlays".into(),
        );
    }
    Ok(out)
}

/// Register the exact local-Turso runtime slice. Registry metadata and schemas
/// remain owned by the canonical surface registration; this function only
/// supplies physical handlers for operations with executable evidence.
pub fn register_turso_local_tools(registry: &mut crate::mcp::ToolRegistry) -> Result<()> {
    register_turso_local_tools_with(registry, FetchConfig::default())
}

/// Register the local-Turso handlers with an explicit guarded-fetch config
/// for contract tests. Production callers use the default policy above.
pub fn register_turso_local_tools_with(
    registry: &mut crate::mcp::ToolRegistry,
    fetch_config: FetchConfig,
) -> Result<()> {
    match (registry.get("ping"), registry.get("engine_info")) {
        (None, None) => crate::mcp::register_builtin_tools(registry)?,
        (Some(_), Some(_)) => {}
        _ => {
            return Err(Error::engine(
                "Turso-local registry has an incomplete built-in tool set",
            ))
        }
    }
    registry.register_engine_handler(
        "ping",
        crate::mcp::EngineKind::TursoLocal,
        |_engine, _caller, arguments| async move {
            if !arguments.as_object().is_some_and(Map::is_empty) {
                return Err(Error::engine("invalid arguments: expected no arguments"));
            }
            Ok(serde_json::json!({"ok":true}))
        },
    )?;
    registry.register_engine_handler(
        "engine_info",
        crate::mcp::EngineKind::TursoLocal,
        |engine, _caller, arguments| async move {
            let crate::mcp::EngineHandle::TursoLocal(db) = engine else {
                unreachable!()
            };
            engine_info(&db, arguments).await
        },
    )?;
    macro_rules! register {
        ($name:literal,$handler:ident) => {
            registry.register_engine_handler(
                $name,
                crate::mcp::EngineKind::TursoLocal,
                |engine, caller, arguments| async move {
                    let crate::mcp::EngineHandle::TursoLocal(db) = engine else {
                        unreachable!()
                    };
                    $handler(&db, &caller, arguments).await
                },
            )?;
        };
    }
    register!("create_record", create_record);
    register!("get_record", get_record);
    for operation in [
        "get_structure",
        "get_dashboard",
        "render_record",
        "query_record",
        "resolve_rollup",
        "search",
        "scan",
        "preview_record_shape",
        "resolve_facets",
        "suggest_facet_values",
    ] {
        registry.register_engine_handler(
            operation,
            crate::mcp::EngineKind::TursoLocal,
            move |engine, caller, arguments| async move {
                let crate::mcp::EngineHandle::TursoLocal(db) = engine else {
                    unreachable!()
                };
                run_portable_view(&db, &caller, arguments, operation).await
            },
        )?;
    }
    register!("manage_facet_observations", manage_facet_observations);
    register!("update_record", update_record);
    #[cfg(feature = "mcp-executor-prototype")]
    register!("correct_record_type", correct_record_type);
    register!("delete_record", delete_record);
    register!("archive_record", archive_record);
    register!("manage_links", manage_links);
    register!("get_history", get_history);
    register!("attach_text", attach_text);
    let fetch_config = Arc::new(fetch_config);
    registry.register_engine_handler(
        "attach_from_url",
        crate::mcp::EngineKind::TursoLocal,
        move |engine, caller, arguments| {
            let fetch_config = Arc::clone(&fetch_config);
            async move {
                let crate::mcp::EngineHandle::TursoLocal(db) = engine else {
                    unreachable!()
                };
                attach_from_url(&db, &caller, arguments, (*fetch_config).clone()).await
            }
        },
    )?;
    register!("read_attachment", read_attachment);
    register!("manage_attachments", manage_attachments);
    register!("describe_schema", describe_schema);
    register!("resolve_external", turso_resolve_external);
    registry.register_engine_handler_for_selector_values(
        "manage_bindings",
        crate::mcp::EngineKind::TursoLocal,
        "action",
        &["list", "add", "remove", "canonicalize", "reconcile"],
        |engine, caller, arguments| async move {
            let crate::mcp::EngineHandle::TursoLocal(db) = engine else {
                unreachable!()
            };
            turso_manage_bindings(&db, &caller, arguments).await
        },
    )?;
    register!("query_sql", query_sql);
    registry.register_engine_handler(
        "set_intent",
        crate::mcp::EngineKind::TursoLocal,
        |_engine, _caller, arguments| async move {
            crate::mcp::tools::intent::declare_without_activity_briefing(arguments)
        },
    )?;
    Ok(())
}

async fn turso_resolve_external(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "resolve_external";
    let request = crate::domain_transaction::parse_resolve_external(arguments)?;
    let caller = caller.clone();
    run_db_operation_write_with_disposition(
        db,
        TOOL,
        &ExecutionControl::default(),
        move |transaction| {
            Box::pin(async move {
                let result = crate::domain_transaction::resolve_external(
                    transaction,
                    principal(&caller),
                    caller.actor(),
                    caller.run_key(),
                    caller.parent_key(),
                    caller.intent(),
                    request,
                )
                .await?;
                let changed = result.created || !result.bindings_added.is_empty();
                let response = serde_json::json!({
                    "status":if result.created{"created"}else{"resolved"},
                    "record_id":result.record_id,
                    "created":result.created,
                    "bindings_added":result.bindings_added,
                });
                Ok(if changed {
                    crate::domain_transaction::TransactionDisposition::Commit(response)
                } else {
                    crate::domain_transaction::TransactionDisposition::Rollback(response)
                })
            })
        },
    )
    .await
}

async fn turso_manage_bindings(
    db: &TursoLocalDb,
    caller: &crate::mcp::Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "manage_bindings";
    let request = crate::domain_transaction::parse_manage_bindings(arguments)?;
    let mutates = request.mutates();
    let caller = caller.clone();
    if mutates {
        run_db_operation_write_with_disposition(
            db,
            TOOL,
            &ExecutionControl::default(),
            move |transaction| {
                Box::pin(async move {
                    let outcome = crate::domain_transaction::manage_bindings(
                        transaction,
                        principal(&caller),
                        caller.actor(),
                        caller.run_key(),
                        caller.parent_key(),
                        caller.intent(),
                        request,
                    )
                    .await?;
                    Ok(if outcome.changed {
                        crate::domain_transaction::TransactionDisposition::Commit(outcome.response)
                    } else {
                        crate::domain_transaction::TransactionDisposition::Rollback(
                            outcome.response,
                        )
                    })
                })
            },
        )
        .await
    } else {
        run_db_operation_snapshot(db, TOOL, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                crate::domain_transaction::manage_bindings(
                    transaction,
                    principal(&caller),
                    caller.actor(),
                    caller.run_key(),
                    caller.parent_key(),
                    caller.intent(),
                    request,
                )
                .await
                .map(|outcome| outcome.response)
            })
        })
        .await
    }
}

#[cfg(all(test, feature = "turso-tests"))]
mod tests {
    use super::*;
    use serde_json::json;

    fn query_sql_source_fingerprint(directory: &Path) -> BTreeMap<String, String> {
        std::fs::read_dir(directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter(|entry| !entry.file_name().to_string_lossy().ends_with(".lock"))
            .map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let digest = hex::encode(Sha256::digest(std::fs::read(entry.path()).unwrap()));
                (name, digest)
            })
            .collect()
    }

    const QUERY_SQL_PARITY_FIXTURE: &[&str] = &[
        "INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id) VALUES
          ('parity:owner:alice','Entity','account','Alice',NULL,NULL,'parity:owner:alice','parity:owner:alice'),
          ('parity:owner:bob','Entity','account','Bob',NULL,NULL,'parity:owner:bob','parity:owner:bob'),
          ('parity:visible','Document','note','Visible','visible body',NULL,'parity:owner:alice','parity:visible'),
          ('parity:hidden','Document','note','Hidden','hidden body',NULL,'parity:owner:bob','parity:hidden'),
          ('parity:hidden-parent','Collection','collection','Hidden parent',NULL,NULL,'parity:owner:bob','parity:hidden-parent'),
          ('parity:child','Document','note','Child',NULL,'parity:hidden-parent','parity:owner:alice','parity:child'),
          ('parity:attachment','Document','attachment','good.bin',NULL,NULL,'parity:owner:bob','parity:attachment'),
          ('parity:attachment-hidden','Document','attachment','hidden.bin',NULL,NULL,'parity:owner:alice','parity:attachment-hidden'),
          ('parity:annotation','Annotation','citation','Annotation',NULL,NULL,'parity:owner:bob','parity:annotation'),
          ('parity:attribution','Annotation','attribution','Attribution',NULL,NULL,'parity:owner:bob','parity:attribution'),
          ('parity:missing','Annotation','citation','Missing bearer',NULL,NULL,'parity:owner:alice','parity:missing'),
          ('parity:malformed','Annotation','citation','Malformed',NULL,NULL,'parity:owner:alice','parity:malformed'),
          ('parity:dead','Document','note','Dead bearer',NULL,NULL,'parity:owner:alice','parity:dead'),
          ('parity:derived-dead','Annotation','citation','Derived dead',NULL,NULL,'parity:owner:alice','parity:derived-dead'),
          ('parity:cycle-a','Annotation','citation','Cycle A',NULL,NULL,'parity:owner:alice','parity:cycle-a'),
          ('parity:cycle-b','Annotation','citation','Cycle B',NULL,NULL,'parity:owner:alice','parity:cycle-b'),
          ('parity:unit','Entity','semantic-unit','Unit',NULL,NULL,'parity:owner:alice','parity:unit'),
          ('parity:attachment-unit','Document','attachment','unit.bin',NULL,NULL,'parity:owner:alice','parity:attachment-unit')",
        "UPDATE records SET created_at='2026-01-01T00:00:00.000Z',updated_at='2026-01-01T00:00:00.000Z' WHERE id LIKE 'parity:%'",
        "UPDATE records SET deleted_at='2026-01-02T00:00:00.000Z' WHERE id='parity:dead'",
        "INSERT INTO record_policies(record_id,created_at) SELECT id,'2026-01-01T00:00:00.000Z' FROM records WHERE id LIKE 'parity:%'",
        "INSERT INTO bindings(record_id,system,identifier,is_canonical,url,etag,last_seen_at) VALUES
          ('parity:owner:alice','account','account:alice',1,NULL,NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:owner:alice','email','alice@example.test',1,NULL,NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:owner:alice','github','alice-gh',1,NULL,NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:owner:bob','account','account:bob',1,NULL,NULL,'2026-01-01T00:00:00.000Z')",
        "INSERT INTO links(id,source_id,target_id,relationship,note,created_at) VALUES
          ('parity:link-visible','parity:visible','parity:child','relates_to',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:link-hidden','parity:visible','parity:hidden','relates_to',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-attachment','parity:attachment','parity:visible','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-hidden','parity:attachment-hidden','parity:hidden','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-annotation','parity:annotation','parity:visible','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-attribution','parity:attribution','parity:visible','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:malformed-a','parity:malformed','parity:visible','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:malformed-b','parity:malformed','parity:hidden','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-dead','parity:derived-dead','parity:dead','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:cycle-a-b','parity:cycle-a','parity:cycle-b','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:cycle-b-a','parity:cycle-b','parity:cycle-a','part_of',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:bear-unit','parity:attachment-unit','parity:unit','part_of',NULL,'2026-01-01T00:00:00.000Z')",
        "INSERT INTO content_events(seq,id,record_id,type,created_at,causal_envelope_version,causal_status) VALUES
          (8001,'parity:event-visible','parity:visible','record.updated','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8002,'parity:event-receipt','parity:visible','receipt.committed.v1','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8003,'parity:event-reconcile','parity:visible','reconciliation.recorded.v1','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8004,'parity:event-superseded','parity:visible','unit.superseded.v1','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8005,'parity:event-audit','parity:visible','receipt.dependency_audited.v1','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8006,'parity:event-hidden','parity:hidden','record.updated','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8007,'parity:event-unit-create','parity:unit','record.created','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
          (8008,'parity:event-attribution','parity:attribution','attribution.target.bound.v1','2026-01-01T00:00:00.000Z',1,'legacy_unknown')",
        "INSERT INTO semantic_units(unit_id,authority_bearer_record_id,creation_event_id,creation_event_seq,label,created_at) VALUES ('parity:unit','parity:visible','parity:event-unit-create',8007,'Unit','2026-01-01T00:00:00.000Z')",
        "INSERT INTO facet_values(id,record_id,key,value,vocab_ref,created_at) VALUES
          ('parity:facet-visible','parity:visible','tag','blue',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:facet-hidden','parity:hidden','tag','red',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:facet-attribution','parity:attribution','tag','private',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:facet-blob','parity:attachment','blob_ref','parity:blob-good',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:facet-blob-hidden','parity:attachment-hidden','blob_ref','parity:blob-hidden',NULL,'2026-01-01T00:00:00.000Z')",
        "INSERT INTO facet_observations(id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq) VALUES
          ('parity:observation-visible','parity:visible','tag','blue','set',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',8001),
          ('parity:observation-hidden','parity:hidden','tag','red','set',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',8006),
          ('parity:observation-attribution','parity:attribution','tag','private','set',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',8008)",
        "INSERT INTO blobs(id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,created_at) VALUES
          ('parity:blob-good',X'010203','application/octet-stream',3,'good','good.bin','inline','2026-01-01T00:00:00.000Z'),
          ('parity:blob-hidden',zeroblob(262145),'application/octet-stream',262145,'hidden','hidden.bin','inline','2026-01-01T00:00:00.000Z')",
        "INSERT INTO vocabularies(id,name,created_at) VALUES ('parity:vocabulary','Parity vocabulary','2026-01-01T00:00:00.000Z')",
        "INSERT INTO vocabulary_values(id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata) VALUES ('parity:vocabulary-value','parity:vocabulary','choice','Choice','active',1.5,'open','{ \"z\": 1, \"a\": 2 }')",
        "INSERT INTO schema_config(id,layer,name,data,applies_to_collection_id,version_lineage,created_at) VALUES
          ('parity:schema-global','user','Global','{ \"global\": true }',NULL,NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:schema-visible','user','Visible','{ \"visible\": true }','parity:child',NULL,'2026-01-01T00:00:00.000Z'),
          ('parity:schema-hidden','user','Hidden','{ \"hidden\": true }','parity:hidden-parent',NULL,'2026-01-01T00:00:00.000Z')",
    ];

    async fn install_query_sql_parity_fixture(sqlite: &crate::db::Db, turso: &TursoLocalDb) {
        let turso_connection = turso.connect().unwrap();
        for statement in QUERY_SQL_PARITY_FIXTURE {
            sqlx::query(statement)
                .execute(sqlite.write_pool())
                .await
                .unwrap_or_else(|error| panic!("SQLite fixture failed for {statement}: {error}"));
            turso_connection
                .execute(statement, ())
                .await
                .unwrap_or_else(|error| panic!("Turso fixture failed for {statement}: {error}"));
        }

        // One more edge than the shared defensive ceiling. Both reference
        // providers must exclude the origin rather than partially resolving
        // the derived chain or borrowing an intermediate policy.
        let mut turso_record = turso_connection
            .prepare(
                "INSERT INTO records(id,type,kind,name,owner_id,policy_anchor_id,created_at,updated_at)
                 VALUES (?1,'Annotation','citation',?1,'parity:owner:alice',?1,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        let mut turso_link = turso_connection
            .prepare(
                "INSERT INTO links(id,source_id,target_id,relationship,created_at)
                 VALUES (?1,?2,?3,'part_of','2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
            let id = format!("parity:depth:{depth:03}");
            sqlx::query(
                "INSERT INTO records(id,type,kind,name,owner_id,policy_anchor_id,created_at,updated_at)
                 VALUES (?,'Annotation','citation',?,'parity:owner:alice',?,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            )
            .bind(&id)
            .bind(&id)
            .bind(&id)
            .execute(sqlite.write_pool())
            .await
            .unwrap();
            turso_record.execute((id.clone(),)).await.unwrap();
        }
        for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
            let id = format!("parity:depth:{depth:03}");
            let target = if depth == crate::authorization::MAX_DERIVED_BEARER_DEPTH {
                "parity:visible".to_string()
            } else {
                format!("parity:depth:{:03}", depth + 1)
            };
            let link_id = format!("parity:depth-link:{depth:03}");
            sqlx::query(
                "INSERT INTO links(id,source_id,target_id,relationship,created_at)
                 VALUES (?,?,?,'part_of','2026-01-01T00:00:00.000Z')",
            )
            .bind(&link_id)
            .bind(&id)
            .bind(&target)
            .execute(sqlite.write_pool())
            .await
            .unwrap();
            turso_link.execute((link_id, id, target)).await.unwrap();
        }
    }

    async fn sqlite_query_sql_value(
        db: crate::db::Db,
        caller: crate::mcp::Caller,
        sql: &str,
    ) -> Value {
        serde_json::to_value(
            crate::query::sql::query_sql_request_owned(
                db,
                (&caller).into(),
                crate::query::sql_contract::QuerySqlRequest {
                    sql: sql.into(),
                    parameters: Vec::new(),
                },
            )
            .await
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn query_sql_matches_sqlite_adversarial_projection_across_all_relations() {
        let sqlite = crate::create_database(":memory:").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let turso = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "query-sql-parity".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        install_query_sql_parity_fixture(&sqlite, &turso).await;
        let caller = crate::mcp::Caller::authenticated("account:alice");
        let queries = [
            "SELECT * FROM records WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM content_events WHERE id LIKE 'parity:%' ORDER BY local_seq",
            "SELECT * FROM links WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM facet_values WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM facet_observations WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM bindings WHERE record_id LIKE 'parity:%' ORDER BY system,identifier",
            "SELECT * FROM blobs WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM vocabularies WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM vocabulary_values WHERE id LIKE 'parity:%' ORDER BY id",
            "SELECT * FROM schema_config WHERE id LIKE 'parity:%' ORDER BY id",
        ];
        for sql in queries {
            let sqlite_result = sqlite_query_sql_value(sqlite.clone(), caller.clone(), sql).await;
            let turso_result = query_sql(&turso, &caller, json!({"sql":sql,"parameters":[]}))
                .await
                .unwrap_or_else(|error| panic!("Turso failed {sql}: {error}"));
            assert_eq!(turso_result, sqlite_result, "projection drift for {sql}");
        }

        let records = query_sql(
            &turso,
            &caller,
            json!({"sql":"SELECT id,home_id FROM records WHERE id LIKE 'parity:%' AND id NOT LIKE 'parity:depth:%' ORDER BY id","parameters":[]}),
        )
        .await
        .unwrap();
        assert_eq!(
            records["rows"],
            json!([
                {"home_id":null,"id":"parity:annotation"},
                {"home_id":null,"id":"parity:attachment"},
                {"home_id":null,"id":"parity:child"},
                {"home_id":null,"id":"parity:owner:alice"},
                {"home_id":null,"id":"parity:visible"}
            ])
        );
        let depth = query_sql(
            &turso,
            &caller,
            json!({"sql":"SELECT id FROM records WHERE id IN ('parity:depth:000','parity:depth:001') ORDER BY id","parameters":[]}),
        )
        .await
        .unwrap();
        assert_eq!(depth["rows"], json!([{"id":"parity:depth:001"}]));
        let rejected_bearers = query_sql(
            &turso,
            &caller,
            json!({"sql":"SELECT id FROM records WHERE id IN ('parity:missing','parity:malformed','parity:derived-dead','parity:cycle-a','parity:cycle-b') ORDER BY id","parameters":[]}),
        )
        .await
        .unwrap();
        assert!(rejected_bearers["rows"].as_array().unwrap().is_empty());
        let hosted_local =
            crate::mcp::Caller::local().with_hosting_context("host:user", "host:database");
        let hosted = query_sql(
            &turso,
            &hosted_local,
            json!({"sql":"SELECT id FROM records WHERE id LIKE 'parity:%'","parameters":[]}),
        )
        .await
        .unwrap();
        assert!(hosted["rows"].as_array().unwrap().is_empty());

        for relation in [
            "records",
            "content_events",
            "links",
            "facet_values",
            "facet_observations",
        ] {
            let bearer_column = match relation {
                "content_events" | "facet_values" | "facet_observations" => "record_id",
                "links" => "source_id",
                _ => "id",
            };
            let hidden = query_sql(
                &turso,
                &caller,
                json!({
                    "sql":format!(
                        "SELECT * FROM {relation} WHERE id LIKE '%attribution%' OR {bearer_column} LIKE '%attribution%'"
                    ),
                    "parameters":[]
                }),
            )
            .await
            .unwrap_or_else(|error| panic!("Turso failed attribution non-disclosure for {relation}: {error}"));
            assert!(
                hidden["rows"].as_array().unwrap().is_empty(),
                "{relation} exposed attribution through Turso query_sql: {hidden}"
            );
        }
    }

    #[tokio::test]
    async fn query_sql_rejects_visible_giant_blob_before_materialization() {
        let sqlite = crate::create_database(":memory:").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let turso = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "query-sql-giant-blob".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        install_query_sql_parity_fixture(&sqlite, &turso).await;
        turso
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "UPDATE blobs SET bytes=zeroblob({}) WHERE id='parity:blob-good'",
                    crate::query::sql_contract::MAX_CELL_ENCODED_BYTES + 1
                ),
                (),
            )
            .await
            .unwrap();
        let before = query_sql_source_fingerprint(directory.path());
        let error = query_sql(
            &turso,
            &crate::mcp::Caller::authenticated("account:alice"),
            json!({"sql":"SELECT bytes FROM blobs","parameters":[]}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("result_too_large"), "{error}");
        assert!(error.contains("cell"), "{error}");
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);
    }

    #[tokio::test]
    async fn query_sql_rejects_near_cap_blob_expansion_before_next_fetch() {
        let sqlite = crate::create_database(":memory:").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let turso = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "query-sql-blob-expansion-cap".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        install_query_sql_parity_fixture(&sqlite, &turso).await;
        let connection = turso.connect().unwrap();
        let mut insert_record = connection
            .prepare(
                "INSERT INTO records(id,type,kind,name,owner_id,policy_anchor_id,created_at,updated_at)
                 VALUES (?1,'Document','attachment',?2,'parity:owner:alice',?1,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        let mut insert_link = connection
            .prepare(
                "INSERT INTO links(id,source_id,target_id,relationship,created_at)
                 VALUES (?1,?2,'parity:visible','part_of','2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        let mut insert_facet = connection
            .prepare(
                "INSERT INTO facet_values(id,record_id,key,value,created_at)
                 VALUES (?1,?2,'blob_ref',?3,'2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        let mut insert_blob = connection
            .prepare(
                "INSERT INTO blobs(id,bytes,size_bytes,sha256,original_filename,storage_tier,created_at)
                 VALUES (?1,zeroblob(245760),245760,?1,?2,'inline','2026-01-01T00:00:00.000Z')",
            )
            .await
            .unwrap();
        for index in 0..64 {
            let attachment = format!("parity:bulk-attachment:{index:02}");
            let blob = format!("parity:bulk-blob:{index:02}");
            insert_record
                .execute((attachment.clone(), format!("blob-{index:02}.bin")))
                .await
                .unwrap();
            insert_link
                .execute((format!("parity:bulk-link:{index:02}"), attachment.clone()))
                .await
                .unwrap();
            insert_facet
                .execute((
                    format!("parity:bulk-facet:{index:02}"),
                    attachment,
                    blob.clone(),
                ))
                .await
                .unwrap();
            insert_blob
                .execute((blob, format!("blob-{index:02}.bin")))
                .await
                .unwrap();
        }
        let before = query_sql_source_fingerprint(directory.path());
        let error = query_sql(
            &turso,
            &crate::mcp::Caller::authenticated("account:alice"),
            json!({"sql":"SELECT count(*) AS n FROM blobs","parameters":[]}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("result_too_large"), "{error}");
        assert!(error.contains("aggregate"), "{error}");
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);
    }

    #[tokio::test]
    async fn query_sql_rejects_escape_heavy_aggregate_candidates_before_fetch() {
        let sqlite = crate::create_database(":memory:").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let turso = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "query-sql-aggregate-source-cap".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        install_query_sql_parity_fixture(&sqlite, &turso).await;
        let connection = turso.connect().unwrap();
        let mut insert_vocabulary = connection
            .prepare("INSERT INTO vocabularies(id,name,created_at) VALUES (?1,?2,'2026-01-01T00:00:00.000Z')")
            .await
            .unwrap();
        let mut insert_value = connection
            .prepare("INSERT INTO vocabulary_values(id,vocabulary_id,value,metadata) VALUES (?1,?2,?3,'{}')")
            .await
            .unwrap();
        // Each physical NUL byte needs a six-byte JSON escape. Raw-byte
        // accounting would admit this relation even though encoding it cannot
        // fit the projection ceiling.
        let payload = "\u{0000}".repeat(140 * 1024);
        for index in 0..64 {
            let vocabulary_id = format!("parity:bulk-vocab:{index}");
            insert_vocabulary
                .execute((vocabulary_id.clone(), format!("{payload}-{index}")))
                .await
                .unwrap();
            insert_value
                .execute((
                    format!("parity:bulk-value:{index}"),
                    vocabulary_id,
                    format!("{payload}-{index}"),
                ))
                .await
                .unwrap();
        }
        let before = query_sql_source_fingerprint(directory.path());
        let error = query_sql(
            &turso,
            &crate::mcp::Caller::authenticated("account:alice"),
            json!({"sql":"SELECT * FROM vocabularies","parameters":[]}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("result_too_large"), "{error}");
        assert!(error.contains("aggregate"), "{error}");
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);
    }

    #[tokio::test]
    async fn query_sql_is_registered_and_filters_two_principals() {
        // Canonical lowercase v4s, hardcoded rather than generated so the
        // fixture is deterministic. The counters ascend in the alphabetical
        // order of the slugs these ids replaced (`owner:alice`, `owner:bob`,
        // `private:alice`, `private:bob`), so the `ORDER BY id` projection
        // below still returns Alice's record before Bob's.
        const OWNER_ALICE: &str = "70250001-0000-4000-8000-000000000101";
        const OWNER_BOB: &str = "70250001-0000-4000-8000-000000000102";
        const PRIVATE_ALICE: &str = "70250001-0000-4000-8000-000000000103";
        const PRIVATE_BOB: &str = "70250001-0000-4000-8000-000000000104";

        let directory = tempfile::tempdir().unwrap();
        let config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "query-sql-two-principals".into(),
            data_directory: directory.path().to_path_buf(),
        };
        let db = config.open().await.unwrap();
        for (id, kind, label) in [
            (OWNER_ALICE, "account", "owner:alice"),
            (OWNER_BOB, "account", "owner:bob"),
            (PRIVATE_ALICE, "note", "private:alice"),
            (PRIVATE_BOB, "note", "private:bob"),
        ] {
            create_record(
                &db,
                &crate::mcp::Caller::local(),
                json!({
                    "id":id,
                    "type":if kind == "account" { "Entity" } else { "Document" },
                    "kind":kind,
                    "name":label,
                    "body":label,
                    "reason":"Build the query_sql authorization fixture."
                }),
            )
            .await
            .unwrap();
        }
        let connection = db.connect().unwrap();
        connection
            .execute_batch(&format!(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES
                   ('{OWNER_ALICE}','account','account:alice',1),
                   ('{OWNER_BOB}','account','account:bob',1);
                 UPDATE records SET owner_id='{OWNER_ALICE}', policy_anchor_id='{PRIVATE_ALICE}'
                   WHERE id='{PRIVATE_ALICE}';
                 UPDATE records SET owner_id='{OWNER_BOB}', policy_anchor_id='{PRIVATE_BOB}'
                   WHERE id='{PRIVATE_BOB}';
                 INSERT INTO record_policies(record_id,created_at) VALUES
                   ('{PRIVATE_ALICE}','2026-01-01T00:00:00.000Z'),
                   ('{PRIVATE_BOB}','2026-01-01T00:00:00.000Z');
                 INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES
                   ('{PRIVATE_ALICE}','account','account:alice','allow','view'),
                   ('{PRIVATE_BOB}','account','account:bob','allow','view');",
            ))
            .await
            .unwrap();

        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        register_turso_local_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        // The ids no longer share a readable prefix, so the two private records
        // are named explicitly. `ORDER BY id` is kept: the counters ascend with
        // the slugs they replaced, so Alice still sorts before Bob.
        let query = json!({
            "sql":format!(
                "SELECT id FROM records WHERE id IN ('{PRIVATE_ALICE}','{PRIVATE_BOB}') ORDER BY id"
            ),
            "parameters":[]
        });
        let before = query_sql_source_fingerprint(directory.path());
        let alice = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db.clone()),
                crate::mcp::Caller::authenticated("account:alice"),
                "query_sql",
                query.clone(),
            )
            .await
            .unwrap();
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);
        let before = query_sql_source_fingerprint(directory.path());
        let bob = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db.clone()),
                crate::mcp::Caller::authenticated("account:bob"),
                "query_sql",
                query,
            )
            .await
            .unwrap();
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);
        assert_eq!(alice["rows"], json!([{"id":PRIVATE_ALICE}]));
        assert_eq!(bob["rows"], json!([{"id":PRIVATE_BOB}]));

        let before = query_sql_source_fingerprint(directory.path());
        let unsafe_error = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db.clone()),
                crate::mcp::Caller::authenticated("account:alice"),
                "query_sql",
                json!({"sql":"ATTACH DATABASE ':memory:' AS aux","parameters":[]}),
            )
            .await
            .unwrap_err();
        assert!(
            unsafe_error.to_string().contains("unsafe_statement"),
            "{unsafe_error}"
        );
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);

        let unavailable = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db.clone()),
                crate::mcp::Caller::authenticated("account:alice"),
                "query_sql",
                json!({"sql":"SELECT * FROM effective_relationships","parameters":[]}),
            )
            .await
            .unwrap_err();
        assert!(
            unavailable.to_string().contains("unauthorized_relation"),
            "{unavailable}"
        );

        let heavy = json!({
            "sql":"SELECT sum(length(a.id)+length(b.id)+length(c.id)+length(d.id)+length(e.id)+length(f.id)+length(g.id)+length(h.id)+length(i.id)+length(j.id)) AS total FROM records a CROSS JOIN records b CROSS JOIN records c CROSS JOIN records d CROSS JOIN records e CROSS JOIN records f CROSS JOIN records g CROSS JOIN records h CROSS JOIN records i CROSS JOIN records j",
            "parameters":[]
        });
        let before = query_sql_source_fingerprint(directory.path());
        let timeout = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db.clone()),
                crate::mcp::Caller::authenticated("account:alice"),
                "query_sql",
                heavy.clone(),
            )
            .await
            .unwrap_err();
        assert!(timeout.to_string().contains("timeout"), "{timeout}");
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);

        let before = query_sql_source_fingerprint(directory.path());
        let (worker_probe, mut cancellation_probe) =
            crate::query::turso_sql::CoreWorkerProbe::new();
        let cancelled_db = db.clone();
        let cancelled = tokio::spawn(async move {
            super::query_sql::query_sql_with_worker_probe(
                &cancelled_db,
                &crate::mcp::Caller::authenticated("account:alice"),
                heavy,
                worker_probe,
            )
            .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cancellation_probe.wait_started(),
        )
        .await
        .expect("cancelled query reached its own blocking worker");
        cancelled.abort();
        let _ = cancelled.await;
        let observed_cancellation = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cancellation_probe.wait_stopped(),
        )
        .await
        .expect("caller abort signalled and stopped its blocking worker");
        assert!(
            observed_cancellation,
            "the stopped worker must observe its own caller's cancellation"
        );
        assert_eq!(query_sql_source_fingerprint(directory.path()), before);

        let recovered = registry
            .call_engine(
                crate::mcp::EngineHandle::from(db),
                crate::mcp::Caller::authenticated("account:alice"),
                "query_sql",
                json!({"sql":"SELECT count(*) AS n FROM records","parameters":[]}),
            )
            .await
            .unwrap();
        assert!(recovered["rows"][0]["n"].as_i64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn fresh_turso_genesis_uses_shared_database_identity_authority() {
        let directory = tempfile::tempdir().unwrap();
        // A UUIDv4 constructor cannot produce this token: both its version and
        // variant nibbles are deliberately outside the UUIDv4 fixed pattern.
        let expected = "ndb_ffffffffffffffffffffffffffffffff";
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "database-identity-authority".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open_with_database_id_minter(|| expected.into())
        .await
        .unwrap();

        let connection = db.connect().unwrap();
        let stored = scalar_text(
            &connection,
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        )
        .await
        .unwrap();
        let audited = scalar_text(
            &connection,
            "SELECT new_origin_db_id FROM database_identity_audit WHERE action='mint'",
        )
        .await
        .unwrap();

        assert_eq!(stored, expected);
        assert_eq!(audited, expected);
        assert!(crate::identity::is_database_id(&stored));
    }

    #[tokio::test]
    async fn existing_v2_profile_marker_upgrades_atomically_to_v4_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "profile-v2-to-v4".into(),
            data_directory: directory.path().to_path_buf(),
        };
        let db = config.open().await.unwrap();
        let connection = db.connect().unwrap();
        connection.execute("BEGIN IMMEDIATE", ()).await.unwrap();
        connection
            .execute(
                "ALTER TABLE _native_turso_runtime RENAME TO _native_turso_runtime_v3",
                (),
            )
            .await
            .unwrap();
        connection
            .execute(TURSO_RUNTIME_TOPOLOGY_DDL_V2, ())
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO _native_turso_runtime(singleton,logical_database_id,profile_revision) SELECT singleton,logical_database_id,2 FROM _native_turso_runtime_v3",
                (),
            )
            .await
            .unwrap();
        connection
            .execute("DROP TABLE _native_turso_runtime_v3", ())
            .await
            .unwrap();
        connection.execute("COMMIT", ()).await.unwrap();
        drop(connection);
        drop(db);

        let reopened = config.open().await.unwrap();
        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert_eq!(health.profile_revision, 4);
        let connection = reopened.connect().unwrap();
        assert_eq!(
            scalar_i64(
                &connection,
                "SELECT profile_revision FROM _native_turso_runtime WHERE singleton=1",
            )
            .await
            .unwrap(),
            4
        );
        assert_eq!(
            scalar_text(
                &connection,
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='_native_turso_runtime'",
            )
            .await
            .unwrap(),
            TURSO_RUNTIME_TOPOLOGY_DDL
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2,
            "profile marker upgrade must preserve authoritative content"
        );
        drop(connection);
        drop(reopened);

        let reopened_again = config.open().await.unwrap();
        assert_eq!(reopened_again.health().await.unwrap().profile_revision, 4);
    }

    #[tokio::test]
    async fn existing_v3_profile_marker_upgrades_atomically_to_v4_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "profile-v3-to-v4".into(),
            data_directory: directory.path().to_path_buf(),
        };
        let db = config.open().await.unwrap();
        let connection = db.connect().unwrap();
        connection.execute("BEGIN IMMEDIATE", ()).await.unwrap();
        connection
            .execute(
                "ALTER TABLE _native_turso_runtime RENAME TO _native_turso_runtime_v4",
                (),
            )
            .await
            .unwrap();
        connection
            .execute(TURSO_RUNTIME_TOPOLOGY_DDL_V3, ())
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO _native_turso_runtime(singleton,logical_database_id,profile_revision) SELECT singleton,logical_database_id,3 FROM _native_turso_runtime_v4",
                (),
            )
            .await
            .unwrap();
        connection
            .execute("DROP TABLE _native_turso_runtime_v4", ())
            .await
            .unwrap();
        connection.execute("COMMIT", ()).await.unwrap();
        drop(connection);
        drop(db);

        let reopened = config.open().await.unwrap();
        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert_eq!(health.profile_revision, 4);
        let connection = reopened.connect().unwrap();
        assert_eq!(
            scalar_i64(
                &connection,
                "SELECT profile_revision FROM _native_turso_runtime WHERE singleton=1",
            )
            .await
            .unwrap(),
            4
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2,
            "profile marker upgrade must preserve authoritative content"
        );
    }

    #[tokio::test]
    async fn turso_record_id_admission_is_atomic_and_preserves_genesis() {
        // The one id this test expects Turso to admit. Hardcoded, canonical,
        // lowercase, version nibble 4 and variant nibble 8: change any of those
        // and the admission rule rejects it, which is the point of the
        // accept/reject pair below.
        const ACCEPTED: &str = "70250001-0000-4000-8000-000000000201";

        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "record-id-admission".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let mut connection = db.connect().unwrap();
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            scalar_i64(
                &connection,
                "SELECT COUNT(*) FROM records WHERE id IN ('native:root','native:unfiled')",
            )
            .await
            .unwrap(),
            2
        );

        let invalid = create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "id":"turso/slash", "type":"Document", "kind":"note",
                "reason":"Reject a malformed Turso record id."
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            invalid.to_string(),
            "record id must contain 1..=128 ASCII bytes using only [A-Za-z0-9._:-]"
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
                .await
                .unwrap(),
            2
        );

        let raw = append_specs(
            &mut connection,
            Arc::new(AtomicUsize::new(0)),
            &ExecutionControl::default(),
            vec![AppendSpec {
                record_id: "raw/slash".into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document", "kind":"note",
                    "home_id":crate::schema::UNFILED_RECORD_ID,
                    "persistence":"enduring"
                }),
                actor: Some("test:record-id".into()),
            }],
        )
        .await
        .unwrap_err();
        assert_eq!(
            raw.to_string(),
            "record id must contain 1..=128 ASCII bytes using only [A-Za-z0-9._:-]"
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
                .await
                .unwrap(),
            2
        );

        // The 128-byte boundary used to be the widest accepted id. It still
        // satisfies the shape gate, so it is rejected by the UUID rule instead
        // and the two errors stay distinguishable. Kept in lockstep with
        // tests/governance/record_id_validation.rs and the Postgres contract.
        let boundary = "t".repeat(128);
        let boundary_error = create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "id":boundary, "type":"Document", "kind":"note",
                "reason":"Reject the former Turso record id boundary."
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            boundary_error.to_string(),
            "record id must be a canonical lowercase UUID of version 4 or 7"
        );
        // A readable slug is shape-valid too, and is turned away by the same
        // rule rather than the shape gate.
        let slug_error = create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "id":"turso-readable-slug", "type":"Document", "kind":"note",
                "reason":"Reject a readable but non-UUID Turso record id."
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            slug_error.to_string(),
            "record id must be a canonical lowercase UUID of version 4 or 7"
        );
        // Neither rejection may leave a partial write behind.
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM records")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
                .await
                .unwrap(),
            2
        );

        let created = create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "id":ACCEPTED, "type":"Document", "kind":"note",
                "reason":"Accept a canonical Turso record id."
            }),
        )
        .await
        .unwrap();
        assert_eq!(created["id"], ACCEPTED);
        let before_retry_events = scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
            .await
            .unwrap();
        assert!(create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "id":ACCEPTED, "type":"Document", "kind":"note",
                "reason":"Retry the same explicit Turso record id."
            }),
        )
        .await
        .is_err());
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM content_events")
                .await
                .unwrap(),
            before_retry_events
        );

        let generated = create_record(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "type":"Document", "kind":"note",
                "reason":"Verify generated Turso record id shape."
            }),
        )
        .await
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let uuid = uuid::Uuid::parse_str(&generated).unwrap();
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        assert_eq!(uuid.hyphenated().to_string(), generated);
    }

    async fn canonical_turso_file() -> (tempfile::TempDir, turso::Database, turso::Connection) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("canonical-turso.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        db.close().await;

        // The file is produced by the canonical schema/bootstrap/migration
        // owner. This transform applies only the two physical differences
        // already pinned by `turso_profile_probe`; no domain table is invented.
        let sqlite = rusqlite::Connection::open(&path).unwrap();
        sqlite
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TRIGGER records_fts_ai;
                 DROP TRIGGER records_fts_ad;
                 DROP TRIGGER records_fts_au;
                 DROP TRIGGER records_name_idx_ai;
                 DROP TRIGGER records_name_idx_ad;
                 DROP TRIGGER records_name_idx_au;
                 DROP TABLE records_fts;
                 DROP TABLE records_name_idx;
                 DROP INDEX idx_facet_values_key;
                 DROP INDEX idx_facet_values_num;
                 ALTER TABLE facet_values RENAME TO facet_values_sqlite_generated;
                 CREATE TABLE facet_values (
                   id TEXT PRIMARY KEY,
                   record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                   key TEXT NOT NULL,
                   value TEXT,
                   value_num REAL,
                   vocab_ref TEXT,
                   created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                   UNIQUE (record_id, key)
                 );
                 INSERT INTO facet_values(id,record_id,key,value,value_num,vocab_ref,created_at)
                   SELECT id,record_id,key,value,value_num,vocab_ref,created_at
                     FROM facet_values_sqlite_generated;
                 DROP TABLE facet_values_sqlite_generated;
                 CREATE INDEX idx_facet_values_key ON facet_values(key,value);
                 PRAGMA foreign_keys=ON;",
            )
            .unwrap();
        drop(sqlite);

        let database = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        (directory, database, connection)
    }

    async fn replay_timestamp_scenario(
        connection: &mut turso::Connection,
        events: Vec<EventRow>,
    ) -> Result<Vec<String>> {
        run_write(
            connection,
            Arc::new(AtomicUsize::new(0)),
            &ExecutionControl::default(),
            move |transaction| {
                Box::pin(async move {
                    let reset = statement(
                        StatementKind::Delete,
                        "records",
                        &["DELETE FROM {{relation}} WHERE id = ", " OR id = ", ""],
                    )
                    .map_err(|error| stable("reset timestamp scenario", error))?;
                    transaction
                        .execute(
                            "reset timestamp scenario",
                            &reset,
                            &[
                                BindValue::Text("timestamp:a".into()),
                                BindValue::Text("timestamp:b".into()),
                            ],
                        )
                        .await?;
                    let read = statement(
                        StatementKind::Select,
                        "records",
                        &["SELECT updated_at FROM {{relation}} WHERE id = ", ""],
                    )
                    .map_err(|error| stable("read timestamp scenario", error))?;
                    let mut tokens = Vec::new();
                    for event in events {
                        let intent = ProjectorIntent::from_event(&event)?;
                        let projection_control = transaction.control.clone();
                        transaction
                            .apply_projector(&intent, &event, &projection_control)
                            .await?;
                        if event.record_id == "timestamp:a" {
                            let rows = transaction
                                .rows(
                                    "read timestamp scenario",
                                    &read,
                                    &[BindValue::Text(event.record_id)],
                                    &[ColumnSpec::required("updated_at", LogicalType::Text)],
                                )
                                .await?;
                            tokens.push(text(&rows[0], "updated_at", "timestamp scenario")?);
                        }
                    }
                    Ok(tokens)
                })
            },
        )
        .await
    }

    #[tokio::test]
    async fn actual_turso_executes_shared_append_project_and_snapshot() {
        // Canonical lowercase v4. Its only load-bearing property is that the
        // same id is used for the append and for the snapshot read-back.
        const PORTABLE_RECORD: &str = "70250001-0000-4000-8000-000000000301";

        let (_directory, _database, mut connection) = canonical_turso_file().await;
        let realtime = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        append_specs(
            &mut connection,
            realtime.clone(),
            &ExecutionControl::default(),
            vec![AppendSpec {
                record_id: PORTABLE_RECORD.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "Portable",
                    "body": "same domain fold",
                    "home_id": crate::schema::UNFILED_RECORD_ID,
                    "persistence": "enduring"
                }),
                actor: Some("agent:conformance".into()),
            }],
        )
        .await
        .unwrap();
        let record = record_snapshot(
            &mut connection,
            &ExecutionControl::default(),
            PORTABLE_RECORD,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(record["name"], "Portable");
        assert_eq!(record["body"], "same domain fold");
        assert_eq!(record["policy_anchor_id"], crate::schema::ROOT_RECORD_ID);
        assert_eq!(realtime.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn record_updated_at_is_strictly_monotonic_and_replay_stable_for_all_mutation_routes() {
        let (_directory, _database, mut connection) = canonical_turso_file().await;
        let event =
            |seq: i64, record_id: &str, event_type: &str, payload: Value, created_at: &str| {
                EventRow {
                    local_seq: seq,
                    id: format!("timestamp:event:{seq}"),
                    record_id: record_id.into(),
                    event_type: event_type.into(),
                    payload: Some(payload.to_string()),
                    actor: Some("agent:timestamp".into()),
                    run_key: None,
                    parent_key: None,
                    intent: None,
                    created_at: created_at.into(),
                    causal_envelope: CausalEnvelopeV1::complete(CausalFrontierV1::empty()),
                }
            };
        let same = "2026-08-10T10:00:00.000Z";
        let backdated = "2025-01-01T00:00:00.000Z";
        let events = vec![
            event(
                1,
                "timestamp:a",
                "record.created",
                json!({
                    "type":"Document", "kind":"note", "name":"A",
                    "home_id":crate::schema::UNFILED_RECORD_ID, "persistence":"enduring"
                }),
                same,
            ),
            event(
                2,
                "timestamp:b",
                "record.created",
                json!({
                    "type":"Document", "kind":"note", "name":"B",
                    "home_id":crate::schema::UNFILED_RECORD_ID, "persistence":"enduring"
                }),
                same,
            ),
            event(
                3,
                "timestamp:a",
                "record.updated",
                json!({"body":"same millisecond"}),
                same,
            ),
            event(
                4,
                "timestamp:a",
                "facet.set",
                json!({"key":"lifecycle", "value":"open"}),
                same,
            ),
            event(
                5,
                "timestamp:a",
                "facet.set",
                json!({"key":"priority", "value":"high"}),
                same,
            ),
            event(
                6,
                "timestamp:a",
                "link.added",
                json!({
                    "source_id":"timestamp:a", "target_id":"timestamp:b",
                    "relationship":"part_of"
                }),
                backdated,
            ),
            event(
                7,
                "timestamp:a",
                "facet.unset",
                json!({"key":"priority"}),
                backdated,
            ),
            event(
                8,
                "timestamp:a",
                "facet.unset",
                json!({"key":"lifecycle"}),
                backdated,
            ),
            event(
                9,
                "timestamp:a",
                "link.removed",
                json!({
                    "source_id":"timestamp:a", "target_id":"timestamp:b",
                    "relationship":"part_of"
                }),
                backdated,
            ),
            event(10, "timestamp:a", "record.deleted", json!({}), backdated),
        ];

        let first = replay_timestamp_scenario(&mut connection, events.clone())
            .await
            .unwrap();
        assert!(first.windows(2).all(|pair| {
            DateTime::parse_from_rfc3339(&pair[1]).unwrap()
                > DateTime::parse_from_rfc3339(&pair[0]).unwrap()
        }));
        let replayed = replay_timestamp_scenario(&mut connection, events)
            .await
            .unwrap();
        assert_eq!(replayed, first);
    }

    #[tokio::test]
    async fn sqlite_and_actual_turso_share_the_canonical_domain_scenario() {
        // Canonical lowercase v4s. Counters ascend with the slugs they replaced
        // (`parity:a`, then `parity:b`), which keeps the `ORDER BY id` link
        // projection and the two-record replay read in their original order.
        // Both ids are also embedded in raw SQL below, so those statements are
        // rebuilt from these consts rather than left as stale literals.
        const PARITY_A: &str = "70250001-0000-4000-8000-000000000401";
        const PARITY_B: &str = "70250001-0000-4000-8000-000000000402";

        let sqlite = crate::create_database(":memory:").await.unwrap();
        let (_directory, _database, mut turso) = canonical_turso_file().await;
        let realtime = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let control = ExecutionControl::default();

        let batches = vec![
            vec![
                AppendSpec {
                    record_id: PARITY_A.into(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type":"Document", "kind":"note", "name":"A", "body":"v1",
                        "home_id":crate::schema::UNFILED_RECORD_ID, "persistence":"enduring"
                    }),
                    actor: Some("agent:parity".into()),
                },
                AppendSpec {
                    record_id: PARITY_B.into(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type":"Document", "kind":"note", "name":"B",
                        "home_id":crate::schema::UNFILED_RECORD_ID, "persistence":"enduring"
                    }),
                    actor: Some("agent:parity".into()),
                },
            ],
            vec![
                AppendSpec {
                    record_id: PARITY_A.into(),
                    event_type: "record.updated".into(),
                    payload: json!({"body":"v2", "summary":"updated"}),
                    actor: Some("agent:parity".into()),
                },
                AppendSpec {
                    record_id: PARITY_A.into(),
                    event_type: "facet.set".into(),
                    payload: json!({"key":"review", "value":"needed"}),
                    actor: Some("agent:parity".into()),
                },
                AppendSpec {
                    record_id: PARITY_A.into(),
                    event_type: "link.added".into(),
                    payload: json!({
                        "source_id":PARITY_A, "target_id":PARITY_B,
                        "relationship":"part_of", "note":"same order"
                    }),
                    actor: Some("agent:parity".into()),
                },
            ],
        ];
        for batch in batches {
            let sqlite_batch = batch
                .iter()
                .map(|spec| AppendSpec {
                    record_id: spec.record_id.clone(),
                    event_type: spec.event_type.clone(),
                    payload: spec.payload.clone(),
                    actor: spec.actor.clone(),
                })
                .collect();
            crate::store::append_batch(&sqlite, sqlite_batch)
                .await
                .unwrap();
            append_specs(&mut turso, realtime.clone(), &control, batch)
                .await
                .unwrap();
        }

        let sqlite_record = sqlx::query(&format!(
            "SELECT type,kind,name,body,home_id,policy_anchor_id,persistence,summary,deleted_at
               FROM records WHERE id='{PARITY_A}'"
        ))
        .fetch_one(sqlite.pool())
        .await
        .unwrap();
        use sqlx::Row as _;
        let turso_record = record_snapshot(&mut turso, &control, PARITY_A)
            .await
            .unwrap()
            .unwrap();
        for column in [
            "type",
            "kind",
            "name",
            "body",
            "home_id",
            "policy_anchor_id",
            "persistence",
            "summary",
            "deleted_at",
        ] {
            let sqlite_value: Option<String> = sqlite_record.try_get(column).unwrap();
            assert_eq!(
                turso_record[column],
                sqlite_value.map(Value::String).unwrap_or(Value::Null),
                "projection mismatch at {column}"
            );
        }

        let (turso_history, turso_link, turso_facet, trusted, member, denied) =
            run_snapshot(&mut turso, &control, |transaction| {
                Box::pin(async move {
                    let history = statement(
                        StatementKind::Select,
                        "content_events",
                        &[
                            "SELECT type FROM {{relation}} WHERE record_id = ",
                            " ORDER BY seq",
                        ],
                    )
                    .map_err(|error| stable("read record history", error))?;
                    let types = transaction
                        .rows(
                            "read record history",
                            &history,
                            &[BindValue::Text(PARITY_A.into())],
                            &[ColumnSpec::required("type", LogicalType::Text)],
                        )
                        .await?
                        .iter()
                        .map(|row| text(row, "type", "record history"))
                        .collect::<Result<Vec<_>>>()?;
                    let links = statement(
                        StatementKind::Select,
                        "links",
                        &[
                            "SELECT target_id, relationship FROM {{relation}} WHERE source_id = ",
                            " ORDER BY id",
                        ],
                    )
                    .map_err(|error| stable("list links", error))?;
                    let link = transaction
                        .rows(
                            "list links",
                            &links,
                            &[BindValue::Text(PARITY_A.into())],
                            &[
                                ColumnSpec::required("target_id", LogicalType::Text),
                                ColumnSpec::required("relationship", LogicalType::Text),
                            ],
                        )
                        .await?;
                    let facets = statement(
                        StatementKind::Select,
                        "facet_values",
                        &[
                            "SELECT value FROM {{relation}} WHERE record_id = ",
                            " AND key = ",
                            "",
                        ],
                    )
                    .map_err(|error| stable("read facet", error))?;
                    let facet = transaction
                        .rows(
                            "read facet",
                            &facets,
                            &[
                                BindValue::Text(PARITY_A.into()),
                                BindValue::Text("review".into()),
                            ],
                            &[ColumnSpec::nullable("value", LogicalType::Text)],
                        )
                        .await?;
                    let trusted = crate::authorization::allows_record_with(
                        transaction,
                        crate::authorization::Principal::trusted_local(),
                        PARITY_A,
                        crate::authorization::Capability::Manage,
                    )
                    .await?;
                    let member = crate::authorization::allows_record_with(
                        transaction,
                        crate::authorization::Principal::bound("account:member", true),
                        PARITY_A,
                        crate::authorization::Capability::Edit,
                    )
                    .await?;
                    let denied = crate::authorization::allows_record_with(
                        transaction,
                        crate::authorization::Principal::unbound(false),
                        PARITY_A,
                        crate::authorization::Capability::View,
                    )
                    .await?;
                    Ok((types, link, facet, trusted, member, denied))
                })
            })
            .await
            .unwrap();
        let sqlite_history: Vec<String> =
            sqlx::query_scalar("SELECT type FROM content_events WHERE record_id=? ORDER BY seq")
                .bind(PARITY_A)
                .fetch_all(sqlite.pool())
                .await
                .unwrap();
        assert_eq!(turso_history, sqlite_history);
        assert_eq!(text(&turso_link[0], "target_id", "link").unwrap(), PARITY_B);
        assert_eq!(
            text(&turso_link[0], "relationship", "link").unwrap(),
            "part_of"
        );
        assert_eq!(
            optional_text(&turso_facet[0], "value", "facet")
                .unwrap()
                .as_deref(),
            Some("needed")
        );
        assert!((trusted, member) == (true, true));
        assert!(!denied);

        let terminal_batch = vec![
            AppendSpec {
                record_id: PARITY_A.into(),
                event_type: "facet.unset".into(),
                payload: json!({"key":"review"}),
                actor: Some("agent:parity".into()),
            },
            AppendSpec {
                record_id: PARITY_A.into(),
                event_type: "link.removed".into(),
                payload: json!({
                    "source_id":PARITY_A, "target_id":PARITY_B,
                    "relationship":"part_of"
                }),
                actor: Some("agent:parity".into()),
            },
            AppendSpec {
                record_id: PARITY_A.into(),
                event_type: "record.deleted".into(),
                payload: json!({}),
                actor: Some("agent:parity".into()),
            },
        ];
        crate::store::append_batch(
            &sqlite,
            terminal_batch
                .iter()
                .map(|spec| AppendSpec {
                    record_id: spec.record_id.clone(),
                    event_type: spec.event_type.clone(),
                    payload: spec.payload.clone(),
                    actor: spec.actor.clone(),
                })
                .collect(),
        )
        .await
        .unwrap();
        append_specs(&mut turso, realtime.clone(), &control, terminal_batch)
            .await
            .unwrap();

        let sqlite_terminal: Vec<String> =
            sqlx::query_scalar("SELECT type FROM content_events WHERE record_id=? ORDER BY seq")
                .bind(PARITY_A)
                .fetch_all(sqlite.pool())
                .await
                .unwrap();
        assert_eq!(
            sqlite_terminal,
            [
                "record.created",
                "record.updated",
                "facet.set",
                "link.added",
                "facet.unset",
                "link.removed",
                "record.deleted"
            ]
        );

        let (before_replay, replay_events) = run_snapshot(&mut turso, &control, |transaction| {
            Box::pin(async move {
                let before = transaction
                    .rows(
                        "read terminal record",
                        &statement(
                            StatementKind::Select,
                            "records",
                            &[
                                "SELECT id, type, kind, name, body, home_id, lifecycle, owner_id, claimed_by_account, claimed_run_key, claimed_at, policy_anchor_id, persistence, maturity, summary, created_at, updated_at, deleted_at FROM {{relation}} WHERE id = ",
                                "",
                            ],
                        )
                        .map_err(|error| stable("read terminal record", error))?,
                        &[BindValue::Text(PARITY_A.into())],
                        &[
                            ColumnSpec::required("id", LogicalType::Text),
                            ColumnSpec::required("type", LogicalType::Text),
                            ColumnSpec::nullable("kind", LogicalType::Text),
                            ColumnSpec::required("name", LogicalType::Text),
                            ColumnSpec::nullable("body", LogicalType::Text),
                            ColumnSpec::nullable("home_id", LogicalType::Text),
                            ColumnSpec::nullable("lifecycle", LogicalType::Text),
                            ColumnSpec::nullable("owner_id", LogicalType::Text),
                            ColumnSpec::nullable("claimed_by_account", LogicalType::Text),
                            ColumnSpec::nullable("claimed_run_key", LogicalType::Text),
                            ColumnSpec::nullable("claimed_at", LogicalType::Text),
                            ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
                            ColumnSpec::required("persistence", LogicalType::Text),
                            ColumnSpec::nullable("maturity", LogicalType::Text),
                            ColumnSpec::nullable("summary", LogicalType::Text),
                            ColumnSpec::required("created_at", LogicalType::Text),
                            ColumnSpec::required("updated_at", LogicalType::Text),
                            ColumnSpec::nullable("deleted_at", LogicalType::Text),
                        ],
                    )
                    .await?;
                let events = transaction
                    .rows(
                        "read replay events",
                        &statement(
                            StatementKind::Select,
                            "content_events",
                            &[
                                "SELECT seq, id, record_id, type, payload, actor, run_key, parent_key, intent, created_at FROM {{relation}} WHERE record_id = ",
                                " OR record_id = ",
                                " ORDER BY seq",
                            ],
                        )
                        .map_err(|error| stable("read replay events", error))?,
                        &[
                            BindValue::Text(PARITY_A.into()),
                            BindValue::Text(PARITY_B.into()),
                        ],
                        &[
                            ColumnSpec::required("seq", LogicalType::Integer),
                            ColumnSpec::required("id", LogicalType::Text),
                            ColumnSpec::required("record_id", LogicalType::Text),
                            ColumnSpec::required("type", LogicalType::Text),
                            ColumnSpec::nullable("payload", LogicalType::Text),
                            ColumnSpec::nullable("actor", LogicalType::Text),
                            ColumnSpec::nullable("run_key", LogicalType::Text),
                            ColumnSpec::nullable("parent_key", LogicalType::Text),
                            ColumnSpec::nullable("intent", LogicalType::Text),
                            ColumnSpec::required("created_at", LogicalType::Text),
                        ],
                    )
                    .await?
                    .iter()
                    .map(|row| {
                        Ok(EventRow {
                            local_seq: integer(row, "seq", "replay event")?,
                            id: text(row, "id", "replay event")?,
                            record_id: text(row, "record_id", "replay event")?,
                            event_type: text(row, "type", "replay event")?,
                            payload: optional_text(row, "payload", "replay event")?,
                            actor: optional_text(row, "actor", "replay event")?,
                            run_key: optional_text(row, "run_key", "replay event")?,
                            parent_key: optional_text(row, "parent_key", "replay event")?,
                            intent: optional_text(row, "intent", "replay event")?,
                            created_at: text(row, "created_at", "replay event")?,
                            causal_envelope: CausalEnvelopeV1::complete(
                                CausalFrontierV1::empty(),
                            ),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok((normalized_record(&before[0])?, events))
            })
        })
        .await
        .unwrap();

        run_write(&mut turso, realtime.clone(), &control, move |transaction| {
            Box::pin(async move {
                let reset = statement(
                    StatementKind::Delete,
                    "records",
                    &["DELETE FROM {{relation}} WHERE id = ", " OR id = ", ""],
                )
                .map_err(|error| stable("reset replay projection", error))?;
                transaction
                    .execute(
                        "reset replay projection",
                        &reset,
                        &[
                            BindValue::Text(PARITY_A.into()),
                            BindValue::Text(PARITY_B.into()),
                        ],
                    )
                    .await?;
                let projection_control = transaction.control.clone();
                for event in replay_events {
                    let intent = ProjectorIntent::from_event(&event)?;
                    transaction
                        .apply_projector(&intent, &event, &projection_control)
                        .await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();
        let after_replay = record_snapshot(&mut turso, &control, PARITY_A)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_replay, before_replay);
        assert_eq!(
            sqlite_terminal,
            run_snapshot(&mut turso, &control, |transaction| {
                Box::pin(async move {
                    transaction
                        .rows(
                            "read replayed history",
                            &statement(
                                StatementKind::Select,
                                "content_events",
                                &[
                                    "SELECT type FROM {{relation}} WHERE record_id = ",
                                    " ORDER BY seq",
                                ],
                            )
                            .map_err(|error| stable("read replayed history", error))?,
                            &[BindValue::Text(PARITY_A.into())],
                            &[ColumnSpec::required("type", LogicalType::Text)],
                        )
                        .await?
                        .iter()
                        .map(|row| text(row, "type", "replayed history"))
                        .collect::<Result<Vec<_>>>()
                })
            })
            .await
            .unwrap()
        );
        assert_eq!(realtime.load(std::sync::atomic::Ordering::SeqCst), 4);
        sqlite.close().await;
    }

    #[tokio::test]
    async fn turso_rolls_back_projection_and_blob_failures_and_poisoned_cancellation() {
        // Canonical lowercase v4s. Counters ascend with the slugs they replaced
        // (`cancelled`, then `rollback:record`). `ROLLBACK_RECORD` must be the
        // same id in the create spec, the link source, and the snapshot probe
        // that proves the whole batch rolled back. The dangling link target and
        // the facet.set record id stay the readable literal `missing`: those
        // are references to a record that must not exist, not ids that reach
        // record creation, and the error message quotes that text verbatim.
        const CANCELLED_RECORD: &str = "70250001-0000-4000-8000-000000000501";
        const ROLLBACK_RECORD: &str = "70250001-0000-4000-8000-000000000502";

        let (_directory, _database, mut connection) = canonical_turso_file().await;
        let realtime = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let result = append_specs(
            &mut connection,
            realtime.clone(),
            &ExecutionControl::default(),
            vec![
                AppendSpec {
                    record_id: ROLLBACK_RECORD.into(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type":"Document", "kind":"note", "name":"rollback",
                        "home_id":crate::schema::UNFILED_RECORD_ID
                    }),
                    actor: None,
                },
                AppendSpec {
                    record_id: ROLLBACK_RECORD.into(),
                    event_type: "link.added".into(),
                    payload: json!({
                        "source_id":ROLLBACK_RECORD, "target_id":"missing",
                        "relationship":"relates_to"
                    }),
                    actor: None,
                },
            ],
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "cannot apply link.added: record missing does not exist"
        );
        assert!(record_snapshot(
            &mut connection,
            &ExecutionControl::default(),
            ROLLBACK_RECORD
        )
        .await
        .unwrap()
        .is_none());

        let blob_result = run_write(
            &mut connection,
            realtime.clone(),
            &ExecutionControl::default(),
            |transaction| {
                Box::pin(async move {
                    transaction
                        .insert_blob(b"orphan", Some("text/plain"), None)
                        .await?;
                    transaction
                        .append_content(AppendSpec {
                            record_id: "missing".into(),
                            event_type: "facet.set".into(),
                            payload: json!({"key":"x", "value":"y"}),
                            actor: None,
                        })
                        .await
                })
            },
        )
        .await;
        assert!(blob_result.is_err());
        let mut rows = connection
            .query("SELECT COUNT(*) FROM blobs", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            0
        );

        let cancelled = ExecutionControl::default();
        cancelled.cancel();
        let error = append_specs(
            &mut connection,
            realtime.clone(),
            &cancelled,
            vec![AppendSpec {
                record_id: CANCELLED_RECORD.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document", "kind":"note", "name":"cancelled",
                    "home_id":crate::schema::UNFILED_RECORD_ID
                }),
                actor: None,
            }],
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "execute Turso domain transaction: storage operation cancelled"
        );
        assert_eq!(realtime.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn turso_attachment_and_request_wrappers_use_the_shared_result_contracts() {
        // Canonical lowercase v4 for the attachment bearer. It is created by the
        // append below and then named as `bearer_id`, so both must stay equal.
        const ATTACHMENT_PARENT: &str = "70250001-0000-4000-8000-000000000601";

        let (_directory, _database, mut connection) = canonical_turso_file().await;
        let realtime = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        append_specs(
            &mut connection,
            realtime.clone(),
            &ExecutionControl::default(),
            vec![AppendSpec {
                record_id: ATTACHMENT_PARENT.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Collection", "kind":"folder", "name":"Attachments",
                    "home_id":crate::schema::ROOT_RECORD_ID, "persistence":"enduring"
                }),
                actor: Some("agent:parity".into()),
            }],
        )
        .await
        .unwrap();
        let created = run_write(
            &mut connection,
            realtime.clone(),
            &ExecutionControl::default(),
            |transaction| {
                Box::pin(crate::domain_transaction::create_attachment(
                    transaction,
                    crate::domain_transaction::AttachmentCreate {
                        tool: "attach_text",
                        bearer_id: ATTACHMENT_PARENT,
                        bytes: b"portable attachment",
                        mime: Some("text/plain"),
                        filename: Some("portable.txt"),
                        name: "portable.txt",
                        lifecycle: None,
                        owner_id: None,
                        persistence: None,
                        maturity: None,
                        extra_facets: Vec::new(),
                        actor: "agent:parity",
                        credential: "local",
                        principal: crate::authorization::Principal::trusted_local(),
                        attachment_id: None,
                        image_insert: None,
                    },
                ))
            },
        )
        .await
        .unwrap();
        let attachment_id = created["attachment_id"].as_str().unwrap().to_string();
        let read_id = attachment_id.clone();
        let read = run_snapshot(
            &mut connection,
            &ExecutionControl::default(),
            move |transaction| {
                Box::pin(async move {
                    crate::domain_transaction::read_attachment(
                        transaction,
                        crate::authorization::Principal::trusted_local(),
                        "read_attachment",
                        &read_id,
                        0,
                        1024,
                        1024,
                    )
                    .await
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(read["content"], "portable attachment");
        assert_eq!(read["content_encoding"], "utf-8");

        let port = TursoRequestLifecycle {
            committed: realtime.clone(),
            ..TursoRequestLifecycle::default()
        };
        let request_committed = realtime.clone();
        let request_control = ExecutionControl::default();
        let outcome = crate::domain_transaction::request::execute_request(
            &port,
            crate::mcp::Caller::local(),
            "portable_request",
            None,
            crate::mcp::interactions::Extractor::Custom(
                crate::mcp::CustomInteractionPolicy::NoRecordInteractions,
            ),
            json!({"run_key":"scout-chair-a748b2"}),
            true,
            None,
            None,
            move |caller, arguments| async move {
                assert_eq!(caller.run_key(), Some("scout-chair-a748b2"));
                assert!(arguments.as_object().unwrap().is_empty());
                append_specs(
                    &mut connection,
                    request_committed,
                    &request_control,
                    vec![AppendSpec {
                        record_id: "c0119117-0000-4000-8000-000000000001".into(),
                        event_type: "record.created".into(),
                        payload: json!({
                            "type":"Document", "kind":"note", "name":"Request commit",
                            "home_id":crate::schema::UNFILED_RECORD_ID,
                            "persistence":"enduring"
                        }),
                        actor: Some("agent:parity".into()),
                    }],
                )
                .await?;
                Ok(crate::mcp::ToolResult::rich(
                    json!({"ok":true}),
                    vec![crate::mcp::TransientEvidence::image(
                        "proof",
                        "image/png",
                        b"pixels",
                    )?],
                ))
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome.run_context["run_key"], "scout-chair-a748b2");
        let result = outcome.outcome.unwrap();
        assert_eq!(result.structured, json!({"ok":true}));
        assert_eq!(result.evidence[0].bytes, b"pixels");
        assert_eq!(port.wakeups.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            *port.events.lock().unwrap(),
            [
                "realtime.enter",
                "strict.enter",
                "strict.exit",
                "realtime.exit",
                "interaction"
            ]
        );
        for operation in ["export", "snapshot", "backup", "restore", "cloud", "sync"] {
            assert_eq!(
                unsupported(operation).to_string(),
                format!("turso-local operation '{operation}' is unsupported by the qualified domain boundary")
            );
        }
    }

    #[tokio::test]
    async fn actual_turso_guarded_writes_have_one_winner_and_one_commit_wakeup() {
        // Canonical lowercase v4. The id text is load-bearing twice over: both
        // racers must name the SAME record for the guard to have anything to
        // conflict over, and the loser's stable error quotes the id, so the
        // expectation is rebuilt from this const rather than hardcoded.
        const RACE_RECORD: &str = "70250001-0000-4000-8000-000000000701";

        let (_directory, database, mut first) = canonical_turso_file().await;
        let mut second = database.connect().unwrap();
        let realtime = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        append_specs(
            &mut first,
            realtime.clone(),
            &ExecutionControl::default(),
            vec![AppendSpec {
                record_id: RACE_RECORD.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document", "kind":"note", "name":"Race", "body":"v1",
                    "home_id":crate::schema::UNFILED_RECORD_ID, "persistence":"enduring"
                }),
                actor: Some("agent:race".into()),
            }],
        )
        .await
        .unwrap();
        realtime.store(0, std::sync::atomic::Ordering::SeqCst);

        let first_realtime = realtime.clone();
        let second_realtime = realtime.clone();
        let first_control = ExecutionControl::default();
        let second_control = ExecutionControl::default();
        let (alpha, beta) = tokio::join!(
            guarded_record_update(
                &mut first,
                first_realtime,
                &first_control,
                RACE_RECORD.into(),
                "v1".into(),
                "alpha".into(),
            ),
            guarded_record_update(
                &mut second,
                second_realtime,
                &second_control,
                RACE_RECORD.into(),
                "v1".into(),
                "beta".into(),
            )
        );
        assert_ne!(alpha.is_ok(), beta.is_ok());
        let stable = alpha
            .as_ref()
            .err()
            .or_else(|| beta.as_ref().err())
            .unwrap()
            .to_string();
        assert!(
            stable == format!("guarded record update conflict for '{RACE_RECORD}'")
                || stable
                    == "execute Turso domain transaction: begin Turso transaction: storage is busy",
            "unexpected guarded-write error: {stable}"
        );
        let record = record_snapshot(&mut first, &ExecutionControl::default(), RACE_RECORD)
            .await
            .unwrap()
            .unwrap();
        assert!(record["body"] == "alpha" || record["body"] == "beta");
        assert_eq!(realtime.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn runtime_fixed_profile_and_realtime_completion_are_request_scoped() {
        use crate::domain_transaction::request::{
            GovernedRequestOperation, RequestLifecyclePort, RequestStageCapability,
        };

        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "wrapper-proof".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let lifecycle = TursoRuntimeRequestLifecycle::new(db.clone());
        assert_eq!(
            lifecycle.capability(GovernedRequestOperation::StrictPortability),
            RequestStageCapability::Applied
        );
        assert_eq!(
            lifecycle.capability(GovernedRequestOperation::RealtimeWakeup),
            RequestStageCapability::Applied
        );
        assert_eq!(
            lifecycle.capability(GovernedRequestOperation::TransientEvidence),
            RequestStageCapability::Applied
        );

        let admitted = lifecycle
            .with_operation_admission(
                "query_sql",
                Some("native.raw-sql"),
                Box::pin(async { Ok(crate::mcp::ToolResult::from(json!({"ok":true}))) }),
            )
            .await
            .unwrap();
        assert_eq!(admitted.structured, json!({"ok":true}));

        let mut tailer = db.subscribe_realtime();
        let release = Arc::new(tokio::sync::Notify::new());
        let passive_release = release.clone();
        let passive = lifecycle.with_realtime_completion(Box::pin(async move {
            passive_release.notified().await;
            Ok(crate::mcp::ToolResult::from(json!({"passive":true})))
        }));
        let writer = lifecycle.with_realtime_completion(Box::pin(async move {
            assert!(mark_turso_request_commit());
            release.notify_one();
            Ok(crate::mcp::ToolResult::from(json!({"writer":true})))
        }));
        let (passive, writer) = tokio::join!(passive, writer);
        passive.unwrap();
        writer.unwrap();
        assert_eq!(tailer.next().await.unwrap().generation, 1);
        assert_eq!(tailer.try_next().unwrap(), None);
    }

    #[tokio::test]
    async fn multi_update_record_is_atomic_idempotent_and_input_correlated() {
        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "multi-update-record".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let caller = crate::mcp::Caller::local();
        let folder = "17000000-0000-4000-8000-000000000001";
        let first = "17000000-0000-4000-8000-000000000002";
        let second = "17000000-0000-4000-8000-000000000003";
        create_record(
            &db,
            &caller,
            json!({
                "id": folder,
                "type": "Collection",
                "kind": "folder",
                "name": "Destination",
                "reason": "Create the multi-update destination."
            }),
        )
        .await
        .unwrap();
        for (id, name) in [(first, "First"), (second, "Second")] {
            create_record(
                &db,
                &caller,
                json!({
                    "id": id,
                    "type": "WorkItem",
                    "kind": "task",
                    "name": name,
                    "maturity": "draft",
                    "facets": { "triage": "untriaged" },
                    "reason": "Create a multi-update target."
                }),
            )
            .await
            .unwrap();
        }

        let patch = json!({
            "ids": [second, first],
            "facets": { "triage": "completed" },
            "maturity": "active",
            "home_id": folder,
            "if_facets": { "triage": "untriaged" },
            "if_maturity": "draft",
            "if_home_id": crate::schema::UNFILED_RECORD_ID,
            "reason": "Reconcile the exact cohort."
        });
        let receipt = update_record(&db, &caller, patch).await.unwrap();
        assert_eq!(receipt["requested"], 2);
        assert_eq!(receipt["changed"], 2);
        assert_eq!(receipt["unchanged"], 0);
        assert_eq!(receipt["results"][0]["id"], second);
        assert_eq!(receipt["results"][1]["id"], first);

        let retry = update_record(
            &db,
            &caller,
            json!({
                "ids": [second, first],
                "facets": { "triage": "completed" },
                "maturity": "active",
                "home_id": folder,
                "reason": "Retry the accepted reconciliation."
            }),
        )
        .await
        .unwrap();
        assert_eq!(retry["changed"], 0);
        assert_eq!(retry["unchanged"], 2);

        update_record(
            &db,
            &caller,
            json!({
                "id": first,
                "maturity": "review",
                "reason": "Make one cohort precondition stale."
            }),
        )
        .await
        .unwrap();
        let rejected = update_record(
            &db,
            &caller,
            json!({
                "ids": [second, first],
                "maturity": "done",
                "if_maturity": "active",
                "reason": "This cohort must reject atomically."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(rejected.contains("nothing was written"));
        assert!(rejected.contains("\"conflicted\":1"));

        let records = get_record(&db, &caller, json!({ "ids": [second, first] }))
            .await
            .unwrap();
        assert_eq!(records["records"][0]["maturity"], "active");
        assert_eq!(records["records"][1]["maturity"], "review");
        for record in records["records"].as_array().unwrap() {
            assert_eq!(record["home_id"], folder);
            assert!(record["facets"].as_array().is_some_and(|facets| {
                facets
                    .iter()
                    .any(|facet| facet["key"] == "triage" && facet["value"] == "completed")
            }));
        }
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn record_type_correction_prepares_truthfully_and_rolls_back_or_rejects_stale_state() {
        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "record-type-correction-parity".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let caller = crate::mcp::Caller::local();
        let id = "17fec000-0000-4000-8000-000000000001";
        create_record(
            &db,
            &caller,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": "Misfiled verdict",
                "body": "The bearer stays the same.",
                "reason": "Install the correction parity fixture."
            }),
        )
        .await
        .unwrap();
        let request = json!({
            "record_id": id,
            "target_type": "Resolution",
            "target_kind": "decision",
            "reason": "Correct the registry-proven wrong spine type."
        });
        let prepared = prepare_correct_record_type(&db, &caller, request.clone())
            .await
            .unwrap();
        assert_eq!(prepared.effect["eligibility"], "confirmation_required");
        assert!(
            correct_record_type(&db, &caller, prepared.canonical_source_arguments.clone())
                .await
                .unwrap_err()
                .to_string()
                .contains("claimed records_write.correct_record_type plan")
        );

        let mut execution_arguments = prepared.canonical_source_arguments.clone();
        execution_arguments["plan_id"] = json!("wpl1:turso-rollback");
        execution_arguments["effect_digest"] = json!("a".repeat(64));
        let execution_caller =
            caller
                .clone()
                .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                    plan_id: "wpl1:turso-rollback".into(),
                    effect_digest: "a".repeat(64),
                    executor: "records_write".into(),
                    operation: "correct_record_type".into(),
                });
        db.inner
            .contract_faults
            .write
            .arm("correct_record_type", TursoContractFaultMode::Fail);
        assert!(
            correct_record_type(&db, &execution_caller, execution_arguments)
                .await
                .unwrap_err()
                .to_string()
                .contains("forced correct_record_type failure")
        );
        let unchanged = get_record(&db, &caller, json!({"ids":[id]})).await.unwrap();
        assert_eq!(unchanged["records"][0]["type"], "Document");

        update_record(
            &db,
            &caller,
            json!({"id":id,"summary":"concurrent change","reason":"Make the prepared correction stale."}),
        )
        .await
        .unwrap();
        let mut stale_arguments = prepared.canonical_source_arguments;
        stale_arguments["plan_id"] = json!("wpl1:turso-stale");
        stale_arguments["effect_digest"] = json!("b".repeat(64));
        let stale_caller =
            caller.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "wpl1:turso-stale".into(),
                effect_digest: "b".repeat(64),
                executor: "records_write".into(),
                operation: "correct_record_type".into(),
            });
        assert!(correct_record_type(&db, &stale_caller, stale_arguments)
            .await
            .unwrap_err()
            .to_string()
            .contains("revision conflict"));
    }

    #[tokio::test]
    async fn turso_advances_the_authorization_epoch_only_for_authorization_changes() {
        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "authorization-epoch-narrowing".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let caller = crate::mcp::Caller::local();
        let id = "47000000-0000-4000-8000-000000000047";

        let connection = db.connect().unwrap();
        assert!(required_runtime_schema_ready(&connection).await.unwrap());
        create_record(
            &db,
            &caller,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": "Epoch probe",
                "body": "first",
                "reason": "Install the epoch-narrowing fixture."
            }),
        )
        .await
        .unwrap();

        let epoch = |connection: turso::Connection| async move {
            scalar_i64(
                &connection,
                "SELECT epoch FROM authorization_revision WHERE id = 1",
            )
            .await
            .unwrap()
        };
        let quiet = epoch(db.connect().unwrap()).await;
        let first_digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"first"));
        for edit in [
            json!({"id":id,"name":"Epoch probe, renamed","reason":"Rename only."}),
            json!({
                "id":id,"body":"second","if_body_digest":first_digest,
                "reason":"Rewrite the body only."
            }),
            json!({"id":id,"summary":"a summary","reason":"Summarize only."}),
        ] {
            update_record(&db, &caller, edit.clone()).await.unwrap();
            assert_eq!(
                epoch(db.connect().unwrap()).await,
                quiet,
                "{edit} advanced the Turso-local authorization epoch"
            );
        }

        delete_record(
            &db,
            &caller,
            json!({"id":id,"reason":"Prove a real authorization change still moves the fence."}),
        )
        .await
        .unwrap();
        assert!(epoch(db.connect().unwrap()).await > quiet);
    }

    #[tokio::test]
    async fn turso_migrates_engine_46_trigger_definitions_to_current() {
        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "engine-46-epoch-migration".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let connection = db.connect().unwrap();
        connection
            .execute("PRAGMA user_version=46", ())
            .await
            .unwrap();
        // `install_schema` built this database at the current shape. An actual
        // engine-46 database has neither the engine-49 canvas tables nor the
        // engine-50 webhook tables, and the additive rungs refuse to recreate
        // existing tables. Drop them so the test exercises the real path.
        for statement in [
            "DROP TABLE webhook_deliveries",
            "DROP TABLE webhook_credentials",
            "DROP TABLE webhook_endpoints",
            "DROP TABLE canvas_batches",
            "DROP TABLE canvas_objects",
        ] {
            connection.execute(statement, ()).await.unwrap();
        }

        migrate_existing_engine_schema(&connection).await.unwrap();
        assert_eq!(
            scalar_i64(&connection, "PRAGMA user_version")
                .await
                .unwrap(),
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        );
        assert!(required_runtime_schema_ready(&connection).await.unwrap());
    }

    #[tokio::test]
    async fn an_engine_48_database_reopens_and_migrates_rather_than_being_refused() {
        // The migration rung accepts 45..=49, but reopening goes through
        // `preflight_existing_runtime` first. When that gate listed versions
        // individually it stopped naming 48 the moment CURRENT moved to 49, so
        // every database written by the previous release refused to open and
        // never reached the rung. Drive the real open path, not the rung.
        let directory = tempfile::tempdir().unwrap();
        let config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "engine-48-reopen".into(),
            data_directory: directory.path().to_path_buf(),
        };
        let db = config.open().await.unwrap();
        let connection = db.connect().unwrap();
        // Stand the file back down to engine 48's additive-table shape.
        for statement in [
            "DROP TABLE webhook_deliveries",
            "DROP TABLE webhook_credentials",
            "DROP TABLE webhook_endpoints",
            "DROP TABLE canvas_batches",
            "DROP TABLE canvas_objects",
        ] {
            connection.execute(statement, ()).await.unwrap();
        }
        connection
            .execute("PRAGMA user_version=48", ())
            .await
            .unwrap();
        drop(connection);
        drop(db);

        let reopened = config.open().await.unwrap();
        let connection = reopened.connect().unwrap();
        assert_eq!(
            scalar_i64(&connection, "PRAGMA user_version")
                .await
                .unwrap(),
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        );
        assert!(required_runtime_schema_ready(&connection).await.unwrap());
    }

    #[tokio::test]
    async fn turso_refuses_the_sqlite_qualified_dogfood_repair_cohort() {
        let directory = tempfile::tempdir().unwrap();
        let db = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            logical_database_id: "engine-47-dogfood-repair-refusal".into(),
            data_directory: directory.path().to_path_buf(),
        }
        .open()
        .await
        .unwrap();
        let connection = db.connect().unwrap();
        let reviewed_id = crate::migrations::dogfood_message_origin_repair_ids()
            .next()
            .unwrap();
        connection
            .execute(
                "INSERT INTO records(id,type,kind,name,body,policy_anchor_id)
                 VALUES (?,'Message','text','Reviewed dogfood id',
                         'Must migrate through SQLite.',?)",
                (reviewed_id, reviewed_id),
            )
            .await
            .unwrap();
        connection
            .execute("PRAGMA user_version=47", ())
            .await
            .unwrap();

        let error = migrate_existing_engine_schema(&connection)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("migrate this database through the reference SQLite engine"));
        assert_eq!(
            scalar_i64(&connection, "PRAGMA user_version")
                .await
                .unwrap(),
            47
        );
    }
}
