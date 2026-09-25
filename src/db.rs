//! Open a native-ce database and stand the frozen schema up.
//!
//! The handle is a connection *pool* (the sqlx analogue of the libSQL client,
//! which also used more than one connection under the hood). Both PRAGMAs are
//! connection-level state in SQLite, not schema state, so they are applied per
//! connection by the pool's connect options rather than living in the DDL.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error as StdError;
use std::ffi::c_void;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::Digest;
use sqlx::error::{DatabaseError, ErrorKind};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};
use tempfile::TempDir;

use crate::embed::EmbedderRef;
use crate::error::{Error, Result};
use crate::schema::DDL_STATEMENTS;
use crate::write_contention::WriteDomain;

const ROLLUP_CACHE_MAX_ENTRIES: usize = 128;
const ROLLUP_CACHE_MAX_BYTES: usize = 1024 * 1024;
const INBOX_SNAPSHOT_MAX_ENTRIES: usize = 128;
const INBOX_SNAPSHOT_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug)]
struct InboxSnapshotCacheEntry {
    expires_at: Instant,
    value: serde_json::Value,
}
// SQLite's documented default `SQLITE_MAX_LENGTH`. `query_sql` temporarily
// lowers the per-connection runtime limit and restores the observed value;
// pool release uses this as the cancellation/unwind backstop.
const SQLITE_DEFAULT_VALUE_LIMIT: i32 = 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RollupCacheKey {
    pub principal: String,
    pub trusted_local_bypass: bool,
    /// Live catalog membership footing. Member- and guest-footed evaluations
    /// of the same credential must never share a cache entry: a demotion
    /// does not bump `authorization_revision` (catalog roles are
    /// host-supplied, not portable inputs), so without this bit a guest
    /// would be served the member-era aggregate.
    pub is_member: bool,
    pub spec_digest: String,
    pub bearer_id: String,
    pub rollup_name: String,
    pub content_event_seq: i64,
    pub meta_event_seq: i64,
    pub authorization_revision: i64,
}

#[derive(Debug)]
struct RollupCacheEntry {
    key: RollupCacheKey,
    value: serde_json::Value,
    bytes: usize,
}

#[derive(Debug, Default)]
struct RollupCache {
    entries: VecDeque<RollupCacheEntry>,
    bytes: usize,
}

impl RollupCache {
    fn get(&mut self, key: &RollupCacheKey) -> Option<serde_json::Value> {
        let index = self.entries.iter().position(|entry| &entry.key == key)?;
        let entry = self.entries.remove(index)?;
        let value = entry.value.clone();
        self.entries.push_back(entry);
        Some(value)
    }

    fn insert(&mut self, key: RollupCacheKey, value: serde_json::Value) {
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            if let Some(replaced) = self.entries.remove(index) {
                self.bytes = self.bytes.saturating_sub(replaced.bytes);
            }
        }
        let bytes = key.principal.len()
            + key.spec_digest.len()
            + key.bearer_id.len()
            + key.rollup_name.len()
            + serde_json::to_vec(&value).map_or(0, |encoded| encoded.len());
        if bytes > ROLLUP_CACHE_MAX_BYTES {
            return;
        }
        self.entries
            .push_back(RollupCacheEntry { key, value, bytes });
        self.bytes += bytes;
        while self.entries.len() > ROLLUP_CACHE_MAX_ENTRIES || self.bytes > ROLLUP_CACHE_MAX_BYTES {
            if let Some(evicted) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(evicted.bytes);
            }
        }
    }
}

/// Engine schema stored in each ejectable user database's file header.
/// This is independent of the product's SemVer and the catalog schema.
pub const CURRENT_ENGINE_SCHEMA_VERSION: i64 = 65;
/// The deliberately selected historical support baseline, once one exists.
///
/// `None` is a product contract, not an implementation gap: development
/// schema numbers are disposable until a release decision freezes a baseline.
/// Adding a migration edge or landing a schema on `main` must not change this
/// value implicitly.
///
/// `Some(39)` is that release decision. Engine 39 is the protocol's first
/// engine baseline (`FIRST_ENGINE_BASELINE`), so once engine 40 landed, this
/// could no longer stay `None`: leaving it would have meant `engine_minimum`
/// falling back to the *current* version, claiming 40 as the oldest engine
/// schema the protocol supports and silently dropping every v39 database.
/// Every version named here must be reachable by contiguous edges in
/// [`crate::migrations::EngineMigrationRegistry::production`], which
/// `EngineMigrationRegistry::new` enforces.
pub const SUPPORTED_ENGINE_SCHEMA_BASELINE: Option<i64> = Some(39);

/// Shape-contract digest measured from the released engine-39 tree at
/// `30350c0e` (the parent of the engine-40 schema change). Unlike the current
/// DDL fingerprint this historical authority never changes with later DDL.
const ENGINE_39_SHAPE_CONTRACT_SHA256: &str =
    "3970006e1e92b8870f86506ba490f4ff8274a798a2df88e4700f12c135d6c1a7";

/// Shape-contract digest measured from the released engine-40 tree at
/// `b0450363` (the parent of the engine-41 schema change), by building the
/// then-current DDL and hashing its shape contract. Like engine 39's, this
/// historical authority never changes with later DDL.
const ENGINE_40_SHAPE_CONTRACT_SHA256: &str =
    "0a7633e7ada382b5fa94fd64b660767c0a845a1822aa826fadece83b51465901";

/// Shape-contract digest measured from the engine-41 tree at `1cd90165`
/// (the parent of the engine-42 schema change), by building the then-current
/// DDL and hashing its shape contract.
const ENGINE_41_SHAPE_CONTRACT_SHA256: &str =
    "232a0c88446200a569f1f0ccb77ae7543de772f2504b617110d7564da1e5b9c8";

/// Shape-contract digest measured from the engine-42 tree at `f7b481b2`
/// (the parent of the engine-43 schema change), by building the then-current
/// DDL and hashing its shape contract:
///
/// ```text
/// # in a checkout of f7b481b2, apply DDL_STATEMENTS to a fresh in-memory
/// # database and evaluate schema_shape_contract_sha256(schema_shape_contract(&mut conn))
/// ```
///
/// `migrations::tests::engine_42_to_43_migration_moves_a_released_42_shape`
/// then holds it honest without a checkout, by reconstructing the same shape
/// from current and requiring this digest to admit it.
const ENGINE_42_SHAPE_CONTRACT_SHA256: &str =
    "483295c84d66a0dc79f5c58fc5db76c1eb3144477c928725af5e2735204f85ae";

/// Shape-contract digest measured from the released engine-43 tree immediately
/// before the explicit Message-origin projection landed.
const ENGINE_43_SHAPE_CONTRACT_SHA256: &str =
    "f73b730628cf1540a760e6260e9752e740e29d008c25facf859fe14979baa12e";

/// Shape-contract digest measured from the released engine-44 tree immediately
/// before durable intentful-run lifecycle state landed.
pub(crate) const ENGINE_44_SHAPE_CONTRACT_SHA256: &str =
    "82a93db8a924a6f6210b8f4bb3e1c523b4a4bc9d85fd6c664c4d0803c7c603bc";

/// Shape-contract digest measured from the released engine-45 tree at
/// `b144c6bf` immediately before versioned content-event causality landed.
/// The value was independently re-derived from that untouched predecessor and
/// cross-checked by reconstructing its engine-44 shape against the pinned
/// engine-44 digest above.
pub(crate) const ENGINE_45_SHAPE_CONTRACT_SHA256: &str =
    "e8dddd5ad595f9c20119d5f5013620ec4741918ce97976e1cfa428321f73a4d1";

/// Shape-contract digest measured from the released engine-46 tree at
/// `87b9b460` immediately before the authorization-epoch triggers gained
/// value-change guards.
pub(crate) const ENGINE_46_SHAPE_CONTRACT_SHA256: &str =
    "969f5ed9a2f486d6caffbeb6e1894f33e3c4578a8afa0cdc3379632a6c666d07";

/// Shape-contract digest measured from the released engine-47 tree at
/// `42cd62f3` immediately before the reviewed dogfood Message-origin repair.
pub(crate) const ENGINE_47_SHAPE_CONTRACT_SHA256: &str =
    "93a0e5773f322a7877bda20019ec4d3779e8e1f841be917d0fabbec824c9366d";

/// Shape-contract digest measured from the released engine-48 tree at
/// `1483c1ad` immediately before the Native Canvas projection tables landed.
/// Engine 48 changed product data only, so this is by construction the same
/// structural digest as engine 47; the 48 → 49 migration test asserts that
/// equality rather than assuming it.
pub(crate) const ENGINE_48_SHAPE_CONTRACT_SHA256: &str =
    "93a0e5773f322a7877bda20019ec4d3779e8e1f841be917d0fabbec824c9366d";

/// Shape-contract digest measured from the released engine-49 tree at
/// `1801dbda`, immediately before inbound webhook storage landed.
pub(crate) const ENGINE_49_SHAPE_CONTRACT_SHA256: &str =
    "d4dab728487fbc8af38c427731f9e30e11ff4d9a49c9ac14b51298c6717c07b1";

/// Shape-contract digest measured from the released engine-50 tree immediately
/// before read-log result annotations landed.
pub(crate) const ENGINE_50_SHAPE_CONTRACT_SHA256: &str =
    "a46f0f66a78d99d53551ba8776ecfc7636f7a71aad011d000198e1011e19aed9";

/// Shape-contract digest of the engine-51 tree immediately before the
/// `read_log_touches` WITHOUT ROWID rebuild. Measured by
/// `docs/evidence/readlog-without-rowid/derive_pins.py`, whose DDL extraction
/// and shape-contract serialization are held to the frozen DDL fingerprint and
/// the engine-50 digest above as known-answer checks;
/// `migrations::tests::engine_51_to_52_rebuilds_read_log_touches_without_rowid`
/// then holds it honest through the real Rust implementation by reconstructing
/// the same shape from current and requiring this digest to admit it.
pub(crate) const ENGINE_51_SHAPE_CONTRACT_SHA256: &str =
    "249f3c96105d2871ac8071c7fd8b0afe9d4ffb27efe8bfa4b0046f3725f2e4e7";

/// Shape-contract digest of the engine-52 tree immediately before the
/// freelist-compaction edge. The 52→53 compaction moves no schema objects, so
/// this is by construction the same structural digest as engine 53; the
/// 52→53 migration test asserts that equality rather than assuming it.
pub(crate) const ENGINE_52_SHAPE_CONTRACT_SHA256: &str =
    "84fbb225d5904d9faa29963aa2ee2e32010c676dcab183d0708741e0be5febce";

/// Released engine-53 shape at c33181fc, before dictionary normalization.
pub(crate) const ENGINE_53_SHAPE_CONTRACT_SHA256: &str =
    "84fbb225d5904d9faa29963aa2ee2e32010c676dcab183d0708741e0be5febce";

/// Engine 54's dictionary shape. Engine 55 compacts pages without changing
/// schema objects; historical validation keeps this measured pin explicit.
pub(crate) const ENGINE_54_SHAPE_CONTRACT_SHA256: &str =
    "ecc7fb3964c4af2ee281aa2bf0f3a898958ab5559660d8f295a47591b7fca96f";

/// Engine 55's shape is byte-identical to engine 54's: the 54→55 edge only
/// vacuums interned read-log dictionary pages and moves no schema objects.
/// Measured from the pre-56 tree (engine-55 DDL) and held honest by the
/// 55→56 migration test, which reconstructs this shape from current.
pub(crate) const ENGINE_55_SHAPE_CONTRACT_SHA256: &str =
    "ecc7fb3964c4af2ee281aa2bf0f3a898958ab5559660d8f295a47591b7fca96f";

/// Engine 56's shape, measured from the pre-57 tree (engine-56 DDL) before
/// the content-event append-only triggers landed. Held honest by the 56→57
/// migration test, which reconstructs this shape from current by dropping
/// exactly those two triggers.
pub(crate) const ENGINE_56_SHAPE_CONTRACT_SHA256: &str =
    "4eca539d36e8cff93dc26df5bf39820a2d432c5eb8679111d1af2b9e4e71f311";

/// Engine 57's shape, measured from the pre-58 tree (engine-57 DDL) before
/// the `agent_runs` reported-identity columns landed. Held honest by the
/// 57→58 migration test, which reconstructs this shape from current by
/// dropping exactly those three columns.
pub(crate) const ENGINE_57_SHAPE_CONTRACT_SHA256: &str =
    "535cc09d6a3d13c835c6d7288e0e7231811d50baa7b9677ae440c1f2740b5a9e";

/// Engine 58's shape from current main before the act-delta-specific edges.
pub(crate) const ENGINE_58_SHAPE_CONTRACT_SHA256: &str =
    "20fb571ac2147221b2649790472b611896459cfae938613e06751dfe9c575503";

/// Engine 59's shape after main's record-mentions projection.
pub(crate) const ENGINE_59_SHAPE_CONTRACT_SHA256: &str =
    "2c82766059d70f706df1716508cdb070dd3877f3a39d6d0c8913ce648dcf1bbc";

/// Engine 60's shape after provenance-validity act stamping.
pub(crate) const ENGINE_60_SHAPE_CONTRACT_SHA256: &str =
    "e9e661f0c23ea380d3627e493514d0d9628e5afd479b78ee581b81bd62656b9d";

/// Engine 61's shape after canonical act indexes and binding-system freeze.
pub(crate) const ENGINE_61_SHAPE_CONTRACT_SHA256: &str =
    "9a42a495e8ee711711af757d77e6d1ac7b3fe6393a0b27a38fdf4692bba7242a";

/// Engine 62's exact shape from main 324b93a11, before the data-only
/// read-log cleanup. Engine 63 changes rows only, so its shape is identical.
pub(crate) const ENGINE_62_SHAPE_CONTRACT_SHA256: &str =
    "638c15fe61dc9b2bf4f9b995abc141d60cb94dce954bea4e207ffb626ca65257";
pub(crate) const ENGINE_63_SHAPE_CONTRACT_SHA256: &str = ENGINE_62_SHAPE_CONTRACT_SHA256;

/// Engine 64's shape is main64's released shape: the 63→64 edge only
/// compacts the freelist (VACUUM) without changing any schema object, so the
/// contract is identical to engine 63's. Held honest by the 64→65 migration
/// test, which reconstructs this shape from current by dropping exactly the
/// `alpha_tab_installs` projection table and its index.
pub(crate) const ENGINE_64_SHAPE_CONTRACT_SHA256: &str = ENGINE_63_SHAPE_CONTRACT_SHA256;
/// A read-only classification of an on-disk SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum DatabaseVersionState {
    Empty,
    Known(i64),
    UnversionedNonEmpty,
    Future(i64),
    Missing,
    Unreadable(String),
}

/// The SQLite authority granted to an open [`Db`] handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseOpenMode {
    /// Ordinary Native operation: internal query snapshots and domain writes
    /// use a read-write pool while public ad-hoc SQL stays read-only.
    ReadWrite,
    /// Local standby operation: both query tiers are opened by SQLite with
    /// `SQLITE_OPEN_READONLY`; no startup reconciliation is performed.
    StandbyReadOnly,
}

impl std::fmt::Display for DatabaseVersionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty"),
            Self::Known(version) => write!(f, "schema {version}"),
            Self::UnversionedNonEmpty => write!(f, "unversioned non-empty"),
            Self::Future(version) => write!(f, "future schema {version}"),
            Self::Missing => write!(f, "missing"),
            Self::Unreadable(message) => write!(f, "unreadable: {message}"),
        }
    }
}

/// An open native-ce database: a pool of connections to one SQLite file.
///
/// Cheap to clone (all clones share all three pools). `close()` closes all
/// three; if the database was an ephemeral `:memory:` one, its backing temp
/// directory is removed when the last clone drops.
#[derive(Clone, Debug)]
pub struct Db {
    /// Engine-internal pool. Every mutation must enter through `begin_write`;
    /// this handle is never exposed outside the crate.
    write_pool: SqlitePool,
    /// Public observation pool opened by SQLite with `SQLITE_OPEN_READONLY`.
    /// Keeping this physically separate makes raw external SQL useful for
    /// inspection without exposing an alternate mutation path.
    read_pool: SqlitePool,
    /// Governed-SQL pool (Tier 1.2): read-write connections reserved for
    /// `query_sql`'s connection-local TEMP-contract path. Dedicated so
    /// governed reads — which hold their connection through per-row JSON
    /// encoding — no longer occupy write-pool slots, and so rung 1.3 can
    /// retain the TEMP contract here without risking unqualified-name
    /// shadowing on any other pool's borrowers.
    governed_pool: SqlitePool,
    /// Filesystem location backing this pool. Snapshot sources use it only for
    /// scratch placement; caller-supplied tool arguments can never override it.
    /// The opening authority shares this existing allocation so adding standby
    /// does not enlarge the hot `Db` handle or its deeply nested async futures.
    location: Arc<DatabaseLocation>,
    /// Stable identity for this open handle: clones share it, fresh opens get a
    /// new one. Lets callers (and the router tests) assert two connects share
    /// one underlying handle.
    handle_id: uuid::Uuid,
    /// The `embed()` seam (`crate::embed`). `None` in every v1 deployment — the
    /// hook is called on the write path regardless and does nothing. Per
    /// database rather than process-global because the hosted tier runs many
    /// user databases in one process (`hosting::router`).
    embedder: Option<EmbedderRef>,
    /// Disposable successful rollup results for this opened handle. Clones
    /// share it; reopening the same file deliberately starts cold.
    rollup_cache: Arc<Mutex<RollupCache>>,
    /// Per-principal visible-record-id sets keyed on (principal bits,
    /// authorization epoch, unit fence) — Tier 1.4, record `fd6c1f2`. Clones
    /// share it; reopening the same file deliberately starts cold.
    visible_set_cache: Arc<Mutex<crate::visible_set_cache::VisibleSetCache>>,
    /// Bounded, handle-local state behind opaque Inbox snapshot nonces. Exact
    /// Message ids and pinned item projections never travel in client tokens.
    inbox_snapshots: Arc<Mutex<HashMap<String, InboxSnapshotCacheEntry>>>,
    /// Optional hosted realtime publisher. Standalone handles leave this unset;
    /// routed handles and active subscribers share one database-scoped hub.
    realtime_hub: Option<Arc<crate::realtime::RealtimeHub>>,
    /// Per-handle workspace index (M1, epic 6b1f3c2): records-minus-body,
    /// facet_values, links, and a bounded content window. Clones share it;
    /// reopening starts cold and dropping the handle evicts it with the
    /// 64-handle LRU. Built on the read-only pool on first request, folded
    /// off the commit wake; never a write-pool slot, never a TTL.
    workspace_index: Arc<tokio::sync::RwLock<Option<crate::workspace_index::WorkspaceIndex>>>,
    /// At-most-one in-flight commit-wake fold for the index above.
    workspace_index_fold: Arc<AtomicBool>,
    /// Bounded over-cap refusal marker (M4): the fences of the rejected
    /// snapshot itself — `(content_seq, relationship_seq,
    /// authorization_epoch)` — never a later live read, so a concurrent
    /// commit that shrank the workspace during the build cannot suppress
    /// the retry that now fits under cap.
    /// While the live fences still equal the marker, `ensure` skips the
    /// rebuild instead of reconstructing — and discarding — the whole index
    /// on every read. Any write moves a fence and re-arms the next attempt
    /// (a delete may have shrunk the workspace back under cap). One triple,
    /// O(1) memory; correctness fallback stays governed throughout.
    workspace_index_refused: Arc<Mutex<Option<(i64, i64, i64)>>>,
    /// M3 pinned snapshot tokens (epic 6b1f3c2): immutable per-principal
    /// public copies of the filtered index, bounded by count, bytes, and TTL.
    /// Clones share it; reopening starts cold. See `crate::workspace_snapshot`.
    pub(crate) workspace_snapshots: Arc<Mutex<crate::workspace_snapshot::SnapshotStore>>,
    /// Serializes strict-portability policy changes against admitted requests
    /// for this shared handle. SQLite remains the durable authority; this lease
    /// closes the in-process admission-to-write race for handlers using any
    /// transaction helper.
    portability_policy_gate: Arc<tokio::sync::RwLock<()>>,
    /// Bounded FIFO queue for response-independent interaction capture.
    /// Clones share it; reopening the same file deliberately starts empty.
    /// One worker preserves enqueue order and holds at most one write-pool
    /// slot, so background writes cannot starve handler writes.
    capture_queue: Arc<crate::mcp::interactions::CaptureQueue>,
    /// Handle-local memo of the immutable `database_identity` singleton.
    /// Successful reads only, never negative: clones share it because the
    /// cell lives behind `Arc`; reopening the same file starts cold.
    /// Offline rekey (`crate::identity::rekey_database_offline`) requires
    /// the caller to drain live handles first; this memo offers no
    /// cross-handle invalidation by design.
    database_id_cache: Arc<tokio::sync::OnceCell<String>>,
    /// Keeps the ephemeral temp dir alive for `:memory:` databases.
    _tmp: Option<Arc<TempDir>>,
}

#[derive(Debug)]
struct DatabaseLocation {
    path: std::path::PathBuf,
    open_mode: DatabaseOpenMode,
}

/// One request-scoped realtime completion marker. Content durability is
/// backend-owned; the request wrapper only defers fan-out until the admitted
/// handler has finished shaping its result. Drop is the cancellation backstop:
/// a commit that completed before its request future was abandoned must still
/// wake the durable tailer.
struct RequestRealtimeCompletion {
    committed: AtomicBool,
    hub: Option<Arc<crate::realtime::RealtimeHub>>,
}

impl RequestRealtimeCompletion {
    fn mark_committed(&self) {
        self.committed.store(true, Ordering::Release);
    }

    fn finish(&self) {
        if self.committed.swap(false, Ordering::AcqRel) {
            if let Some(hub) = self.hub.as_ref() {
                hub.wake();
            }
        }
    }
}

impl Drop for RequestRealtimeCompletion {
    fn drop(&mut self) {
        self.finish();
    }
}

tokio::task_local! {
    static REQUEST_REALTIME_COMPLETION: Arc<RequestRealtimeCompletion>;
}

/// Clears the per-handle workspace-index fold flag when it leaves scope,
/// including on panic or task abort. Without it a fold that panicked mid-run
/// would leave `workspace_index_fold` set forever and silently disable every
/// later fold for the life of the handle.
///
/// The drain loop clears and re-acquires the flag on each pass under the
/// existing clear-then-recheck protocol, so the guard is `armed` for the whole
/// task and only disarmed when the task explicitly hands ownership to another
/// fold task that has already set the flag — it must not clobber that task's
/// ownership on the way out.
struct WorkspaceIndexFoldGuard {
    flag: Arc<AtomicBool>,
    armed: bool,
}

impl WorkspaceIndexFoldGuard {
    fn new(flag: Arc<AtomicBool>) -> Self {
        Self { flag, armed: true }
    }

    fn hand_off(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkspaceIndexFoldGuard {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod workspace_index_fold_guard_tests {
    use super::WorkspaceIndexFoldGuard;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn the_guard_clears_the_flag_on_panic() {
        let flag = Arc::new(AtomicBool::new(true));
        let armed = flag.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = WorkspaceIndexFoldGuard::new(armed);
            panic!("fold panicked");
        }));
        assert!(result.is_err());
        assert!(
            !flag.load(Ordering::SeqCst),
            "a panicked fold must not leave folding disabled for the handle"
        );
    }

    #[test]
    fn a_handed_off_guard_leaves_the_new_owners_flag_set() {
        let flag = Arc::new(AtomicBool::new(true));
        {
            let mut guard = WorkspaceIndexFoldGuard::new(flag.clone());
            // The takeover protocol: another fold task has set the flag and we
            // must not clear it on the way out.
            guard.hand_off();
        }
        assert!(flag.load(Ordering::SeqCst));

        // An armed guard still clears on ordinary drop.
        {
            let _guard = WorkspaceIndexFoldGuard::new(flag.clone());
        }
        assert!(!flag.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod workspace_index_refusal_tests {
    /// The refusal marker suppresses repeat full builds while nothing
    /// changed, and any fence movement re-arms the next attempt. This pins
    /// the keying without needing a 32 MiB over-cap workspace.
    #[tokio::test]
    async fn refusal_marker_tracks_live_fences() {
        let db = super::open_database(":memory:").await.unwrap();
        crate::apply_schema(&db).await.unwrap();
        crate::seed_content_tier(&db).await.unwrap();
        crate::identity::seed_database_identity(&db).await.unwrap();
        assert!(
            !db.workspace_index_refusal_current().await.unwrap(),
            "fresh handle must hold no refusal"
        );
        db.note_workspace_index_refusal(db.live_index_fences().await.unwrap())
            .unwrap();
        assert!(
            db.workspace_index_refusal_current().await.unwrap(),
            "a just-stamped refusal must suppress the rebuild"
        );
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "e5555555-5555-4555-8555-555555555555",
                "type": "Document", "kind": "note", "name": "fence mover",
            }),
        )
        .await
        .unwrap();
        assert!(
            !db.workspace_index_refusal_current().await.unwrap(),
            "a content write must re-arm the build attempt"
        );
        db.close().await;
    }
}

// Handler-body counts of workspace-pool connection acquisitions, for the
// readonly-pool migration. The production request-work counters and the
// test-only migration counters share these acquisition hooks. Both are
// task-local, so concurrent requests keep independent totals; outside a scope
// each hook is a cheap miss.
#[cfg(test)]
tokio::task_local! {
    static WRITE_POOL_ACQUISITIONS: Arc<AtomicU64>;
    static READ_POOL_ACQUISITIONS: Arc<AtomicU64>;
}

// Test-only handoff for the handler-body count. Production dispatch discards
// the count; tests observe it by wrapping `registry.call(...)` in
// the matching acquisition sink and reading it afterwards.
#[cfg(test)]
tokio::task_local! {
    static WRITE_POOL_ACQUISITION_SINK: Arc<AtomicU64>;
    static READ_POOL_ACQUISITION_SINK: Arc<AtomicU64>;
}

/// Run `future` with a fresh write-pool acquisition counter and return its
/// output alongside the number of write-pool acquisitions it performed.
/// This scope is test-only. The pool hooks also feed the separate opt-in
/// production request-work counters.
///
/// Test dispatch (`dispatch_with_request_port`) scopes the handler invocation
/// only — after reference resolution, before capture — so the count is
/// attributable to the handler body specifically. Two reads bracket every
/// request outside that scope on the read-only pool and must never be
/// attributed to the handler: pre-handler `record_ref::resolve_record_ids`
/// takes a read-pool (`db.pool().begin()`) snapshot to expand short
/// references, and `storage_profile::with_operation` loads the admission
/// policy via `load_policy_from_pool(db.pool())` around the whole execution
/// (`domain_transaction::request`, outside the handler scope).
/// Post-handler capture still writes the read envelope through
/// `begin_capture_write` on the write pool from the handle's background
/// capture queue (no pool policy pre-read; enforcement happens inside the
/// write transaction), so it is excluded from the handler count by running
/// off-scope rather than by pool.
///
/// Why the pool hooks: `Db::write_pool()` hands out `&SqlitePool`, and
/// callers acquire implicitly by executing queries against it, so counting
/// calls to `write_pool()` would be a proxy, not a measurement. The hooks
/// are the only seam observing every *`acquire`-path* checkout the pool
/// hands out: sqlx 0.8 fires `before_acquire` for reused idle connections
/// only and `after_connect` for newly established connections only, so both
/// are wired and each increments the same task-local counter. Wiring only
/// one of them would undercount (a false "zero");
/// `new_write_pool_connection_is_counted` pins the fresh-connect half by
/// forcing the connect path (second checkout while the first is still held,
/// so reuse is impossible) and `reused_write_pool_connection_is_counted`
/// pins the reuse half against a pre-warmed idle connection. Deliberately
/// not built on `begin_write`: governed writes go through it, but read
/// transactions use raw `pool.begin()`, so it sees none of the read traffic
/// this instrument exists to measure.
///
/// What it captures: one increment per pooled connection acquisition on the
/// write pool while the scoped future runs — whether the acquisition serves
/// a direct query, `pool.acquire()`, or `pool.begin()`. A transaction or an
/// explicitly acquired connection held across N statements counts once: the
/// unit is pool slots taken, which is the contention metric behind the pool
/// timeouts, not statements run.
///
/// What it misses — each a way to read a false zero, so grep before trusting
/// one:
/// - direct `SqliteConnection::connect` calls (migrations/probes), which
///   never touch the pool at all;
/// - `try_acquire` / `try_begin` / `try_begin_with`: these pop an idle
///   connection directly (`PoolInner::try_acquire`) and skip
///   `check_idle_conn`, so **no hook fires** for a genuine pooled
///   acquisition from either workspace pool. Nothing in the tree calls these
///   on a pool today (verified by grep — the `try_begin` hits are non-pool
///   types), so this is latent; but a handler switching to a pool's
///   `try_begin()` would hold a slot while reporting zero;
/// - work handed to the handle's background capture queue, since the queue
///   worker never runs inside the scoped future. Load-bearing for capture
///   exclusion (`interactions::enqueue_record_call` returns before the
///   queue worker runs), verified
///   by `spawned_write_pool_use_is_not_attributed` and the `quickstart`
///   end-to-end test. Otherwise verified safe today, not an open hole:
///   every `tokio::spawn` under `src/mcp/tools/` and
///   `src/mcp/deployment_read_only.rs` sits inside a `#[tokio::test]` fn
///   (checked per site), and the production `spawn_blocking` uses (mdx
///   parsing, html validation in `artifacts.rs` / `artifact_interactions.rs`)
///   capture only owned data, never a pool;
/// - nested dispatch: an inner `dispatch_with_request_port` scope shadows
///   the outer counter, so a re-entrant handler's acquisitions are invisible
///   to the outer count. That is an undercount risk, not a feature: all
///   re-entrant `registry.call` sites today are in test modules (verified),
///   but a stage-2 composite tool dispatching sub-tools through the registry
///   would trip it.
///
/// Eager-pool note: `open_pool` does NOT start empty. sqlx `connect_with`
/// always runs one `acquire` + `release` (`max(1, min_connections)`), so
/// every handle holds one live idle write-pool connection before any scope
/// exists. That eager connection cannot pollute a later scope — no scope is
/// active when it is established, so the hooks' `try_with` finds nothing
/// and counts nothing. (An earlier version of this comment claimed
/// construction was lazy because `min_connections` is 0; it is not.)
///
/// Production cost outside an opt-in request scope is one failed task-local
/// lookup per acquisition. The test-only compatibility counter adds its own
/// lookup only in test builds.
#[cfg(test)]
pub(crate) async fn with_write_pool_acquisition_counter<F>(future: F) -> (F::Output, u64)
where
    F: std::future::Future,
{
    let counter = Arc::new(AtomicU64::new(0));
    let output = WRITE_POOL_ACQUISITIONS
        .scope(Arc::clone(&counter), future)
        .await;
    (output, counter.load(Ordering::Relaxed))
}

#[cfg(test)]
pub(crate) async fn with_read_pool_acquisition_counter<F>(future: F) -> (F::Output, u64)
where
    F: std::future::Future,
{
    let counter = Arc::new(AtomicU64::new(0));
    let output = READ_POOL_ACQUISITIONS
        .scope(Arc::clone(&counter), future)
        .await;
    (output, counter.load(Ordering::Relaxed))
}

/// Acquisitions so far in the enclosing
/// [`with_write_pool_acquisition_counter`] scope, or 0 outside one.
/// Test-only: the only readers are the instrument's own tests.
#[cfg(test)]
pub(crate) fn write_pool_acquisitions() -> u64 {
    WRITE_POOL_ACQUISITIONS
        .try_with(|counter| counter.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Scope a test sink that receives the handler-body count published by
/// production dispatch. Without a sink the count is discarded.
#[cfg(test)]
pub(crate) async fn with_write_pool_acquisition_sink<F>(
    sink: Arc<AtomicU64>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    WRITE_POOL_ACQUISITION_SINK.scope(sink, future).await
}

#[cfg(test)]
pub(crate) async fn with_read_pool_acquisition_sink<F>(sink: Arc<AtomicU64>, future: F) -> F::Output
where
    F: std::future::Future,
{
    READ_POOL_ACQUISITION_SINK.scope(sink, future).await
}

/// Called by production dispatch with the just-finished handler-body count.
/// Stores into the test sink when one is scoped, otherwise a no-op.
#[cfg(test)]
pub(crate) fn publish_write_pool_acquisitions(count: u64) {
    WRITE_POOL_ACQUISITION_SINK
        .try_with(|sink| {
            sink.store(count, Ordering::Relaxed);
        })
        .ok();
}

#[cfg(test)]
pub(crate) fn publish_read_pool_acquisitions(count: u64) {
    READ_POOL_ACQUISITION_SINK
        .try_with(|sink| {
            sink.store(count, Ordering::Relaxed);
        })
        .ok();
}

fn count_read_pool_reuse(
    _connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<bool, sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_workspace_reader_acquisition();
        #[cfg(test)]
        READ_POOL_ACQUISITIONS
            .try_with(|counter| {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .ok();
        Ok(true)
    })
}

fn count_read_pool_new_connection(
    _connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<(), sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_workspace_reader_acquisition();
        #[cfg(test)]
        READ_POOL_ACQUISITIONS
            .try_with(|counter| {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .ok();
        Ok(())
    })
}

/// One half of the acquisition counter. Runs inline on the acquiring task
/// inside `PoolInner::acquire`, so the task-local scope is visible here.
/// Never fails acquisition: counting must not turn a healthy checkout into
/// an error, so the boolean is unconditionally `true`.
fn count_write_pool_reuse(
    _connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<bool, sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_workspace_writer_acquisition();
        #[cfg(test)]
        WRITE_POOL_ACQUISITIONS
            .try_with(|counter| {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .ok();
        Ok(true)
    })
}

/// The other half: newly established connections never see `before_acquire`,
/// so without this every first-use checkout would be invisible.
fn count_write_pool_new_connection(
    _connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<(), sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_workspace_writer_acquisition();
        #[cfg(test)]
        WRITE_POOL_ACQUISITIONS
            .try_with(|counter| {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .ok();
        Ok(())
    })
}

static CATALOG_TRACE_CONTEXTS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
static ACTIVE_CATALOG_TRACES: AtomicUsize = AtomicUsize::new(0);

fn catalog_trace_contexts() -> &'static Mutex<HashMap<usize, usize>> {
    CATALOG_TRACE_CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe extern "C" fn catalog_trace(
    event: u32,
    context: *mut c_void,
    statement: *mut c_void,
    _detail: *mut c_void,
) -> i32 {
    if event == libsqlite3_sys::SQLITE_TRACE_STMT as u32 {
        // SAFETY: the trace installation transfers one Arc reference to
        // SQLite and release/close removes the callback before reclaiming it.
        unsafe { &*context.cast::<crate::request_work::Counters>() }.record_catalog_statement();
    } else if event == libsqlite3_sys::SQLITE_TRACE_CLOSE as u32 {
        let connection = statement.cast::<libsqlite3_sys::sqlite3>();
        // SQLITE_CLOSE runs under SQLite's connection mutex. Detach first so
        // a failed close cannot invoke this callback twice with freed state.
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(connection, 0, None, std::ptr::null_mut());
        }
        let stored = catalog_trace_contexts()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(connection as usize));
        if stored.is_some() {
            ACTIVE_CATALOG_TRACES.fetch_sub(1, Ordering::Release);
            // SAFETY: installation transferred exactly this Arc reference.
            drop(unsafe { Arc::from_raw(context.cast::<crate::request_work::Counters>()) });
        }
    }
    0
}

async fn attach_catalog_trace(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    let Some(counters) = crate::request_work::current() else {
        return Ok(());
    };
    let mut handle = connection.lock_handle().await?;
    let raw = handle.as_raw_handle().as_ptr();
    let key = raw as usize;
    let context = Arc::into_raw(counters);
    let mut contexts = catalog_trace_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if contexts.contains_key(&key) {
        // This pool owns the one SQLite trace slot, and release must always
        // detach it before a physical connection can be acquired again.
        drop(unsafe { Arc::from_raw(context) });
        return Err(sqlx::Error::Protocol(
            "catalog SQLite trace remained attached across checkout".into(),
        ));
    }
    let status = unsafe {
        libsqlite3_sys::sqlite3_trace_v2(
            raw,
            (libsqlite3_sys::SQLITE_TRACE_STMT | libsqlite3_sys::SQLITE_TRACE_CLOSE) as u32,
            Some(catalog_trace),
            context.cast_mut().cast(),
        )
    };
    if status != libsqlite3_sys::SQLITE_OK {
        drop(unsafe { Arc::from_raw(context) });
        return Err(sqlx::Error::Protocol(format!(
            "catalog SQLite trace install failed: {status}"
        )));
    }
    contexts.insert(key, context as usize);
    ACTIVE_CATALOG_TRACES.fetch_add(1, Ordering::Release);
    Ok(())
}

async fn detach_catalog_trace(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    if ACTIVE_CATALOG_TRACES.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    let mut handle = connection.lock_handle().await?;
    let raw = handle.as_raw_handle().as_ptr();
    let context = catalog_trace_contexts()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&(raw as usize));
    if let Some(context) = context {
        ACTIVE_CATALOG_TRACES.fetch_sub(1, Ordering::Release);
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(raw, 0, None, std::ptr::null_mut());
            drop(Arc::from_raw(
                context as *const crate::request_work::Counters,
            ));
        }
    }
    Ok(())
}

fn attach_catalog_trace_on_reuse(
    connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<bool, sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_catalog_acquisition();
        attach_catalog_trace(connection).await?;
        Ok(true)
    })
}

fn attach_catalog_trace_on_connect(
    connection: &mut SqliteConnection,
    _metadata: sqlx::pool::PoolConnectionMetadata,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = std::result::Result<(), sqlx::Error>> + Send + '_>,
> {
    Box::pin(async move {
        crate::request_work::record_catalog_acquisition();
        attach_catalog_trace(connection).await
    })
}

#[cfg(test)]
mod write_contention_measurement_tests {
    use super::*;
    use crate::write_contention::observed::{observing, section_for};
    use crate::write_contention::WriteDomain;

    /// Contention needs one database, and every connection to `:memory:` gets
    /// a private one — two writers there can never meet. Anything asserting
    /// about the reserved lock has to be file-backed.
    async fn file_backed_database() -> (TempDir, Db) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("contention.db");
        let db = create_database(path.to_str().unwrap()).await.unwrap();
        (directory, db)
    }

    /// Wait for the connection's section to close. The close runs when SQLx
    /// returns the connection to its pool, which is not guaranteed to be this
    /// task, so the sample can land just after `commit()` resolves.
    async fn closed_section(key: usize) -> (WriteDomain, Duration) {
        for _ in 0..200 {
            if let Some(section) = section_for(key) {
                return section;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the critical section for {key:#x} never closed");
    }

    #[tokio::test]
    async fn a_committed_write_records_its_critical_section() {
        let (_directory, db) = file_backed_database().await;
        let (key, observations) = observing(async {
            let mut transaction = begin_write(db.write_pool()).await.unwrap();
            let key = connection_key(&mut transaction).await.unwrap();
            // Returning the connection to the pool is what closes the section,
            // so an open transaction must have no sample yet. If this ever
            // fails, the instrument is timing something shorter than the
            // reserved lock is actually held.
            assert!(
                section_for(key).is_none(),
                "a section was closed while its transaction was still open"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
            transaction.commit().await.unwrap();
            key
        })
        .await;
        assert_eq!(observations.begins.len(), 1);
        assert_eq!(observations.begins[0].domain, WriteDomain::Workspace);
        assert!(!observations.begins[0].failed);
        let (domain, held) = closed_section(key).await;
        assert_eq!(domain, WriteDomain::Workspace);
        assert!(
            held >= Duration::from_millis(30),
            "the measured section is shorter than the lock was demonstrably held: {held:?}"
        );
    }

    /// A rollback returns its connection the same way a commit does. This is
    /// the half a commit-site measurement would miss, and missing it would
    /// bias the distribution towards whatever ordinary commits look like.
    #[tokio::test]
    async fn a_rolled_back_write_records_its_critical_section() {
        let (_directory, db) = file_backed_database().await;
        let mut transaction = begin_write(db.write_pool()).await.unwrap();
        let key = connection_key(&mut transaction).await.unwrap();
        transaction.rollback().await.unwrap();
        closed_section(key).await;
    }

    /// An ordinary query on the write pool takes a pool slot without ever
    /// taking the reserved lock. It must contribute no sample at all: a zero
    /// would drag every percentile down, and read traffic on the write pool is
    /// common enough to swamp the writes this exists to describe.
    #[tokio::test]
    async fn a_non_transactional_write_pool_query_records_nothing() {
        let (_directory, db) = file_backed_database().await;
        let ((), observations) = observing(async {
            sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        })
        .await;
        assert!(observations.begins.is_empty());
    }

    /// The number this whole instrument exists to stop discarding: a writer
    /// that had to queue behind another writer.
    #[tokio::test]
    async fn a_writer_that_queues_is_counted_as_having_retried() {
        let (_directory, db) = file_backed_database().await;
        let holder_pool = db.write_pool().clone();
        let (released, wait_for_release) = tokio::sync::oneshot::channel::<()>();
        let (held, holding) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::spawn(async move {
            let transaction = begin_write(&holder_pool).await.unwrap();
            held.send(()).unwrap();
            // Hold the reserved lock past at least one 20ms retry iteration,
            // then release it so the contender completes rather than
            // exhausting its 15s deadline.
            tokio::time::sleep(Duration::from_millis(80)).await;
            transaction.rollback().await.unwrap();
            released.send(()).unwrap();
        });
        holding.await.unwrap();
        let ((), observations) = observing(async {
            begin_write(db.write_pool())
                .await
                .unwrap()
                .rollback()
                .await
                .unwrap();
        })
        .await;
        wait_for_release.await.unwrap();
        holder.await.unwrap();
        assert_eq!(observations.begins.len(), 1);
        let begin = observations.begins[0];
        // Note what is *not* asserted: a retry. SQLite's own `busy_timeout` is
        // 5s, so a contending `BEGIN IMMEDIATE` blocks inside SQLite and the
        // bounded retry loop above it never iterates until the queue exceeds
        // that. The retry count therefore only counts waits longer than five
        // seconds, and the elapsed wait is the measurement that actually
        // answers how often and how long writers queue.
        assert_eq!(
            begin.retries.busy, 0,
            "a busy retry appeared below the 5s busy timeout, so the instrument's \
             premise about where queueing shows up has changed"
        );
        assert!(
            begin.wait >= Duration::from_millis(60),
            "the queueing time was not retained: {:?}",
            begin.wait
        );
    }

    /// Request-local counters are the operator-facing half, and they must see
    /// the same event. The opt-in scope is what `X-Native-Measure` installs.
    #[tokio::test]
    async fn the_request_scoped_counters_see_the_same_write() {
        let (_directory, db) = file_backed_database().await;
        let work = crate::request_work::RequestWork::new();
        work.scope(async {
            begin_write(db.write_pool())
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
        })
        .await;
        let counts = work.snapshot();
        assert_eq!(counts.write_transactions, 1);
        assert_eq!(counts.write_begin_busy_retried_transactions, 0);
        assert_eq!(counts.write_begin_busy_retries, 0);
        assert_eq!(counts.write_begin_cleanup_retries, 0);
    }

    /// Outside a measured request the counters stay untouched, so an ordinary
    /// request pays a failed task-local lookup and nothing else.
    #[tokio::test]
    async fn an_unmeasured_write_leaves_the_request_counters_alone() {
        let (_directory, db) = file_backed_database().await;
        let work = crate::request_work::RequestWork::new();
        begin_write(db.write_pool())
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(work.snapshot().write_transactions, 0);
    }

    /// The hosted control-plane catalogue is a different database under
    /// different pressure. Mixing it into the workspace distribution would
    /// corrupt the only number the MVCC question turns on.
    #[tokio::test]
    async fn control_plane_writes_are_kept_out_of_the_workspace_distribution() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        let pool = open_pool(path.to_str().unwrap(), true, WritePoolKind::HostCatalog)
            .await
            .unwrap();
        let (key, observations) = observing(async {
            let mut transaction = begin_host_control_plane_sqlite_write(&pool).await.unwrap();
            let key = connection_key(&mut transaction).await.unwrap();
            transaction.commit().await.unwrap();
            key
        })
        .await;
        assert_eq!(observations.begins.len(), 1);
        assert_eq!(observations.begins[0].domain, WriteDomain::HostCatalog);
        assert_eq!(closed_section(key).await.0, WriteDomain::HostCatalog);
    }
}

#[cfg(test)]
mod write_pool_acquisition_tests {
    use super::*;

    /// Fresh-connect half, pinned structurally rather than by timing: check
    /// out one connection and hold it, then assert no idle connection
    /// remains. With the idle queue provably empty the in-scope query MUST
    /// establish a new connection, so its count can only come from
    /// `after_connect`. (The pool holds exactly one connection here — the
    /// eager one `connect_with` always establishes — so one held checkout
    /// drains idle to zero; the `num_idle` precondition makes that
    /// structural instead of assumed. Unwiring `after_connect` drops this to
    /// 0 and fails.)
    #[tokio::test]
    async fn new_write_pool_connection_is_counted() {
        let db = open_database(":memory:").await.unwrap();
        let held = db.write_pool().acquire().await.unwrap();
        assert_eq!(
            db.write_pool().num_idle(),
            0,
            "precondition failed: an idle connection exists, so reuse is possible"
        );
        let (_, count) = with_write_pool_acquisition_counter(async {
            sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        })
        .await;
        assert_eq!(count, 1, "fresh-connect checkout was not counted");
        drop(held);
        db.close().await;
    }

    /// Reuse half, pinned structurally: warm exactly one idle connection
    /// BEFORE the scope (outside it, so the warmup itself is uncounted) and
    /// assert it is idle. The in-scope query must then pop it via
    /// `check_idle_conn` — the pool never opens a second connection while
    /// its idle queue is non-empty — so the count can only come from
    /// `before_acquire`. (Unwiring `before_acquire` drops this to 0 and
    /// fails. A ping failure would also open a fresh connection and count
    /// via the other half, but a failed ping on a just-used local SQLite
    /// connection fails the query loudly rather than silently.)
    #[tokio::test]
    async fn reused_write_pool_connection_is_counted() {
        let db = open_database(":memory:").await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        // The pool returns connections asynchronously on drop (the checkout
        // is handed back by a spawned task), so the warmed connection may
        // not be idle yet. Poll until it lands — bounded, because a missing
        // return would be a pool bug, not a slow machine. Without this wait
        // the in-scope query could itself take the connect path and this
        // test would pin the wrong half.
        tokio::time::timeout(Duration::from_secs(5), async {
            while db.write_pool().num_idle() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("warmed connection never returned to idle");
        let (_, count) = with_write_pool_acquisition_counter(async {
            sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        })
        .await;
        assert_eq!(count, 1, "reused checkout was not counted");
        db.close().await;
    }

    #[tokio::test]
    async fn request_work_counts_reused_and_new_workspace_writer_checkouts() {
        let db = open_database(":memory:").await.unwrap();
        let work = crate::request_work::RequestWork::new();
        work.scope(async {
            sqlx::query("SELECT 1")
                .execute(db.write_pool())
                .await
                .unwrap();
        })
        .await;
        assert_eq!(work.snapshot().workspace_writer_acquisitions, 1);

        tokio::time::timeout(Duration::from_secs(5), async {
            while db.write_pool().num_idle() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("measured connection never returned to idle");
        let held = db.write_pool().acquire().await.unwrap();
        assert_eq!(db.write_pool().num_idle(), 0);
        let fresh = crate::request_work::RequestWork::new();
        fresh
            .scope(async {
                sqlx::query("SELECT 1")
                    .execute(db.write_pool())
                    .await
                    .unwrap();
            })
            .await;
        assert_eq!(fresh.snapshot().workspace_writer_acquisitions, 1);
        drop(held);
        db.close().await;
    }

    #[tokio::test]
    async fn request_work_counts_host_catalog_checkouts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog-acquisitions.db");
        let pool = open_pool(path.to_str().unwrap(), true, WritePoolKind::HostCatalog)
            .await
            .unwrap();
        let work = crate::request_work::RequestWork::new();
        work.scope(async {
            sqlx::query("SELECT 1").execute(&pool).await.unwrap();
        })
        .await;
        let snapshot = work.snapshot();
        assert_eq!(snapshot.catalog_acquisitions, 1);
        assert!(
            snapshot.catalog_statements > 0,
            "the measured checkout did not attach its statement trace"
        );
        pool.close().await;
    }

    /// Read-pool work remains separate from the write-pool count.
    #[tokio::test]
    async fn untouched_write_pool_reports_zero() {
        let db = open_database(":memory:").await.unwrap();
        let (_, count) = with_write_pool_acquisition_counter(async {
            let value = sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(value, 1);
            assert_eq!(
                write_pool_acquisitions(),
                0,
                "read-pool query leaked into the write-pool count"
            );
        })
        .await;
        assert_eq!(count, 0);
        let (_, idle) = with_write_pool_acquisition_counter(async {}).await;
        assert_eq!(idle, 0);
        assert_eq!(write_pool_acquisitions(), 0);
        db.close().await;
    }

    #[tokio::test]
    async fn reused_and_new_read_pool_connections_are_counted() {
        let fresh_db = open_database(":memory:").await.unwrap();
        let held = fresh_db.pool().acquire().await.unwrap();
        assert_eq!(fresh_db.pool().num_idle(), 0);
        let (_, fresh) = with_read_pool_acquisition_counter(async {
            sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(fresh_db.pool())
                .await
                .unwrap();
        })
        .await;
        assert_eq!(fresh, 1, "fresh read-pool checkout was not counted");
        drop(held);
        fresh_db.close().await;

        let reused_db = open_database(":memory:").await.unwrap();
        let (_, reused) = with_read_pool_acquisition_counter(async {
            sqlx::query_scalar::<_, i64>("SELECT 1")
                .fetch_one(reused_db.pool())
                .await
                .unwrap();
        })
        .await;
        assert_eq!(reused, 1, "reused read-pool checkout was not counted");
        reused_db.close().await;
    }

    /// The spawn boundary the capture exclusion relies on: a write-pool query
    /// executed in a `tokio::spawn`ed task — awaited inside the scope — is
    /// not attributed to the scope, because task-locals do not cross spawn
    /// boundaries. Post-handler capture (`interactions::spawn_record_call`)
    /// runs in exactly such a detached task.
    #[tokio::test]
    async fn spawned_write_pool_use_is_not_attributed() {
        let db = open_database(":memory:").await.unwrap();
        let pool = db.write_pool().clone();
        let (_, count) = with_write_pool_acquisition_counter(async {
            let handle = tokio::spawn(async move {
                sqlx::query_scalar::<_, i64>("SELECT 1")
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            });
            assert_eq!(handle.await.unwrap(), 1);
        })
        .await;
        assert_eq!(
            count, 0,
            "spawned write-pool use leaked into the enclosing count"
        );
        db.close().await;
    }
}

/// The SQLite kernel satisfies all four of query's named read capabilities.
/// `snapshot_pool` is the read-your-writes tier (the engine write pool, whose
/// raw use for writes remains crate-private via `write_pool`); `shared_pool`
/// is the physically read-only shared pool.
impl crate::query::lens::ProjectionCapability for Db {
    fn snapshot_pool(&self) -> &SqlitePool {
        &self.write_pool
    }
    fn shared_pool(&self) -> &SqlitePool {
        &self.read_pool
    }
}

impl crate::query::lens::MetaCapability for Db {
    fn snapshot_pool(&self) -> &SqlitePool {
        &self.write_pool
    }
    fn shared_pool(&self) -> &SqlitePool {
        &self.read_pool
    }
}

impl crate::query::lens::BlobCapability for Db {
    fn shared_pool(&self) -> &SqlitePool {
        &self.read_pool
    }
}

impl crate::query::lens::ContentLogCapability for Db {
    fn snapshot_pool(&self) -> &SqlitePool {
        &self.write_pool
    }
}

/// Tri-state outcome of one optimistic M4 point-read attempt, so the caller
/// repairs only what moved: nothing on a hit, a content fold on content lag,
/// a full rebuild on authorization/relationship movement, and neither on an
/// absent index or an unheld record.
enum FacetsRecordAttempt {
    // Boxed: the point-read payload dwarfs the other variants (clippy
    // large_enum_variant); only the hit path allocates it.
    Hit(Box<crate::workspace_index::IndexedFacetsRecord>),
    Absent,
    StaleContent,
    StaleFences,
}

/// Tri-state outcome of one optimistic M4 links point-read attempt. Same
/// repair contract as `FacetsRecordAttempt`, sharing its drivers (ensure,
/// content fold, refusal-aware rebuild, live triple) so the slices cannot
/// thrash over-cap builds against each other. Kept as a sibling enum because
/// the hit payload differs: a touching-link subset, where empty is servable
/// (anchor existence/visibility stays governed at the call site), rather
/// than a single held record.
enum LinksCandidatesAttempt {
    // Boxed for the same dwarfing reason as above.
    Hit(Box<crate::workspace_index::IndexedLinkCandidates>),
    Absent,
    StaleContent,
    StaleFences,
}

/// Only the requested record heads, with the held index's physical fences.
/// A caller must compare these fences inside its read transaction before
/// combining the heads with any live body or enrichment rows.
pub(crate) struct IndexedRecordHeads {
    pub heads: std::collections::HashMap<String, crate::workspace_index::RecordHead>,
    pub fences: (i64, i64, i64),
}

/// A header batch may contain absent ids; those are still a valid indexed
/// hit because the governed reader distinguishes their final status.
enum RecordHeadsAttempt {
    Hit(Box<IndexedRecordHeads>),
    Absent,
    StaleContent,
    StaleFences,
}

impl Db {
    /// The physically read-only pool. A serving path, not only a diagnostic
    /// one: `bootstrap` and `get_structure` read exclusively through it, and
    /// further non-mutating handlers are migrating onto it (c331eb8). In WAL
    /// these connections never wait on the serialised writer, which is the
    /// point — a non-mutating handler on the write pool is pure contention.
    ///
    /// SQLite opens these connections with `SQLITE_OPEN_READONLY`, so mutation
    /// statements and writable transactions fail at the engine boundary. All
    /// supported writes must use Native's domain APIs, where strict portability
    /// admission and mutation-boundary checks are enforced.
    ///
    /// These connections are a different snapshot from the write pool's, so a
    /// read moved here no longer observes writes made in a still-open
    /// transaction earlier in the same request. Establish that no such
    /// dependency exists before moving a read onto this tier.
    pub fn pool(&self) -> &SqlitePool {
        &self.read_pool
    }

    /// The immutable SQLite authority selected when this handle was opened.
    pub fn open_mode(&self) -> DatabaseOpenMode {
        self.location.open_mode
    }

    /// Point-in-time write-pool size and idle count for hosted diagnostics.
    /// These gauges do not identify the acquisition or lock that timed out.
    #[doc(hidden)]
    pub fn write_pool_gauges(&self) -> (u32, usize) {
        (self.write_pool.size(), self.write_pool.num_idle())
    }

    /// Privileged engine pool. Crate-private by design: callers must not gain a
    /// raw route around `begin_write` and strict-portability enforcement.
    pub(crate) fn write_pool(&self) -> &SqlitePool {
        &self.write_pool
    }

    /// Governed-SQL pool serving `query_sql`'s owned path. Crate-private like
    /// `write_pool`: callers must go through `query_sql`, never raw pool
    /// access, so one request's TEMP principal state cannot leak into the
    /// next borrower's visibility computation.
    pub(crate) fn governed_pool(&self) -> &SqlitePool {
        &self.governed_pool
    }

    #[cfg(feature = "postgres-tests")]
    #[doc(hidden)]
    pub fn qualification_write_pool(&self) -> &SqlitePool {
        &self.write_pool
    }

    pub fn path(&self) -> &Path {
        &self.location.path
    }

    /// Identity of this open handle (shared by clones).
    pub fn handle_id(&self) -> uuid::Uuid {
        self.handle_id
    }

    pub(crate) fn portability_policy_gate(&self) -> &tokio::sync::RwLock<()> {
        &self.portability_policy_gate
    }

    /// Handle-local `database_identity` memo cell. Clones share it;
    /// fresh opens get a new empty one (see each constructor).
    pub(crate) fn database_id_cell(&self) -> &tokio::sync::OnceCell<String> {
        &self.database_id_cache
    }

    /// Install the `embed()` seam's implementation on this handle. Returns a
    /// new handle over the same pool — existing clones keep whatever they had,
    /// so this is an opening-time decision, not a runtime switch.
    pub fn with_embedder(mut self, embedder: EmbedderRef) -> Self {
        self.embedder = Some(embedder);
        self
    }

    /// The installed embedder, if any. `None` is the v1 state: the seam fires
    /// and there is nothing on the other end.
    pub fn embedder(&self) -> Option<&EmbedderRef> {
        self.embedder.as_ref()
    }

    pub(crate) fn with_realtime_hub(mut self, hub: Arc<crate::realtime::RealtimeHub>) -> Self {
        self.realtime_hub = Some(hub);
        self
    }

    pub(crate) fn realtime_hub(&self) -> Option<Arc<crate::realtime::RealtimeHub>> {
        self.realtime_hub.clone()
    }

    /// Run one registry handler with realtime completion deferred to the
    /// request boundary. Transactions still commit themselves through the
    /// backend; this scope merely coalesces successful commits and guarantees
    /// the wake occurs after durability, including when the request is later
    /// cancelled.
    pub(crate) async fn with_request_realtime_completion<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future,
    {
        let completion = Arc::new(RequestRealtimeCompletion {
            committed: AtomicBool::new(false),
            hub: self.realtime_hub.clone(),
        });
        let output = REQUEST_REALTIME_COMPLETION
            .scope(Arc::clone(&completion), future)
            .await;
        completion.finish();
        output
    }

    fn complete_realtime_commit(&self) {
        // The index folds off the same commit wake that drives the hub, on
        // the read-only pool only. Unbuilt handles no-op; see the method.
        self.spawn_workspace_index_fold();
        if REQUEST_REALTIME_COMPLETION
            .try_with(|completion| completion.mark_committed())
            .is_err()
        {
            if let Some(hub) = self.realtime_hub.as_ref() {
                hub.wake();
            }
        }
    }

    /// Commit a transaction which appended content events and wake the durable
    /// tailer only after SQLite has made those rows visible. Fan-out is best
    /// effort and can never turn a completed write into a transport failure.
    pub(crate) async fn commit_content(
        &self,
        mut tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    ) -> Result<()> {
        crate::provenance::issue_pending_action_in(&mut tx).await?;
        let committed_attestations =
            crate::provenance::pending_attestations_visible_in(&mut tx).await?;
        tx.commit().await?;
        crate::provenance::confirm_committed_attestations(&committed_attestations);
        self.complete_realtime_commit();
        Ok(())
    }

    /// Backend-owned commit for the canonical transaction lifecycle. Driver
    /// diagnostics are normalized before crossing the shared seam; realtime
    /// completion remains identical to the established content commit path.
    pub(crate) async fn commit_content_for_domain(
        &self,
        mut tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    ) -> crate::portable_sql::SqlResult<()> {
        crate::provenance::issue_pending_action_in(&mut tx)
            .await
            .map_err(|error| crate::portable_sql::SqlError::contract(error.to_string()))?;
        let committed_attestations = crate::provenance::pending_attestations_visible_in(&mut tx)
            .await
            .map_err(|error| crate::portable_sql::SqlError::contract(error.to_string()))?;
        tx.commit().await.map_err(|error| {
            crate::portable_sql::normalize_sqlx_error(
                crate::portable_sql::Backend::Sqlite,
                crate::portable_sql::ExecutionPhase::Commit,
                &error,
            )
        })?;
        crate::provenance::confirm_committed_attestations(&committed_attestations);
        self.complete_realtime_commit();
        Ok(())
    }

    /// Commit a dedicated awareness/candidate transaction, then wake realtime
    /// invalidation after durability. The wake is latency machinery only and
    /// never constitutes presentation, acknowledgement, or delivery.
    pub(crate) async fn commit_awareness(
        &self,
        tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    ) -> Result<()> {
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    /// Commit an authorization-domain transaction, then wake realtime
    /// invalidation after durability. The wake carries no policy detail: it
    /// only prompts connected callers to discard authorization-sensitive
    /// reads and resolve them again against current policy.
    pub(crate) async fn commit_authorization(
        &self,
        tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    ) -> Result<()> {
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    /// Read the workspace's current act number without allocating one: the
    /// act of the most recently committed write transaction, or 0 when no
    /// write has been stamped yet. This is the read side of the act-number
    /// contract (decision 4e152d5): producers stamp, and anything that must
    /// describe or verify whole-write coverage reads here.
    pub async fn current_act(&self) -> Result<i64> {
        let mut conn = self.write_pool.acquire().await?;
        crate::act::current_act(&mut conn).await
    }

    /// Read the recorded act cutover for one canonical domain: the last
    /// replay position whose transaction grouping is permanently unknown.
    /// `None` names no canonical domain.
    pub async fn act_cutover_for(&self, domain: &str) -> Result<Option<i64>> {
        let mut conn = self.write_pool.acquire().await?;
        crate::act::act_cutover_for(&mut conn, domain).await
    }

    pub(crate) fn rollup_cache_get(&self, key: &RollupCacheKey) -> Option<serde_json::Value> {
        self.rollup_cache.lock().ok()?.get(key)
    }

    pub(crate) fn rollup_cache_insert(&self, key: RollupCacheKey, value: serde_json::Value) {
        if let Ok(mut cache) = self.rollup_cache.lock() {
            cache.insert(key, value);
        }
    }

    /// Look up one cached visible-id set. `None` is a miss, never an empty
    /// workspace — the caller evaluates live and may store the answer.
    pub(crate) fn visible_set_cache_get(
        &self,
        key: &crate::visible_set_cache::VisibleSetCacheKey,
    ) -> Option<std::sync::Arc<std::collections::HashSet<String>>> {
        self.visible_set_cache.lock().ok()?.get(key)
    }

    /// Store one evaluated visible-id set. Refusal (oversize) returns
    /// `false`; the caller still serves the live answer it just computed.
    pub(crate) fn visible_set_cache_insert(
        &self,
        key: crate::visible_set_cache::VisibleSetCacheKey,
        ids: std::sync::Arc<std::collections::HashSet<String>>,
    ) -> bool {
        if let Ok(mut cache) = self.visible_set_cache.lock() {
            cache.insert(key, ids)
        } else {
            false
        }
    }

    /// Record a lookup that found no entry, so hit/miss ratios stay honest
    /// across the live-fallback path.
    pub(crate) fn visible_set_cache_record_miss(&self) {
        if let Ok(mut cache) = self.visible_set_cache.lock() {
            cache.record_miss();
        }
    }

    /// (hits, misses) for the handle cache. Measurement only.
    #[cfg(test)]
    pub(crate) fn visible_set_cache_stats(&self) -> (u64, u64) {
        self.visible_set_cache
            .lock()
            .map(|cache| cache.stats())
            .unwrap_or((0, 0))
    }

    /// Build the per-handle workspace index on first request (read-only
    /// pool), or return immediately when already built. The build runs inside
    /// one read transaction, so it is consistent by construction; this then
    /// folds to the current fence, because a commit that landed after the
    /// build snapshot may have fired its wake while this handle had no index
    /// (the wake no-ops then) and would otherwise wait for an unrelated later
    /// commit. Reopening starts cold; dropping the handle evicts the whole
    /// index with the LRU entry. Consumed by the M3 snapshot read and the M4
    /// point reads (`indexed_facets_record`, `indexed_link_candidates`); M1
    /// wires the state and the wake.
    #[allow(dead_code)]
    pub(crate) async fn ensure_workspace_index(&self) -> Result<()> {
        if self.workspace_index.read().await.is_some() {
            return Ok(());
        }
        // Steady over-cap: a current refusal marker skips the rebuild. The
        // full build below reads every record, facet, and link only to
        // discard them again; one triple SELECT replaces that per read.
        if self.workspace_index_refusal_current().await? {
            return Ok(());
        }
        let mut built = crate::workspace_index::build_on(&self.read_pool).await?;
        if !built.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
            // Refuse rather than hold a subset: partially evicting records,
            // facets or links would silently break the equivalence contract.
            // Nothing is stored, so callers stay on the governed path. The
            // marker stamps the REJECTED snapshot's own fences (not a later
            // live read): a concurrent commit that shrank the workspace
            // during the build must not suppress the retry that would now
            // fit under cap.
            self.note_workspace_index_refusal((
                built.cursor_seq,
                built.relationship_seq,
                built.authorization_epoch,
            ))?;
            return Ok(());
        }
        crate::workspace_index::refresh_from(&self.read_pool, &mut built).await?;
        let mut guard = self.workspace_index.write().await;
        if guard.is_none() {
            *guard = Some(built);
        }
        Ok(())
    }

    /// The live index fence triple, one row on the read pool. Shared by the
    /// refusal marker and the M4 point-read gate so both key to the same
    /// fences.
    async fn live_index_fences(&self) -> Result<(i64, i64, i64)> {
        let live: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1)",
        )
        .fetch_one(&self.read_pool)
        .await?;
        Ok(live)
    }

    /// True when a refusal marker is held and the live fences still equal
    /// it: nothing changed, so a rebuild would refuse again. Any fence
    /// movement (including a shrinking delete) re-arms the next attempt.
    async fn workspace_index_refusal_current(&self) -> Result<bool> {
        let marker: Option<(i64, i64, i64)> = *self
            .workspace_index_refused
            .lock()
            .map_err(|_| Error::engine("workspace index refusal lock is unavailable"))?;
        let Some(marked) = marker else {
            return Ok(false);
        };
        Ok(self.live_index_fences().await? == marked)
    }

    /// Stamp a refusal marker: the fences of the rejected snapshot itself.
    /// Stamping a later live read would be wrong — a concurrent commit that
    /// shrank the workspace during the build would suppress, until the next
    /// write, the retry that now fits under cap. Every other refuse site
    /// funnels through here. Synchronous: no fence read, just the store.
    fn note_workspace_index_refusal(&self, refused_fences: (i64, i64, i64)) -> Result<()> {
        *self
            .workspace_index_refused
            .lock()
            .map_err(|_| Error::engine("workspace index refusal lock is unavailable"))? =
            Some(refused_fences);
        Ok(())
    }

    /// Fold committed content events into the handle index (read-only pool).
    /// Builds on first use. Returns events folded. Never a write-pool slot.
    /// Consumed by the M3 snapshot read; M1 wires the state and the wake.
    #[allow(dead_code)]
    pub(crate) async fn refresh_workspace_index(&self) -> Result<usize> {
        self.ensure_workspace_index().await?;
        let mut guard = self.workspace_index.write().await;
        let Some(index) = guard.as_mut() else {
            // No index held: the workspace was refused as over-cap (or the
            // handle has none), so there is nothing to fold. Callers fall
            // back to the governed path.
            return Ok(0);
        };
        let folded = crate::workspace_index::refresh_from(&self.read_pool, index).await?;
        if !index.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
            let refused = (
                index.cursor_seq,
                index.relationship_seq,
                index.authorization_epoch,
            );
            *guard = None;
            drop(guard);
            self.note_workspace_index_refusal(refused)?;
        }
        Ok(folded)
    }

    /// Extract a bounded batch of body-free heads for live `get_record`.
    /// A stable hit uses the read lock only. Content lag gets one fold;
    /// authorization or relationship movement gets one refusal-aware rebuild.
    /// Any failed repair, absent index, or over-cap refusal falls back to the
    /// governed reader rather than implying the requested ids are absent.
    pub(crate) async fn indexed_record_heads_for(
        &self,
        ids: &[String],
    ) -> Option<IndexedRecordHeads> {
        if self.ensure_workspace_index().await.is_err() {
            return None;
        }
        match self.indexed_record_heads_attempt(ids).await.ok()? {
            RecordHeadsAttempt::Hit(hit) => Some(*hit),
            RecordHeadsAttempt::Absent => None,
            RecordHeadsAttempt::StaleContent => {
                self.refresh_workspace_index().await.ok()?;
                match self.indexed_record_heads_attempt(ids).await.ok()? {
                    RecordHeadsAttempt::Hit(hit) => Some(*hit),
                    _ => None,
                }
            }
            RecordHeadsAttempt::StaleFences => {
                self.rebuild_workspace_index().await.ok()?;
                match self.indexed_record_heads_attempt(ids).await.ok()? {
                    RecordHeadsAttempt::Hit(hit) => Some(*hit),
                    _ => None,
                }
            }
        }
    }

    async fn indexed_record_heads_attempt(&self, ids: &[String]) -> Result<RecordHeadsAttempt> {
        let held = {
            let guard = self.workspace_index.read().await;
            let Some(index) = guard.as_ref() else {
                return Ok(RecordHeadsAttempt::Absent);
            };
            let heads = ids
                .iter()
                .filter_map(|id| {
                    index
                        .records
                        .get(id)
                        .cloned()
                        .map(|head| (id.clone(), head))
                })
                .collect();
            IndexedRecordHeads {
                heads,
                fences: (
                    index.cursor_seq,
                    index.relationship_seq,
                    index.authorization_epoch,
                ),
            }
        };
        let live = self.live_index_fences().await?;
        if held.fences != live {
            return Ok(if held.fences.1 != live.1 || held.fences.2 != live.2 {
                RecordHeadsAttempt::StaleFences
            } else {
                RecordHeadsAttempt::StaleContent
            });
        }
        Ok(RecordHeadsAttempt::Hit(Box::new(held)))
    }

    /// Live authorization, relationship, and semantic-unit fences for M3 page validation.
    /// Content may advance under a pin (pages are immutable); fences may not.
    /// One row, read-pool only, no visibility evaluation.
    pub(crate) async fn live_snapshot_fences(&self) -> Result<(i64, i64, i64)> {
        let fences: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT epoch FROM authorization_revision WHERE id = 1), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT COALESCE(MAX(creation_event_seq), 0) FROM semantic_units)",
        )
        .fetch_one(&self.read_pool)
        .await?;
        Ok(fences)
    }

    /// M2 backend seam for one principal's sequence- and epoch-stamped index.
    /// `None` explicitly requests a governed fallback: it never means an empty
    /// workspace. M3 will own the HTTP/MCP projection and fallback response.
    #[allow(dead_code)]
    pub(crate) async fn filtered_workspace_index(
        &self,
        principal: crate::query::QueryPrincipal,
    ) -> Result<Option<crate::workspace_index::FilteredWorkspaceIndex>> {
        // This is the single governed visibility evaluation for the request.
        let visible = crate::query::sql::workspace_visible_set(self, principal).await?;
        self.refresh_workspace_index().await?;
        let stale_fences = self
            .workspace_index
            .read()
            .await
            .as_ref()
            .is_some_and(|index| {
                index.authorization_epoch != visible.authorization_epoch
                    || index.relationship_seq != visible.relationship_seq
            });
        if stale_fences {
            // Content folding cannot repair descendant policy anchors or
            // relationship-owned links. Rebuild the full physical index, then
            // require an exact fence match before intersecting.
            let mut rebuilt = crate::workspace_index::build_on(&self.read_pool).await?;
            if !rebuilt.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
                *self.workspace_index.write().await = None;
                return Ok(None);
            }
            crate::workspace_index::refresh_from(&self.read_pool, &mut rebuilt).await?;
            if !rebuilt.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
                *self.workspace_index.write().await = None;
                return Ok(None);
            }
            *self.workspace_index.write().await = Some(rebuilt);
        }
        // The visibility transaction has ended, so reject any write between
        // its snapshot and the held index. One SELECT gives a coherent current
        // fence tuple. A later commit cannot mutate the read-locked index.
        let live: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1), \
                    (SELECT COALESCE(MAX(creation_event_seq), 0) FROM semantic_units)",
        )
        .fetch_one(&self.read_pool)
        .await?;
        if live
            != (
                visible.content_seq,
                visible.relationship_seq,
                visible.authorization_epoch,
                visible.unit_seq_max,
            )
        {
            return Ok(None);
        }
        let guard = self.workspace_index.read().await;
        let Some(index) = guard.as_ref() else {
            return Ok(None);
        };
        if !index.within_cap(crate::workspace_index::MAX_INDEX_BYTES)
            || index.cursor_seq != visible.content_seq
            || index.authorization_epoch != visible.authorization_epoch
            || index.relationship_seq != visible.relationship_seq
        {
            return Ok(None);
        }
        Ok(Some(
            crate::workspace_index::FilteredWorkspaceIndex::intersect(
                index,
                &visible.ids,
                visible.authorization_epoch,
                visible.relationship_seq,
                visible.unit_seq_max,
            ),
        ))
    }

    /// M4 point read for the `resolve_facets` record path: clone one record's
    /// head plus its facet rows under the read lock, gated on the exact live
    /// fence triple. No `FilteredWorkspaceIndex::intersect`, no full-index
    /// clone, no write-pool slot. `None` is always a governed-fallback signal
    /// — absent/refused index, fence race, or unheld record — never an empty
    /// result. Record-level visibility itself stays governed at the call site
    /// (`can_record_in_pool` on the read pool), exactly as the existing
    /// handler gates with `can_record`.
    pub(crate) async fn indexed_facets_record(
        &self,
        record_id: &str,
    ) -> Result<Option<crate::workspace_index::IndexedFacetsRecord>> {
        // Steady state takes only the read lock: ensure (cold build only),
        // then an optimistic read-lock extraction gated on the exact live
        // fence triple. The write lock is taken only when the held fences are
        // stale — a fold for content lag, a rebuild for authorization or
        // relationship movement (which content folding cannot repair, per the
        // M1 fold boundary) — and never for a hit, so concurrent M4 readers
        // do not serialize behind each other. Anything still mismatched
        // after one repair falls back to governed rather than serving stale.
        self.ensure_workspace_index().await?;
        match self.indexed_facets_record_attempt(record_id).await? {
            FacetsRecordAttempt::Hit(hit) => Ok(Some(*hit)),
            // Absent index (cold-build refused over-cap) or a record the
            // current index does not hold: no fold, no rebuild. A second
            // full build would just refuse again; an unheld record under
            // current fences is for the governed path to distinguish
            // (nonexistent vs hidden), which the index alone cannot.
            FacetsRecordAttempt::Absent => Ok(None),
            FacetsRecordAttempt::StaleContent => {
                self.refresh_workspace_index().await?;
                match self.indexed_facets_record_attempt(record_id).await? {
                    FacetsRecordAttempt::Hit(hit) => Ok(Some(*hit)),
                    _ => Ok(None),
                }
            }
            FacetsRecordAttempt::StaleFences => {
                self.rebuild_workspace_index().await?;
                match self.indexed_facets_record_attempt(record_id).await? {
                    FacetsRecordAttempt::Hit(hit) => Ok(Some(*hit)),
                    _ => Ok(None),
                }
            }
        }
    }
    /// Single optimistic attempt with a tri-state outcome. Read lock plus one
    /// live fence triple only — no write lock, no fold, no rebuild.
    async fn indexed_facets_record_attempt(&self, record_id: &str) -> Result<FacetsRecordAttempt> {
        let held = {
            let guard = self.workspace_index.read().await;
            let Some(index) = guard.as_ref() else {
                // No index held: cold build refused over-cap (or was dropped
                // for the same reason). Never rebuild here — it would just
                // refuse again.
                return Ok(FacetsRecordAttempt::Absent);
            };
            let head = index.records.get(record_id).cloned();
            let mut facets: Vec<crate::workspace_index::FacetRow> = index
                .facets
                .values()
                .filter(|facet| facet.record_id == record_id)
                .cloned()
                .collect();
            // Governed reads `ORDER BY fv.key`; facet keys are unique per
            // record, so the id tiebreak only orders a state the governed
            // path leaves unspecified. The differential oracle pins this.
            facets.sort_by(|a, b| a.key.cmp(&b.key).then(a.id.cmp(&b.id)));
            head.map(|head| {
                (
                    head,
                    facets,
                    index.cursor_seq,
                    index.authorization_epoch,
                    index.relationship_seq,
                )
            })
        };
        let live: (i64, i64, i64) = self.live_index_fences().await?;
        let Some((head, facets, index_content, index_auth, index_rel)) = held else {
            // Fences are current enough to check first would be ideal, but a
            // missing head under a stale cursor is indistinguishable from a
            // missing record without the live triple — which we now have.
            let (live_content, live_rel, live_auth) = live;
            // Re-read held fences cheaply: if any fence moved, repair can
            // still bring this record in, so classify stale, not absent.
            let guard = self.workspace_index.read().await;
            let stale = guard.as_ref().is_some_and(|index| {
                index.cursor_seq != live_content
                    || index.relationship_seq != live_rel
                    || index.authorization_epoch != live_auth
            });
            return Ok(if stale {
                if guard.as_ref().is_some_and(|index| {
                    index.relationship_seq != live_rel || index.authorization_epoch != live_auth
                }) {
                    FacetsRecordAttempt::StaleFences
                } else {
                    FacetsRecordAttempt::StaleContent
                }
            } else {
                FacetsRecordAttempt::Absent
            });
        };
        if (index_content, index_rel, index_auth) != live {
            let (_, live_rel, live_auth) = live;
            // Content folding cannot repair descendant policy anchors or
            // relationship-owned links (M1 fold boundary): those need the
            // full rebuild below, mirroring `filtered_workspace_index`.
            return Ok(if index_rel != live_rel || index_auth != live_auth {
                FacetsRecordAttempt::StaleFences
            } else {
                FacetsRecordAttempt::StaleContent
            });
        }
        Ok(FacetsRecordAttempt::Hit(Box::new(
            crate::workspace_index::IndexedFacetsRecord {
                head,
                facets,
                content_seq: index_content,
                authorization_epoch: index_auth,
                relationship_seq: index_rel,
            },
        )))
    }

    /// Full physical rebuild for authorization/relationship fence movement,
    /// mirroring `filtered_workspace_index`. Content folding alone cannot
    /// repair those tiers; without this, indexed hits would never return
    /// after a narrowing event. Over-cap refusal drops the index and stamps
    /// the marker (so steady over-cap reads skip the rebuild); a successful
    /// install clears it. The caller falls back — never a partial hold.
    async fn rebuild_workspace_index(&self) -> Result<()> {
        let mut rebuilt = crate::workspace_index::build_on(&self.read_pool).await?;
        if !rebuilt.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
            let refused = (
                rebuilt.cursor_seq,
                rebuilt.relationship_seq,
                rebuilt.authorization_epoch,
            );
            *self.workspace_index.write().await = None;
            self.note_workspace_index_refusal(refused)?;
            return Ok(());
        }
        crate::workspace_index::refresh_from(&self.read_pool, &mut rebuilt).await?;
        if !rebuilt.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
            let refused = (
                rebuilt.cursor_seq,
                rebuilt.relationship_seq,
                rebuilt.authorization_epoch,
            );
            *self.workspace_index.write().await = None;
            self.note_workspace_index_refusal(refused)?;
            return Ok(());
        }
        *self.workspace_index.write().await = Some(rebuilt);
        *self
            .workspace_index_refused
            .lock()
            .map_err(|_| Error::engine("workspace index refusal lock is unavailable"))? = None;
        Ok(())
    }

    /// M4 point read for `manage_links.list`: clone one record's touching
    /// links under the read lock, gated on the exact live fence triple. No
    /// full-index clone, no write-pool slot. Same repair policy as
    /// `indexed_facets_record` — one content fold on content lag, one
    /// refusal-aware rebuild on authorization/relationship movement, neither
    /// on an absent index — so steady over-cap reads skip the rebuild via
    /// the shared marker instead of reconstructing and discarding the whole
    /// index on every read. `None` is always a governed-fallback signal,
    /// never an empty link set.
    pub(crate) async fn indexed_link_candidates(
        &self,
        record_id: &str,
    ) -> Result<Option<crate::workspace_index::IndexedLinkCandidates>> {
        // Steady state takes only the read lock: ensure (cold build only,
        // refusal-skipped while fences are current), then an optimistic
        // read-lock extraction gated on the exact live fence triple. The
        // write lock is taken only when the held fences are stale, and never
        // for a hit, so concurrent M4 readers do not serialize behind each
        // other. Anything still mismatched after one repair falls back to
        // governed rather than serving stale.
        self.ensure_workspace_index().await?;
        match self.indexed_link_candidates_attempt(record_id).await? {
            LinksCandidatesAttempt::Hit(hit) => Ok(Some(*hit)),
            // Absent index (cold-build refused over-cap): no fold, no
            // rebuild. A second full build would just refuse again — the
            // marker in `ensure` already covers the steady case.
            LinksCandidatesAttempt::Absent => Ok(None),
            LinksCandidatesAttempt::StaleContent => {
                self.refresh_workspace_index().await?;
                match self.indexed_link_candidates_attempt(record_id).await? {
                    LinksCandidatesAttempt::Hit(hit) => Ok(Some(*hit)),
                    _ => Ok(None),
                }
            }
            LinksCandidatesAttempt::StaleFences => {
                self.rebuild_workspace_index().await?;
                match self.indexed_link_candidates_attempt(record_id).await? {
                    LinksCandidatesAttempt::Hit(hit) => Ok(Some(*hit)),
                    _ => Ok(None),
                }
            }
        }
    }

    /// Single optimistic attempt with a tri-state outcome. Read lock plus one
    /// live fence triple only — no write lock, no fold, no rebuild, no
    /// per-call cap scan (cap discipline is the shared refusal marker, owned
    /// by the build/refresh/rebuild paths). Unlike the facets point read, an
    /// unheld record — zero touching links — is a Hit, not Absent: anchor
    /// existence and visibility stay governed at the call site through the
    /// visible set, which the index alone cannot distinguish.
    async fn indexed_link_candidates_attempt(
        &self,
        record_id: &str,
    ) -> Result<LinksCandidatesAttempt> {
        let held = {
            let guard = self.workspace_index.read().await;
            let Some(index) = guard.as_ref() else {
                // No index held: cold build refused over-cap (or was dropped
                // for the same reason). Never rebuild here — it would just
                // refuse again.
                return Ok(LinksCandidatesAttempt::Absent);
            };
            let links: Vec<crate::workspace_index::LinkRow> = index
                .links
                .values()
                .filter(|link| link.source_id == record_id || link.target_id == record_id)
                .cloned()
                .collect();
            (
                links,
                index.cursor_seq,
                index.authorization_epoch,
                index.relationship_seq,
            )
        };
        let live: (i64, i64, i64) = self.live_index_fences().await?;
        let (links, index_content, index_auth, index_rel) = held;
        if (index_content, index_rel, index_auth) != live {
            let (_, live_rel, live_auth) = live;
            // Content folding cannot repair descendant policy anchors or
            // relationship-owned links (M1 fold boundary): those need the
            // full rebuild above, mirroring `filtered_workspace_index`.
            return Ok(if index_rel != live_rel || index_auth != live_auth {
                LinksCandidatesAttempt::StaleFences
            } else {
                LinksCandidatesAttempt::StaleContent
            });
        }
        Ok(LinksCandidatesAttempt::Hit(Box::new(
            crate::workspace_index::IndexedLinkCandidates {
                links,
                content_seq: index_content,
                authorization_epoch: index_auth,
                relationship_seq: index_rel,
            },
        )))
    }

    /// Borrow the physical index for one live structure walk. The governed
    /// visibility set and all three physical fences must describe the same
    /// committed state. No rows are cloned out of the index on a hit.
    pub(crate) async fn indexed_structure_nodes(
        &self,
        principal: crate::query::QueryPrincipal,
        root_id: &str,
        opts: &crate::query::tree::TreeOptions,
    ) -> Result<Option<(Vec<crate::query::tree::TreeNode>, (i64, i64, i64))>> {
        let Ok(visible) = crate::query::sql::workspace_visible_set(self, principal).await else {
            return Ok(None);
        };
        let expected = (
            visible.content_seq,
            visible.relationship_seq,
            visible.authorization_epoch,
        );
        let held = self.workspace_index.read().await.as_ref().map(|index| {
            (
                index.cursor_seq,
                index.relationship_seq,
                index.authorization_epoch,
            )
        });
        let maintenance = match held {
            None => self.ensure_workspace_index().await.map(|_| ()),
            Some((_, relationship, authorization))
                if (relationship, authorization) != (expected.1, expected.2) =>
            {
                // Content folding cannot repair relationship-owned links or
                // policy anchors. Share the refusal-aware physical rebuild
                // used by the other M4 point reads, once per stale attempt.
                self.rebuild_workspace_index().await.map(|_| ())
            }
            Some((content, relationship, authorization))
                if (relationship, authorization) == (expected.1, expected.2)
                    && content != expected.0 =>
            {
                self.refresh_workspace_index().await.map(|_| ())
            }
            _ => Ok(()),
        };
        if maintenance.is_err() {
            return Ok(None);
        }
        let live: std::result::Result<(i64, i64, i64), _> = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1)",
        )
        .fetch_one(&self.read_pool)
        .await;
        if live.ok() != Some(expected) {
            return Ok(None);
        }
        let guard = self.workspace_index.read().await;
        let Some(index) = guard.as_ref() else {
            return Ok(None);
        };
        if !index.within_cap(crate::workspace_index::MAX_INDEX_BYTES)
            || (
                index.cursor_seq,
                index.relationship_seq,
                index.authorization_epoch,
            ) != expected
        {
            return Ok(None);
        }
        let nodes = crate::query::tree::descendants_from_index(index, &visible.ids, root_id, opts);
        drop(guard);
        // A commit during the in-memory walk would otherwise let the response
        // combine an old tree with later live successor decoration.
        let after: std::result::Result<(i64, i64, i64), _> = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1)",
        )
        .fetch_one(&self.read_pool)
        .await;
        Ok((after.ok() == Some(expected))
            .then_some(nodes)
            .flatten()
            .map(|nodes| (nodes, expected)))
    }

    /// The final live fence after successor decoration, which may perform
    /// separate SQL reads. An index hit is discarded if a commit moved any
    /// tier while those reads were in flight.
    pub(crate) async fn structure_index_fences_match(&self, expected: (i64, i64, i64)) -> bool {
        let live: std::result::Result<(i64, i64, i64), _> = sqlx::query_as(
            "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                    (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                    (SELECT epoch FROM authorization_revision WHERE id = 1)",
        )
        .fetch_one(&self.read_pool)
        .await;
        live.ok() == Some(expected)
    }

    /// Best-effort commit-wake fold: the same wake that drives the realtime
    /// hub. At most one fold task runs per handle; the drain loop re-checks
    /// the fence after clearing so a commit landing mid-fold re-arms rather
    /// than being missed. Errors are logged, never propagated: fan-out must
    /// not turn a completed write into a transport failure.
    fn spawn_workspace_index_fold(&self) {
        let built = self
            .workspace_index
            .try_read()
            .map(|guard| guard.is_some())
            .unwrap_or(true);
        if !built {
            return;
        }
        if self
            .workspace_index_fold
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            self.workspace_index_fold.store(false, Ordering::SeqCst);
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            this.fold_workspace_index_drain().await;
        });
    }

    async fn fold_workspace_index_drain(&self) {
        // Panic/abort backstop: if this task dies mid-fold the guard clears the
        // flag on unwind rather than disabling folding for the handle's life.
        let mut fold_guard = WorkspaceIndexFoldGuard::new(self.workspace_index_fold.clone());
        loop {
            {
                let mut guard = self.workspace_index.write().await;
                if let Some(index) = guard.as_mut() {
                    if let Err(error) =
                        crate::workspace_index::refresh_from(&self.read_pool, index).await
                    {
                        eprintln!("[native-ce] workspace index fold failed: {error}");
                    }
                    if !index.within_cap(crate::workspace_index::MAX_INDEX_BYTES) {
                        // A wake can grow a previously admitted index past
                        // the cap. Refuse the whole index just as a cold build
                        // does; the next request uses the governed fallback.
                        *guard = None;
                    }
                }
            }
            self.workspace_index_fold.store(false, Ordering::SeqCst);
            // Clear-then-recheck: a commit that landed between the last fence
            // read above and the clear re-arms here instead of being missed.
            let fence =
                sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                    .fetch_one(&self.read_pool)
                    .await;
            let guard = self.workspace_index.read().await;
            let Some(index) = guard.as_ref() else {
                return;
            };
            match fence {
                Err(_) => return,
                Ok(fence) if fence <= index.cursor_seq => return,
                Ok(_) => {
                    if self
                        .workspace_index_fold
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_err()
                    {
                        // A fresh fold task took over and owns the flag now, so
                        // leave it set for that task rather than clobbering it.
                        fold_guard.hand_off();
                        return;
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn workspace_index_built_for_tests(&self) -> bool {
        self.workspace_index.read().await.is_some()
    }

    #[cfg(test)]
    pub(crate) async fn workspace_index_snapshot_for_tests(
        &self,
    ) -> Option<crate::workspace_index::WorkspaceIndex> {
        self.workspace_index.read().await.clone()
    }

    /// Test-only oracle lever for the M4 differential test: drop the held
    /// index so the next read takes the governed fallback. Production code
    /// never calls this; over-cap refusal uses the same `None` signal.
    #[cfg(test)]
    pub(crate) async fn clear_workspace_index_for_tests(&self) {
        *self.workspace_index.write().await = None;
    }

    pub(crate) fn put_inbox_snapshot(&self, value: serde_json::Value) -> Result<String> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut snapshots = self
            .inbox_snapshots
            .lock()
            .map_err(|_| Error::engine("Inbox snapshot store is unavailable"))?;
        let now = Instant::now();
        snapshots.retain(|_, entry| entry.expires_at > now);
        if snapshots.len() >= INBOX_SNAPSHOT_MAX_ENTRIES {
            let oldest = snapshots
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                snapshots.remove(&oldest);
            }
        }
        snapshots.insert(
            token.clone(),
            InboxSnapshotCacheEntry {
                expires_at: now + INBOX_SNAPSHOT_TTL,
                value,
            },
        );
        Ok(token)
    }

    pub(crate) fn get_inbox_snapshot(&self, token: &str) -> Result<serde_json::Value> {
        if token.len() != 36 || uuid::Uuid::parse_str(token).is_err() {
            return Err(Error::engine(
                "cursor_reset_required: invalid inbox snapshot",
            ));
        }
        let mut snapshots = self
            .inbox_snapshots
            .lock()
            .map_err(|_| Error::engine("Inbox snapshot store is unavailable"))?;
        let now = Instant::now();
        snapshots.retain(|_, entry| entry.expires_at > now);
        snapshots
            .get(token)
            .map(|entry| entry.value.clone())
            .ok_or_else(|| Error::engine("cursor_reset_required: invalid inbox snapshot"))
    }

    /// Mark all three pools closed before returning a future to their physical
    /// shutdown. This is intentionally synchronous: every clone must refuse a
    /// new public read or internal write as soon as handle lifecycle ends.
    fn mark_pools_closed(&self) {
        drop(self.read_pool.close());
        drop(self.write_pool.close());
        drop(self.governed_pool.close());
    }

    /// Close all three pools, draining response-independent captures first.
    /// Queued captures are awaited (bounded by
    /// [`crate::mcp::interactions::CAPTURE_DRAIN_TIMEOUT`]) before the pools
    /// refuse checkouts, so graceful shutdown keeps captures rather than
    /// failing them on a closed pool. Leftovers past the cap fail on the
    /// closed pool and are counted, never silently lost. Ephemeral backing
    /// files are deleted once every clone of this handle has dropped.
    pub async fn close(&self) {
        self.capture_queue.initiate_shutdown();
        self.capture_queue.drain_capped().await;
        self.mark_pools_closed();
        tokio::join!(
            close_pool_and_drain(&self.read_pool),
            close_pool_and_drain(&self.write_pool),
            close_pool_and_drain(&self.governed_pool)
        );
    }

    /// Monotonic counters for this handle's background capture queue.
    /// Test-only: production observes drops/failures via stderr, and shutdown
    /// via `close`; no serving path reads these counters.
    #[cfg(test)]
    pub(crate) fn capture_stats(&self) -> crate::mcp::interactions::CaptureStats {
        self.capture_queue.stats()
    }

    /// Run one semantic declaration to durability in an owned task and await
    /// it. Bypasses the lossy queue; accounting stays coherent with queued
    /// captures. See `CaptureQueue::record_declaration`.
    pub(crate) async fn record_declaration(
        &self,
        capture: crate::mcp::interactions::PendingCapture,
    ) {
        self.capture_queue.record_declaration(capture).await;
    }

    /// Test-only: refuse all further queue admissions. The synchronous
    /// declaration path bypasses the queue and is unaffected.
    #[cfg(test)]
    pub(crate) fn capture_queue_for_test_initiate_shutdown(&self) {
        self.capture_queue.initiate_shutdown();
    }

    /// Enqueue one prepared interaction capture without blocking. Returns
    /// false (counted and stderr-reported by the queue) when shut down or
    /// full. The response path never awaits the result.
    pub(crate) fn enqueue_capture(
        &self,
        capture: crate::mcp::interactions::PendingCapture,
    ) -> bool {
        self.capture_queue.enqueue(capture)
    }

    /// Wait until every enqueued capture has completed. Unbounded; prefer
    /// [`Self::close`] (which caps the wait) for shutdown paths. Tests use
    /// this to observe captures deterministically.
    pub(crate) async fn drain_captures(&self) {
        self.capture_queue.drain().await;
    }

    /// Test-only drain for integration harnesses outside the crate: wait
    /// until every enqueued capture has completed. Unbounded, like
    /// [`Self::drain_captures`].
    #[doc(hidden)]
    pub async fn drain_captures_for_tests(&self) {
        self.capture_queue.drain().await;
    }

    /// End a shared handle from a synchronous lifecycle boundary such as LRU
    /// eviction. All three pools are marked closed before this function returns;
    /// when a runtime is available it also drains their physical shutdown in
    /// the background.
    ///
    /// Eviction is not graceful shutdown: captures still queued or in flight
    /// fail on the closed pool and are counted as failures (never silently
    /// lost). Use [`Self::close`] where captures must be kept.
    pub(crate) fn close_in_background(&self) {
        self.capture_queue.initiate_shutdown();
        self.mark_pools_closed();
        let read_pool = self.read_pool.clone();
        let write_pool = self.write_pool.clone();
        let governed_pool = self.governed_pool.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                tokio::join!(
                    close_pool_and_drain(&read_pool),
                    close_pool_and_drain(&write_pool),
                    close_pool_and_drain(&governed_pool)
                );
            });
        }
    }
}

// SQLx 0.8.6 can return from Pool::close with a checked-out connection when
// closing idle connections over-credits its semaphore. The pool is fenced at
// that point, but physical drain requires size == 0. Retry close to collect
// connections whose asynchronous return raced with the initial close; sleep
// between retries so held transactions do not cause a busy loop.
async fn close_pool_and_drain(pool: &SqlitePool) {
    loop {
        pool.close().await;
        if pool.size() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Retire a cached hosted-router handle from a synchronous eviction or
/// shutdown boundary. All pools refuse new work before this returns; a live
/// runtime drains their physical shutdown in the background.
#[doc(hidden)]
pub fn close_hosted_router_database_in_background(db: &Db) {
    db.close_in_background();
}

/// Checkpoint every committed hosted-adoption frame into the main database
/// file, then close the handle before that file is hashed or moved.
///
/// SQLite may report a busy or partial checkpoint as a successful pragma row,
/// so both status and frame counts are verified before the handoff succeeds.
/// The database is closed on every outcome.
#[doc(hidden)]
pub async fn checkpoint_and_close_hosted_adoption_database(db: Db) -> Result<()> {
    let checkpoint = async {
        let (busy, log_frames, checkpointed): (i64, i64, i64) =
            sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(db.write_pool())
                .await?;
        validate_hosted_adoption_checkpoint(busy, log_frames, checkpointed)
    }
    .await;
    db.close().await;
    checkpoint
}

fn validate_hosted_adoption_checkpoint(
    busy: i64,
    log_frames: i64,
    checkpointed: i64,
) -> Result<()> {
    if busy != 0 || log_frames != checkpointed {
        return Err(Error::engine(format!(
            "adoption WAL checkpoint incomplete: busy={busy}, log_frames={log_frames}, checkpointed={checkpointed}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod hosted_adoption_checkpoint_tests {
    use super::validate_hosted_adoption_checkpoint;

    #[test]
    fn incomplete_hosted_adoption_checkpoints_fail_closed() {
        validate_hosted_adoption_checkpoint(0, 0, 0).unwrap();
        validate_hosted_adoption_checkpoint(0, 7, 7).unwrap();

        assert_eq!(
            validate_hosted_adoption_checkpoint(1, 7, 7)
                .unwrap_err()
                .to_string(),
            "adoption WAL checkpoint incomplete: busy=1, log_frames=7, checkpointed=7"
        );
        assert_eq!(
            validate_hosted_adoption_checkpoint(0, 7, 6)
                .unwrap_err()
                .to_string(),
            "adoption WAL checkpoint incomplete: busy=0, log_frames=7, checkpointed=6"
        );
    }
}

#[cfg(test)]
mod close_tests {
    use super::*;

    async fn assert_all_pools_closed(db: &Db) {
        assert!(db.pool().is_closed(), "public read pool remained open");
        assert!(
            db.write_pool().is_closed(),
            "internal write pool remained open"
        );
        assert!(
            db.governed_pool().is_closed(),
            "governed SQL pool remained open"
        );
        assert!(sqlx::query("SELECT 1").fetch_one(db.pool()).await.is_err());
        assert!(sqlx::query("SELECT 1")
            .fetch_one(db.write_pool())
            .await
            .is_err());
        assert!(sqlx::query("SELECT 1")
            .fetch_one(db.governed_pool())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn close_invalidates_both_pools_for_every_handle_clone() {
        let db = create_database(":memory:").await.unwrap();
        let clone = db.clone();
        db.close().await;
        assert_all_pools_closed(&clone).await;
    }

    #[tokio::test]
    async fn close_waits_for_checkouts_even_when_other_connections_are_idle() {
        for hold_writer in [false, true] {
            let db = create_database(":memory:").await.unwrap();
            let pool = if hold_writer {
                db.write_pool()
            } else {
                db.pool()
            };
            let held = pool.acquire().await.unwrap();
            let spare = pool.acquire().await.unwrap();
            drop(spare);
            tokio::time::timeout(Duration::from_secs(2), async {
                while pool.num_idle() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("spare connection was not returned");

            let closing_db = db.clone();
            let mut closing = tokio::spawn(async move { closing_db.close().await });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !pool.is_closed() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("close did not fence the pool");
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut closing)
                    .await
                    .is_err(),
                "close completed with a retained connection (writer={hold_writer})"
            );
            drop(held);
            tokio::time::timeout(Duration::from_secs(2), closing)
                .await
                .expect("close did not drain the released connection")
                .unwrap();
            assert_eq!(db.pool().size(), 0);
            assert_eq!(db.write_pool().size(), 0);
        }
    }

    #[tokio::test]
    async fn background_close_invalidates_both_pools_synchronously() {
        let db = create_database(":memory:").await.unwrap();
        let clone = db.clone();
        db.close_in_background();
        assert_all_pools_closed(&clone).await;
    }
}

/// Begin a WRITE transaction (`BEGIN IMMEDIATE`) — the analogue of the libSQL
/// client's `transaction('write')`. A deferred BEGIN that reads before its
/// first write can hit SQLite's deadlock-upgrade `SQLITE_BUSY` (which
/// `busy_timeout` deliberately does not wait out) under a concurrent writer;
/// taking the reserved lock up front serializes writers instead. The bounded
/// retry also covers SQLx's transient invalid-savepoint signal when a canceled
/// transaction's queued rollback is still draining before pooled reuse.
pub(crate) async fn begin_write(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    begin_write_in(pool, WriteDomain::Workspace).await
}

/// [`begin_write`], told which pool it is opening on.
///
/// The domain is a parameter rather than something inferred from the pool
/// because the measurement in [`crate::write_contention`] must not mix the
/// per-workspace writer — the serialisation point whose cost is the open
/// question — with the hosted control-plane catalogue, which is a different
/// database under different pressure. Every ordinary caller reaches this
/// through `begin_write` and is a workspace write; the one control-plane
/// caller declares itself.
async fn begin_write_in(
    pool: &SqlitePool,
    domain: WriteDomain,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    #[cfg(test)]
    BEFORE_BEGIN_WRITE_NOTIFICATION
        .try_with(|notification| notification.notify_one())
        .ok();
    let started_at = Instant::now();
    let begun =
        begin_write_attempts_with(|| pool.begin_with("BEGIN IMMEDIATE"), WRITER_DEADLINE).await;
    let wait = started_at.elapsed();
    let (retries, failed) = match &begun {
        Ok(success) => (success.retries, false),
        Err(failure) => (failure.retries, true),
    };
    // The retry count and the queueing time this loop computes used to be
    // discarded on every ordinary write, which is why nobody could say whether
    // the single-writer rule was under pressure. Retain both before the error
    // path can return.
    crate::write_contention::record_begin(domain, retries, wait, failed);
    crate::request_work::record_write_begin(
        retries,
        u64::try_from(wait.as_micros()).unwrap_or(u64::MAX),
    );
    crate::mcp::request_timing::record_write_wait(wait);
    let mut transaction = begun
        .map(|success| success.transaction)
        .map_err(|failure| failure.error)?;
    // The reserved lock is held from here. The section closes when this
    // connection returns to its pool — the seam that sees commits, rollbacks
    // and drops alike. Not every ending reaches it; `write_contention`'s module
    // doc names the cases that do not and how they are counted.
    if let Some(key) = connection_key(&mut transaction).await {
        crate::write_contention::open_critical_section(domain, key, None);
    }
    if let Err(error) = crate::storage_profile::enforce_write_boundary(&mut transaction).await {
        let _ = transaction.rollback().await;
        return Err(error);
    }
    Ok(transaction)
}

/// The raw SQLite connection pointer, used only as an identity for pairing a
/// `BEGIN IMMEDIATE` with the release of the connection that ran it. The
/// pointer is never dereferenced and never outlives the pairing: the entry is
/// removed when the connection is released.
async fn connection_key(connection: &mut SqliteConnection) -> Option<usize> {
    let mut handle = connection.lock_handle().await.ok()?;
    Some(handle.as_raw_handle().as_ptr() as usize)
}

/// The opened half of a capture-path write: the transaction plus the bounded
/// `BEGIN IMMEDIATE` retry count that [`begin_write`] discards.
pub(crate) struct CaptureBegin {
    pub transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
    pub retry_count: usize,
}

/// Begin a response-independent interaction-capture write. Same `BEGIN
/// IMMEDIATE` bounded retry and write-profile enforcement as [`begin_write`],
/// but exhaustion keeps its retry count inside the returned error so the
/// background capture path can log it instead of swallowing it: a read tool
/// call can stall up to the writer deadline on this write and still return
/// 200, and the count is what distinguishes contention from a poisoned lock.
pub(crate) async fn begin_capture_write(pool: &SqlitePool) -> Result<CaptureBegin> {
    let started_at = Instant::now();
    let begun =
        begin_write_attempts_with(|| pool.begin_with("BEGIN IMMEDIATE"), WRITER_DEADLINE).await;
    let wait = started_at.elapsed();
    // Capture writes are the dominant source of per-workspace write pressure,
    // so they belong in the same aggregate as ordinary writes rather than only
    // in the exhaustion message below.
    crate::write_contention::record_begin(
        WriteDomain::Workspace,
        match &begun {
            Ok(success) => success.retries,
            Err(failure) => failure.retries,
        },
        wait,
        begun.is_err(),
    );
    let success = match begun {
        Ok(success) => success,
        Err(failure) => {
            return Err(Error::engine(format!(
                "interaction capture begin_write {} after {} retries in {}ms: {}",
                failure.retry_outcome,
                failure.retry_count,
                wait.as_millis(),
                failure.error
            )));
        }
    };
    let mut transaction = success.transaction;
    if let Some(key) = connection_key(&mut transaction).await {
        crate::write_contention::open_critical_section(WriteDomain::Workspace, key, None);
    }
    if let Err(error) = crate::storage_profile::enforce_write_boundary(&mut transaction).await {
        let _ = transaction.rollback().await;
        return Err(error);
    }
    Ok(CaptureBegin {
        transaction,
        retry_count: success.retry_count,
    })
}

/// Begin an authoritative hosted control-plane SQLite write.
///
/// Hosted catalogues own their pool directly rather than receiving a portable
/// [`Db`]. This purpose-specific boundary preserves the engine's exact
/// `BEGIN IMMEDIATE`, bounded retry, and write-profile enforcement without
/// exposing either [`Db::write_pool`] or a general public transaction helper.
#[doc(hidden)]
pub async fn begin_host_control_plane_sqlite_write(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    begin_write_in(pool, WriteDomain::HostCatalog).await
}

/// A hosted control-plane write carrying bounded-BEGIN diagnostics through its
/// statement and commit stages.
///
/// This is deliberately purpose-specific: hosted migration-journal callers
/// need retained diagnostics even when stderr has no tracing subscriber, while
/// ordinary engine callers keep the existing raw-error behaviour of
/// [`begin_write`].
#[doc(hidden)]
pub struct DiagnosedHostControlPlaneSqliteWrite {
    transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
    operation: &'static str,
    started_at: Instant,
    begin_retry_count: usize,
}

impl DiagnosedHostControlPlaneSqliteWrite {
    /// Borrow the underlying SQLite connection for one journal statement.
    pub fn connection(&mut self) -> &mut SqliteConnection {
        &mut self.transaction
    }

    /// Add operation, stage, bounded-BEGIN outcome, and elapsed time to a
    /// journal statement error without discarding a SQLite database error's
    /// code or classification.
    pub fn statement_error(&self, statement: &'static str, error: sqlx::Error) -> Error {
        self.stage_error(
            "statement",
            Some(("statement", statement)),
            Error::Sqlx(error),
        )
    }

    /// Commit the journal transition, retaining the same operation and BEGIN
    /// history if SQLite rejects the commit.
    pub async fn commit(self) -> Result<()> {
        let Self {
            transaction,
            operation,
            started_at,
            begin_retry_count,
        } = self;
        match transaction.commit().await {
            Ok(()) => Ok(()),
            Err(error) => Err(contextualize_write_error(
                write_diagnostic_context(
                    operation,
                    "commit",
                    None,
                    started_at.elapsed(),
                    successful_begin_retry_outcome(begin_retry_count),
                    begin_retry_count,
                ),
                Error::Sqlx(error),
            )),
        }
    }

    fn stage_error(
        &self,
        stage: &'static str,
        detail: Option<(&'static str, &'static str)>,
        error: Error,
    ) -> Error {
        contextualize_write_error(
            write_diagnostic_context(
                self.operation,
                stage,
                detail,
                self.started_at.elapsed(),
                successful_begin_retry_outcome(self.begin_retry_count),
                self.begin_retry_count,
            ),
            error,
        )
    }
}

/// Begin a diagnosed authoritative hosted control-plane SQLite write.
///
/// The operation must be a fixed server-side label. It is retained in errors;
/// callers must not put tenant identifiers or other request data in it.
#[doc(hidden)]
pub async fn begin_diagnosed_host_control_plane_sqlite_write(
    pool: &SqlitePool,
    operation: &'static str,
) -> Result<DiagnosedHostControlPlaneSqliteWrite> {
    begin_diagnosed_host_control_plane_sqlite_write_with_deadline(pool, operation, WRITER_DEADLINE)
        .await
}

/// [`begin_diagnosed_host_control_plane_sqlite_write`] with an explicit
/// bounded-BEGIN deadline. The hosted migration journal retries a busy begin
/// across several [`WRITER_DEADLINE`] windows; tests pass a short deadline so
/// they exercise the retry without waiting out the production budget.
#[doc(hidden)]
pub async fn begin_diagnosed_host_control_plane_sqlite_write_with_deadline(
    pool: &SqlitePool,
    operation: &'static str,
    retry_for: Duration,
) -> Result<DiagnosedHostControlPlaneSqliteWrite> {
    let started_at = Instant::now();
    let begin = begin_write_attempts_with(|| pool.begin_with("BEGIN IMMEDIATE"), retry_for).await;
    // This path predates the measurement and kept its own diagnostics, but it
    // is ordinary hosted control-plane write traffic: leaving it out would make
    // the catalogue domain silently undercount while presenting itself as a
    // measured distribution.
    let wait = started_at.elapsed();
    let retries = match &begin {
        Ok(success) => success.retries,
        Err(failure) => failure.retries,
    };
    crate::write_contention::record_begin(WriteDomain::HostCatalog, retries, wait, begin.is_err());
    crate::request_work::record_write_begin(
        retries,
        u64::try_from(wait.as_micros()).unwrap_or(u64::MAX),
    );
    crate::mcp::request_timing::record_write_wait(wait);
    let BeginWriteSuccess {
        mut transaction,
        retry_count,
        retries: _,
    } = match begin {
        Ok(begin) => begin,
        Err(failure) => {
            let context = write_diagnostic_context(
                operation,
                "begin",
                None,
                started_at.elapsed(),
                failure.retry_outcome,
                failure.retry_count,
            );
            return Err(contextualize_write_error(context, failure.error));
        }
    };
    if let Some(key) = connection_key(&mut transaction).await {
        crate::write_contention::open_critical_section(
            WriteDomain::HostCatalog,
            key,
            Some(operation),
        );
    }
    if let Err(error) = crate::storage_profile::enforce_write_boundary(&mut transaction).await {
        let context = write_diagnostic_context(
            operation,
            "begin",
            Some(("boundary", "write_profile")),
            started_at.elapsed(),
            successful_begin_retry_outcome(retry_count),
            retry_count,
        );
        let error = contextualize_write_error(context, error);
        let _ = transaction.rollback().await;
        return Err(error);
    }
    Ok(DiagnosedHostControlPlaneSqliteWrite {
        transaction,
        operation,
        started_at,
        begin_retry_count: retry_count,
    })
}

fn successful_begin_retry_outcome(retry_count: usize) -> &'static str {
    if retry_count == 0 {
        "not_needed"
    } else {
        "succeeded_after_retry"
    }
}

fn write_diagnostic_context(
    operation: &'static str,
    stage: &'static str,
    detail: Option<(&'static str, &'static str)>,
    elapsed: Duration,
    begin_retry_outcome: &'static str,
    begin_retry_count: usize,
) -> String {
    let detail = detail
        .map(|(key, value)| format!(" {key}={value}"))
        .unwrap_or_default();
    format!(
        "migration journal operation={operation} stage={stage}{detail} elapsed_ms={} begin_retry_outcome={begin_retry_outcome} begin_retry_count={begin_retry_count}",
        elapsed.as_millis()
    )
}

fn contextualize_write_error(context: String, error: Error) -> Error {
    match error {
        Error::Sqlx(sqlx::Error::Database(source)) => Error::Sqlx(sqlx::Error::Database(Box::new(
            ContextualDatabaseError::new(context, source),
        ))),
        error => Error::engine(format!("{context}: {error}")),
    }
}

#[derive(Debug)]
struct ContextualDatabaseError {
    message: String,
    context: String,
    source: Box<dyn DatabaseError>,
}

impl ContextualDatabaseError {
    fn new(context: String, source: Box<dyn DatabaseError>) -> Self {
        let message = format!("{context}: {}", source.message());
        Self {
            message,
            context,
            source,
        }
    }
}

impl fmt::Display for ContextualDatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.context, self.source)
    }
}

impl StdError for ContextualDatabaseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_error())
    }
}

impl DatabaseError for ContextualDatabaseError {
    fn message(&self) -> &str {
        &self.message
    }

    fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
        self.source.code()
    }

    fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self.source.as_error()
    }

    fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
        self.source.as_error_mut()
    }

    fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
        self.source.into_error()
    }

    fn is_transient_in_connect_phase(&self) -> bool {
        self.source.is_transient_in_connect_phase()
    }

    fn constraint(&self) -> Option<&str> {
        self.source.constraint()
    }

    fn table(&self) -> Option<&str> {
        self.source.table()
    }

    fn kind(&self) -> ErrorKind {
        self.source.kind()
    }
}

/// How long a writer will queue for `BEGIN IMMEDIATE` before giving up.
/// Derived from the measurement's largest histogram bucket, rather than stated
/// twice, so the bound and the deadline it exists to describe cannot drift.
pub(crate) const WRITER_DEADLINE: Duration =
    Duration::from_micros(crate::write_contention::WRITER_DEADLINE_MICROS);

struct BeginWriteSuccess {
    transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
    retry_count: usize,
    retries: BeginRetries,
}

struct BeginWriteFailure {
    error: Error,
    retry_count: usize,
    retry_outcome: &'static str,
    retries: BeginRetries,
}

/// Why a bounded `BEGIN IMMEDIATE` had to go round again. The two causes are
/// counted apart because they mean opposite things: `busy` is a writer queueing
/// behind another writer for longer than SQLite's own five-second
/// `busy_timeout`, which is an incident; `cleanup` is a canceled transaction's
/// rollback still draining before pooled reuse, which is ordinary housekeeping
/// and carries a 20ms sleep rather than five seconds of contention. Summed
/// together they describe neither.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BeginRetries {
    pub busy: usize,
    pub cleanup: usize,
}

async fn begin_write_attempts_with<F, Fut>(
    mut begin: F,
    retry_for: Duration,
) -> std::result::Result<BeginWriteSuccess, BeginWriteFailure>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
        Output = std::result::Result<sqlx::Transaction<'static, sqlx::Sqlite>, sqlx::Error>,
    >,
{
    let deadline = Instant::now() + retry_for;
    let mut retry_count = 0;
    let mut retries = BeginRetries::default();
    loop {
        match begin().await {
            Ok(transaction) => {
                return Ok(BeginWriteSuccess {
                    transaction,
                    retry_count,
                    retries,
                })
            }
            Err(sqlx_error) => {
                let error = Error::from(sqlx_error);
                // A canceled SQLite transaction queues its rollback on the
                // connection worker. Under concurrent pool reuse, a custom
                // BEGIN can briefly arrive while SQLx still reports non-zero
                // transaction depth and reject it as an invalid savepoint
                // statement. Like lock contention, this clears once cleanup
                // drains; retry it within the same bounded writer deadline.
                let cleanup_pending =
                    matches!(&error, Error::Sqlx(sqlx::Error::InvalidSavePointStatement));
                let retryable = error.is_busy() || cleanup_pending;
                if !retryable || Instant::now() >= deadline {
                    return Err(BeginWriteFailure {
                        error,
                        retry_count,
                        retry_outcome: if retryable {
                            "exhausted"
                        } else {
                            "not_retriable"
                        },
                        retries,
                    });
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                retry_count += 1;
                if cleanup_pending {
                    retries.cleanup += 1;
                } else {
                    retries.busy += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod begin_write_tests {
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct TestDatabaseError {
        code: &'static str,
        message: &'static str,
    }

    impl fmt::Display for TestDatabaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "(code: {}) {}", self.code, self.message)
        }
    }

    impl StdError for TestDatabaseError {}

    impl DatabaseError for TestDatabaseError {
        fn message(&self) -> &str {
            self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[tokio::test]
    async fn retries_a_transient_invalid_savepoint_before_begin_immediate() {
        let db = create_database(":memory:").await.unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let begun = begin_write_attempts_with(
            || {
                let pool = db.write_pool().clone();
                let attempts = attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(sqlx::Error::InvalidSavePointStatement)
                    } else {
                        pool.begin_with("BEGIN IMMEDIATE").await
                    }
                }
            },
            WRITER_DEADLINE,
        )
        .await
        .unwrap_or_else(|failure| panic!("bounded begin did not retry: {}", failure.error));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(begun.retry_count, 1, "the retry was not counted");
        begun.transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn diagnosed_begin_reports_bounded_exhaustion_and_preserves_busy_code() {
        let failure = match begin_write_attempts_with(
            || async {
                Err(sqlx::Error::database(TestDatabaseError {
                    code: "5",
                    message: "database is locked",
                }))
            },
            Duration::ZERO,
        )
        .await
        {
            Ok(_) => panic!("zero-length busy retry unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert_eq!(failure.retry_count, 0);
        assert_eq!(failure.retry_outcome, "exhausted");

        let error = contextualize_write_error(
            write_diagnostic_context(
                "reserve_migration_attempt",
                "begin",
                None,
                Duration::from_millis(3),
                failure.retry_outcome,
                failure.retry_count,
            ),
            failure.error,
        );
        assert!(error.is_busy());
        let message = error.to_string();
        assert!(message.contains("operation=reserve_migration_attempt stage=begin"));
        assert!(message.contains("elapsed_ms=3"));
        assert!(message.contains("begin_retry_outcome=exhausted begin_retry_count=0"));
        let Error::Sqlx(sqlx::Error::Database(database)) = error else {
            panic!("diagnosed busy error lost its database variant");
        };
        assert_eq!(database.code().as_deref(), Some("5"));
        assert!(database.try_downcast_ref::<TestDatabaseError>().is_some());
    }

    #[tokio::test]
    async fn diagnosed_write_carries_successful_begin_retry_into_later_stages() {
        let db = create_database(":memory:").await.unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let begin = match begin_write_attempts_with(
            || {
                let pool = db.write_pool().clone();
                let attempts = attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(sqlx::Error::InvalidSavePointStatement)
                    } else {
                        pool.begin_with("BEGIN IMMEDIATE").await
                    }
                }
            },
            Duration::from_secs(1),
        )
        .await
        {
            Ok(begin) => begin,
            Err(_) => panic!("transient invalid savepoint was not retried"),
        };
        assert_eq!(begin.retry_count, 1);
        let write = DiagnosedHostControlPlaneSqliteWrite {
            transaction: begin.transaction,
            operation: "finalize_migration_attempt",
            started_at: Instant::now(),
            begin_retry_count: begin.retry_count,
        };

        let statement = write.statement_error(
            "finalize_prepared_attempt",
            sqlx::Error::Protocol("statement failed".into()),
        );
        let statement = statement.to_string();
        assert!(statement.contains(
            "operation=finalize_migration_attempt stage=statement statement=finalize_prepared_attempt"
        ));
        assert!(statement.contains("begin_retry_outcome=succeeded_after_retry begin_retry_count=1"));
        assert!(statement.ends_with(": encountered unexpected or invalid data: statement failed"));

        write.transaction.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn diagnosed_write_contextualizes_an_actual_commit_failure() {
        // File-backed, and the diagnosed write goes through a pool of the kind
        // it declares. Handing it a workspace pool would still exercise the
        // diagnostics, but the contention measurement would see a section
        // opened as the catalogue and released by the workspace and correctly
        // refuse it — a test quietly driving the error path of an unrelated
        // subsystem.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("diagnosed.db");
        let path = path.to_str().unwrap();
        let db = create_database(path).await.unwrap();
        let mut setup = begin_write(db.write_pool()).await.unwrap();
        sqlx::query("CREATE TABLE diagnostic_parent (id INTEGER PRIMARY KEY)")
            .execute(&mut *setup)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE diagnostic_child (
                 parent_id INTEGER REFERENCES diagnostic_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             )",
        )
        .execute(&mut *setup)
        .await
        .unwrap();
        setup.commit().await.unwrap();

        let catalog = open_pool(path, false, WritePoolKind::HostCatalog)
            .await
            .unwrap();
        let mut write =
            begin_diagnosed_host_control_plane_sqlite_write(&catalog, "finish_migration_run")
                .await
                .unwrap();
        sqlx::query("INSERT INTO diagnostic_child (parent_id) VALUES (42)")
            .execute(write.connection())
            .await
            .unwrap();
        let error = write.commit().await.unwrap_err();
        assert!(!error.is_busy());
        let message = error.to_string();
        assert!(message.contains("operation=finish_migration_run stage=commit"));
        assert!(message.contains("elapsed_ms="));
        assert!(message.contains("begin_retry_outcome=not_needed begin_retry_count=0"));
        assert!(message.contains("FOREIGN KEY constraint failed"));
    }
}

#[cfg(test)]
tokio::task_local! {
    static BEFORE_BEGIN_WRITE_NOTIFICATION: Arc<tokio::sync::Notify>;
}

/// Test-only scheduling seam: notify synchronously immediately before the
/// scoped future's next `BEGIN IMMEDIATE` is submitted to SQLite.
#[cfg(test)]
pub(crate) async fn with_before_begin_write_notification<F>(
    notification: Arc<tokio::sync::Notify>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    BEFORE_BEGIN_WRITE_NOTIFICATION
        .scope(notification, future)
        .await
}

/// Why not a real in-memory DB for `:memory:`? A bare `:memory:` gives every
/// *connection* its own private database, and the pool uses more than one
/// connection, so the schema created on one connection is invisible to the
/// next write. The only in-memory DB shared across connections is the
/// process-global `file::memory:?cache=shared`, which is NOT isolated between
/// databases — fatal for the rebuild-and-diff harness, whose fresh database
/// must differ from the live one. A unique temp file gives us both: shared
/// across connections and isolated per database. It is deleted when the last
/// handle drops.
fn ephemeral_file() -> Result<(String, Arc<TempDir>)> {
    let dir = tempfile::Builder::new()
        .prefix("native-ce-mem-")
        .tempdir()?;
    let path = dir.path().join("ephemeral.db");
    Ok((path.to_string_lossy().into_owned(), Arc::new(dir)))
}

/// Cap the on-disk write-ahead log at 64 MiB.
///
/// SQLite's default is no limit: a checkpoint resets the WAL and lets the next
/// writer reuse the file from the start, but never shrinks it, so the file
/// keeps whatever size its busiest moment demanded for the lifetime of the
/// database. Measured on the production volume on 5 Sep 2026, the Native HQ
/// WAL sat at 689 MiB beside a 3.21 GiB database — unchanging in size across
/// samples a minute apart while its mtime advanced with every one, which is
/// the signature of a WAL that is cycling correctly inside a file nothing ever
/// truncates.
///
/// With this limit set, the file comes back down on the first write
/// transaction *after* a checkpoint resets the WAL — not on the checkpoint
/// itself, which leaves the file at full size. Do not read a still-large WAL
/// immediately after forcing a checkpoint as this setting having failed; an
/// idle database keeps the oversized file until something writes again. The
/// limit also does not prevent regrowth during a burst. It stops a peak from
/// becoming permanent, which is all it is for.
///
/// 64 MiB is deliberate headroom, not a target. The default autocheckpoint
/// fires every 1000 pages (~4 MiB at this page size), so a healthy WAL sits
/// far below the limit and never pays for a truncation; the limit exists to
/// stop an outlier burst from becoming permanent.
const WAL_JOURNAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;

fn connect_options(path: &str, create_if_missing: bool) -> Result<SqliteConnectOptions> {
    // Accept a plain path or a `file:` URL (the CLI contract accepts both).
    let options = SqliteConnectOptions::from_str(&format!(
        "sqlite:{}",
        path.strip_prefix("file:").unwrap_or(path)
    ))?;
    Ok(options
        .create_if_missing(create_if_missing)
        .journal_mode(SqliteJournalMode::Wal)
        // Only a connection that can write can checkpoint, and only a
        // checkpoint can truncate. The read-only options below therefore do
        // not carry this pragma: it would be inert there.
        .pragma(
            "journal_size_limit",
            WAL_JOURNAL_SIZE_LIMIT_BYTES.to_string(),
        )
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5)))
}

fn read_only_connect_options(path: &str) -> Result<SqliteConnectOptions> {
    let options = SqliteConnectOptions::from_str(&format!(
        "sqlite:{}",
        path.strip_prefix("file:").unwrap_or(path)
    ))?;
    Ok(options
        .create_if_missing(false)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5)))
}

fn immutable_read_only_connect_options(path: &str) -> Result<SqliteConnectOptions> {
    Ok(read_only_connect_options(path)?.immutable(true))
}

// Public views precede their internal dependencies. SQLite permits dropping a
// referenced object, so keeping this teardown order explicit prevents a pooled
// connection from retaining a dangling public view if the contract changes.
// Trailing entries are helper tables, dropped as tables rather than views;
// VIEW_COUNT below must stay in step with their number.
const QUERY_SQL_TEMP_CONTRACT_OBJECTS: &[&str] = &[
    "records",
    "content_events",
    "links",
    "facet_values",
    "facet_observations",
    "bindings",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "effective_relationships",
    "agent_activity",
    "agent_activity_claims",
    "messages_awaiting_reply",
    "catalog_relations",
    "catalog_columns",
    "_query_sql_visible_records",
    "_query_sql_authorization_subjects",
    "_query_sql_principal",
    "_query_sql_activity_observations",
    "_query_sql_activity_capture",
    "_query_sql_activity_members",
    "_query_sql_messages_awaiting_reply",
    "_query_sql_claim_candidates",
    "_query_sql_claim_releases",
];
const QUERY_SQL_TEMP_VIEW_COUNT: usize = QUERY_SQL_TEMP_CONTRACT_OBJECTS.len() - 7;

#[cfg(test)]
mod wal_journal_size_limit_tests {
    use super::*;

    /// The bug this guards against is a setting that never reaches SQLite.
    /// Assert the readback on a real pooled connection rather than trusting
    /// that the builder call was written.
    #[tokio::test]
    async fn write_pool_connections_carry_the_journal_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal-size-limit.db");
        let pool = open_pool(path.to_str().unwrap(), true, WritePoolKind::Workspace)
            .await
            .unwrap();

        let limit: i64 = sqlx::query_scalar("PRAGMA journal_size_limit")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(
            limit, WAL_JOURNAL_SIZE_LIMIT_BYTES,
            "journal_size_limit did not reach the write connection"
        );
        pool.close().await;
    }

    /// Pin the mechanism the fix actually depends on: SQLite applies the limit
    /// on the commit that follows a WAL restart, not on the checkpoint.
    /// Testing this with `wal_checkpoint(TRUNCATE)` would prove nothing,
    /// because that mode truncates to zero whatever the limit is — including
    /// when there is no limit at all. So restart the WAL, commit once more,
    /// and require the commit to be what brings the file down.
    #[tokio::test]
    async fn the_commit_after_a_wal_restart_truncates_to_the_limit() {
        const TEST_LIMIT: u64 = 65536;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("truncation.db");
        let pool = open_pool(path.to_str().unwrap(), true, WritePoolKind::Workspace)
            .await
            .unwrap();
        let wal = directory.path().join("truncation.db-wal");
        // Every statement below must land on one physical connection:
        // `journal_size_limit` and `wal_autocheckpoint` are per-connection
        // settings, and this pool holds five.
        let mut connection = pool.acquire().await.unwrap();

        sqlx::query(&format!("PRAGMA journal_size_limit = {TEST_LIMIT}"))
            .execute(&mut *connection)
            .await
            .unwrap();
        // Hold the WAL open across the writes, so the growth assertion below
        // observes a WAL that autocheckpointing has not already reset.
        sqlx::query("PRAGMA wal_autocheckpoint = 0")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bulk (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
            .execute(&mut *connection)
            .await
            .unwrap();
        for _ in 0..64 {
            sqlx::query("INSERT INTO bulk (payload) VALUES (zeroblob(65536))")
                .execute(&mut *connection)
                .await
                .unwrap();
        }

        let grown = std::fs::metadata(&wal).unwrap().len();
        assert!(
            grown > TEST_LIMIT,
            "the WAL only reached {grown} bytes, so truncating to {TEST_LIMIT} proves nothing"
        );

        let (busy, _, _): (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(RESTART)")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert_eq!(busy, 0, "checkpoint did not complete");
        assert_eq!(
            std::fs::metadata(&wal).unwrap().len(),
            grown,
            "the restart itself shrank the file, so this test is not observing the commit-time limit"
        );

        sqlx::query("INSERT INTO bulk (payload) VALUES (zeroblob(16))")
            .execute(&mut *connection)
            .await
            .unwrap();

        assert_eq!(
            std::fs::metadata(&wal).unwrap().len(),
            TEST_LIMIT,
            "the commit after the restart did not truncate to the limit"
        );
        drop(connection);
        pool.close().await;
    }
}

#[derive(Clone, Copy)]
enum WritePoolKind {
    Workspace,
    HostCatalog,
}

async fn open_pool(path: &str, create_if_missing: bool, kind: WritePoolKind) -> Result<SqlitePool> {
    let options = match kind {
        WritePoolKind::Workspace => SqlitePoolOptions::new()
            .max_connections(5)
            // Both hooks are required: SQLx uses `before_acquire` for an idle
            // connection and `after_connect` for a newly opened one.
            .before_acquire(count_write_pool_reuse)
            .after_connect(count_write_pool_new_connection),
        WritePoolKind::HostCatalog => SqlitePoolOptions::new()
            .max_connections(5)
            .before_acquire(attach_catalog_trace_on_reuse)
            .after_connect(attach_catalog_trace_on_connect),
    };
    let pool = options
        // `query_sql` installs connection-local views, principal state, and a
        // SQLite progress callback. This hook is the structural cleanup and
        // cancellation/unwind backstop before a pooled physical connection can
        // serve any later request, including an ordinary non-SQL query whose
        // unqualified relation names must never resolve to the TEMP contract.
        .after_release(move |connection, _metadata| {
            Box::pin(async move {
                // The reserved lock is gone by the time a connection comes
                // back, whether it committed, rolled back, or was dropped, so
                // this is the unbiased close for the critical-section
                // measurement. A connection that never opened one — an
                // ordinary query on the write pool — closes nothing.
                if let Some(key) = connection_key(connection).await {
                    crate::write_contention::close_critical_section(
                        match kind {
                            WritePoolKind::Workspace => WriteDomain::Workspace,
                            WritePoolKind::HostCatalog => WriteDomain::HostCatalog,
                        },
                        key,
                    );
                }
                if matches!(kind, WritePoolKind::HostCatalog) {
                    // The snapshot counts statements executed while this
                    // request owns the checkout. Pool housekeeping below is
                    // deliberately outside that interval.
                    detach_catalog_trace(connection).await?;
                }
                sanitize_released_write_connection(connection).await
            })
        })
        .connect_with(connect_options(path, create_if_missing)?)
        .await?;
    Ok(pool)
}

async fn sanitize_released_write_connection(
    connection: &mut SqliteConnection,
) -> std::result::Result<bool, sqlx::Error> {
    match connection.lock_handle().await {
        Ok(mut handle) => {
            handle.remove_progress_handler();
            // A custom SQLx `begin_with` starts SQLite before its final
            // transaction-state verification await. If that future is
            // cancelled in between, no `Transaction` guard is ever created
            // and therefore no rollback is queued. Never let that physical
            // connection return to the pool: closing it is SQLite's
            // fail-closed rollback boundary.
            // SAFETY: the locked handle is exclusive and live. SQLite reports
            // autocommit off for every active explicit transaction.
            let transaction_open = unsafe {
                libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) == 0
            };
            if transaction_open {
                return Ok(false);
            }
            // SAFETY: the locked handle is exclusive and live.
            unsafe {
                libsqlite3_sys::sqlite3_limit(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                    SQLITE_DEFAULT_VALUE_LIMIT,
                );
            }
        }
        Err(_) => return Ok(false),
    }
    // SQLx's transaction depth is a distinct driver-side authority. It can
    // outlive SQLite's transaction after an engine-initiated rollback, so
    // require both views to be clean before pooled reuse.
    if connection.is_in_transaction() {
        return Ok(false);
    }
    let placeholders = vec!["?"; QUERY_SQL_TEMP_CONTRACT_OBJECTS.len()].join(", ");
    let sentinel = format!(
        "SELECT EXISTS (
           SELECT 1 FROM temp.sqlite_schema WHERE name IN ({placeholders})
         )"
    );
    let mut query = sqlx::query_scalar::<_, bool>(&sentinel);
    for object in QUERY_SQL_TEMP_CONTRACT_OBJECTS {
        query = query.bind(*object);
    }
    match query.fetch_one(&mut *connection).await {
        Ok(false) => return Ok(true),
        Ok(true) => {}
        Err(_) => return Ok(false),
    }
    for view in &QUERY_SQL_TEMP_CONTRACT_OBJECTS[..QUERY_SQL_TEMP_VIEW_COUNT] {
        let statement = format!("DROP VIEW IF EXISTS temp.{view}");
        if sqlx::query(&statement)
            .execute(&mut *connection)
            .await
            .is_err()
        {
            return Ok(false);
        }
    }
    for table in [
        "_query_sql_principal",
        "_query_sql_activity_observations",
        "_query_sql_activity_capture",
        "_query_sql_activity_members",
        "_query_sql_messages_awaiting_reply",
        "_query_sql_claim_candidates",
        "_query_sql_claim_releases",
    ] {
        if sqlx::query(&format!("DROP TABLE IF EXISTS temp.{table}"))
            .execute(&mut *connection)
            .await
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod released_write_connection_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_custom_begin_is_quarantined_before_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cancelled-begin.db");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_release(|connection, _metadata| {
                Box::pin(sanitize_released_write_connection(connection))
            })
            .connect_with(connect_options(path.to_str().unwrap(), true).unwrap())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE lifecycle_probe (value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();

        let mut connection = pool.acquire().await.unwrap();
        let mut abandoned = connection.begin_with("BEGIN IMMEDIATE").await.unwrap();
        sqlx::query("INSERT INTO lifecycle_probe (value) VALUES ('uncommitted')")
            .execute(&mut *abandoned)
            .await
            .unwrap();
        // Deterministically model cancellation after SQLx has begun SQLite's
        // transaction but before it has returned the RAII guard to the
        // request future. That path loses the guard without queuing rollback.
        std::mem::forget(abandoned);
        drop(connection);

        let mut reloaded =
            tokio::time::timeout(Duration::from_secs(1), pool.begin_with("BEGIN IMMEDIATE"))
                .await
                .expect("reload did not wait on a leaked transaction")
                .expect("reload received non-zero transaction depth");
        let leaked_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lifecycle_probe")
            .fetch_one(&mut *reloaded)
            .await
            .unwrap();
        assert_eq!(leaked_rows, 0, "abandoned work was not rolled back");
        reloaded.rollback().await.unwrap();
        pool.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_pool_release_still_drops_the_temp_contract() {
        // Tier 1.2 adds a pool; it must not relax this one. Pin one physical
        // connection, plant governed TEMP state on it, release, and require
        // the same connection back clean.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("write-sanitize.db");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .after_release(|connection, _metadata| {
                Box::pin(sanitize_released_write_connection(connection))
            })
            .connect_with(connect_options(path.to_str().unwrap(), true).unwrap())
            .await
            .unwrap();
        {
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("CREATE TEMP VIEW temp.records AS SELECT 1 AS id")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query("CREATE TEMP VIEW temp.catalog_columns AS SELECT 1 AS column_position")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query(
                "CREATE TEMP TABLE temp._query_sql_principal (
                   singleton INTEGER PRIMARY KEY, account_id TEXT NOT NULL,
                   trusted_local_bypass INTEGER NOT NULL,
                   activity_read INTEGER NOT NULL, observed_at TEXT NOT NULL)",
            )
            .execute(&mut *connection)
            .await
            .unwrap();
        }
        let leftover: bool = {
            let mut connection = pool.acquire().await.unwrap();
            let leftover: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                   SELECT 1 FROM temp.sqlite_schema
                    WHERE name IN ('records', 'catalog_columns', '_query_sql_principal'))",
            )
            .fetch_one(&mut *connection)
            .await
            .unwrap();
            leftover
        };
        assert!(
            !leftover,
            "write-pool release stopped dropping the TEMP contract"
        );
        pool.close().await;
    }
}

async fn open_read_pool(path: &str) -> Result<SqlitePool> {
    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .before_acquire(count_read_pool_reuse)
        .after_connect(count_read_pool_new_connection)
        .connect_with(read_only_connect_options(path)?)
        .await?)
}

/// Default governed-SQL pool size (Tier 1.2).
///
/// Why 3, and why not Postgres's 4: the Postgres governed pool bounds
/// *backend sessions* on a server that multiplexes many databases; this pool
/// bounds *SQLite connections* on one file, so the number answers to SQLite's
/// costs, not Postgres's. Three is the smallest size at which one governed
/// read holding its connection through per-row JSON encoding cannot serialize
/// every other viewer (two slots remain); it stays strictly below the
/// five-connection write pool so the governed tier is never the largest
/// writer-side pool; and it caps the per-connection TEMP-contract memory — and
/// rung 1.4's per-connection visible-set cache copies — at three. Tune with
/// [`GOVERNED_SQL_POOL_SIZE_ENV`] after live measurement; saturation then
/// surfaces as a bounded acquire wait, never as writer starvation.
pub const DEFAULT_GOVERNED_SQL_POOL_SIZE: u32 = 3;

/// Environment override for the governed-SQL pool size. Unset, unparseable, or
/// zero values fall back to [`DEFAULT_GOVERNED_SQL_POOL_SIZE`]: a zero-slot
/// pool would refuse every governed read, so misconfiguration fails safe to
/// the default rather than to an unusable handle.
pub const GOVERNED_SQL_POOL_SIZE_ENV: &str = "NATIVE_CE_GOVERNED_SQL_POOL_SIZE";

/// Bounded wait for a governed-SQL slot. Saturation must surface as an error a
/// surface can report, not a hang: a surface in a loop that outruns the pool
/// waits at most this long before its excess queries fail while the slots
/// they waited for keep serving. Shorter than SQLx's 30-second default and
/// inside `begin_write`'s 15-second writer deadline, so a governed burst can
/// never out-wait a writer.
pub const GOVERNED_SQL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn governed_sql_pool_size() -> u32 {
    parse_governed_sql_pool_size(std::env::var(GOVERNED_SQL_POOL_SIZE_ENV).ok().as_deref())
}

fn parse_governed_sql_pool_size(raw: Option<&str>) -> u32 {
    raw.and_then(|value| value.parse::<u32>().ok())
        .filter(|size| *size >= 1)
        .unwrap_or(DEFAULT_GOVERNED_SQL_POOL_SIZE)
}

/// Open the governed-SQL pool: read-write connections (the governed path
/// writes TEMP tables and opens a transaction, so the read-only tier cannot
/// serve it) with the TEMP-contract half of the write pool's release hook.
///
/// Release runs [`sanitize_released_write_connection`] and nothing else — a
/// deliberate subset of `open_pool`'s `after_release`, not an omission:
/// governed connections never open a write critical section (only
/// `begin_write_in` opens one; the governed path takes a deferred read
/// transaction), so a contention close could only consume a pointer-reused
/// key as a domain mismatch; the catalog trace is a HostCatalog-pool concern;
/// and the acquisition counters feed the write/read-pool handler-body
/// migration instruments, which a third pool must not inflate. Like the write
/// pool, the hook drops the TEMP contract, clears the progress handler, and
/// restores per-connection limits, so no principal state survives a borrow.
/// Rung 1.3 may retain the *contract* portion of that teardown — safe only
/// here, because these connections never serve the unqualified-name queries
/// (`bootstrap`, `get_structure`) that retained TEMP state would shadow — but
/// principal cleanup stays regardless of what 1.3 retains.
async fn open_governed_pool(path: &str, create_if_missing: bool) -> Result<SqlitePool> {
    open_governed_pool_with_size(path, create_if_missing, governed_sql_pool_size()).await
}

async fn open_governed_pool_with_size(
    path: &str,
    create_if_missing: bool,
    size: u32,
) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(size.max(1))
        .acquire_timeout(GOVERNED_SQL_ACQUIRE_TIMEOUT)
        .after_release(|connection, _metadata| {
            Box::pin(sanitize_released_write_connection(connection))
        })
        .connect_with(connect_options(path, create_if_missing)?)
        .await?;
    Ok(pool)
}

#[cfg(test)]
mod governed_sql_pool_config_tests {
    use super::*;

    #[test]
    fn pool_size_defaults_and_rejects_misconfiguration() {
        assert_eq!(
            parse_governed_sql_pool_size(None),
            DEFAULT_GOVERNED_SQL_POOL_SIZE
        );
        assert_eq!(
            parse_governed_sql_pool_size(Some("")),
            DEFAULT_GOVERNED_SQL_POOL_SIZE
        );
        assert_eq!(
            parse_governed_sql_pool_size(Some("not-a-number")),
            DEFAULT_GOVERNED_SQL_POOL_SIZE
        );
        // A zero-slot pool would refuse every governed read; fail safe to the
        // default rather than opening an unusable handle.
        assert_eq!(
            parse_governed_sql_pool_size(Some("0")),
            DEFAULT_GOVERNED_SQL_POOL_SIZE
        );
        assert_eq!(parse_governed_sql_pool_size(Some("1")), 1);
        assert_eq!(parse_governed_sql_pool_size(Some("8")), 8);
    }

    #[tokio::test]
    async fn open_databases_expose_a_separate_governed_pool() {
        let db = create_database(":memory:").await.unwrap();
        // Pools open lazily: check out every configured slot so `size`
        // observes the bound rather than the warm-up state.
        let mut held = Vec::new();
        for _ in 0..governed_sql_pool_size() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        assert_eq!(
            db.governed_pool().size(),
            governed_sql_pool_size(),
            "governed pool ignores its configured size"
        );
        assert_eq!(
            governed_sql_pool_size(),
            DEFAULT_GOVERNED_SQL_POOL_SIZE,
            "default governed pool size changed without updating its recorded reason"
        );
        drop(held);
        db.close().await;
    }
}

async fn open_immutable_read_pool(path: &str) -> Result<SqlitePool> {
    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .before_acquire(count_read_pool_reuse)
        .after_connect(count_read_pool_new_connection)
        .connect_with(immutable_read_only_connect_options(path)?)
        .await?)
}

/// Open a database. Pass a path (or `file:` URL) for a real on-disk file, or
/// `:memory:` for an ephemeral one backed by a temp file that is removed when
/// the last handle drops — used by tests and the rebuild-and-diff harness.
///
/// Both are WAL-journalled with foreign keys enforced.
pub async fn open_database(url: &str) -> Result<Db> {
    open_database_with_write_pool_kind(url, WritePoolKind::Workspace).await
}

async fn open_database_with_write_pool_kind(url: &str, kind: WritePoolKind) -> Result<Db> {
    if url == ":memory:" {
        let (path, tmp) = ephemeral_file()?;
        let write_pool = open_pool(&path, true, kind).await?;
        let read_pool = open_read_pool(&path).await?;
        let governed_pool = open_governed_pool(&path, true).await?;
        return Ok(Db {
            write_pool,
            read_pool,
            governed_pool,
            location: Arc::new(DatabaseLocation {
                path: std::path::PathBuf::from(path),
                open_mode: DatabaseOpenMode::ReadWrite,
            }),
            handle_id: uuid::Uuid::new_v4(),
            embedder: None,
            rollup_cache: Arc::new(Mutex::new(RollupCache::default())),
            visible_set_cache: Arc::new(Mutex::new(
                crate::visible_set_cache::VisibleSetCache::default(),
            )),
            inbox_snapshots: Arc::new(Mutex::new(HashMap::new())),
            realtime_hub: None,
            workspace_index: Arc::new(tokio::sync::RwLock::new(None)),
            workspace_index_fold: Arc::new(AtomicBool::new(false)),
            workspace_index_refused: Arc::new(Mutex::new(None)),
            workspace_snapshots: Arc::new(Mutex::new(
                crate::workspace_snapshot::SnapshotStore::default(),
            )),
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            capture_queue: crate::mcp::interactions::CaptureQueue::spawn(),
            database_id_cache: Arc::new(tokio::sync::OnceCell::new()),
            _tmp: Some(tmp),
        });
    }
    let write_pool = open_pool(url, true, kind).await?;
    let read_pool = open_read_pool(url).await?;
    let governed_pool = match open_governed_pool(url, true).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            read_pool.close().await;
            return Err(error);
        }
    };
    Ok(Db {
        write_pool,
        read_pool,
        governed_pool,
        location: Arc::new(DatabaseLocation {
            path: std::path::PathBuf::from(url.strip_prefix("file:").unwrap_or(url)),
            open_mode: DatabaseOpenMode::ReadWrite,
        }),
        handle_id: uuid::Uuid::new_v4(),
        embedder: None,
        rollup_cache: Arc::new(Mutex::new(RollupCache::default())),
        visible_set_cache: Arc::new(Mutex::new(
            crate::visible_set_cache::VisibleSetCache::default(),
        )),
        inbox_snapshots: Arc::new(Mutex::new(HashMap::new())),
        realtime_hub: None,
        workspace_index: Arc::new(tokio::sync::RwLock::new(None)),
        workspace_index_fold: Arc::new(AtomicBool::new(false)),
        workspace_index_refused: Arc::new(Mutex::new(None)),
        workspace_snapshots: Arc::new(Mutex::new(
            crate::workspace_snapshot::SnapshotStore::default(),
        )),
        portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
        capture_queue: crate::mcp::interactions::CaptureQueue::spawn(),
        database_id_cache: Arc::new(tokio::sync::OnceCell::new()),
        _tmp: None,
    })
}

/// Open a database at a filesystem path (convenience over [`open_database`]).
pub async fn open_database_at(path: &Path) -> Result<Db> {
    open_database(&path.to_string_lossy()).await
}

/// Open the authoritative SQLite pool for a hosted control plane.
///
/// The opening and handoff are deliberately identical to the historical
/// catalogue path: open the database through Native's write/read-pool
/// configuration, retain the write pool, and await physical shutdown of the
/// read-only observation pool before dropping the temporary [`Db`] handle.
/// This pool owns its SQLite trace slot while a measured checkout is active;
/// test tracing uses separate, dedicated pools and never shares this pool.
#[doc(hidden)]
pub async fn open_host_control_plane_sqlite_pool(path: &Path) -> Result<SqlitePool> {
    let database =
        open_database_with_write_pool_kind(&path.to_string_lossy(), WritePoolKind::HostCatalog)
            .await?;
    Ok(retain_host_control_plane_sqlite_pool(database).await)
}

async fn retain_host_control_plane_sqlite_pool(database: Db) -> SqlitePool {
    let write_pool = database.write_pool().clone();
    database.pool().close().await;
    write_pool
}

#[cfg(test)]
mod host_control_plane_pool_tests {
    use super::*;

    #[tokio::test]
    async fn catalog_trace_counts_every_statement_in_one_checkout() {
        let directory = tempfile::tempdir().unwrap();
        let pool = open_host_control_plane_sqlite_pool(&directory.path().join("catalog.db"))
            .await
            .unwrap();
        let work = crate::request_work::RequestWork::new();
        work.scope(async {
            sqlx::raw_sql("SELECT 1; SELECT 2; SELECT 3;")
                .execute(&pool)
                .await
                .unwrap();
        })
        .await;
        assert_eq!(work.snapshot().catalog_statements, 3);
        pool.close().await;
    }

    #[tokio::test]
    async fn catalog_trace_is_request_local_and_detaches_on_release() {
        let directory = tempfile::tempdir().unwrap();
        let pool = open_host_control_plane_sqlite_pool(&directory.path().join("catalog.db"))
            .await
            .unwrap();
        let first = crate::request_work::RequestWork::new();
        let second = crate::request_work::RequestWork::new();
        tokio::join!(
            first.scope(async {
                sqlx::query("SELECT 1").execute(&pool).await.unwrap();
                sqlx::query("SELECT 2").execute(&pool).await.unwrap();
            }),
            second.scope(async {
                sqlx::query("SELECT 3").execute(&pool).await.unwrap();
            }),
        );
        assert_eq!(first.snapshot().catalog_statements, 2);
        assert_eq!(second.snapshot().catalog_statements, 1);

        sqlx::query("SELECT 4").execute(&pool).await.unwrap();
        assert_eq!(first.snapshot().catalog_statements, 2);
        assert_eq!(second.snapshot().catalog_statements, 1);

        let third = crate::request_work::RequestWork::new();
        third
            .scope(async {
                sqlx::query("SELECT 5").execute(&pool).await.unwrap();
            })
            .await;
        assert_eq!(third.snapshot().catalog_statements, 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn closing_a_traced_catalog_connection_releases_its_counter_arc() {
        let directory = tempfile::tempdir().unwrap();
        let pool = open_host_control_plane_sqlite_pool(&directory.path().join("catalog.db"))
            .await
            .unwrap();
        let work = crate::request_work::RequestWork::new();
        let weak = work
            .scope(async {
                let counters = crate::request_work::current().unwrap();
                let weak = Arc::downgrade(&counters);
                drop(counters);
                let connection = pool.acquire().await.unwrap();
                connection.close().await.unwrap();
                weak
            })
            .await;
        drop(work);
        assert!(
            weak.upgrade().is_none(),
            "SQLite close retained the trace-owned request counter Arc"
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn opening_a_host_control_plane_pool_awaits_unused_read_pool_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let database = open_database_at(&directory.path().join("catalog.db"))
            .await
            .unwrap();
        let read_pool = database.pool().clone();

        let write_pool = retain_host_control_plane_sqlite_pool(database).await;

        assert!(read_pool.is_closed(), "unused read pool remained open");
        assert_eq!(read_pool.size(), 0, "unused read pool was not drained");
        assert!(!write_pool.is_closed(), "retained write pool was closed");
        let mut transaction = begin_host_control_plane_sqlite_write(&write_pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE lifecycle_probe (value TEXT NOT NULL)")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        write_pool.close().await;
    }
}

fn path_from_url(url: &str) -> &Path {
    Path::new(url.strip_prefix("file:").unwrap_or(url))
}

macro_rules! probe_database_body {
    ($path:expr, $current_version:expr, $immutable:expr) => {{
        let path = $path;
        let current_version = $current_version;
        if !path.exists() {
            return DatabaseVersionState::Missing;
        }
        // Probing must not negotiate or change journal mode: doing so can checkpoint
        // a healthy WAL or create/remove sidecars. A dedicated read-only connection
        // makes the non-mutating contract structural.
        let options = match SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display())) {
            Ok(options) => options
                .create_if_missing(false)
                .read_only(true)
                .immutable($immutable)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5)),
            Err(err) => return DatabaseVersionState::Unreadable(err.to_string()),
        };
        let mut connection = match SqliteConnection::connect_with(&options).await {
            Ok(connection) => connection,
            Err(err) => return DatabaseVersionState::Unreadable(err.to_string()),
        };
        let result: Result<(i64, i64)> = async {
            let version: i64 = sqlx::query("PRAGMA user_version")
                .fetch_one(&mut connection)
                .await?
                .get(0);
            let objects: i64 =
                sqlx::query("SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
                    .fetch_one(&mut connection)
                    .await?
                    .get(0);
            let integrity: String = sqlx::query("PRAGMA quick_check(1)")
                .fetch_one(&mut connection)
                .await?
                .get(0);
            if integrity != "ok" {
                return Err(crate::error::Error::engine(format!(
                    "SQLite quick_check failed: {integrity}"
                )));
            }
            Ok((version, objects))
        }
        .await;
        let _ = connection.close().await;
        match result {
            Err(err) => DatabaseVersionState::Unreadable(err.to_string()),
            Ok((0, 0)) => DatabaseVersionState::Empty,
            Ok((0, _)) => DatabaseVersionState::UnversionedNonEmpty,
            Ok((version, _)) if version > current_version => DatabaseVersionState::Future(version),
            Ok((version, _)) => DatabaseVersionState::Known(version),
        }
    }};
}

/// Probe an existing SQLite file without creating it.
pub async fn probe_database(path: &Path, current_version: i64) -> DatabaseVersionState {
    probe_database_body!(path, current_version, false)
}

async fn probe_database_immutable(path: &Path, current_version: i64) -> DatabaseVersionState {
    probe_database_body!(path, current_version, true)
}

/// Validate every current engine table/column/index/trigger against a fresh
/// schema built from the compiled DDL, while keeping the target file strictly
/// read-only.
///
/// `probe_database` intentionally answers only the version/integrity question.
/// Release planning needs this stronger seam so a partially applied or
/// hand-stamped current schema cannot be classified as `current` merely because
/// `PRAGMA user_version` has the expected value.
macro_rules! validate_current_engine_shape_body {
    ($path:expr, $immutable:expr) => {{
        let path = $path;
        let actual_options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .create_if_missing(false)
            .read_only(true)
            .immutable($immutable)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let mut actual = SqliteConnection::connect_with(&actual_options).await?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut actual)
            .await?;
        if version != CURRENT_ENGINE_SCHEMA_VERSION {
            actual.close().await?;
            return Err(Error::engine(
                "engine structural validation requires the current schema version",
            ));
        }

        let validation = validate_engine_shape_on(&mut actual, CURRENT_ENGINE_SCHEMA_VERSION).await;
        actual.close().await?;
        if !validation? {
            return Err(Error::engine(
                "engine schema is current-version but has an unknown or partial structural shape",
            ));
        }
        Ok(())
    }};
}

pub async fn validate_current_engine_shape_read_only(path: &Path) -> Result<()> {
    validate_current_engine_shape_body!(path, false)
}

pub(crate) async fn validate_current_engine_shape_immutable(path: &Path) -> Result<()> {
    validate_current_engine_shape_body!(path, true)
}

/// Validate a supported migration source against its released structural
/// shape, using the same contract comparison as current-schema admission.
///
/// Engine 39 is the first frozen engine baseline. Its complete contract digest
/// was measured from the immutable database emitted by released revision
/// `30350c0e`, independently of current DDL. That rejects a current database
/// whose version header was merely restamped to 39 and stays stable when later
/// engine schemas advance.
pub(crate) async fn validate_supported_engine_migration_source(
    connection: &mut SqliteConnection,
    version: i64,
) -> Result<()> {
    let actual_version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *connection)
        .await?;
    if actual_version != version || !validate_engine_shape_on(connection, version).await? {
        return Err(Error::engine(format!(
            "engine schema {version} has an unknown or partial structural shape"
        )));
    }
    Ok(())
}

pub(crate) async fn validate_engine_shape_on(
    actual: &mut SqliteConnection,
    version: i64,
) -> Result<bool> {
    let actual_contract = schema_shape_contract(actual).await?;
    if version == 39 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_39_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 40 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_40_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 41 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_41_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 42 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_42_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 43 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_43_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 44 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_44_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 45 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_45_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 46 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_46_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 47 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_47_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 48 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_48_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 49 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_49_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 50 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_50_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 51 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_51_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 52 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_52_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 53 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_53_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 54 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_54_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 55 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_55_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 56 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_56_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 57 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_57_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 58 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_58_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 59 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_59_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 60 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_60_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 61 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_61_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 62 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_62_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 63 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_63_SHAPE_CONTRACT_SHA256
        );
    }
    if version == 64 {
        return Ok(
            schema_shape_contract_sha256(&actual_contract) == ENGINE_64_SHAPE_CONTRACT_SHA256
        );
    }
    if version != CURRENT_ENGINE_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "no frozen engine structural shape is registered for schema {version}"
        )));
    }
    let reference_contract = current_reference_shape_contract().await?;
    Ok(actual_contract == *reference_contract)
}

/// Caches the successful immutable compiled reference only; each actual
/// database is freshly inspected; failed or cancelled init retries.
type CurrentShapeContract = BTreeMap<(String, String), Vec<String>>;

static CURRENT_REFERENCE_SHAPE: tokio::sync::OnceCell<CurrentShapeContract> =
    tokio::sync::OnceCell::const_new();

async fn current_reference_shape_contract() -> Result<&'static CurrentShapeContract> {
    CURRENT_REFERENCE_SHAPE
        .get_or_try_init(|| async {
            let reference_options = SqliteConnectOptions::from_str("sqlite::memory:")?
                .create_if_missing(true)
                .foreign_keys(true);
            let mut reference = SqliteConnection::connect_with(&reference_options).await?;
            for statement in DDL_STATEMENTS {
                sqlx::query(statement).execute(&mut reference).await?;
            }
            let contract = schema_shape_contract(&mut reference).await?;
            reference.close().await?;
            Ok(contract)
        })
        .await
}

fn schema_shape_contract_sha256(contract: &BTreeMap<(String, String), Vec<String>>) -> String {
    let ordered = contract.iter().collect::<Vec<_>>();
    hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&ordered).expect("engine shape contract is serializable"),
    ))
}

#[cfg(test)]
pub(crate) async fn schema_shape_contract_sha256_for_test(
    connection: &mut SqliteConnection,
) -> Result<String> {
    Ok(schema_shape_contract_sha256(
        &schema_shape_contract(connection).await?,
    ))
}

#[cfg(test)]
pub(crate) async fn validate_engine_shape_on_for_test(
    connection: &mut SqliteConnection,
    version: i64,
) -> Result<bool> {
    validate_engine_shape_on(connection, version).await
}

fn schema_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '$')
}

fn schema_trivia_end(characters: &[char], mut index: usize) -> usize {
    loop {
        let start = index;
        while characters
            .get(index)
            .is_some_and(|character| character.is_whitespace())
        {
            index += 1;
        }
        if characters.get(index) == Some(&'-') && characters.get(index + 1) == Some(&'-') {
            index += 2;
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
        } else if characters.get(index) == Some(&'/') && characters.get(index + 1) == Some(&'*') {
            index += 2;
            while index + 1 < characters.len()
                && !(characters[index] == '*' && characters[index + 1] == '/')
            {
                index += 1;
            }
            index = (index + 2).min(characters.len());
        }
        if index == start {
            return index;
        }
    }
}

fn schema_keyword_end(characters: &[char], index: usize, keyword: &str) -> Option<usize> {
    if index > 0 && schema_identifier_character(characters[index - 1]) {
        return None;
    }
    let mut end = index;
    for expected in keyword.chars() {
        let actual = *characters.get(end)?;
        if !actual.eq_ignore_ascii_case(&expected) {
            return None;
        }
        end += 1;
    }
    if characters
        .get(end)
        .is_some_and(|character| schema_identifier_character(*character))
    {
        return None;
    }
    Some(end)
}

fn if_not_exists_end(characters: &[char], index: usize) -> Option<usize> {
    let after_if = schema_keyword_end(characters, index, "if")?;
    let before_not = schema_trivia_end(characters, after_if);
    if before_not == after_if {
        return None;
    }
    let after_not = schema_keyword_end(characters, before_not, "not")?;
    let before_exists = schema_trivia_end(characters, after_not);
    if before_exists == after_not {
        return None;
    }
    schema_keyword_end(characters, before_exists, "exists")
}

pub(crate) fn normalized_schema_sql(sql: Option<String>) -> String {
    let Some(sql) = sql else {
        return "<implicit>".to_owned();
    };
    let characters: Vec<char> = sql.chars().collect();
    let mut normalized = String::with_capacity(sql.len());
    let mut index = 0;
    while index < characters.len() {
        let after_trivia = schema_trivia_end(&characters, index);
        if after_trivia != index {
            index = after_trivia;
            continue;
        }
        if let Some(after_clause) = if_not_exists_end(&characters, index) {
            index = after_clause;
            continue;
        }
        let character = characters[index];
        if matches!(character, '\'' | '"' | '`' | '[') {
            let closing = if character == '[' { ']' } else { character };
            normalized.push(character);
            index += 1;
            while index < characters.len() {
                let quoted = characters[index];
                normalized.push(quoted);
                index += 1;
                if quoted == closing {
                    if characters.get(index) == Some(&closing) {
                        normalized.push(closing);
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            continue;
        }
        normalized.extend(character.to_lowercase());
        index += 1;
    }
    normalized
}

async fn schema_shape_contract(
    connection: &mut SqliteConnection,
) -> Result<BTreeMap<(String, String), Vec<String>>> {
    let tables = sqlx::query(
        "SELECT name, sql FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )
    .fetch_all(&mut *connection)
    .await?;
    let mut contract = BTreeMap::new();
    for table in tables {
        let table_name: String = table.get("name");
        contract.insert(
            ("table".to_owned(), table_name.clone()),
            vec![normalized_schema_sql(table.get::<Option<String>, _>("sql"))],
        );

        for column in sqlx::query(
            "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden
             FROM pragma_table_xinfo(?) ORDER BY cid",
        )
        .bind(&table_name)
        .fetch_all(&mut *connection)
        .await?
        {
            let cid: i64 = column.get("cid");
            contract.insert(
                ("column".to_owned(), format!("{table_name}:{cid}")),
                vec![
                    column.get::<String, _>("name"),
                    column.get::<String, _>("type"),
                    column.get::<i64, _>("notnull").to_string(),
                    column
                        .get::<Option<String>, _>("dflt_value")
                        .unwrap_or_else(|| "<none>".to_owned()),
                    column.get::<i64, _>("pk").to_string(),
                    column.get::<i64, _>("hidden").to_string(),
                ],
            );
        }

        for foreign_key in sqlx::query(
            "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\"
             FROM pragma_foreign_key_list(?) ORDER BY id, seq",
        )
        .bind(&table_name)
        .fetch_all(&mut *connection)
        .await?
        {
            let id: i64 = foreign_key.get("id");
            let seq: i64 = foreign_key.get("seq");
            contract.insert(
                ("foreign_key".to_owned(), format!("{table_name}:{id}:{seq}")),
                vec![
                    foreign_key.get::<String, _>("table"),
                    foreign_key
                        .get::<Option<String>, _>("from")
                        .unwrap_or_else(|| "<none>".to_owned()),
                    foreign_key
                        .get::<Option<String>, _>("to")
                        .unwrap_or_else(|| "<none>".to_owned()),
                    foreign_key.get::<String, _>("on_update"),
                    foreign_key.get::<String, _>("on_delete"),
                    foreign_key.get::<String, _>("match"),
                ],
            );
        }

        for index in sqlx::query(
            "SELECT seq, name, \"unique\", origin, partial
             FROM pragma_index_list(?) ORDER BY seq",
        )
        .bind(&table_name)
        .fetch_all(&mut *connection)
        .await?
        {
            let index_name: String = index.get("name");
            // FTS shadow tables expose implicit primary-key indexes through
            // pragma_index_list without corresponding sqlite_schema rows.
            let index_sql: Option<String> = sqlx::query_scalar(
                "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?",
            )
            .bind(&index_name)
            .fetch_optional(&mut *connection)
            .await?
            .flatten();
            contract.insert(
                ("index".to_owned(), index_name.clone()),
                vec![
                    table_name.clone(),
                    index.get::<i64, _>("unique").to_string(),
                    index.get::<String, _>("origin"),
                    index.get::<i64, _>("partial").to_string(),
                    normalized_schema_sql(index_sql),
                ],
            );
            for index_column in sqlx::query(
                "SELECT seqno, cid, name, \"desc\", coll, key
                 FROM pragma_index_xinfo(?) ORDER BY seqno",
            )
            .bind(&index_name)
            .fetch_all(&mut *connection)
            .await?
            {
                let seqno: i64 = index_column.get("seqno");
                contract.insert(
                    ("index_column".to_owned(), format!("{index_name}:{seqno}")),
                    vec![
                        index_column.get::<i64, _>("cid").to_string(),
                        index_column
                            .get::<Option<String>, _>("name")
                            .unwrap_or_else(|| "<none>".to_owned()),
                        index_column.get::<i64, _>("desc").to_string(),
                        index_column
                            .get::<Option<String>, _>("coll")
                            .unwrap_or_else(|| "<none>".to_owned()),
                        index_column.get::<i64, _>("key").to_string(),
                    ],
                );
            }
        }
    }

    for trigger in sqlx::query(
        "SELECT name, tbl_name, sql FROM sqlite_schema
         WHERE type = 'trigger' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        contract.insert(
            ("trigger".to_owned(), trigger.get::<String, _>("name")),
            vec![
                trigger.get::<String, _>("tbl_name"),
                normalized_schema_sql(trigger.get::<Option<String>, _>("sql")),
            ],
        );
    }
    Ok(contract)
}

/// Open a current engine database, refusing every schema state that ordinary
/// serving must not repair or migrate. The missing-file path is non-creating.
/// Engine-shipped meta defaults are reconciled only after version validation.
pub async fn open_existing_database(url: &str) -> Result<Db> {
    if url == ":memory:" {
        return Err(crate::error::Error::engine(
            "open_existing_database requires an on-disk path",
        ));
    }
    let path = path_from_url(url);
    let state = probe_database(path, CURRENT_ENGINE_SCHEMA_VERSION).await;
    if state != DatabaseVersionState::Known(CURRENT_ENGINE_SCHEMA_VERSION) {
        // Serving still refuses every non-current database, but the remedy now
        // depends on where the database sits. Since a baseline exists, one at
        // or above it can be migrated forward, and telling its owner to
        // "reset or recreate" would be advice to destroy recoverable data.
        let migratable = matches!(
            (&state, SUPPORTED_ENGINE_SCHEMA_BASELINE),
            (DatabaseVersionState::Known(version), Some(baseline))
                if (baseline..CURRENT_ENGINE_SCHEMA_VERSION).contains(version)
        );
        let remedy = if migratable {
            "ordinary serving does not migrate; run `operator migrate-db` to bring it to engine schema"
        } else {
            "it is outside the supported schema window; reset or recreate this database at engine schema"
        };
        return Err(crate::error::Error::engine(format!(
            "refusing to open {}: {state}; {remedy} {CURRENT_ENGINE_SCHEMA_VERSION}",
            path.display()
        )));
    }
    let write_pool = open_pool(url, false, WritePoolKind::Workspace).await?;
    let read_pool = open_read_pool(url).await?;
    let governed_pool = match open_governed_pool(url, false).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            read_pool.close().await;
            return Err(error);
        }
    };
    let db = Db {
        write_pool,
        read_pool,
        governed_pool,
        location: Arc::new(DatabaseLocation {
            path: path.to_path_buf(),
            open_mode: DatabaseOpenMode::ReadWrite,
        }),
        handle_id: uuid::Uuid::new_v4(),
        embedder: None,
        rollup_cache: Arc::new(Mutex::new(RollupCache::default())),
        visible_set_cache: Arc::new(Mutex::new(
            crate::visible_set_cache::VisibleSetCache::default(),
        )),
        inbox_snapshots: Arc::new(Mutex::new(HashMap::new())),
        realtime_hub: None,
        workspace_index: Arc::new(tokio::sync::RwLock::new(None)),
        workspace_index_fold: Arc::new(AtomicBool::new(false)),
        workspace_index_refused: Arc::new(Mutex::new(None)),
        workspace_snapshots: Arc::new(Mutex::new(
            crate::workspace_snapshot::SnapshotStore::default(),
        )),
        portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
        capture_queue: crate::mcp::interactions::CaptureQueue::spawn(),
        database_id_cache: Arc::new(tokio::sync::OnceCell::new()),
        _tmp: None,
    };
    let revision_violations = crate::authorization_revision::state_violations(&db).await?;
    if !revision_violations.is_empty() {
        db.close().await;
        return Err(crate::error::Error::engine(format!(
            "refusing to open malformed authorization revision state: {}",
            revision_violations.join("; ")
        )));
    }
    let violations = crate::authorization::state_violations(&db).await?;
    if !violations.is_empty() {
        db.close().await;
        return Err(crate::error::Error::engine(format!(
            "refusing to open malformed authorization state: {}",
            violations.join("; ")
        )));
    }
    let policy_log_violations = crate::policy::state_violations(&db).await?;
    if !policy_log_violations.is_empty() {
        db.close().await;
        return Err(crate::error::Error::engine(format!(
            "refusing to open malformed policy event log: {}",
            policy_log_violations.join("; ")
        )));
    }
    let control_log_violations = crate::control::state_violations(&db).await?;
    if !control_log_violations.is_empty() {
        db.close().await;
        return Err(crate::error::Error::engine(format!(
            "refusing to open malformed instruction control event log: {}",
            control_log_violations.join("; ")
        )));
    }
    let identity_violations = crate::identity::state_violations(&db).await?;
    if !identity_violations.is_empty() {
        db.close().await;
        return Err(crate::error::Error::engine(format!(
            "refusing to open malformed identity state: {}",
            identity_violations.join("; ")
        )));
    }
    seed_meta_tier(&db).await?;
    Ok(db)
}

/// Open an existing current-engine SQLite database for local standby reads.
///
/// Both internal snapshot queries and public observation queries are backed by
/// pools opened with SQLite's physical `SQLITE_OPEN_READONLY` flag. This path
/// never creates a missing database and deliberately skips migrations, repair,
/// seed reconciliation, and every other startup write.
pub async fn open_existing_database_standby_read_only(url: &str) -> Result<Db> {
    if url == ":memory:" {
        return Err(crate::error::Error::engine(
            "standby read-only open requires an existing on-disk database",
        ));
    }
    let path = path_from_url(url);
    let state = probe_database_immutable(path, CURRENT_ENGINE_SCHEMA_VERSION).await;
    if state != DatabaseVersionState::Known(CURRENT_ENGINE_SCHEMA_VERSION) {
        return Err(crate::error::Error::engine(format!(
            "refusing standby read-only open of {}: {state}; expected engine schema {CURRENT_ENGINE_SCHEMA_VERSION}",
            path.display()
        )));
    }

    validate_current_engine_shape_immutable(path).await?;

    let write_pool = open_immutable_read_pool(url).await?;
    let read_pool = match open_immutable_read_pool(url).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            return Err(error);
        }
    };
    // Standby keeps today's behaviour exactly: the governed path acquires from
    // the same physically read-only tier as the write pool does, so governed
    // SQL neither gains nor loses capability in standby mode. A dedicated
    // read-write governed pool here would be the only writable handle on an
    // immutable open.
    let governed_pool = match open_immutable_read_pool(url).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            read_pool.close().await;
            return Err(error);
        }
    };
    let db = Db {
        write_pool,
        read_pool,
        governed_pool,
        location: Arc::new(DatabaseLocation {
            path: path.to_path_buf(),
            open_mode: DatabaseOpenMode::StandbyReadOnly,
        }),
        handle_id: uuid::Uuid::new_v4(),
        embedder: None,
        rollup_cache: Arc::new(Mutex::new(RollupCache::default())),
        visible_set_cache: Arc::new(Mutex::new(
            crate::visible_set_cache::VisibleSetCache::default(),
        )),
        inbox_snapshots: Arc::new(Mutex::new(HashMap::new())),
        realtime_hub: None,
        workspace_index: Arc::new(tokio::sync::RwLock::new(None)),
        workspace_index_fold: Arc::new(AtomicBool::new(false)),
        workspace_index_refused: Arc::new(Mutex::new(None)),
        workspace_snapshots: Arc::new(Mutex::new(
            crate::workspace_snapshot::SnapshotStore::default(),
        )),
        portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
        capture_queue: crate::mcp::interactions::CaptureQueue::spawn(),
        database_id_cache: Arc::new(tokio::sync::OnceCell::new()),
        _tmp: None,
    };
    for (label, violations) in [
        (
            "authorization revision state",
            crate::authorization_revision::state_violations(&db).await?,
        ),
        (
            "authorization state",
            crate::authorization::state_violations(&db).await?,
        ),
        (
            "policy event log",
            crate::policy::state_violations(&db).await?,
        ),
        (
            "instruction control event log",
            crate::control::state_violations(&db).await?,
        ),
        (
            "identity state",
            crate::identity::state_violations(&db).await?,
        ),
    ] {
        if !violations.is_empty() {
            db.close().await;
            return Err(crate::error::Error::engine(format!(
                "refusing standby read-only open of malformed {label}: {}",
                violations.join("; ")
            )));
        }
    }
    Ok(db)
}

#[cfg(test)]
mod standby_read_only_open_tests {
    use super::*;

    #[tokio::test]
    async fn standby_open_refuses_missing_and_memory_databases() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.db");
        assert!(
            open_existing_database_standby_read_only(missing.to_str().unwrap())
                .await
                .is_err()
        );
        assert!(!missing.exists());
        assert!(open_existing_database_standby_read_only(":memory:")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn standby_open_makes_all_query_tiers_physically_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standby.db");
        let source = create_database(path.to_str().unwrap()).await.unwrap();
        // Immutable standby readers deliberately ignore WAL sidecars. Publish
        // the fixture through the same verified checkpoint boundary as a real
        // whole-file handoff; merely closing all three pools concurrently can leave
        // committed schema frames in the WAL under a parallel test load.
        checkpoint_and_close_hosted_adoption_database(source)
            .await
            .unwrap();

        let db = open_existing_database_standby_read_only(path.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(db.open_mode(), DatabaseOpenMode::StandbyReadOnly);
        assert!(
            sqlx::query("CREATE TABLE public_pool_write_probe (value INTEGER)")
                .execute(db.pool())
                .await
                .is_err()
        );
        assert!(
            sqlx::query("CREATE TABLE snapshot_pool_write_probe (value INTEGER)")
                .execute(db.write_pool())
                .await
                .is_err()
        );
        assert!(
            sqlx::query("CREATE TABLE governed_pool_write_probe (value INTEGER)")
                .execute(db.governed_pool())
                .await
                .is_err()
        );
        db.close().await;
    }
}

pub async fn open_existing_database_at(path: &Path) -> Result<Db> {
    open_existing_database(&path.to_string_lossy()).await
}

/// Apply the full v1 candidate schema to a fresh database.
pub async fn apply_schema(db: &Db) -> Result<()> {
    // Statements are ordered so every FK target exists before its referrer;
    // applied in one write transaction (the libSQL client's `batch('write')`).
    let mut tx = begin_write(&db.write_pool).await?;
    for statement in DDL_STATEMENTS {
        sqlx::query(statement).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    sqlx::query(&format!(
        "PRAGMA application_id = {}",
        crate::interchange::source_history_application_id(crate::interchange::REVISION)
    ))
    .execute(db.write_pool())
    .await?;
    let revision_violations = crate::authorization_revision::state_violations(db).await?;
    if !revision_violations.is_empty() {
        return Err(crate::error::Error::engine(format!(
            "schema application left malformed authorization revision state: {}",
            revision_violations.join("; ")
        )));
    }
    Ok(())
}

/// Open a database and stand the schema up in one call. The workspace is named
/// [`DEFAULT_WORKSPACE_NAME`]; callers that know a better name at genesis (the
/// hosted per-account provisioner) use [`create_database_named`] instead of
/// renaming the root afterwards.
pub async fn create_database(url: &str) -> Result<Db> {
    create_database_named(url, crate::schema::DEFAULT_WORKSPACE_NAME).await
}

/// [`create_database`] with an explicit workspace (root record) display name.
/// The name is written by the genesis batch itself, so the database is never
/// briefly named something else and the event log carries no synthetic rename.
pub async fn create_database_named(url: &str, workspace_name: &str) -> Result<Db> {
    let db = open_database(url).await?;
    apply_schema(&db).await?;
    seed_meta_tier(&db).await?;
    seed_content_tier_named(&db, workspace_name).await?;
    crate::policy::seed_root_policy(&db).await?;
    crate::identity::seed_database_identity(&db).await?;
    Ok(db)
}

/// Install the deterministic engine-owned root folders in a schema-only
/// database. Public for migration/replay fixtures that deliberately manage the
/// meta tier themselves. The rows are ordinary event-sourced content so
/// rebuild-and-diff needs no startup exception; a partial seed is corruption,
/// not something to guess at.
pub async fn seed_content_tier(db: &Db) -> Result<()> {
    seed_content_tier_named(db, crate::schema::DEFAULT_WORKSPACE_NAME).await
}

/// [`seed_content_tier`] with an explicit workspace (root record) display name.
pub async fn seed_content_tier_named(db: &Db, workspace_name: &str) -> Result<()> {
    use crate::schema::{ROOT_RECORD_ID, UNFILED_RECORD_ID};
    use crate::store::{append_engine_seed_batch, AppendSpec};
    use serde_json::json;

    let present: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id IN (?, ?)")
        .bind(ROOT_RECORD_ID)
        .bind(UNFILED_RECORD_ID)
        .fetch_one(db.write_pool())
        .await?;
    match present {
        2 => return Ok(()),
        1 => {
            return Err(crate::error::Error::engine(
                "content home seed is partial: expected both native:root and native:unfiled",
            ))
        }
        _ => {}
    }
    append_engine_seed_batch(
        db,
        vec![
            AppendSpec {
                record_id: ROOT_RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Collection",
                    "kind": "folder",
                    "name": workspace_name,
                    "home_id": null,
                    "persistence": "enduring"
                }),
                actor: Some("engine:seed".into()),
            },
            AppendSpec {
                record_id: UNFILED_RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Collection",
                    "kind": "folder",
                    "name": "Unfiled",
                    "home_id": ROOT_RECORD_ID,
                    "persistence": "enduring"
                }),
                actor: Some("engine:seed".into()),
            },
        ],
    )
    .await?;
    Ok(())
}

/// Install the engine-shipped meta tier after the schema is known to exist.
/// Both seeders are log-idempotent, so this is safe on fresh creation and on
/// every subsequent open without growing `meta_events` with no-op writes.
pub(crate) async fn seed_meta_tier(db: &Db) -> Result<()> {
    crate::storage_profile::with_operation(
        db,
        "engine_seed_meta_tier",
        Some("native.guarded-write.v1"),
        async {
            crate::meta::seed_vocabularies(db).await?;
            crate::meta::seed_recommended_pack_schema_config(db).await?;
            Ok(())
        },
    )
    .await
}

#[cfg(test)]
mod rollup_cache_tests {
    use super::*;
    use serde_json::json;

    fn key(index: usize) -> RollupCacheKey {
        RollupCacheKey {
            principal: "test-principal".into(),
            trusted_local_bypass: false,
            is_member: true,
            spec_digest: format!("digest-{index}"),
            bearer_id: "bearer".into(),
            rollup_name: "total".into(),
            content_event_seq: 1,
            meta_event_seq: 1,
            authorization_revision: 1,
        }
    }

    #[test]
    fn rollup_cache_is_entry_bounded_and_lru() {
        let mut cache = RollupCache::default();
        for index in 0..ROLLUP_CACHE_MAX_ENTRIES {
            cache.insert(key(index), json!({ "value": index }));
        }
        assert!(cache.get(&key(0)).is_some(), "touch oldest entry");
        cache.insert(key(ROLLUP_CACHE_MAX_ENTRIES), json!({ "value": "new" }));
        assert_eq!(cache.entries.len(), ROLLUP_CACHE_MAX_ENTRIES);
        assert!(cache.get(&key(0)).is_some(), "recently used entry survives");
        assert!(
            cache.get(&key(1)).is_none(),
            "least recently used entry evicts"
        );
    }

    #[test]
    fn rollup_cache_refuses_an_oversized_single_result() {
        let mut cache = RollupCache::default();
        cache.insert(
            key(0),
            json!({ "value": "x".repeat(ROLLUP_CACHE_MAX_BYTES) }),
        );
        assert!(cache.entries.is_empty());
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn rollup_cache_keys_distinguish_member_from_guest_footing() {
        // A demotion does not bump authorization_revision (catalog roles are
        // host-supplied, not portable inputs), so the footing bit is the
        // only thing stopping a guest from being served a member-era entry.
        let mut member = key(0);
        member.is_member = true;
        let mut guest = key(0);
        guest.is_member = false;
        assert_ne!(member, guest);
        let mut cache = RollupCache::default();
        cache.insert(member.clone(), json!({ "value": "member" }));
        assert_eq!(
            cache.get(&guest),
            None,
            "guest footing must miss the member entry"
        );
        assert!(cache.get(&member).is_some());
    }
}

#[cfg(test)]
mod release_preflight_shape_tests {
    use super::*;

    #[tokio::test]
    async fn legacy_v38_shape_is_refused_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-v38.db");
        let database = create_database(path.to_str().unwrap()).await.unwrap();
        database.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("DROP TRIGGER binding_audit_no_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER binding_audit_no_delete")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 38")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        checkpoint_fixture_wal(&path).await;
        let before = std::fs::read(&path).unwrap();
        let error = open_existing_database(path.to_str().unwrap())
            .await
            .unwrap_err()
            .to_string();
        // 38 is below the declared baseline, so recreating really is the only
        // remedy and the message must not offer a migration that cannot run.
        assert_eq!(
            error,
            format!(
                "refusing to open {}: schema 38; it is outside the supported schema window; reset or recreate this database at engine schema {}",
                path.display(),
                CURRENT_ENGINE_SCHEMA_VERSION
            )
        );
        assert_main_file_unchanged(&path, &before);
    }

    #[tokio::test]
    async fn current_version_shape_with_fts_shadow_indexes_is_accepted_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("current.db");
        let database = create_database(path.to_str().unwrap()).await.unwrap();
        database.close().await;

        checkpoint_fixture_wal(&path).await;
        let before = std::fs::read(&path).unwrap();
        validate_current_engine_shape_read_only(&path)
            .await
            .unwrap();
        assert_main_file_unchanged(&path, &before);
    }

    #[test]
    fn schema_sql_normalization_ignores_if_not_exists_keyword_formatting() {
        let with_clause = normalized_schema_sql(Some(
            "CREATE TABLE IF /* deployment guard */ NOT\n EXISTS example (value TEXT)".into(),
        ));
        let without_clause = normalized_schema_sql(Some("create table example(value text)".into()));

        assert_eq!(with_clause, without_clause);
    }

    #[test]
    fn schema_sql_normalization_preserves_if_not_exists_inside_identifier() {
        let identifier =
            normalized_schema_sql(Some("CREATE TABLE myifnotexiststable (value TEXT)".into()));
        let different_identifier =
            normalized_schema_sql(Some("CREATE TABLE mytable (value TEXT)".into()));

        assert_ne!(identifier, different_identifier);
        assert!(identifier.contains("myifnotexiststable"));
    }

    #[test]
    fn schema_sql_normalization_preserves_if_not_exists_inside_literal() {
        let literal = normalized_schema_sql(Some(
            "CREATE TABLE example (value TEXT DEFAULT 'IF NOT EXISTS')".into(),
        ));
        let different_literal =
            normalized_schema_sql(Some("CREATE TABLE example (value TEXT DEFAULT '')".into()));

        assert_ne!(literal, different_literal);
        assert!(literal.contains("'IF NOT EXISTS'"));
    }

    /// Bring the fixture database fully to rest before a byte-identity
    /// snapshot.
    ///
    /// The fixtures in this module take a whole-file `before` snapshot and
    /// assert the operation under test left it byte-for-byte unchanged. That
    /// assertion is only meaningful when no WAL checkpoint can land in the
    /// snapshot window. `Db::close`/`SqliteConnection::close` are awaited, but
    /// SQLite skips the close-time checkpoint whenever another handle still
    /// has the file open (the three pools of a `Db` close concurrently, and a
    /// physical close can lag under heavy load, e.g. coverage
    /// instrumentation). A residual `-wal` left by such a skipped checkpoint
    /// is later folded into the main file by whichever writable handle closes
    /// last — growing the main file mid-assertion even though the operation
    /// under test (which opens with `SQLITE_OPEN_READONLY` and provably
    /// cannot checkpoint) never wrote a byte.
    ///
    /// A successful `wal_checkpoint(TRUNCATE)` is the barrier that excludes
    /// that: it waits (busy handler) for any straggling checkpointer, folds
    /// every frame into the main file, and truncates the WAL, so a late close
    /// afterwards has nothing left to write.
    async fn checkpoint_fixture_wal(path: &Path) {
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(30));
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        let (busy, log_frames, checkpointed): (i64, i64, i64) =
            sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(busy, 0, "fixture checkpoint must not be busy");
        assert_eq!(
            log_frames, checkpointed,
            "fixture WAL must be fully checkpointed"
        );
        connection.close().await.unwrap();
    }

    /// Byte-identity assertion with a diagnosable failure: on mismatch it
    /// reports the sizes and first differing offset instead of dumping two
    /// multi-megabyte byte arrays into the test log.
    fn assert_main_file_unchanged(path: &Path, before: &[u8]) {
        let after = std::fs::read(path).unwrap();
        if after != before {
            let first_diff = before
                .iter()
                .zip(after.iter())
                .position(|(b, a)| b != a)
                .unwrap_or_else(|| before.len().min(after.len()));
            panic!(
                "main database file changed during a read-only operation: \
                 before={} bytes, after={} bytes, first difference at offset {}",
                before.len(),
                after.len(),
                first_diff
            );
        }
    }

    async fn assert_schema_text_edit_is_refused(table: &str, from: &str, to: &str) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial-current.db");
        let database = create_database(path.to_str().unwrap()).await.unwrap();
        database.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(30));
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA writable_schema = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        let changed = sqlx::query(
            "UPDATE sqlite_schema SET sql = replace(sql, ?, ?)
             WHERE type = 'table' AND name = ? AND instr(sql, ?) > 0",
        )
        .bind(from)
        .bind(to)
        .bind(table)
        .bind(from)
        .execute(&mut connection)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(changed, 1, "schema fixture did not match {table}: {from}");
        sqlx::query("PRAGMA writable_schema = OFF")
            .execute(&mut connection)
            .await
            .unwrap();
        // The quiescing checkpoint must run on this same connection: the
        // deliberately corrupted schema text makes any *new* writable
        // connection fail its schema parse ("orphan index"), while this
        // connection still holds the schema it parsed before the edit.
        // Read-only connections (the validator) tolerate the corruption.
        let (busy, log_frames, checkpointed): (i64, i64, i64) =
            sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(busy, 0, "fixture checkpoint must not be busy");
        assert_eq!(
            log_frames, checkpointed,
            "fixture WAL must be fully checkpointed"
        );
        connection.close().await.unwrap();

        let before = std::fs::read(&path).unwrap();
        assert!(validate_current_engine_shape_read_only(&path)
            .await
            .is_err());
        assert_main_file_unchanged(&path, &before);
    }

    #[tokio::test]
    async fn current_version_with_altered_same_name_index_is_refused_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial-current.db");
        let database = create_database(path.to_str().unwrap()).await.unwrap();
        database.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("DROP INDEX idx_records_type")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("CREATE INDEX idx_records_type ON records(kind)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        assert_eq!(
            probe_database(&path, CURRENT_ENGINE_SCHEMA_VERSION).await,
            DatabaseVersionState::Known(CURRENT_ENGINE_SCHEMA_VERSION),
            "the shallow version/integrity probe intentionally cannot detect the partial shape"
        );
        checkpoint_fixture_wal(&path).await;
        let before = std::fs::read(&path).unwrap();
        assert!(validate_current_engine_shape_read_only(&path)
            .await
            .is_err());
        assert_main_file_unchanged(&path, &before);
    }

    #[tokio::test]
    async fn current_version_with_removed_table_constraints_is_refused_without_writing() {
        assert_schema_text_edit_is_refused(
            "records",
            "name          TEXT NOT NULL DEFAULT ''",
            "name          TEXT NOT NULL",
        )
        .await;
        assert_schema_text_edit_is_refused(
            "content_event_sources",
            "TEXT PRIMARY KEY REFERENCES content_events(id) ON DELETE CASCADE",
            "TEXT PRIMARY KEY",
        )
        .await;
        assert_schema_text_edit_is_refused(
            "content_events",
            "id                      TEXT NOT NULL UNIQUE",
            "id                      TEXT NOT NULL",
        )
        .await;
        assert_schema_text_edit_is_refused(
            "policy_events",
            "TEXT NOT NULL CHECK (type IN ('policy.replaced','policy.inheritance_restored'))",
            "TEXT NOT NULL",
        )
        .await;
        assert_schema_text_edit_is_refused(
            "policy_events",
            "'policy.replaced'",
            "'Policy. Replaced'",
        )
        .await;
    }

    #[tokio::test]
    async fn warmed_reference_still_rejects_later_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let valid = directory.path().join("warmed-valid.db");
        let invalid = directory.path().join("warmed-invalid.db");

        let database = create_database(valid.to_str().unwrap()).await.unwrap();
        database.close().await;
        checkpoint_fixture_wal(&valid).await;
        validate_current_engine_shape_read_only(&valid)
            .await
            .unwrap();

        let database = create_database(invalid.to_str().unwrap()).await.unwrap();
        database.close().await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", invalid.display()))
            .unwrap()
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("DROP INDEX idx_records_type")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("CREATE INDEX idx_records_type ON records(kind)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        checkpoint_fixture_wal(&invalid).await;

        assert_eq!(
            probe_database(&invalid, CURRENT_ENGINE_SCHEMA_VERSION).await,
            DatabaseVersionState::Known(CURRENT_ENGINE_SCHEMA_VERSION),
            "the shallow probe cannot see the corruption; only the cached reference comparison can"
        );
        let before = std::fs::read(&invalid).unwrap();
        assert!(
            validate_current_engine_shape_read_only(&invalid)
                .await
                .is_err(),
            "a warmed reference must still reject a later-corrupted shape"
        );
        assert_main_file_unchanged(&invalid, &before);

        validate_current_engine_shape_read_only(&valid)
            .await
            .unwrap();
    }
}
