//! Typed sources for structured reads.
//!
//! A replay database contains a content projection, not a complete Native
//! database.  These wrappers make that boundary visible in function
//! signatures: projection-only helpers cannot reach live metadata or blobs,
//! while cross-tier readers must ask for each source explicitly.

use chrono::{DateTime, SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

use crate::db::Db;
use crate::error::Result;
use crate::events::EventRow;
use crate::mcp::registry::CounterFooting;

use super::error::contract_violation;

/// One explicit point in the authoritative content log.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AsOfSelector {
    ContentSeq(ContentSeqSelector),
    Timestamp(TimestampSelector),
    /// The position of the content event with this id, or `origin` for the
    /// empty prefix. Available to every caller; see [`crate::position`].
    EventId(EventIdSelector),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentSeqSelector {
    #[schemars(range(min = 0))]
    pub content_seq: i64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampSelector {
    pub timestamp: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventIdSelector {
    pub event_id: String,
}

/// Resolution metadata echoed by every explicit historical read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedAsOf {
    pub as_of: AsOfSelector,
    pub resolved_content_seq: i64,
    pub content_head_seq: i64,
}

/// The four named read capabilities of the query contract. Query names WHAT
/// it reads (projection, live meta, live blobs, the content log) and the two
/// consistency tiers it reads at; the SQLite kernel's `Db` implements them.
/// Query code never needs — and after the capability migration never gets —
/// the concrete `Db` handle out of a lens.
///
/// `snapshot_pool` is the read-your-writes tier (today `Db::write_pool`);
/// `shared_pool` is the concurrent shared read tier (today `Db::pool`). The
/// distinction is deliberate and load-bearing: several readers require
/// snapshot consistency with the latest commit. Migrations between tiers are
/// never a mechanical simplification.
pub(crate) trait ProjectionCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Live schema and vocabulary capability.
pub(crate) trait MetaCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Live content-addressed blob capability.
pub(crate) trait BlobCapability {
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Authoritative content-event capability used for anchored citation evidence.
pub(crate) trait ContentLogCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
}

/// The content projection capability (`records`, links, facets, targets,
/// projection-maintained indexes). It deliberately exposes no `Db` publicly.
#[derive(Clone, Copy)]
pub struct ProjectionRead<'a> {
    db: &'a Db,
}

impl<'a> ProjectionRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Read-your-writes projection tier.
    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        ProjectionCapability::snapshot_pool(self.db)
    }

    /// Concurrent shared projection tier.
    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        ProjectionCapability::shared_pool(self.db)
    }
}

/// Live schema and vocabulary capability.
#[derive(Clone, Copy)]
pub struct LiveMetaRead<'a> {
    db: &'a Db,
}

impl<'a> LiveMetaRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        MetaCapability::snapshot_pool(self.db)
    }

    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        MetaCapability::shared_pool(self.db)
    }
}

/// Live content-addressed blob capability.
#[derive(Clone, Copy)]
pub struct LiveBlobRead<'a> {
    db: &'a Db,
}

impl<'a> LiveBlobRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        BlobCapability::shared_pool(self.db)
    }
}

/// Authoritative content-event capability used for anchored citation evidence.
#[derive(Clone, Copy)]
pub struct ContentLogRead<'a> {
    db: &'a Db,
}

impl<'a> ContentLogRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        ContentLogCapability::snapshot_pool(self.db)
    }
}

/// The complete, honest source set for a structured read.
#[derive(Clone, Copy)]
pub struct ReadLens<'a> {
    projection: ProjectionRead<'a>,
    meta: LiveMetaRead<'a>,
    blobs: LiveBlobRead<'a>,
    content_log: ContentLogRead<'a>,
    temporal: Option<&'a ResolvedAsOf>,
    /// Member-copy serving (contract c323277 §1.3, §2.3): the projection holds
    /// only E(m), so per-id authorization is slice presence and the excluded
    /// companion reads are replaced by their member answer. False for every
    /// online caller.
    member: bool,
}

impl<'a> ReadLens<'a> {
    /// The unchanged live fast path: every capability addresses the live DB.
    pub fn live(db: &'a Db) -> Self {
        Self {
            projection: ProjectionRead::new(db),
            meta: LiveMetaRead::new(db),
            blobs: LiveBlobRead::new(db),
            content_log: ContentLogRead::new(db),
            temporal: None,
            member: db.open_mode() == crate::db::DatabaseOpenMode::MemberReadOnly,
        }
    }

    /// True for an admitted member copy. Every `if member` branch below gives
    /// the contract's member answer; online callers are unaffected.
    pub fn is_member(&self) -> bool {
        self.member
    }

    /// A replayed content projection combined with explicit live tiers.
    pub fn historical(projection: &'a Db, live: &'a Db, temporal: &'a ResolvedAsOf) -> Self {
        Self {
            projection: ProjectionRead::new(projection),
            meta: LiveMetaRead::new(live),
            blobs: LiveBlobRead::new(live),
            content_log: ContentLogRead::new(live),
            temporal: Some(temporal),
            member: false,
        }
    }

    /// Re-derive this lens with a different content projection while retaining
    /// its live metadata, blob and content-log tiers.
    pub(crate) fn with_projection<'b>(
        &'b self,
        projection: &'b Db,
        temporal: &'b ResolvedAsOf,
    ) -> ReadLens<'b> {
        ReadLens {
            projection: ProjectionRead::new(projection),
            meta: LiveMetaRead::new(self.meta.db),
            blobs: LiveBlobRead::new(self.blobs.db),
            content_log: ContentLogRead::new(self.content_log.db),
            temporal: Some(temporal),
            member: self.member,
        }
    }

    pub fn projection(self) -> ProjectionRead<'a> {
        self.projection
    }

    pub fn meta(self) -> LiveMetaRead<'a> {
        self.meta
    }

    pub fn blobs(self) -> LiveBlobRead<'a> {
        self.blobs
    }

    pub fn content_log(self) -> ContentLogRead<'a> {
        self.content_log
    }

    pub fn temporal(self) -> Option<&'a ResolvedAsOf> {
        self.temporal
    }
}

/// Resolve an explicit selector against one observed content-log head.
///
/// An event-id selector is resolved as a non-owner would (deny by default);
/// callers holding a [`Caller`](crate::mcp::Caller) use [`resolve_as_of_for`].
pub async fn resolve_as_of(db: &Db, selector: AsOfSelector) -> Result<ResolvedAsOf> {
    resolve_as_of_in_pool(db.write_pool(), selector).await
}

/// [`resolve_as_of`] for a caller whose counter footing decides how an event
/// id is resolved.
pub async fn resolve_as_of_for(
    db: &Db,
    footing: CounterFooting,
    selector: AsOfSelector,
) -> Result<ResolvedAsOf> {
    resolve_as_of_in_pool_for(db.write_pool(), footing, selector).await
}

/// Pool-scoped selector resolution for callers that must not queue on the
/// writer. Identical logic to [`resolve_as_of`]: the content-log head (and,
/// for timestamps, the resolved prefix) in one statement over committed
/// event state, with no same-transaction dependency.
pub async fn resolve_as_of_in_pool(
    pool: &sqlx::SqlitePool,
    selector: AsOfSelector,
) -> Result<ResolvedAsOf> {
    resolve_as_of_in_pool_for(pool, CounterFooting::NonOwner, selector).await
}

pub async fn resolve_as_of_in_pool_for(
    pool: &sqlx::SqlitePool,
    footing: CounterFooting,
    selector: AsOfSelector,
) -> Result<ResolvedAsOf> {
    // One connection for the whole resolution, including the holding
    // observation below. It does not make the two a single snapshot — that
    // would need a transaction — but it keeps them on one reader rather than
    // two, and the residue is bounded: only a compaction interleaving exactly
    // here could let a position pass the guard and then be gone, and
    // compaction is a single transactional writer that does not exist yet.
    let mut conn = pool.acquire().await?;
    let (resolved_content_seq, content_head_seq) = match &selector {
        AsOfSelector::ContentSeq(value) => {
            if value.content_seq < 0 {
                return Err(contract_violation("as_of content_seq must be >= 0"));
            }
            let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(&mut *conn)
                .await?;
            if value.content_seq > head {
                return Err(contract_violation(format!(
                    "as_of content_seq {} is beyond current content head {}",
                    value.content_seq, head
                )));
            }
            (value.content_seq, head)
        }
        AsOfSelector::EventId(value) => {
            let seq = crate::position::resolve(&mut conn, footing, &value.event_id).await?;
            let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(&mut *conn)
                .await?;
            (seq, head)
        }
        AsOfSelector::Timestamp(value) => {
            let parsed = DateTime::parse_from_rfc3339(&value.timestamp).map_err(|_| {
                contract_violation("as_of timestamp must be a valid RFC 3339 timestamp")
            })?;
            let normalized = parsed
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true);
            // Both values come from one SQLite statement and therefore one
            // snapshot. MAX(seq) is the deterministic tie-break for equal
            // event timestamps.
            let row = sqlx::query(
                "SELECT COALESCE(MAX(seq), 0) AS head,\n\
                        COALESCE(MAX(CASE WHEN created_at <= ? THEN seq END), 0) AS resolved\n\
                   FROM content_events",
            )
            .bind(normalized)
            .fetch_one(&mut *conn)
            .await?;
            (row.try_get("resolved")?, row.try_get("head")?)
        }
    };
    // Honest absence (`docs/honest-absence-contract.md` §3, §5c). An as-of
    // read is served by replaying the content prefix into a scratch
    // projection, which is only correct when the whole prefix is held. Over a
    // windowed log it would replay a *suffix* as though it were a prefix and
    // return a rendering of an empty workspace as truthful history — a
    // confident wrong answer, not a short one. So the surface refuses.
    //
    // At window = ∞ the floor is the first event and this cannot fire: every
    // caller-supplied position is at or above the position before it.
    let holding = crate::holding::HoldingDisclosure::observe(&mut conn).await?;
    if !holding.holds_content_position(resolved_content_seq) {
        // A pruned position is refused like an unknown one: the windowed
        // refusal below names sequence numbers.
        if matches!(selector, AsOfSelector::EventId(_)) {
            return Err(crate::position::unknown_position());
        }
        return Err(holding.not_held(
            "as_of",
            &format!("the state at content_seq {resolved_content_seq}"),
        ));
    }
    Ok(ResolvedAsOf {
        as_of: selector,
        resolved_content_seq,
        content_head_seq,
    })
}

/// Replay one pinned content prefix into a fresh projection database.
///
/// The fold runs inside one transaction. Without it every projector statement
/// autocommits, and since a scratch database is an ordinary WAL file under
/// `$TMPDIR` (`open_database` gives `:memory:` a temp file so pooled
/// connections share one database) at SQLite's default `synchronous=FULL`,
/// each of the four to six statements an event projects costs its own commit
/// and flush. That is the whole of this function's cost: it is not the size of
/// the fold, it is committing several thousand times per render. One
/// transaction turns those into one commit.
///
/// The scratch database is discarded when the read completes, so the
/// transaction buys no durability — it is purely the batching that makes an
/// `as_of` read affordable. Every caller either propagates the error or
/// returns a diagnostic and closes the scratch, so rolling the fold back on
/// failure is not observable. The wrapping is here rather than inside
/// `replay_with_blob_seeds` because that function's failure behaviour is
/// asserted directly by tests which replay a deliberately invalid prefix and
/// then read what survived; keeping it a plain connection leaves those
/// assertions meaning what they meant.
///
/// This deliberately does not go through `Db::begin_write`. That boundary is
/// for governed writes to a real store — it enforces the storage-portability
/// policy, which a private temp file rebuilding a derived projection is not
/// subject to. The `BEGIN IMMEDIATE` it takes guards against a deferred
/// transaction reading before its first write and hitting SQLite's
/// deadlock-upgrade `SQLITE_BUSY`; neither half of that applies here, because
/// the fold's first statement on the scratch is an insert and a scratch
/// database has exactly one writer.
pub async fn replay_projection(live: &Db, scratch: &Db, seq: i64) -> Result<()> {
    replay_projection_in_pool(live.write_pool(), scratch, seq).await
}

pub(crate) async fn replay_projection_in_pool(
    live_pool: &sqlx::SqlitePool,
    scratch: &Db,
    seq: i64,
) -> Result<()> {
    let events = crate::query::events::log_prefix_in_pool(live_pool, seq).await?;
    replay_projection_events(scratch, &events).await
}

/// Advance a private replay projection with the next ordered, disjoint slice
/// of the content log. The caller owns the sequence boundary; the projector
/// still applies every event exactly once and in order.
///
/// A fold over a long history spends almost all of its time re-deriving, for
/// every body-carrying event, state that the next body-carrying event for the
/// same record overwrites: the four body-derived tables (`body_blocks`,
/// `record_mentions`, `body_task_items`, `record_body_json_nodes`), and the
/// FTS5 maintenance triggers on `records` (`records_fts` re-tokenises the old
/// and new body on every `records` write; `records_name_idx` indexes only the
/// name but fires on those same writes). A slice of at least
/// [`DEFERRED_FOLD_MIN_EVENTS`] events therefore folds like this, in one
/// transaction on a connection this function owns:
///
/// 1. fold pragmas go on the connection before `BEGIN` (`synchronous` cannot
///    change inside a transaction) and are put back afterwards, because the
///    connection returns to the scratch's pool and the same scratch is read
///    and advanced again;
/// 2. exactly the six FTS maintenance triggers are dropped — every other
///    trigger (authorization epochs, grant revisions, content-event metadata,
///    append-only guards) stays enabled, because several of them write state
///    during a fold and the rest cost nothing worth removing;
/// 3. the slice replays with body derivations deferred into an explicit
///    [`BodyDeferrals`], then flushed once per surviving (table, record);
/// 4. both FTS indexes are rebuilt from the final `records` rows;
/// 5. the six triggers are recreated from the schema authority's own DDL;
/// 6. commit.
///
/// A shorter slice takes the immediate path (see [`DEFERRED_FOLD_MIN_EVENTS`]):
/// one transaction, every event projecting its own derivations with all
/// triggers enabled. Both paths leave a fully materialised scratch on `Ok`,
/// which is what lets a caller read between two slices, as the version diff
/// does (`history.rs` reads the scratch after the first fold, then advances
/// it), and why an empty slice is legitimate.
///
/// What an error or a cancelled future leaves behind depends on when it
/// happens:
///
/// - Before the commit (a fold error, a failed rebuild, or the future being
///   dropped), the transaction rolls back — the drops, the replay, the flush
///   and the rebuild together — and the scratch is as it was. A connection
///   that was dropped mid-fold is closed rather than returned to the pool, so
///   the fold's pragmas can never reach another borrower.
/// - The commit itself is the line. If it succeeded, the slice is fully
///   materialised even if the future is dropped, or the pragma restoration
///   that follows fails, before this function returns. Restoration failure
///   after a successful commit does not fail the fold: the connection is
///   closed instead of reused and the slice stands. An `Err` therefore means
///   "this slice was not applied" except when the commit itself reports
///   failure after SQLite processed it, which no caller can distinguish; the
///   callers (the `as_of` readers) discard their private scratch on any
///   error.
///
/// Why the deferred path matches the immediate one on every prefix the
/// immediate path accepts. The deferred tables are written only by
/// body-carrying events and read by nothing during the fold, and each
/// replacement is a pure function of its last call's arguments, so running
/// only that last call yields the same rows (see [`BodyDeferrals`] for the
/// per-table argument, including tombstones that clear only mentions). The
/// FTS indexes are external-content indexes over `records`: rebuilding them
/// from the final rows indexes the same documents with the same tokenizers as
/// maintaining them one statement at a time, tombstones included (visibility
/// is a read concern). Shadow-table bytes and rowids of derived tables may
/// differ; logical contents and search answers do not.
///
/// The paths differ in what they REJECT, and since the mode is chosen by
/// slice length, so does this function. A body whose extraction fails and
/// that a later event supersedes aborts an immediate fold at that event but
/// not a deferred one; when a prefix is invalid the error reported, and its
/// order against a later event's own validation error, can differ; and a body
/// invalid at the end of slice A but replaced in slice B fails A alone yet
/// succeeds as one fold of A+B. The same invalid-then-valid history can thus
/// fail below the threshold and succeed once padded past it. An invalid FINAL
/// body fails either way. Callers that need event-by-event admission
/// (conformance, bounded attested replay) do not come through here; the
/// low-level `replay_with_blob_*` helpers stay immediate and keep their own
/// tests that read what survived a bad prefix.
pub(crate) async fn replay_projection_events(scratch: &Db, events: &[EventRow]) -> Result<()> {
    replay_projection_events_in_mode(scratch, events, FoldMode::for_slice(events.len()), None).await
}

/// Slices shorter than this take the immediate path.
///
/// Deferral buys a cost that scales with the history folded (re-deriving a
/// body on every rewrite) at the price of a cost that scales with the whole
/// scratch (rebuilding both FTS indexes from every `records` row, about 13 s
/// at Native HQ's 11,450 records). A small tail on a large scratch — the
/// second slice of a version diff, say — pays that fixed rebuild for a
/// handful of events whose per-event FTS and body maintenance would have cost
/// milliseconds. At HQ scale per-event maintenance averaged about 15 ms
/// before deferral, which puts the break-even somewhere around a thousand
/// events; 2,000 is a round number just past that. It is a heuristic, not a
/// tuned optimum and not a bound: the immediate side can still repeat
/// arbitrarily expensive extraction below it, and a large run of cheap
/// non-body events above it pays a rebuild it did not need. The paths also
/// differ in which invalid histories they reject (see
/// [`replay_projection_events`]), so this is not purely a cost choice.
const DEFERRED_FOLD_MIN_EVENTS: usize = 2_000;

/// How one slice is folded into a scratch. Both modes run in a single
/// transaction and leave a fully materialised scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FoldMode {
    /// Every event projects its body derivations and FTS maintenance as it
    /// goes, with all triggers enabled: the low-level replay behaviour.
    Immediate,
    /// Body derivations deferred to one flush, FTS triggers dropped and both
    /// indexes rebuilt; see [`replay_projection_events`].
    Deferred,
}

impl FoldMode {
    fn for_slice(events: usize) -> Self {
        if events < DEFERRED_FOLD_MIN_EVENTS {
            Self::Immediate
        } else {
            Self::Deferred
        }
    }
}

/// Points in a deferred fold at which a test can pause it, to drop the future
/// at a known place. Production passes no probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FoldStage {
    /// Between the two pragma mutations on entry.
    PragmasPartlyEntered,
    AfterPragmas,
    AfterTriggersDropped,
    AfterReplay,
    AfterFlush,
    AfterRebuild,
    /// Triggers recreated, `COMMIT` not yet issued.
    BeforeCommit,
    /// Committed, pragmas not yet restored.
    AfterCommit,
    /// Between the two pragma restorations on exit.
    PragmasPartlyRestored,
}

type FoldProbe<'a> = &'a (dyn Fn(FoldStage) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
         + Sync);

async fn reached(probe: Option<FoldProbe<'_>>, stage: FoldStage) {
    if let Some(probe) = probe {
        probe(stage).await;
    }
}

/// [`replay_projection_events`] with the mode named, so tests can exercise
/// each path (and mixes of them across slices) on small fixtures, and an
/// optional probe to pause the deferred fold.
async fn replay_projection_events_in_mode(
    scratch: &Db,
    events: &[EventRow],
    mode: FoldMode,
    probe: Option<FoldProbe<'_>>,
) -> Result<()> {
    if mode == FoldMode::Immediate {
        let mut tx = scratch.write_pool().begin().await?;
        crate::projector::replay_with_blob_placeholders(&mut tx, events).await?;
        tx.commit().await?;
        return Ok(());
    }
    let trigger_ddl = crate::schema::ddl::fts_index_trigger_ddl().ok_or_else(|| {
        crate::error::Error::engine(
            "scratch fold cannot restore its FTS triggers: the schema no longer declares them",
        )
    })?;
    // Armed from the moment the connection is ours, before the first pragma
    // changes: unless restoration completes, dropping the guard (an error, or
    // the future being cancelled at any await below) closes the connection.
    let mut conn = FoldConnection::new(scratch.write_pool().acquire().await?);
    let saved = FoldPragmas::enter(&mut conn.conn, probe).await?;
    reached(probe, FoldStage::AfterPragmas).await;
    let report = fold_deferred(&mut conn.conn, events, &trigger_ddl, probe).await;
    if report.connection_clean {
        reached(probe, FoldStage::AfterCommit).await;
        match saved.leave(&mut conn.conn, probe).await {
            Ok(()) => conn.restored = true,
            // The slice is already committed (or already rolled back, and the
            // fold's own error is the one to report): the unrestored
            // connection is closed by the guard instead of reused.
            Err(error) => tracing::warn!(
                %error,
                "scratch fold could not restore connection pragmas; discarding the connection"
            ),
        }
    }
    report.result
}

/// A pooled scratch connection that is closed, not returned to the pool,
/// unless its fold pragmas were restored. `Drop` is synchronous, so this holds
/// even when the owning future is cancelled mid-await.
struct FoldConnection {
    conn: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    restored: bool,
}

impl FoldConnection {
    fn new(conn: sqlx::pool::PoolConnection<sqlx::Sqlite>) -> Self {
        Self {
            conn,
            restored: false,
        }
    }
}

impl Drop for FoldConnection {
    fn drop(&mut self) {
        if !self.restored {
            self.conn.close_on_drop();
        }
    }
}

/// Connection settings for one scratch fold, and the values to put back.
///
/// `synchronous = OFF` skips fsyncs on a file that is deleted when the read
/// ends; `temp_store = MEMORY` keeps the FTS rebuild's sorts off disk. The
/// page cache is left at SQLite's default: a large cache is a per-request
/// memory multiplier on a shared host and measured as a small win.
struct FoldPragmas {
    synchronous: i64,
    temp_store: i64,
}

impl FoldPragmas {
    async fn enter(
        conn: &mut sqlx::SqliteConnection,
        probe: Option<FoldProbe<'_>>,
    ) -> Result<Self> {
        let synchronous = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&mut *conn)
            .await?;
        let temp_store = sqlx::query_scalar("PRAGMA temp_store")
            .fetch_one(&mut *conn)
            .await?;
        sqlx::query("PRAGMA synchronous = OFF")
            .execute(&mut *conn)
            .await?;
        reached(probe, FoldStage::PragmasPartlyEntered).await;
        sqlx::query("PRAGMA temp_store = MEMORY")
            .execute(&mut *conn)
            .await?;
        Ok(Self {
            synchronous,
            temp_store,
        })
    }

    async fn leave(
        self,
        conn: &mut sqlx::SqliteConnection,
        probe: Option<FoldProbe<'_>>,
    ) -> Result<()> {
        // The values are integers read from SQLite itself, not caller input.
        sqlx::query(&format!("PRAGMA synchronous = {}", self.synchronous))
            .execute(&mut *conn)
            .await?;
        reached(probe, FoldStage::PragmasPartlyRestored).await;
        sqlx::query(&format!("PRAGMA temp_store = {}", self.temp_store))
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

/// How a deferred fold's transaction ended.
struct FoldReport {
    /// `Ok` only if the transaction committed.
    result: Result<()>,
    /// Whether the transaction is over (committed or rolled back), so the
    /// connection is outside any transaction and pragma restoration can take
    /// effect. After a failed `BEGIN`, `COMMIT` or `ROLLBACK` it is not, and
    /// the connection is discarded unrestored.
    connection_clean: bool,
}

/// Steps 2–6 of [`replay_projection_events`], in one transaction. A failure
/// before the commit rolls the whole transaction back, trigger drops
/// included. If the rollback itself fails, the connection is marked unclean
/// (so it is discarded rather than returned to the pool) and the fold's own
/// error is the one returned.
async fn fold_deferred(
    conn: &mut sqlx::SqliteConnection,
    events: &[EventRow],
    trigger_ddl: &[&str],
    probe: Option<FoldProbe<'_>>,
) -> FoldReport {
    use crate::schema::ddl::{FTS_INDEX_TABLES, FTS_INDEX_TRIGGERS};

    let mut tx = match sqlx::Connection::begin(conn).await {
        Ok(tx) => tx,
        Err(error) => {
            return FoldReport {
                result: Err(error.into()),
                connection_clean: false,
            }
        }
    };
    let folded: Result<()> = async {
        for trigger in FTS_INDEX_TRIGGERS {
            sqlx::query(&format!("DROP TRIGGER {trigger}"))
                .execute(&mut *tx)
                .await?;
        }
        reached(probe, FoldStage::AfterTriggersDropped).await;
        let mut deferrals = crate::projector::BodyDeferrals::new();
        // Blob identities are projector prerequisites only. Read paths never
        // treat these placeholders as retained evidence; the lens routes bytes
        // live.
        crate::projector::replay_with_blob_placeholders_deferred(&mut tx, events, &mut deferrals)
            .await?;
        reached(probe, FoldStage::AfterReplay).await;
        deferrals.flush(&mut tx).await?;
        reached(probe, FoldStage::AfterFlush).await;
        for table in FTS_INDEX_TABLES {
            sqlx::query(&format!("INSERT INTO {table}({table}) VALUES ('rebuild')"))
                .execute(&mut *tx)
                .await?;
        }
        reached(probe, FoldStage::AfterRebuild).await;
        for statement in trigger_ddl {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        reached(probe, FoldStage::BeforeCommit).await;
        Ok(())
    }
    .await;
    match folded {
        Ok(()) => match tx.commit().await {
            Ok(()) => FoldReport {
                result: Ok(()),
                connection_clean: true,
            },
            Err(error) => FoldReport {
                result: Err(error.into()),
                connection_clean: false,
            },
        },
        Err(error) => FoldReport {
            // Surface the fold's error, not a secondary rollback failure.
            connection_clean: tx.rollback().await.is_ok(),
            result: Err(error),
        },
    }
}

/// Whether a response for this read must stay numberless: the caller named the
/// position by event id and has no standing to see workspace counters. Such a
/// caller learns that the id resolved, never which sequence it resolved to or
/// how long the log is. Numeric and timestamp selectors keep their existing
/// metadata (their input already is a number, or a time).
pub fn withholds_counters(resolved: &ResolvedAsOf, footing: CounterFooting) -> bool {
    !footing.is_owner() && matches!(resolved.as_of, AsOfSelector::EventId(_))
}

/// Add temporal metadata to a structured response without changing live
/// response shapes when `as_of` was omitted. For a non-owner reading by event
/// id the numeric `resolved_content_seq` and `content_head_seq` are left out,
/// and any copy a handler already inserted is removed.
pub fn echo_temporal(value: &mut Value, resolved: &ResolvedAsOf, footing: CounterFooting) {
    let object = value
        .as_object_mut()
        .expect("structured read responses are JSON objects");
    object.insert(
        "as_of".into(),
        serde_json::to_value(&resolved.as_of).expect("as_of selector serializes"),
    );
    if withholds_counters(resolved, footing) {
        object.remove("resolved_content_seq");
        object.remove("content_head_seq");
        return;
    }
    object.insert(
        "resolved_content_seq".into(),
        resolved.resolved_content_seq.into(),
    );
    object.insert("content_head_seq".into(), resolved.content_head_seq.into());
}

/// Remove and validate the optional selector before a handler deserializes its
/// ordinary arguments with `deny_unknown_fields`.
pub fn take_as_of(tool: &str, arguments: &mut Value) -> Result<Option<AsOfSelector>> {
    let Some(object) = arguments.as_object_mut() else {
        return Ok(None);
    };
    object
        .remove("as_of")
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                contract_violation(format!("invalid arguments for {tool}: {error}"))
            })
        })
        .transpose()
}

pub fn as_of_input_schema() -> Value {
    // Exactly one key: a single object schema is a third the size of one arm
    // per selector, and the tool descriptors are budgeted.
    serde_json::json!({
        "type": "object",
        "properties": {
            "content_seq": { "type": "integer", "minimum": 0 },
            "timestamp": { "type": "string", "format": "date-time" },
            "event_id": { "type": "string" }
        },
        "minProperties": 1,
        "maxProperties": 1,
        "additionalProperties": false,
        "description": "Replay the pinned content projection at exactly one of: content_seq, timestamp (RFC 3339), or event_id (a write receipt's previous_event_id; `origin` is the empty prefix). Schema/vocabulary and retained blob bytes resolve live."
    })
}

#[cfg(test)]
mod deferred_fold_tests;

#[cfg(test)]
mod incremental_replay_tests {
    use serde_json::json;
    use sqlx::Row;

    use super::*;
    use crate::db::{apply_schema, create_database, open_database};
    use crate::events::CausalEnvelopeV1;
    use crate::mcp::{register_surface_tools, Caller, ToolRegistry};

    #[tokio::test]
    async fn advancing_replay_preserves_blob_placeholders_and_legacy_cutover() {
        let db = create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        let bearer = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"WorkItem", "kind":"task", "name":"Bearer", "reason":"fixture"
                }),
            )
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let attachment = registry
            .call(
                db.clone(),
                Caller::local(),
                "attach_text",
                json!({
                    "record_id":bearer, "text":"alpha beta", "filename":"evidence.txt",
                "mime":"text/plain"
                }),
            )
            .await
            .unwrap()["attachment_id"]
            .as_str()
            .unwrap()
            .to_owned();
        for (start, end) in [(0, 5), (6, 10)] {
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "create_record",
                    json!({
                        "type":"Annotation", "kind":"citation", "name":format!("Cite {start}"),
                        "links":[{"target_id":bearer,"relationship":"part_of"}],
                        "target":{"target_record_id":attachment,"source_slot":"blob",
                                  "selectors":[{"type":"data_position","start":start,"end":end}]},
                        "reason":"fixture"
                    }),
                )
                .await
                .unwrap();
        }
        let head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let mut events = crate::query::events::log_prefix(&db, head).await.unwrap();
        let target_seqs = events
            .iter()
            .filter(|event| event.event_type == "annotation.target.set")
            .map(|event| event.local_seq)
            .collect::<Vec<_>>();
        assert_eq!(target_seqs.len(), 2);
        // Both target events reference the same retained blob. An older event
        // also marks the causal cutover; the later slice has no legacy event.
        let blob_id: String = sqlx::query_scalar(
            "SELECT value FROM facet_values WHERE record_id=? AND key='blob_ref'",
        )
        .bind(&attachment)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        events[0].causal_envelope = CausalEnvelopeV1::legacy_unknown();
        let split = events.partition_point(|event| event.local_seq <= target_seqs[0]);

        let incremental = open_database(":memory:").await.unwrap();
        apply_schema(&incremental).await.unwrap();
        replay_projection_events(&incremental, &events[..split])
            .await
            .unwrap();
        replay_projection_events(&incremental, &events[split..])
            .await
            .unwrap();
        let full = open_database(":memory:").await.unwrap();
        apply_schema(&full).await.unwrap();
        replay_projection_events(&full, &events).await.unwrap();

        for scratch in [&incremental, &full] {
            let blobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE id=?")
                .bind(&blob_id)
                .fetch_one(scratch.write_pool())
                .await
                .unwrap();
            assert_eq!(blobs, 1);
            let target_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM annotation_targets")
                .fetch_one(scratch.write_pool())
                .await
                .unwrap();
            assert_eq!(target_count, 2);
            let cutover: i64 = sqlx::query(
                "SELECT last_legacy_local_seq FROM content_event_causal_cutover WHERE singleton=1",
            )
            .fetch_one(scratch.write_pool())
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
            assert_eq!(cutover, events[0].local_seq);
        }
        let incremental_targets: Vec<(String, String)> = sqlx::query_as(
            "SELECT annotation_id, blob_id FROM annotation_targets ORDER BY annotation_id",
        )
        .fetch_all(incremental.write_pool())
        .await
        .unwrap();
        let full_targets: Vec<(String, String)> = sqlx::query_as(
            "SELECT annotation_id, blob_id FROM annotation_targets ORDER BY annotation_id",
        )
        .fetch_all(full.write_pool())
        .await
        .unwrap();
        assert_eq!(incremental_targets, full_targets);
        incremental.close().await;
        full.close().await;
        db.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time evidence: a projection capability has no route to a live
    // metadata/blob source. Cross-tier code must receive ReadLens explicitly.
    fn projection_only(source: ProjectionRead<'_>) -> &sqlx::SqlitePool {
        source.snapshot_pool()
    }

    #[test]
    fn selector_requires_exactly_one_arm() {
        assert!(serde_json::from_value::<AsOfSelector>(serde_json::json!({
            "content_seq": 1,
            "timestamp": "2026-01-01T00:00:00Z"
        }))
        .is_err());
        assert!(serde_json::from_value::<AsOfSelector>(serde_json::json!({})).is_err());
        let _ = projection_only;
    }
}
