//! Post-commit advisor hook for fresh, successful SQLite writes.
//!
//! After a `create_record` (keyless) or `update_record` commits, registered
//! advisors may inspect a small declared context and attach advisories to the
//! write's receipt. Advisors never block, mutate, or fail a write: each call
//! runs under [`ADVISOR_TIMEOUT_MS`], and every error or timeout is swallowed
//! with a `tracing::warn!`.
//!
//! Every [`Db`](crate::db::Db) carries the [`startup::default_installs`] set
//! (the long-record nudge), so the capability is on with no configuration.
//! [`advisories_for_write`] still returns `None` without touching the
//! database when the registry is empty or nothing `watches` the write —
//! the gate runs on write-path type/kind, before any context read.
//! Postgres and Turso paths are untouched (same scope as `similar_existing`).

pub mod builtin;
pub mod http;
pub mod install;
pub mod long_record;
pub mod manifest;
pub mod startup;

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::future::BoxFuture;
use futures::FutureExt as _;
use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::error::Result;
use crate::query::lifecycle::LifecycleInterpreter;

/// End-to-end advisor budget: one deadline, measured from hook entry, covers
/// the context build and every advisor run together. A single slow stage
/// cannot stack with another — worst-case added latency is ~150 ms total.
/// An advisor that cannot answer within the remaining budget has no answer
/// the receipt should wait for.
pub const ADVISOR_TIMEOUT_MS: u64 = 150;

/// Test-only hook budget (ms) for presence-asserting functional tests. The
/// production budget above never changes; slow-advisor budget tests keep
/// exercising it. Functional tests opt in per registry via
/// [`AdvisorRegistry::set_test_timeout_ms`] (scoped per test Db, never
/// process-global, so parallel tests cannot interfere).
#[cfg(test)]
pub(crate) const TEST_ADVISOR_BUDGET_MS: u64 = 30_000;

/// Cap on `recent_body_revisions`. The long-record nudge needs to know a
/// record is long-lived, not exactly how long-lived; the `LIMIT` keeps the
/// count a bounded index walk.
pub const ADVISOR_BODY_REVISIONS_CAP: i64 = 10;

/// Time window for the repeated same-run append advisory. Four same-run append
/// transitions (five body-bearing revisions) inside this window look like an
/// upload in pieces rather than ordinary editing. Bounded so the context read
/// stays a short index walk.
pub const ADVISOR_APPEND_WINDOW_SECS: i64 = 600;

/// One bounded append-streak row: the newest-first body-bearing revisions of a
/// record, with only the small fields the streak needs. `is_append` is decided
/// in SQL (strictly longer and a prefix of the previous body revision), so no
/// body text crosses into Rust.
const APPEND_STREAK_SQL: &str = "\
WITH recent AS (\
    SELECT seq, run_key, created_at, json_extract(payload, '$.body') AS body \
    FROM content_events \
    WHERE record_id = ?1 AND type IN ('record.created', 'record.updated') \
      AND json_type(payload, '$.body') IS NOT NULL \
    ORDER BY seq DESC LIMIT ?2\
), \
paired AS (\
    SELECT seq, run_key, created_at, body, \
        (SELECT json_extract(payload, '$.body') FROM content_events \
          WHERE record_id = ?1 AND type IN ('record.created', 'record.updated') \
            AND json_type(payload, '$.body') IS NOT NULL \
            AND seq < recent.seq \
          ORDER BY seq DESC LIMIT 1) AS prev_body \
    FROM recent\
) \
SELECT created_at, run_key, \
    CASE WHEN body IS NOT NULL AND prev_body IS NOT NULL \
              AND length(body) > length(prev_body) \
              AND substr(body, 1, length(prev_body)) = prev_body \
         THEN 1 ELSE 0 END AS is_append \
FROM paired ORDER BY seq DESC";

/// The small declared context an advisor may inspect. Identity fields come
/// from one PK-row point lookup on the committed projection; the count
/// fields are filled only after the `watches` gate passes, each as one
/// bounded indexed read:
///
/// - `body_chars_before`: on `update_record`, the pre-write body length in
///   Unicode scalars — reused from the write path's own
///   `body_receipt.before_chars` (same unit), never re-queried. On
///   `create_record`, `Some(0)`. `None` when the update carried no body op
///   (facet-only; the body is untouched, so it equals `body_chars_after`).
/// - `recent_body_revisions`: count of body-bearing revisions including the
///   just-committed write, capped at [`ADVISOR_BODY_REVISIONS_CAP`].
/// - `recent_same_run_append_streak`: consecutive same-run append transitions
///   ending at this write, where each newer body is strictly longer than and
///   prefixed by the previous body-bearing revision, all within
///   [`ADVISOR_APPEND_WINDOW_SECS`]; `None` when no run key is known. It counts
///   transitions, so `N` rows can yield at most `N - 1`; a value at or above 4
///   (five body-bearing revisions) is the upload-in-pieces signal. A body clear
///   (present-but-null) breaks the streak; non-body edits are skipped.
/// - The `lifecycle_*` / `summary_*` / `claim_*` fields serve the completion
///   advisors (`builtin:completion_outcome`, `builtin:release_after_completion`).
///   They are filled only after the `watches` gate passes, only for `WorkItem`
///   writes, and only when a registered advisor asks for them (see
///   [`Advisor::needs_completion_context`]) — each as bounded indexed reads
///   inside the existing single deadline. Unwatched writes still do zero extra
///   reads. `None` means "not filled or not knowable", never "false": advisors
///   must stay silent on `None` rather than guess.
#[derive(Debug, Clone)]
pub struct AdviceContext {
    pub tool: String,
    pub record_id: String,
    pub record_type: String,
    pub record_kind: String,
    pub record_name: Option<String>,
    pub body_chars_before: Option<i64>,
    pub body_chars_after: Option<i64>,
    pub recent_body_revisions: Option<i64>,
    pub recent_same_run_append_streak: Option<i64>,
    pub links_out_count: Option<i64>,
    pub mentions_out_count: Option<i64>,
    pub run_key: Option<String>,
    /// Lifecycle value in effect immediately before this write (`None` when
    /// absent — e.g. a fresh create — or when the history walk cannot tell).
    pub lifecycle_before: Option<String>,
    /// Lifecycle value after this write, from the committed projection.
    pub lifecycle_after: Option<String>,
    /// Governed terminality (`open` / `terminal_positive` / `terminal_negative`)
    /// of [`Self::lifecycle_before`], via the lifecycle interpreter.
    pub lifecycle_before_terminality: Option<String>,
    /// Governed terminality of [`Self::lifecycle_after`].
    pub lifecycle_after_terminality: Option<String>,
    /// Whether this write's own record event carried a `summary` key.
    pub summary_changed_in_write: Option<bool>,
    /// Whether any `summary` was recorded at or after the seq where the task
    /// last entered a governed-open (`active`) lifecycle state. Includes this
    /// write, so a completing write that sets the summary counts.
    pub summary_changed_since_active: Option<bool>,
    /// Whether a non-empty `summary` is present after this write.
    pub summary_present: Option<bool>,
    /// Whether any claim is still held on the record after this write.
    pub claim_held: Option<bool>,
    /// Whether the writing run (`run_key`) is the claim holder.
    pub writer_holds_claim: Option<bool>,
}

/// How strongly an advisory asks for attention. Serialised as a string;
/// missing means `advise` (external advisors pre-dating the field stay
/// compatible).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisoryLevel {
    #[default]
    Advise,
    Warn,
}

impl AdvisoryLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advise => "advise",
            Self::Warn => "warn",
        }
    }

    /// Map an external `level` value onto a level. Anything but exactly
    /// `"warn"` — including absent and unknown — means `advise`: advisors are
    /// fail-open, and an unknown severity must not escalate.
    pub fn from_external(value: Option<&str>) -> Self {
        match value {
            Some("warn") => Self::Warn,
            _ => Self::Advise,
        }
    }
}

/// One advisory attached to a write receipt. Serialises to
/// `{"advisor_id", "version", "manifest_digest", "code", "record_id",
/// "message", "level"}` — plus `details` when present (omitted when `None`).
/// `level` is always serialized (a deliberate addition: every advisor now
/// states its severity); `details` stays omitted when `None`. `level`
/// defaults to `"advise"` when missing on parse. `details` carries
/// machine-readable numbers (e.g. the long-record milestones); the prose
/// render uses `message` only (plus a `[warn]` marker for `warn` levels).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub advisor_id: String,
    pub version: String,
    pub manifest_digest: Option<String>,
    pub code: String,
    pub record_id: String,
    pub message: String,
    #[serde(default)]
    pub level: AdvisoryLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// A post-commit advisor. Implementations must be pure readers of the
/// declared context: the write has already committed and nothing they do can
/// change it. The boxed-future shape matches the repo idiom (see
/// `SnapshotSource`, `AuthorityActSource`); there is no `async_trait` in the
/// tree.
///
/// `advise` returns every advisory for the write (usually zero or one):
/// external advisors answer a list per call (contract v0), so the trait does
/// too rather than dropping all but the first (S4).
pub trait Advisor: Send + Sync {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    /// Whether this advisor wants to see a write. Must be pure — no I/O,
    /// no mutation, deterministic on its inputs: the hook may call it more
    /// than once per write (once at the gate, once per run), and a
    /// panicking predicate is swallowed and treated as not-watching.
    fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool;
    /// Whether this advisor can only fire when the write changed the body.
    /// The hook skips the context build for body-untouched writes when every
    /// watching advisor answers true here — so answer true only when a
    /// body-unchanged write genuinely cannot produce an advisory. Pure like
    /// `watches`; a panicking answer is treated as false (fail open).
    fn needs_body_change(&self) -> bool {
        false
    }
    /// Whether filling the completion context (`lifecycle_*`, `summary_*`,
    /// `claim_*`) is worth its reads for this advisor. Default false, so
    /// advisors that pre-date the completion slice pay nothing for it. Like
    /// `watches`, must be pure; a panicking predicate is swallowed and
    /// treated as not-needing. Only consulted after the `watches` gate
    /// passes, inside the shared deadline.
    fn needs_completion_context(&self) -> bool {
        false
    }
    fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>>;
}

/// A shared advisor, as [`crate::Db`] holds it.
pub type AdvisorRef = Arc<dyn Advisor>;

/// The advisor set for one database handle. Clones share it. Db constructors
/// install the [`startup::default_installs`] set; a bare
/// `AdvisorRegistry::default()` (unit tests) stays empty.
#[derive(Clone, Default)]
pub struct AdvisorRegistry {
    advisors: Arc<RwLock<Vec<AdvisorRef>>>,
    /// Test-only count of advisor context builds, proving the watches gate
    /// skips the context read for unwatched writes (see
    /// `unwatched_write_reads_no_advisor_context`).
    #[cfg(test)]
    context_builds: Arc<std::sync::atomic::AtomicU64>,
    /// Test-only hook budget override in milliseconds (`0` = production
    /// budget). Scoped to this registry handle's clones — every test Db
    /// carries its own registry, so parallel tests cannot interfere.
    #[cfg(test)]
    test_timeout_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Hold context work inside the real build's timeout boundary. Per-registry
    /// and test-only; releasing the gate still executes the real projection reads.
    #[cfg(test)]
    test_context_gate: Arc<RwLock<Option<Arc<TestContextGate>>>>,
}

/// A controlled context stage for budget tests; absent on every ordinary Db.
#[cfg(test)]
#[derive(Default)]
struct TestContextGate {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    finished_at: std::sync::Mutex<Option<tokio::time::Instant>>,
    hook_finished: tokio::sync::Notify,
    hook_release: tokio::sync::Notify,
}

#[cfg(test)]
struct TestContextBuildGuard(Arc<TestContextGate>);

#[cfg(test)]
impl Drop for TestContextBuildGuard {
    fn drop(&mut self) {
        *self.0.finished_at.lock().unwrap() = Some(tokio::time::Instant::now());
    }
}

impl std::fmt::Debug for AdvisorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .advisors
            .read()
            .map(|advisors| advisors.len())
            .unwrap_or(0);
        f.debug_struct("AdvisorRegistry")
            .field("advisor_count", &count)
            .finish()
    }
}

impl AdvisorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an advisor. Visible to every clone of the holding handle;
    /// an opening-time decision, not a per-request switch. A poisoned lock
    /// is reported and the advisor is dropped: failing open here too.
    /// Same-id registration replaces in place: install layers reconcile by
    /// id (a config-dir override retunes the default rather than doubling
    /// it), so the registry holds at most one advisor per id.
    pub fn register(&self, advisor: AdvisorRef) {
        match self.advisors.write() {
            Ok(mut advisors) => {
                let id = id_guarded(&advisor);
                if let Some(slot) = advisors.iter_mut().find(|slot| id_guarded(slot) == id) {
                    *slot = advisor;
                } else {
                    advisors.push(advisor);
                }
            }
            Err(_) => tracing::warn!(
                target: "native::advisors",
                "advisor registry lock poisoned; advisor not registered"
            ),
        }
    }

    /// Remove the advisor with this id, if present. A disabled install
    /// suppresses its same-id default this way.
    pub fn unregister(&self, advisor_id: &str) {
        match self.advisors.write() {
            Ok(mut advisors) => advisors.retain(|slot| id_guarded(slot) != advisor_id),
            Err(_) => tracing::warn!(
                target: "native::advisors",
                "advisor registry lock poisoned; advisor not unregistered"
            ),
        }
    }

    /// Test-only advisor-context build count (see the field).
    #[cfg(test)]
    pub fn context_build_count(&self) -> u64 {
        self.context_builds
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn note_context_build(&self) {
        self.context_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test-only hook budget override for presence-asserting functional
    /// tests: the hook waits up to `ms` instead of [`ADVISOR_TIMEOUT_MS`],
    /// so a loaded runner cannot flip a presence assertion into silence.
    /// Scoped to this registry (one per test Db). Budget behaviour itself
    /// stays pinned by the slow-advisor tests, which never call this.
    #[cfg(test)]
    pub fn set_test_timeout_ms(&self, ms: u64) {
        self.test_timeout_ms
            .store(ms, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn test_timeout_ms(&self) -> Option<u64> {
        match self
            .test_timeout_ms
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            ms => Some(ms),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.advisors
            .read()
            .map(|advisors| advisors.is_empty())
            .unwrap_or(true)
    }

    fn snapshot(&self) -> Vec<AdvisorRef> {
        self.advisors
            .read()
            .map(|advisors| advisors.clone())
            .unwrap_or_default()
    }

    /// Whether at least one registered advisor watches this write. The hook
    /// checks this before running anything, on caller-supplied type/kind, so
    /// unwatched writes pay no query at all. Each predicate runs under a
    /// panic guard (see `watches_guarded`).
    pub fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
        self.snapshot()
            .iter()
            .any(|advisor| watches_guarded(advisor, tool, record_type, record_kind))
    }

    /// Whether at least one watching advisor may fire for this write given
    /// whether the body changed. A body-untouched write skips every advisor
    /// that needs a body change; when none remains, the hook returns before
    /// any context read.
    pub fn watches_for_body(
        &self,
        tool: &str,
        record_type: &str,
        record_kind: &str,
        body_changed: bool,
    ) -> bool {
        self.snapshot().iter().any(|advisor| {
            watches_guarded(advisor, tool, record_type, record_kind)
                && (body_changed || !needs_body_change_guarded(advisor))
        })
    }

    /// Run every watching advisor concurrently against the shared `deadline`:
    /// worst-case added latency is ~one budget total, not one per advisor.
    /// `join_all` preserves input order, so output stays in registration
    /// order. Errors, timeouts and panics are swallowed with a
    /// `tracing::warn!`; every emitted advisory is also logged once as a
    /// structured event on `native::advisors` carrying the advisory JSON.
    pub async fn advise_all(
        &self,
        ctx: &AdviceContext,
        deadline: tokio::time::Instant,
    ) -> Vec<Advisory> {
        let runs = self
            .snapshot()
            .into_iter()
            .map(|advisor| async move { Self::run_one(&advisor, ctx, deadline).await });
        futures::future::join_all(runs)
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Run one advisor inside every guard: the `watches` check, the `id`
    /// read, the shared deadline and the panic boundary — including around
    /// future *construction*. Returns every emitted advisory (usually zero
    /// or one: the external contract answers a list, so the trait does too);
    /// a broken advisor yields an empty vec and a warn, never an error and
    /// never another advisor's silence.
    async fn run_one(
        advisor: &AdvisorRef,
        ctx: &AdviceContext,
        deadline: tokio::time::Instant,
    ) -> Vec<Advisory> {
        // The per-advisor `watches` check lives inside the guarded region: a
        // panicking predicate is swallowed here, never in the caller.
        if !watches_guarded(advisor, &ctx.tool, &ctx.record_type, &ctx.record_kind) {
            return Vec::new();
        }
        let id = id_guarded(advisor);
        // Guard construction too: `advise(ctx)` runs BEFORE the future is
        // wrapped, so a synchronous panic while building the BoxFuture would
        // otherwise escape the boundary and fail the committed write.
        let future = match std::panic::catch_unwind(AssertUnwindSafe(|| advisor.advise(ctx))) {
            Ok(future) => future,
            Err(_) => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = id.as_str(),
                    "advisor advise panicked during construction; swallowing"
                );
                return Vec::new();
            }
        };
        // `FutureExt::catch_unwind` runs the future to completion inside the
        // boundary (same shape as the interaction capture worker): an async
        // panic is caught here rather than unwinding the write path.
        let outcome =
            tokio::time::timeout_at(deadline, AssertUnwindSafe(future).catch_unwind()).await;
        match outcome {
            Err(_) => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = id.as_str(),
                    timeout_ms = ADVISOR_TIMEOUT_MS,
                    "advisor timed out; swallowing"
                );
                Vec::new()
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = id.as_str(),
                    "advisor panicked; swallowing"
                );
                Vec::new()
            }
            Ok(Ok(Err(error))) => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = id.as_str(),
                    error = %error,
                    "advisor failed; swallowing"
                );
                Vec::new()
            }
            Ok(Ok(Ok(advisories))) => {
                for advisory in &advisories {
                    tracing::info!(
                        target: "native::advisors",
                        advisor_id = advisory.advisor_id.as_str(),
                        code = advisory.code.as_str(),
                        record_id = advisory.record_id.as_str(),
                        advisory = %serde_json::to_string(&advisory).unwrap_or_default(),
                        "advisor emitted advisory"
                    );
                }
                advisories
            }
        }
    }
}

/// Run one `watches` predicate under a panic guard. A panicking gate is
/// treated as not-watching (plus a warn): a broken predicate must neither
/// fail an already-committed write nor hide other advisors' output.
fn watches_guarded(advisor: &AdvisorRef, tool: &str, record_type: &str, record_kind: &str) -> bool {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        advisor.watches(tool, record_type, record_kind)
    })) {
        Ok(watching) => watching,
        Err(_) => {
            tracing::warn!(
                target: "native::advisors",
                advisor_id = %id_guarded(advisor),
                "advisor watches panicked; treating as not watching"
            );
            false
        }
    }
}

/// Read one `needs_body_change` predicate under a panic guard. A panicking
/// answer is treated as false: the advisor may still fire, so the hook
/// builds context rather than risk skipping it.
fn needs_body_change_guarded(advisor: &AdvisorRef) -> bool {
    match std::panic::catch_unwind(AssertUnwindSafe(|| advisor.needs_body_change())) {
        Ok(needs) => needs,
        Err(_) => {
            tracing::warn!(
                target: "native::advisors",
                advisor_id = %id_guarded(advisor),
                "advisor needs_body_change panicked; treating as not needed"
            );
            false
        }
    }
}

/// Run one `needs_completion_context` predicate under a panic guard. A
/// panicking gate is treated as not-needing: completion context is an
/// optimisation input, never load-bearing for a committed write.
fn needs_completion_guarded(advisor: &AdvisorRef) -> bool {
    match std::panic::catch_unwind(AssertUnwindSafe(|| advisor.needs_completion_context())) {
        Ok(needing) => needing,
        Err(_) => {
            tracing::warn!(
                target: "native::advisors",
                advisor_id = %id_guarded(advisor),
                "advisor needs_completion_context panicked; treating as not needing"
            );
            false
        }
    }
}

/// Best-effort advisor id for log lines. A panicking `id()` degrades to a
/// placeholder rather than failing the write.
fn id_guarded(advisor: &AdvisorRef) -> String {
    std::panic::catch_unwind(AssertUnwindSafe(|| advisor.id().to_owned()))
        .unwrap_or_else(|_| "<advisor-id-panicked>".to_owned())
}

/// One `APPEND_STREAK_SQL` row, newest-first. Only small values: the `is_append`
/// decision (strictly-longer prefix of the previous body revision) is made in
/// SQL, never here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppendStreakRow {
    created_at: String,
    run_key: Option<String>,
    is_append: bool,
}

/// Longest run of same-run append transitions ending at the newest row, where
/// every transition in the run is within [`ADVISOR_APPEND_WINDOW_SECS`] of that
/// newest row. Rows are newest-first and `is_append` was decided in SQL:
/// strictly longer than, and a prefix of, the previous body-bearing revision.
/// A clear or a missing body revision sets `is_append = 0` and breaks the run.
/// A non-consecutive run (either endpoint not `run`), an unparseable
/// timestamp, a non-append transition, or a gap wider than the window also
/// breaks it. Counts transitions: `N` rows can yield at most `N - 1`.
fn same_run_append_streak(rows: &[AppendStreakRow], run: &str) -> i64 {
    let Some(anchor_at) = rows
        .first()
        .and_then(|row| chrono::DateTime::parse_from_rfc3339(&row.created_at).ok())
    else {
        return 0;
    };
    let mut streak = 0_i64;
    for pair in rows.windows(2) {
        let (newer, older) = (&pair[0], &pair[1]);
        if newer.run_key.as_deref() != Some(run) || older.run_key.as_deref() != Some(run) {
            break;
        }
        let Ok(older_at) = chrono::DateTime::parse_from_rfc3339(&older.created_at) else {
            break;
        };
        if (anchor_at - older_at).num_seconds().max(0) > ADVISOR_APPEND_WINDOW_SECS {
            break;
        }
        if newer.is_append {
            streak += 1;
        } else {
            break;
        }
    }
    streak
}

impl AdviceContext {
    /// Read the committed projection for a just-written record. Runs after
    /// commit on the write pool with an immediate rollback, like
    /// `similar::notice_for_create`: it describes what was actually written.
    ///
    /// Runs only for watched writes: the caller gates on
    /// [`AdvisorRegistry::watches`] with write-path type/kind before calling,
    /// so the identity row and the count reads below are never paid for
    /// unrelated writes.
    #[allow(clippy::too_many_arguments)]
    async fn build(
        db: &Db,
        tool: &str,
        record_id: &str,
        run_key: Option<String>,
        body_chars_before: Option<i64>,
        written_seq: Option<i64>,
        completion_wanted: bool,
        lifecycle_may_have_changed: bool,
    ) -> Result<Option<Self>> {
        #[cfg(test)]
        let gate = db.advisors().test_context_gate.read().unwrap().clone();
        #[cfg(test)]
        let _context_guard = gate.clone().map(TestContextBuildGuard);
        #[cfg(test)]
        if let Some(gate) = gate {
            gate.started.notify_one();
            gate.release.notified().await;
        }
        // One transaction for the whole build: identity, counts, interpreter
        // index and history walk share a single pool acquisition instead of
        // one per stage, tightening the latency tail under contention. All
        // reads with an immediate rollback at the end, like
        // `similar::notice_for_create`: the build describes what was
        // actually written.
        let mut tx = db.write_pool().begin().await?;
        let identity = read_identity_in(&mut tx, record_id).await?;
        let links_out_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id = ?")
                .bind(record_id)
                .fetch_one(&mut *tx)
                .await?;
        let mentions_out_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM record_mentions WHERE source_id = ?")
                .bind(record_id)
                .fetch_one(&mut *tx)
                .await?;
        let recent_body_revisions = sqlx::query(
            "SELECT 1 FROM content_events WHERE record_id = ? \
             AND type IN ('record.created','record.updated','receipt.committed.v1') \
             AND json_type(payload,'$.body') = 'text' ORDER BY seq DESC LIMIT ?",
        )
        .bind(record_id)
        .bind(ADVISOR_BODY_REVISIONS_CAP)
        .fetch_all(&mut *tx)
        .await?
        .len() as i64;
        // Same-run append streak, for the upload-in-pieces advisory. All
        // body-bearing `record.created`/`record.updated` revisions are
        // considered in order; a present-but-null body (a clear) is a
        // revision that breaks the streak, while non-body edits (no `$.body`
        // key) are skipped. `APPEND_STREAK_SQL` decides the strictly-longer
        // prefix test in SQL, so only timestamps, run keys and booleans cross
        // into Rust — no body text — and the `LIMIT` keeps it a bounded walk.
        let recent_same_run_append_streak = match run_key.as_deref() {
            Some(run) => {
                use sqlx::Row as _;
                let rows = sqlx::query(APPEND_STREAK_SQL)
                    .bind(record_id)
                    .bind(ADVISOR_BODY_REVISIONS_CAP)
                    .fetch_all(&mut *tx)
                    .await?;
                let mut revisions: Vec<AppendStreakRow> = Vec::with_capacity(rows.len());
                for row in &rows {
                    revisions.push(AppendStreakRow {
                        created_at: row.try_get("created_at")?,
                        run_key: row.try_get("run_key")?,
                        is_append: row.try_get::<i64, _>("is_append")? != 0,
                    });
                }
                Some(same_run_append_streak(revisions.as_slice(), run))
            }
            None => None,
        };
        // Completion lifecycle/summary context is opt-in per advisor (not per
        // write): registries without a completion advisor pay nothing for it,
        // and non-WorkItem writes skip it even when one is registered. Claim
        // state rides on the identity row above (no extra read) and is
        // reported only alongside a filled completion context, so unwatched
        // writes still expose nothing.
        let completion = if completion_wanted && identity.record_type == "WorkItem" {
            read_completion_context_in(
                &mut tx,
                tool,
                record_id,
                &identity.record_kind,
                identity.lifecycle.clone(),
                identity.summary.clone(),
                written_seq,
                lifecycle_may_have_changed,
            )
            .await?
        } else {
            CompletionContext::default()
        };
        let (claim_held, writer_holds_claim) = match completion.filled {
            true => {
                let held = identity.claimed_by_account.is_some();
                let writer = match (&run_key, &identity.claimed_run_key) {
                    (Some(run), Some(holder)) => run == holder,
                    _ => false,
                };
                (Some(held), Some(writer))
            }
            false => (None, None),
        };
        tx.rollback().await?;
        Ok(Some(Self {
            tool: tool.to_owned(),
            record_id: record_id.to_owned(),
            record_type: identity.record_type,
            record_kind: identity.record_kind,
            record_name: Some(identity.record_name),
            body_chars_before,
            body_chars_after: identity.body_chars_after,
            recent_body_revisions: Some(recent_body_revisions),
            recent_same_run_append_streak,
            links_out_count: Some(links_out_count),
            mentions_out_count: Some(mentions_out_count),
            run_key,
            lifecycle_before: completion.lifecycle_before,
            lifecycle_after: completion.lifecycle_after,
            lifecycle_before_terminality: completion.lifecycle_before_terminality,
            lifecycle_after_terminality: completion.lifecycle_after_terminality,
            summary_changed_in_write: completion.summary_changed_in_write,
            summary_changed_since_active: completion.summary_changed_since_active,
            summary_present: completion.summary_present,
            claim_held,
            writer_holds_claim,
        }))
    }
}

/// Completion-context values resolved by [`read_completion_context_in`]. All
/// `Option`: `None` means "not filled or not knowable" and advisors must stay
/// silent on it rather than guess. `filled` distinguishes "ran and found
/// nothing" (all-`None` but claims still reported) from "did not run".
#[derive(Debug, Default)]
struct CompletionContext {
    filled: bool,
    lifecycle_before: Option<String>,
    lifecycle_after: Option<String>,
    lifecycle_before_terminality: Option<String>,
    lifecycle_after_terminality: Option<String>,
    summary_changed_in_write: Option<bool>,
    summary_changed_since_active: Option<bool>,
    summary_present: Option<bool>,
}

/// Cap on the history walk in [`read_completion_context`]. The active-entry
/// marker a completing task needs is near the tip (the `in_progress` write
/// just before completion); 200 lifecycle/summary events is far beyond any
/// real completion story, and a truncated walk aborts the fill rather than
/// reasoning from a partial history.
const ADVISOR_COMPLETION_HISTORY_CAP: i64 = 200;

/// One projected history row: only the lifecycle value and whether a summary
/// key is present. Bodies never leave the database: `json_extract` projects
/// the small fields out of the payload in SQLite.
struct CompletionHistoryRow {
    seq: i64,
    event_type: String,
    lifecycle: Option<String>,
    has_lifecycle: bool,
    has_summary: bool,
}

/// Fill the completion slice of [`AdviceContext`] for a `WorkItem` write.
///
/// Reads, all bounded and indexed, inside the caller's single deadline:
/// one interpreter load (schema rows plus the small vocabulary tables),
/// one history walk (at most [`ADVISOR_COMPLETION_HISTORY_CAP`] projected
/// rows — no bodies), and nothing else. Any failure aborts the fill with an
/// error the hook swallows: advisors stay silent rather than advise from a
/// partial history.
///
/// `written_seq` is this write's own record event seq (the write path has it
/// in hand — zero extra reads). It scopes the walk so a concurrent newer
/// write cannot be mistaken for this one, and it identifies "this write"
/// exactly even for same-value lifecycle rewrites, which the engine appends
/// without deduplicating. `None` (facet-only updates, which cannot move
/// lifecycle or summary) leaves the before/after attribution to the newest
/// row, which is still correct because such writes change neither.
#[allow(clippy::too_many_arguments)]
async fn read_completion_context_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tool: &str,
    record_id: &str,
    record_kind: &str,
    lifecycle_after: Option<String>,
    summary_after: Option<String>,
    written_seq: Option<i64>,
    lifecycle_may_have_changed: bool,
) -> Result<CompletionContext> {
    let summary_present = Some(summary_after.is_some_and(|summary| !summary.trim().is_empty()));
    // Skip level 0 — no interpreter load, no history walk. An update that
    // carried no lifecycle arg cannot move lifecycle (before would equal
    // after, so the transition gate could never pass), and an absent
    // after-lifecycle can never be terminal-positive. `summary_present`
    // rides the already-read projection row, so it is still reported.
    if !lifecycle_may_have_changed || lifecycle_after.is_none() {
        return Ok(CompletionContext {
            filled: true,
            summary_present,
            ..Default::default()
        });
    }
    use sqlx::Row as _;
    // Same committed snapshot as the rest of the build: the caller-selected
    // schema rows (global, no principal — the identical query the pool
    // loader runs with `None`) plus the vocabulary index, read on the
    // build's own transaction rather than fresh pool acquisitions.
    let schema_rows = crate::query::cascade::schema_config_rows_in(tx).await?;
    let interpreter = LifecycleInterpreter::load_from_connection(tx, schema_rows).await?;
    let interpret = |value: Option<&str>| match value {
        Some(token) => {
            match interpreter.interpret("WorkItem", Some(record_kind), None, Some(token)) {
                crate::query::lifecycle::LifecycleInterpretation::Governed(governed) => {
                    Some(governed.terminality)
                }
                _ => None,
            }
        }
        None => None,
    };
    let after_terminality = interpret(lifecycle_after.as_deref());
    // Skip level 1 — no history walk. A non-terminal after-lifecycle fails
    // the transition gate on its own; the walk only matters for completions,
    // which are rare against the background of ordinary task edits.
    if after_terminality.as_deref() != Some("terminal_positive") {
        return Ok(CompletionContext {
            filled: true,
            lifecycle_after,
            lifecycle_after_terminality: after_terminality,
            summary_present,
            ..Default::default()
        });
    }
    // `has_lifecycle` distinguishes a cleared lifecycle (key present, null
    // value — an effective absent that a later re-entry must compare
    // against) from an untouched one (key absent — claim, body and
    // summary-only events must not disturb the walk).
    let sql = if written_seq.is_some() {
        "SELECT seq, type, CAST(json_extract(payload,'$.lifecycle') AS TEXT) AS lifecycle, \
         (json_type(payload,'$.lifecycle') IS NOT NULL) AS has_lifecycle, \
         (json_type(payload,'$.summary') IS NOT NULL) AS has_summary \
         FROM content_events WHERE record_id = ? \
         AND type IN ('record.created','record.updated') AND seq <= ? \
         ORDER BY seq DESC LIMIT ?"
    } else {
        "SELECT seq, type, CAST(json_extract(payload,'$.lifecycle') AS TEXT) AS lifecycle, \
         (json_type(payload,'$.lifecycle') IS NOT NULL) AS has_lifecycle, \
         (json_type(payload,'$.summary') IS NOT NULL) AS has_summary \
         FROM content_events WHERE record_id = ? \
         AND type IN ('record.created','record.updated') \
         ORDER BY seq DESC LIMIT ?"
    };
    let mut query = sqlx::query(sql).bind(record_id);
    if let Some(seq) = written_seq {
        query = query.bind(seq);
    }
    query = query.bind(ADVISOR_COMPLETION_HISTORY_CAP);
    // No rollback here: the caller owns the transaction and rolls it back
    // after the whole build, so this walk shares one pool acquisition with
    // the identity, counts and interpreter reads above.
    let fetched = query.fetch_all(&mut **tx).await?;
    let mut rows: Vec<CompletionHistoryRow> = Vec::with_capacity(fetched.len());
    for row in fetched {
        rows.push(CompletionHistoryRow {
            seq: row.try_get("seq")?,
            event_type: row.try_get("type")?,
            lifecycle: row.try_get("lifecycle")?,
            has_lifecycle: row.try_get::<i64, _>("has_lifecycle")? != 0,
            has_summary: row.try_get::<i64, _>("has_summary")? != 0,
        });
    }
    // A walk that stops at the cap without reaching `record.created` is
    // partial: abort rather than reason from it.
    let truncated = rows.len() as i64 >= ADVISOR_COMPLETION_HISTORY_CAP
        && !rows.iter().any(|row| row.event_type == "record.created");
    if truncated {
        return Ok(CompletionContext::default());
    }
    // This write's own record event. Absent only when the write appended no
    // record event (facet-only) or the cap cut it off (handled above): fall
    // back to the newest row, which such writes never move.
    let my_seq = match written_seq {
        Some(seq) if rows.iter().any(|row| row.seq == seq) => Some(seq),
        Some(_) => return Ok(CompletionContext::default()),
        None => None,
    };
    let horizon = my_seq.unwrap_or(i64::MAX);
    let summary_changed_in_write = rows
        .iter()
        .find(|row| Some(row.seq) == my_seq)
        .map(|row| row.has_summary);
    // Lifecycle before this write. Creates have none; updates take the newest
    // lifecycle set strictly before this write's event (same-value rewrites
    // append, so an equal value here means the write genuinely re-set it and
    // the older value is still the "before").
    let lifecycle_before = if tool == "create_record" {
        None
    } else {
        rows.iter()
            .filter(|row| row.seq < horizon)
            .find_map(|row| row.lifecycle.clone())
    };
    // Active-entry marker: walk chronologically (rows arrive newest-first,
    // so reverse) tracking the last-seen effective lifecycle value. Rows
    // without a lifecycle key (claims, body edits, summary-only updates)
    // are skipped without touching it; a present-but-null key is a clearing
    // and resets the effective value to absent. The marker moves only on a
    // genuine transition into a governed-open value — a same-value rewrite
    // (e.g. re-sending `in_progress`) is not an entry, so it must not drag
    // the marker past a summary recorded while the task was already active.
    // Creation counts as entry into its initial value (previous is absent).
    // Unknown (unclassified/absent) values are never "active": only a
    // confirmed-open entry moves the marker.
    let mut active_entry: Option<i64> = None;
    // `None` doubles as "before creation" and "cleared": both are absent,
    // so a re-entry after either compares unequal and moves the marker.
    let mut previous: Option<&str> = None;
    for row in rows.iter().rev() {
        if !row.has_lifecycle {
            continue;
        }
        let current = row.lifecycle.as_deref();
        if current != previous && interpret(current).as_deref() == Some("open") {
            active_entry = Some(row.seq);
        }
        previous = current;
    }
    let summary_changed_since_active = active_entry.map(|marker| {
        rows.iter()
            .any(|row| row.has_summary && row.seq >= marker && row.seq <= horizon)
    });
    Ok(CompletionContext {
        filled: true,
        lifecycle_before_terminality: interpret(lifecycle_before.as_deref()),
        lifecycle_after_terminality: after_terminality,
        lifecycle_before,
        lifecycle_after,
        summary_changed_in_write,
        summary_changed_since_active,
        summary_present,
    })
}

/// The identity half of [`AdviceContext`]: one PK-row point lookup. `name`
/// is `NOT NULL DEFAULT ''` in the DDL so it binds as `String`; `kind` is
/// nullable in the DDL, so it binds as `Option` and defaults to `''` (spine
/// records always carry one — the default only keeps the hook fail-open).
/// The `lifecycle`, `summary` and claim columns ride on the same row: they
/// cost nothing extra and are only *reported* after the `watches` gate
/// passes, so unwatched writes still do zero extra reads.
struct Identity {
    record_type: String,
    record_kind: String,
    record_name: String,
    body_chars_after: Option<i64>,
    lifecycle: Option<String>,
    summary: Option<String>,
    claimed_by_account: Option<String>,
    claimed_run_key: Option<String>,
}

/// One identity row: `(type, kind, name, body_chars, lifecycle, summary,
/// claimed_by_account, claimed_run_key)`.
type IdentityRow = (
    String,
    Option<String>,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The identity half of the build, on the build's transaction: one PK-row
/// point lookup sharing the single pool acquisition (no rollback here —
/// the caller rolls back after the whole build).
async fn read_identity_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record_id: &str,
) -> Result<Identity> {
    let row: Option<IdentityRow> = sqlx::query_as(
        "SELECT type, kind, name, length(body), lifecycle, summary, \
         claimed_by_account, claimed_run_key FROM records \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((
        record_type,
        record_kind,
        record_name,
        body_chars_after,
        lifecycle,
        summary,
        claimed_by_account,
        claimed_run_key,
    )) = row
    else {
        return Err(crate::error::Error::engine(
            "advisors: written record is not readable after commit",
        ));
    };
    Ok(Identity {
        record_type,
        record_kind: record_kind.unwrap_or_default(),
        record_name,
        body_chars_after,
        lifecycle,
        summary,
        claimed_by_account,
        claimed_run_key,
    })
}

/// The hook the write path calls after a fresh, successful commit. Returns
/// the receipt-ready advisory values, or `None` when the receipt must stay
/// byte-identical (no advisors, nothing watching, or nothing emitted).
/// Fail-silent: any context-read failure or context-build overrun is
/// swallowed with a `tracing::warn!` and yields `None`, never an error.
///
/// `record_type`/`record_kind` come from the write path (which already knows
/// them), so the watches gate below needs no query: unwatched writes return
/// before any context read. `body_changed` is likewise caller-supplied
/// (`update_record` reuses its own `body_content_changed`; `create_record`
/// passes true): when the body is untouched, advisors that need a body
/// change are skipped, and when none remains the hook returns before any
/// query. `body_chars_before` is supplied when the caller already knows the
/// pre-write length (`update_record` reuses `body_receipt.before_chars`;
/// `create_record` passes `Some(0)`): the hook never re-queries history.
/// `written_seq` is this write's own record event seq, which the write path
/// already holds: it scopes the completion history walk so a concurrent
/// newer write cannot be mistaken for this one (and it tells same-value
/// lifecycle rewrites, which the engine appends without deduplicating, apart
/// from genuine transitions). `None` for writes that appended no record
/// event (facet-only updates, which move neither lifecycle nor summary).
/// `lifecycle_may_have_changed` is caller-supplied (`update_record` passes
/// whether it carried a lifecycle arg; `create_record` passes true): an
/// update without one cannot move lifecycle, so no transition is possible
/// and the completion fill is skipped outright — the transition gate could
/// never pass, since before would equal after.
#[allow(clippy::too_many_arguments)]
pub async fn advisories_for_write(
    db: &Db,
    tool: &str,
    record_id: &str,
    record_type: &str,
    record_kind: &str,
    body_changed: bool,
    run_key: Option<String>,
    body_chars_before: Option<i64>,
    written_seq: Option<i64>,
    lifecycle_may_have_changed: bool,
) -> Option<Vec<serde_json::Value>> {
    #[cfg(test)]
    let gate = db.advisors().test_context_gate.read().unwrap().clone();
    let result = advisories_for_write_inner(
        db,
        tool,
        record_id,
        record_type,
        record_kind,
        body_changed,
        run_key,
        body_chars_before,
        written_seq,
        lifecycle_may_have_changed,
    )
    .await;
    // Budget tests stop after all timed hook work, before the caller can
    // begin receipt I/O. The driver captures the independent timer witness
    // and probes late work, then resumes time before releasing this barrier.
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.hook_finished.notify_one();
        gate.hook_release.notified().await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn advisories_for_write_inner(
    db: &Db,
    tool: &str,
    record_id: &str,
    record_type: &str,
    record_kind: &str,
    body_changed: bool,
    run_key: Option<String>,
    body_chars_before: Option<i64>,
    written_seq: Option<i64>,
    lifecycle_may_have_changed: bool,
) -> Option<Vec<serde_json::Value>> {
    let registry = db.advisors();
    if registry.is_empty()
        || !registry.watches_for_body(tool, record_type, record_kind, body_changed)
    {
        return None;
    }
    #[cfg(test)]
    registry.note_context_build();
    // One end-to-end deadline from hook entry: the context build and every
    // advisor run share it, so worst-case added latency is ~one budget
    // total. A stage that starts with no budget left times out immediately.
    // Production always uses ADVISOR_TIMEOUT_MS; tests may widen it per
    // registry (functional presence tests do; budget tests never do).
    #[cfg(test)]
    let budget_ms = registry.test_timeout_ms().unwrap_or(ADVISOR_TIMEOUT_MS);
    #[cfg(not(test))]
    let budget_ms = ADVISOR_TIMEOUT_MS;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(budget_ms);
    // Completion context is opt-in per advisor: only compute the flag (no
    // reads) here; the fill itself runs inside the build, after the gate.
    let completion_wanted = registry.snapshot().iter().any(needs_completion_guarded);
    let built = tokio::time::timeout_at(
        deadline,
        AdviceContext::build(
            db,
            tool,
            record_id,
            run_key,
            body_chars_before,
            written_seq,
            completion_wanted,
            lifecycle_may_have_changed,
        ),
    )
    .await;
    let ctx = match built {
        Ok(Ok(Some(ctx))) => ctx,
        Ok(Ok(None)) => return None,
        Ok(Err(error)) => {
            tracing::warn!(
                target: "native::advisors",
                tool = tool,
                record_id = record_id,
                error = %error,
                "advisor context unreadable; swallowing"
            );
            return None;
        }
        Err(_) => {
            tracing::warn!(
                target: "native::advisors",
                tool = tool,
                record_id = record_id,
                timeout_ms = budget_ms,
                "advisor context timed out; swallowing"
            );
            return None;
        }
    };
    let advisories = registry.advise_all(&ctx, deadline).await;
    if advisories.is_empty() {
        return None;
    }
    Some(
        advisories
            .into_iter()
            .map(|advisory| serde_json::to_value(&advisory).unwrap_or(serde_json::Value::Null))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn setup() -> (Db, crate::mcp::ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    /// Fires on `update_record` for `WorkItem`/`task` only.
    struct UpdateTaskAdvisor;

    impl Advisor for UpdateTaskAdvisor {
        fn id(&self) -> &str {
            "test-update-task"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                Ok(vec![Advisory {
                    advisor_id: self.id().to_owned(),
                    version: self.version().to_owned(),
                    manifest_digest: None,
                    code: "test_notice".to_owned(),
                    record_id: ctx.record_id.clone(),
                    message: "test advisor fired".to_owned(),
                    level: AdvisoryLevel::Advise,
                    details: None,
                }])
            })
        }
    }

    /// Fires on `create_record` for `Document`/`note` only.
    struct CreateNoteAdvisor;

    impl Advisor for CreateNoteAdvisor {
        fn id(&self) -> &str {
            "test-create-note"
        }

        fn version(&self) -> &str {
            "0.2.0"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "create_record" && record_type == "Document" && record_kind == "note"
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                Ok(vec![Advisory {
                    advisor_id: self.id().to_owned(),
                    version: self.version().to_owned(),
                    manifest_digest: None,
                    code: "test_create_notice".to_owned(),
                    record_id: ctx.record_id.clone(),
                    message: "create advisor fired".to_owned(),
                    level: AdvisoryLevel::Advise,
                    details: None,
                }])
            })
        }
    }

    /// Always fails; the write must still succeed without advisories.
    struct ErrorAdvisor;

    impl Advisor for ErrorAdvisor {
        fn id(&self) -> &str {
            "test-error"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, _ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move { Err(crate::error::Error::engine("test advisor boom")) })
        }
    }

    /// Sleeps past the timeout; the write must not wait for it.
    struct SleepAdvisor;

    impl Advisor for SleepAdvisor {
        fn id(&self) -> &str {
            "test-sleep"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(ADVISOR_TIMEOUT_MS * 4)).await;
                Ok(vec![Advisory {
                    advisor_id: self.id().to_owned(),
                    version: self.version().to_owned(),
                    manifest_digest: None,
                    code: "too_late".to_owned(),
                    record_id: ctx.record_id.clone(),
                    message: "should have timed out".to_owned(),
                    level: AdvisoryLevel::Advise,
                    details: None,
                }])
            })
        }
    }

    async fn create_task(db: &Db, registry: &crate::mcp::ToolRegistry) -> (String, String) {
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "advisor probe",
                    "body": "probe prose",
                    "reason": "seed an advisor probe",
                }),
            )
            .await
            .unwrap();
        // The create path is unwatched by UpdateTaskAdvisor: no key appears.
        assert!(created.get("advisories").is_none());
        (
            created["id"].as_str().unwrap().to_owned(),
            created["body_digest"].as_str().unwrap().to_owned(),
        )
    }

    #[tokio::test]
    async fn update_advisory_appears_in_structured_result_and_compact_receipt() {
        let (db, registry) = setup().await;
        // Presence assertion, not a budget assertion: run generous so a
        // loaded runner cannot flip it into silence. Budget behaviour stays
        // pinned by the slow-advisor tests, which never opt in.
        db.advisors().set_test_timeout_ms(TEST_ADVISOR_BUDGET_MS);
        db.advisors().register(Arc::new(UpdateTaskAdvisor));
        let (id, _) = create_task(&db, &registry).await;
        // Default mode is the compact receipt: advisories must survive it.
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": " plus",
                    "reason": "exercise the advisor hook",
                }),
            )
            .await
            .unwrap();
        let advisories = updated
            .get("advisories")
            .and_then(serde_json::Value::as_array)
            .expect("update receipt must carry advisories");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0]["advisor_id"], json!("test-update-task"));
        assert_eq!(advisories[0]["version"], json!("0.1.0"));
        assert_eq!(advisories[0]["manifest_digest"], json!(null));
        assert_eq!(advisories[0]["code"], json!("test_notice"));
        assert_eq!(advisories[0]["record_id"], json!(id));
        assert_eq!(advisories[0]["message"], json!("test advisor fired"));
        // Verbose mode carries the same key: it is receipt content, not a
        // compact projection artefact.
        let verbose = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": " more",
                    "reason": "exercise the verbose advisor hook",
                    "response_mode": "verbose",
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            verbose["advisories"][0]["advisor_id"],
            json!("test-update-task")
        );
        db.close().await;
    }

    #[tokio::test]
    async fn content_identical_update_fires_no_advisors() {
        let (db, registry) = setup().await;
        db.advisors().register(Arc::new(UpdateTaskAdvisor));
        let (id, digest) = create_task(&db, &registry).await;
        // Same body the create wrote: observably a no-op. The whole-body
        // guard requires the current digest for any non-empty-body
        // replacement, identical or not.
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": "probe prose",
                    "if_body_digest": digest,
                    "reason": "content-identical rewrite must stay silent",
                }),
            )
            .await
            .unwrap();
        assert!(updated.get("advisories").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn create_advisory_appears_on_fresh_keyless_create() {
        let (db, registry) = setup().await;
        db.advisors().set_test_timeout_ms(TEST_ADVISOR_BUDGET_MS);
        db.advisors().register(Arc::new(CreateNoteAdvisor));
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "advisor create probe",
                    "body": "probe prose",
                    "reason": "exercise the create advisor hook",
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            created["advisories"][0]["code"],
            json!("test_create_notice")
        );
        db.close().await;
    }

    #[tokio::test]
    async fn erroring_and_sleeping_advisors_leave_write_unchanged() {
        let (db, registry) = setup().await;
        db.advisors().register(Arc::new(ErrorAdvisor));
        db.advisors().register(Arc::new(SleepAdvisor));
        let (id, _) = create_task(&db, &registry).await;
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": " plus",
                    "reason": "advisor failures must not fail the write",
                }),
            )
            .await
            .unwrap();
        assert!(updated.get("advisories").is_none());
        assert!(updated.get("body_receipt").is_some());
        db.close().await;
    }

    #[tokio::test]
    async fn keyed_create_replay_is_identical_and_carries_no_advisories() {
        let (db, registry) = setup().await;
        // The advisor WOULD fire on this shape: keyed creates skip the hook
        // entirely (first call and replay alike) so the replayed identity
        // holds byte-for-byte.
        db.advisors().register(Arc::new(CreateNoteAdvisor));
        let args = json!({
            "type": "Document",
            "kind": "note",
            "name": "replay probe",
            "body": "probe prose",
            "reason": "exercise advisor replay identity",
            "idempotency_key": "advisor-replay-probe",
        });
        let first = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                args.clone(),
            )
            .await
            .unwrap();
        let second = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                args,
            )
            .await
            .unwrap();
        assert!(first.get("advisories").is_none());
        assert_eq!(first, second);
        db.close().await;
    }

    #[tokio::test]
    async fn unwatched_write_reads_no_advisor_context() {
        // Every Db carries the default long-record install; the gate runs on
        // write-path type/kind before any context read, so unwatched writes
        // must neither build context nor carry the key.
        let (db, registry) = setup().await;
        assert!(!db.advisors().is_empty());
        assert_eq!(db.advisors().context_build_count(), 0);
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "Entity",
                    "kind": "person",
                    "name": "quiet probe",
                    "body": "probe prose",
                    "reason": "unwatched shape",
                }),
            )
            .await
            .unwrap();
        assert!(created.get("advisories").is_none());
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": created["id"],
                    "body_append": " plus",
                    "reason": "still unwatched",
                }),
            )
            .await
            .unwrap();
        assert!(updated.get("advisories").is_none());
        assert_eq!(
            db.advisors().context_build_count(),
            0,
            "unwatched writes must skip the advisor context read"
        );
        // A watched write still builds context (proving the counter works),
        // staying silent here on a small body below every milestone. The
        // create itself is watched (the completion defaults watch creates),
        // but stays silent: a fresh task is open, never completed.
        let task = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "watched probe",
                    "body": "probe prose",
                    "reason": "watched shape",
                }),
            )
            .await
            .unwrap();
        assert!(task.get("advisories").is_none());
        assert_eq!(db.advisors().context_build_count(), 1);
        let touched = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": task["id"],
                    "body_append": " plus",
                    "reason": "watched but small",
                }),
            )
            .await
            .unwrap();
        assert!(touched.get("advisories").is_none());
        assert_eq!(db.advisors().context_build_count(), 2);
        // A summary-only update on the watched task changes no body, but the
        // completion defaults watch body-untouched writes too (a completion
        // carries lifecycle, not body): context builds again, staying silent
        // on an open task with no transition and no claim.
        let renamed = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": task["id"],
                    "summary": "still small",
                    "reason": "body untouched",
                }),
            )
            .await
            .unwrap();
        assert!(renamed.get("advisories").is_none());
        assert_eq!(
            db.advisors().context_build_count(),
            3,
            "body-untouched writes build context while a watching advisor wants them"
        );
        // Suppressing the completion defaults restores the skip: with only
        // the body-needing long-record default watching, a body-untouched
        // write returns before any context read.
        let suppressed: Vec<_> = crate::mcp::advisors::startup::default_installs()
            .into_iter()
            .filter(|install| install.advisor_id != "native.long_record")
            .map(|mut install| {
                install.enabled = false;
                install
            })
            .collect();
        crate::mcp::advisors::startup::apply_installs(db.advisors(), &suppressed);
        let renamed_again = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": task["id"],
                    "summary": "still small, again",
                    "reason": "body untouched after suppression",
                }),
            )
            .await
            .unwrap();
        assert!(renamed_again.get("advisories").is_none());
        assert_eq!(
            db.advisors().context_build_count(),
            3,
            "suppressed completion defaults must not force a context build"
        );
        db.close().await;
    }

    /// Panics inside `advise`; the write must still succeed.
    struct PanicAdvisor;

    impl Advisor for PanicAdvisor {
        fn id(&self) -> &str {
            "test-panic"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, _ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                panic!("test advisor panic");
            })
        }
    }

    /// Panics synchronously while *constructing* the future (outside any
    /// async block); the construction guard must catch it.
    struct SyncPanicAdvisor;

    impl Advisor for SyncPanicAdvisor {
        fn id(&self) -> &str {
            "test-sync-panic"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, _ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            panic!("test sync construction panic");
        }
    }

    /// Panics inside `watches`; treated as not-watching, never fatal.
    struct WatchesPanicAdvisor;

    impl Advisor for WatchesPanicAdvisor {
        fn id(&self) -> &str {
            "test-watches-panic"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, _tool: &str, _record_type: &str, _record_kind: &str) -> bool {
            panic!("test watches panic");
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                Ok(vec![Advisory {
                    advisor_id: self.id().to_owned(),
                    version: self.version().to_owned(),
                    manifest_digest: None,
                    code: "unreachable".to_owned(),
                    record_id: ctx.record_id.clone(),
                    message: "must never emit".to_owned(),
                    level: AdvisoryLevel::Advise,
                    details: None,
                }])
            })
        }
    }

    /// Second firing advisor on the same shape, for order stability.
    struct SecondTaskAdvisor;

    impl Advisor for SecondTaskAdvisor {
        fn id(&self) -> &str {
            "test-second-task"
        }

        fn version(&self) -> &str {
            "0.1.0"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            tool == "update_record" && record_type == "WorkItem" && record_kind == "task"
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                Ok(vec![Advisory {
                    advisor_id: self.id().to_owned(),
                    version: self.version().to_owned(),
                    manifest_digest: None,
                    code: "second_notice".to_owned(),
                    record_id: ctx.record_id.clone(),
                    message: "second advisor fired".to_owned(),
                    level: AdvisoryLevel::Advise,
                    details: None,
                }])
            })
        }
    }

    #[tokio::test]
    async fn panicking_advisors_are_swallowed_and_do_not_hide_others() {
        let (db, registry) = setup().await;
        db.advisors().set_test_timeout_ms(TEST_ADVISOR_BUDGET_MS);
        db.advisors().register(Arc::new(PanicAdvisor));
        db.advisors().register(Arc::new(SyncPanicAdvisor));
        db.advisors().register(Arc::new(WatchesPanicAdvisor));
        db.advisors().register(Arc::new(UpdateTaskAdvisor));
        let (id, _) = create_task(&db, &registry).await;
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": " plus",
                    "reason": "panics must not fail a committed write",
                }),
            )
            .await
            .unwrap();
        // The healthy advisor still emits; neither panicking advisor appears.
        let advisories = updated
            .get("advisories")
            .and_then(serde_json::Value::as_array)
            .expect("healthy advisor must still emit");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0]["advisor_id"], json!("test-update-task"));
        db.close().await;
    }

    #[derive(Default)]
    struct BudgetProbeState {
        started_at: Option<tokio::time::Instant>,
        dropped_at: Option<tokio::time::Instant>,
        emitted: bool,
    }

    struct BudgetProbe {
        id: &'static str,
        delay: Duration,
        started: tokio::sync::Notify,
        state: std::sync::Mutex<BudgetProbeState>,
    }

    struct BudgetFutureDrop<'a>(&'a BudgetProbe);

    impl Drop for BudgetFutureDrop<'_> {
        fn drop(&mut self) {
            self.0.state.lock().unwrap().dropped_at = Some(tokio::time::Instant::now());
        }
    }

    impl Advisor for BudgetProbe {
        fn id(&self) -> &str {
            self.id
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
            UpdateTaskAdvisor.watches(tool, record_type, record_kind)
        }

        fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
            Box::pin(async move {
                let _drop = BudgetFutureDrop(self);
                self.state.lock().unwrap().started_at = Some(tokio::time::Instant::now());
                self.started.notify_one();
                tokio::time::sleep(self.delay).await;
                self.state.lock().unwrap().emitted = true;
                let mut advisory = UpdateTaskAdvisor.advise(ctx).await?;
                advisory[0].advisor_id = self.id.to_owned();
                Ok(advisory)
            })
        }
    }

    /// A runnable task prevents Tokio's paused clock from auto-advancing while
    /// SQLite is working on another thread. Drop it only once real context
    /// reads are done (an advisor started), or while the context gate is held.
    /// Then timer auto-advance measures the hook's actual chosen deadlines;
    /// the hook completion barrier keeps subsequent receipt I/O out of it.
    struct PreventAutoAdvance(tokio::task::JoinHandle<()>);

    impl PreventAutoAdvance {
        fn new() -> Self {
            Self(tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            }))
        }
    }

    impl Drop for PreventAutoAdvance {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    // A context duration beyond the budget means hold the gate until the
    // hook cancels it; release afterwards to probe for forbidden late work.
    async fn assert_shared_budget(context_ms: u64) {
        let (db, registry) = setup().await;
        let (id, _) = create_task(&db, &registry).await;
        // These advisors straddle the remaining 50 ms when context takes
        // 100 ms: resetting to a fresh 150 ms would let the first emit.
        let probes: Vec<_> = [("test-budget-short", 80), ("test-budget-long", 600)]
            .into_iter()
            .map(|(id, ms)| {
                Arc::new(BudgetProbe {
                    id,
                    delay: Duration::from_millis(ms),
                    started: tokio::sync::Notify::new(),
                    state: std::sync::Mutex::new(BudgetProbeState::default()),
                })
            })
            .collect();
        for probe in &probes {
            db.advisors().register(probe.clone());
        }
        db.advisors().register(Arc::new(UpdateTaskAdvisor));
        let context_gate = Arc::new(TestContextGate::default());
        *db.advisors().test_context_gate.write().unwrap() = Some(context_gate.clone());

        // Setup is complete. No budget override: exercise the production
        // 150 ms through the entire committed update + real context hook.
        tokio::time::pause();
        let clock_guard = PreventAutoAdvance::new();
        let start = tokio::time::Instant::now();
        let deadline = start + Duration::from_millis(ADVISOR_TIMEOUT_MS);
        // An independent timer witnesses the production budget's expiry.
        // Tokio timers may fire one tick after the raw Instant; compare actual
        // cancellation with this witness, without widening the deadline or
        // adding a scheduling tolerance. Reset deadlines still fail this check.
        let budget_expiry = tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            tokio::time::Instant::now()
        });
        let call_db = db.clone();
        let call_id = id.clone();
        let mut call = tokio::spawn(async move {
            registry
                .call(
                    call_db,
                    crate::mcp::Caller::local(),
                    "update_record",
                    json!({
                        "id": call_id,
                        "body_append": " plus",
                        "reason": "advisor stages must share one absolute deadline",
                    }),
                )
                .await
                .unwrap()
        });
        tokio::select! {
            _ = context_gate.started.notified() => {},
            result = &mut call => panic!("write bypassed context: {result:?}"),
        }
        if context_ms < ADVISOR_TIMEOUT_MS {
            tokio::time::advance(Duration::from_millis(context_ms)).await;
            context_gate.release.notify_one();
            tokio::select! {
                _ = probes[0].started.notified() => {},
                result = &mut call => panic!("context failed before advisors: {result:?}"),
            }
        }
        drop(clock_guard);
        tokio::select! {
            _ = context_gate.hook_finished.notified() => {},
            result = &mut call => panic!("write bypassed hook completion barrier: {result:?}"),
        }
        let expired_at = budget_expiry.await.unwrap();
        // The hook is held before any receipt I/O. Finish virtual-time probes
        // while it is held: releasing expired context and advancing past both
        // sleeps cannot revive cancelled futures. Resume before the call can
        // continue. Notification alone would race with receipt acquisition.
        context_gate.release.notify_one();
        tokio::time::advance(Duration::from_millis(1000)).await;
        tokio::task::yield_now().await;
        for probe in &probes {
            let state = probe.state.lock().unwrap();
            assert!(!state.emitted);
            if context_ms >= ADVISOR_TIMEOUT_MS {
                assert!(state.started_at.is_none());
            }
        }
        tokio::time::resume();
        context_gate.hook_release.notify_one();
        let updated = call.await.unwrap();
        // Observe cancellation inside the hook, before receipt rendering can
        // do unrelated I/O. The total registry.call duration is not the budget.
        assert_eq!(
            *context_gate.finished_at.lock().unwrap(),
            Some(if context_ms < ADVISOR_TIMEOUT_MS {
                start + Duration::from_millis(context_ms)
            } else {
                expired_at
            })
        );
        if context_ms < ADVISOR_TIMEOUT_MS {
            let advisories = updated["advisories"].as_array().expect("healthy advice");
            assert_eq!(advisories.len(), 1);
            assert_eq!(advisories[0]["advisor_id"], json!("test-update-task"));
            assert_eq!(advisories[0]["record_id"], json!(id));
            for probe in &probes {
                let state = probe.state.lock().unwrap();
                assert_eq!(
                    state.started_at,
                    Some(start + Duration::from_millis(context_ms)),
                    "advisors must start together with only the remaining budget"
                );
                assert_eq!(
                    state.dropped_at,
                    Some(expired_at),
                    "timed-out future must be cancelled when the shared budget expires"
                );
                assert!(!state.emitted, "late advice must not be computed");
            }
        } else {
            assert!(updated.get("advisories").is_none());
            for probe in &probes {
                assert!(probe.state.lock().unwrap().started_at.is_none());
            }
        }
        let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            body, "probe prose plus",
            "timeout cannot undo the committed write"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn advisor_budget_includes_prior_context_work_and_cancels_all_slow_advisors() {
        assert_shared_budget(100).await;
    }

    #[tokio::test]
    async fn advisor_budget_cancels_overrunning_context_before_advisors_start() {
        assert_shared_budget(200).await;
    }

    #[tokio::test]
    async fn concurrent_advisories_keep_registration_order() {
        let (db, registry) = setup().await;
        db.advisors().set_test_timeout_ms(TEST_ADVISOR_BUDGET_MS);
        db.advisors().register(Arc::new(UpdateTaskAdvisor));
        db.advisors().register(Arc::new(SecondTaskAdvisor));
        let (id, _) = create_task(&db, &registry).await;
        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": " plus",
                    "reason": "two advisors must both emit in order",
                }),
            )
            .await
            .unwrap();
        let advisories = updated
            .get("advisories")
            .and_then(serde_json::Value::as_array)
            .expect("both advisors must emit");
        assert_eq!(advisories.len(), 2);
        assert_eq!(advisories[0]["advisor_id"], json!("test-update-task"));
        assert_eq!(advisories[1]["advisor_id"], json!("test-second-task"));
        db.close().await;
    }

    #[test]
    fn advisory_serialises_to_the_contract_shape() {
        let value = serde_json::to_value(&Advisory {
            advisor_id: "demo".to_owned(),
            version: "1.0".to_owned(),
            manifest_digest: None,
            code: "notice".to_owned(),
            record_id: "rec".to_owned(),
            message: "hello".to_owned(),
            level: AdvisoryLevel::Advise,
            details: None,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "advisor_id": "demo",
                "version": "1.0",
                "manifest_digest": null,
                "code": "notice",
                "record_id": "rec",
                "message": "hello",
                "level": "advise",
            })
        );
    }

    fn streak_row(offset_secs: i64, run: &str, is_append: bool) -> AppendStreakRow {
        let anchor = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:10:00.000Z").unwrap();
        let stamp = anchor - chrono::Duration::seconds(offset_secs);
        AppendStreakRow {
            created_at: stamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            run_key: Some(run.to_owned()),
            is_append,
        }
    }

    #[test]
    fn append_streak_counts_only_consecutive_recent_same_run_transitions() {
        let run = "scout-chair-a748b2";
        // Newest-first: four append transitions inside the window.
        let rapid = vec![
            streak_row(0, run, true),
            streak_row(60, run, true),
            streak_row(120, run, true),
            streak_row(180, run, true),
            streak_row(240, run, false),
        ];
        assert_eq!(same_run_append_streak(&rapid, run), 4);
        // A gap wider than the window ends the run at the first old row.
        let spread = vec![
            streak_row(0, run, true),
            streak_row(700, run, true),
            streak_row(800, run, true),
            streak_row(900, run, true),
            streak_row(1000, run, false),
        ];
        assert_eq!(same_run_append_streak(&spread, run), 0);
        // A non-append transition (replacement or clear) breaks immediately.
        let replaced = vec![
            streak_row(0, run, false),
            streak_row(30, run, true),
            streak_row(60, run, true),
        ];
        assert_eq!(same_run_append_streak(&replaced, run), 0);
        // A different run between the endpoints is not a same-run transition.
        let other = vec![
            streak_row(0, run, true),
            streak_row(30, "scout-chair-b748b2", true),
            streak_row(60, run, true),
        ];
        assert_eq!(same_run_append_streak(&other, run), 0);
        // Degenerate inputs return 0 rather than panicking.
        assert_eq!(same_run_append_streak(&[], run), 0);
        assert_eq!(
            same_run_append_streak(
                &[AppendStreakRow {
                    created_at: "not-a-time".to_owned(),
                    run_key: Some(run.to_owned()),
                    is_append: true,
                }],
                run,
            ),
            0
        );
    }

    async fn insert_body_event(db: &Db, id: &str, record: &str, body: Option<&str>, run: &str) {
        let payload = match body {
            Some(text) => json!({ "body": text }),
            None => json!({ "body": null }),
        };
        sqlx::query(
            "INSERT INTO content_events \
             (id, record_id, type, payload, actor, run_key, causal_envelope_version, causal_status, created_at) \
             VALUES (?1, ?2, 'record.updated', ?3, 'test', ?4, 1, 'legacy_unknown', '2026-01-01T00:10:00.000Z')",
        )
        .bind(id)
        .bind(record)
        .bind(payload.to_string())
        .bind(run)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn streak_sql_rows(db: &Db, record: &str) -> Vec<AppendStreakRow> {
        use sqlx::Row as _;
        let rows = sqlx::query(APPEND_STREAK_SQL)
            .bind(record)
            .bind(ADVISOR_BODY_REVISIONS_CAP)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        rows.iter()
            .map(|row| AppendStreakRow {
                created_at: row.try_get("created_at").unwrap(),
                run_key: row.try_get("run_key").unwrap(),
                is_append: row.try_get::<i64, _>("is_append").unwrap() != 0,
            })
            .collect()
    }

    #[tokio::test]
    async fn append_streak_sql_decides_prefix_length_clears_and_non_body_edits() {
        let run = "scout-chair-a748b2";
        let db = crate::create_database(":memory:").await.unwrap();

        // A clean growing chain: four transitions, newest-first.
        for (index, body) in ["a", "ab", "abc", "abcd", "abcde"].iter().enumerate() {
            insert_body_event(&db, &format!("clean-{index}"), "clean", Some(body), run).await;
        }
        let clean = streak_sql_rows(&db, "clean").await;
        assert_eq!(
            clean.iter().map(|row| row.is_append).collect::<Vec<_>>(),
            vec![true, true, true, true, false]
        );
        assert_eq!(same_run_append_streak(&clean, run), 4);

        // Equal consecutive bodies are not strictly longer, so neither is an
        // append (finding 4: identical re-sends do not count).
        for (index, body) in ["same", "same"].iter().enumerate() {
            insert_body_event(&db, &format!("equal-{index}"), "equal", Some(body), run).await;
        }
        let equal = streak_sql_rows(&db, "equal").await;
        assert_eq!(
            equal.iter().map(|row| row.is_append).collect::<Vec<_>>(),
            vec![false, false]
        );

        // A present-but-null clear is a body revision that breaks the chain:
        // the text after it cannot be an append of the pre-clear body.
        insert_body_event(&db, "clear-0", "clear", Some("abc"), run).await;
        insert_body_event(&db, "clear-1", "clear", None, run).await;
        insert_body_event(&db, "clear-2", "clear", Some("abcd"), run).await;
        let clear = streak_sql_rows(&db, "clear").await;
        assert_eq!(
            clear.iter().map(|row| row.is_append).collect::<Vec<_>>(),
            vec![false, false, false]
        );

        // A non-body edit (no `$.body` key) is skipped when finding the
        // previous body revision, so it does not break the chain.
        insert_body_event(&db, "skip-0", "skip", Some("a"), run).await;
        sqlx::query(
            "INSERT INTO content_events \
             (id, record_id, type, payload, actor, run_key, causal_envelope_version, causal_status, created_at) \
             VALUES ('skip-1', 'skip', 'record.updated', '{\"summary\":\"metadata\"}', 'test', ?1, 1, 'legacy_unknown', '2026-01-01T00:10:00.000Z')",
        )
        .bind(run)
        .execute(db.write_pool())
        .await
        .unwrap();
        insert_body_event(&db, "skip-2", "skip", Some("ab"), run).await;
        let skip = streak_sql_rows(&db, "skip").await;
        assert_eq!(
            skip.iter().map(|row| row.is_append).collect::<Vec<_>>(),
            vec![true, false]
        );

        db.close().await;
    }
}
