//! Opt-in measurements of the shipped link reader, on its pinned connection.
//! Own the connection's single SQLite trace slot exclusively. Do not combine
//! this scope with another trace observer. The progress/deadline handler stays
//! installed throughout; EXPLAIN work has its own phase, outside query timings.
use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, Row, SqliteConnection};

use crate::{error::Error, Result};

#[derive(Clone, Default)]
pub(crate) struct Options {
    pub explain: bool,
    pub before_batch: Option<Arc<tokio::sync::Barrier>>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryPreparation {
    #[default]
    Ordinary,
    PrepareFirst,
}

tokio::task_local! {
    static PREPARATION: (QueryPreparation, bool);
    static STATEMENT_METADATA: ();
    static GENERIC_VISIBILITY_CANDIDATE: bool;
}

pub(crate) async fn with_generic_visibility_variant<F: std::future::Future>(
    candidate: bool,
    work: F,
) -> F::Output {
    GENERIC_VISIBILITY_CANDIDATE.scope(candidate, work).await
}

// Ordinary tests follow production; experiments must explicitly opt in.
pub(super) fn generic_visibility_candidate() -> bool {
    GENERIC_VISIBILITY_CANDIDATE
        .try_with(|candidate| *candidate)
        .unwrap_or(false)
}

pub(crate) async fn with_link_statement_metadata<F: std::future::Future>(work: F) -> F::Output {
    STATEMENT_METADATA.scope((), work).await
}

unsafe extern "C" fn destroy_connection_identity(value: *mut c_void) {
    // SAFETY: only SQLite owns this Box after clientdata registration, and
    // invokes this destructor once on replacement, registration failure or close.
    drop(unsafe { Box::from_raw(value.cast::<u64>()) });
}

unsafe fn identity_on_handle(raw: *mut libsqlite3_sys::sqlite3) -> Result<u64> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let key = b"native_ce.link_diagnostic.connection.v1\0";
    let existing = unsafe { libsqlite3_sys::sqlite3_get_clientdata(raw, key.as_ptr().cast()) };
    if !existing.is_null() {
        return Ok(unsafe { *existing.cast::<u64>() });
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let value = Box::into_raw(Box::new(id));
    // SQLite calls the destructor even if registration fails. Do not free it
    // again on that path. This tag registers no function or SQL statement.
    let status = unsafe {
        libsqlite3_sys::sqlite3_set_clientdata(
            raw,
            key.as_ptr().cast(),
            value.cast(),
            Some(destroy_connection_identity),
        )
    };
    if status != libsqlite3_sys::SQLITE_OK {
        return Err(Error::engine(format!(
            "diagnostic connection identity failed: {status}"
        )));
    }
    Ok(id)
}

/// Stable for the physical connection lifetime, including after pool return.
/// A missing observation does not establish that a connection was closed.
pub(crate) async fn connection_identity(conn: &mut SqliteConnection) -> Result<u64> {
    let mut handle = conn.lock_handle().await?;
    // SAFETY: SQLx's handle lock excludes all connection work and close.
    unsafe { identity_on_handle(handle.as_raw_handle().as_ptr()) }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatementCounters {
    pub statement_token: String,
    pub sql_sha256: String,
    pub runs: i32,
    pub reprepares: i32,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ConnectionMetadata {
    pub connection_id: u64,
    pub cached_statements: usize,
    pub raw_statement_count: usize,
    pub main_cookie: i64,
    pub temp_cookie: i64,
    /// Only statements whose original SQL exactly matches the lane's SQL.
    pub matching_statements: Vec<StatementCounters>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatementDelta {
    pub statement_token: String,
    pub runs: Option<u64>,
    pub reprepares: Option<u64>,
    /// A matching pointer token and monotonic counters are evidence of reuse,
    /// not a proof against a finalized statement being replaced at that address.
    pub continuity: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct QueryMetadata {
    pub lane: &'static str,
    pub sql_sha256: String,
    pub before: ConnectionMetadata,
    pub after: Option<ConnectionMetadata>,
    pub deltas: Vec<StatementDelta>,
}

fn metadata_phase(lane: &str) -> &'static str {
    match lane {
        "generic" => "generic_metadata",
        "legacy" => "legacy_metadata",
        "provider" => "provider_metadata",
        "control_generic" => "control_generic_metadata",
        "control_legacy" => "control_legacy_metadata",
        "control_provider" => "control_provider_metadata",
        _ => "statement_metadata",
    }
}

async fn connection_metadata(conn: &mut SqliteConnection, sql: &str) -> Result<ConnectionMetadata> {
    let sql_hash = hex::encode(Sha256::digest(sql.as_bytes()));
    // Inspect before the metadata PRAGMAs so those probes do not enter this
    // inventory. All status reads use reset=0 on an idle, exclusively locked DB.
    let (connection_id, raw_statement_count, matching_statements) = {
        let mut handle = conn.lock_handle().await?;
        let raw = handle.as_raw_handle().as_ptr();
        let connection_id = unsafe { identity_on_handle(raw)? };
        let mut count = 0;
        let mut matches = Vec::new();
        let mut statement = std::ptr::null_mut();
        loop {
            // SAFETY: the handle lock keeps the DB and every enumerated
            // statement alive and excludes concurrent finalize/reset/step.
            statement = unsafe { libsqlite3_sys::sqlite3_next_stmt(raw, statement) };
            if statement.is_null() {
                break;
            }
            count += 1;
            let original = unsafe { libsqlite3_sys::sqlite3_sql(statement) };
            if original.is_null() {
                continue;
            }
            let bytes = unsafe { CStr::from_ptr(original) }.to_bytes();
            if bytes != sql.as_bytes() {
                continue;
            }
            let mut token = Sha256::new();
            token.update(connection_id.to_le_bytes());
            token.update((statement as usize).to_le_bytes());
            matches.push(StatementCounters {
                statement_token: hex::encode(token.finalize()),
                sql_sha256: sql_hash.clone(),
                runs: unsafe {
                    libsqlite3_sys::sqlite3_stmt_status(
                        statement,
                        libsqlite3_sys::SQLITE_STMTSTATUS_RUN,
                        0,
                    )
                },
                reprepares: unsafe {
                    libsqlite3_sys::sqlite3_stmt_status(
                        statement,
                        libsqlite3_sys::SQLITE_STMTSTATUS_REPREPARE,
                        0,
                    )
                },
            });
        }
        (connection_id, count, matches)
    };
    // The handle lock also fences SQLx's post-result cache publication.
    let cached_statements = conn.cached_statements_size();
    let mut cookies = Vec::new();
    for pragma in ["PRAGMA main.schema_version", "PRAGMA temp.schema_version"] {
        // Drive each probe through SQLITE_DONE; fetch_one could leave its
        // PROFILE/reset work attributed to the following query phase.
        let rows = sqlx::query(pragma)
            .persistent(false)
            .fetch_all(&mut *conn)
            .await?;
        if rows.len() != 1 {
            return Err(Error::engine(
                "statement metadata cookie returned an unexpected row count",
            ));
        }
        cookies.push(rows[0].try_get::<i64, _>(0)?);
    }
    Ok(ConnectionMetadata {
        connection_id,
        cached_statements,
        raw_statement_count,
        main_cookie: cookies[0],
        temp_cookie: cookies[1],
        matching_statements,
    })
}

fn statement_deltas(
    before: &ConnectionMetadata,
    after: &ConnectionMetadata,
) -> Vec<StatementDelta> {
    let mut deltas = Vec::new();
    for next in &after.matching_statements {
        let previous = before.matching_statements.iter().find(|previous| {
            previous.statement_token == next.statement_token
                && previous.sql_sha256 == next.sql_sha256
        });
        let counters = previous.filter(|p| {
            before.connection_id == after.connection_id
                && p.runs >= 0
                && p.reprepares >= 0
                && next.runs >= p.runs
                && next.reprepares >= p.reprepares
        });
        deltas.push(StatementDelta {
            statement_token: next.statement_token.clone(),
            runs: counters.map(|p| (next.runs - p.runs) as u64),
            reprepares: counters.map(|p| (next.reprepares - p.reprepares) as u64),
            continuity: if counters.is_some() {
                "same_token_monotonic_counters"
            } else if previous.is_some() {
                "counter_decrease_or_connection_change"
            } else {
                "not_present_before"
            },
        });
    }
    for previous in &before.matching_statements {
        if !after
            .matching_statements
            .iter()
            .any(|next| next.statement_token == previous.statement_token)
        {
            deltas.push(StatementDelta {
                statement_token: previous.statement_token.clone(),
                runs: None,
                reprepares: None,
                continuity: "not_present_after",
            });
        }
    }
    deltas
}

/// Compare preparation on the same SQLx execution path. Cache priming/clearing
/// belongs to the caller; this scope never replaces its progress guard.
pub(crate) async fn with_link_query_preparation<F: std::future::Future>(
    mode: QueryPreparation,
    invalidate_temp: bool,
    work: F,
) -> F::Output {
    PREPARATION.scope((mode, invalidate_temp), work).await
}

pub(super) async fn before_query(
    conn: &mut SqliteConnection,
    lane: &'static str,
    sql: &str,
) -> Result<()> {
    if STATEMENT_METADATA.try_with(|_| ()).is_ok() && ACTIVE.try_with(|_| ()).is_ok() {
        phase(metadata_phase(lane));
        let before = connection_metadata(conn, sql).await?;
        ACTIVE.with(|observation| {
            observation
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .diagnostic
                .query_metadata
                .push(QueryMetadata {
                    lane,
                    sql_sha256: hex::encode(Sha256::digest(sql.as_bytes())),
                    before,
                    after: None,
                    deltas: Vec::new(),
                })
        });
    }
    let (prepare, invalidation, query) = match lane {
        "generic" => ("generic_prepare", "generic_invalidation", "generic_query"),
        "legacy" => ("legacy_prepare", "legacy_invalidation", "legacy_query"),
        "provider" => (
            "provider_prepare",
            "provider_invalidation",
            "provider_query",
        ),
        "control_generic" => (
            "control_generic_prepare",
            "control_generic_invalidation",
            "control_generic_query",
        ),
        "control_legacy" => (
            "control_legacy_prepare",
            "control_legacy_invalidation",
            "control_legacy_query",
        ),
        "control_provider" => (
            "control_provider_prepare",
            "control_provider_invalidation",
            "control_provider_query",
        ),
        _ => return Err(Error::engine("unknown link preparation diagnostic lane")),
    };
    let (mode, invalidate_temp) = PREPARATION
        .try_with(|configuration| *configuration)
        .unwrap_or_default();
    if matches!(mode, QueryPreparation::PrepareFirst) {
        phase(prepare);
        let statement = (&mut *conn).prepare_with(sql, &[]).await?;
        drop(statement);
    }
    if invalidate_temp {
        phase(invalidation);
        // Deliberately refuse a name collision; never remove pre-existing
        // caller state. This opt-in scratch DDL is outside prepare/query sums.
        sqlx::query("CREATE TEMP TABLE _native_diag_link_prepare_invalidation(x)")
            .persistent(false)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP TABLE temp._native_diag_link_prepare_invalidation")
            .persistent(false)
            .execute(&mut *conn)
            .await?;
    }
    phase(query);
    Ok(())
}

pub(super) async fn after_query(
    conn: &mut SqliteConnection,
    lane: &'static str,
    sql: &str,
) -> Result<()> {
    if STATEMENT_METADATA.try_with(|_| ()).is_err() || ACTIVE.try_with(|_| ()).is_err() {
        return Ok(());
    }
    phase(metadata_phase(lane));
    let after = connection_metadata(conn, sql).await?;
    ACTIVE.with(|observation| {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(query) = state
            .diagnostic
            .query_metadata
            .iter_mut()
            .rev()
            .find(|query| query.lane == lane && query.after.is_none())
        {
            query.deltas = statement_deltas(&query.before, &after);
            query.after = Some(after);
        }
    });
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Phase {
    pub phase: &'static str,
    pub elapsed_us: u64,
    pub statements: u64,
    pub vm_steps: u64,
    /// SQLite's PROFILE wall time, including time descheduled in sqlite3_step;
    /// this is not a CPU-time counter and may have coarse clock resolution.
    pub sqlite_profile_ns: u64,
    pub sqlite_rows: u64,
    /// Home anchors returned by scope preparation, or rows returned by a
    /// complete link query before shaping; cached scope output still counts.
    pub returned_rows: u64,
    /// Offsets from observer creation; repeated phases keep separate intervals.
    pub intervals: Vec<PhaseInterval>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PhaseInterval {
    pub started_ns: u64,
    pub finished_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatementTimeline {
    pub phase: &'static str,
    pub started_ns: u64,
    pub first_row_ns: Option<u64>,
    /// None means no PROFILE completion was observed before detach.
    pub finished_ns: Option<u64>,
    /// Same SQLx worker thread, STMT to PROFILE; not preparation CPU time.
    pub worker_cpu_ns: Option<u64>,
    pub vm_steps: u64,
    pub sqlite_rows: u64,
    pub sqlite_profile_ns: Option<u64>,
    pub stmt_events: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PlanRow {
    pub id: i64,
    pub parent: i64,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Plan {
    pub phase: &'static str,
    pub rows: Vec<PlanRow>,
    /// Static EXPLAIN program length, not executed VM work or compiler CPU.
    pub bytecode_ops: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Diagnostic {
    pub barrier_wait_us: u64,
    /// Observer lifetime through detach, including trace install/cleanup.
    /// Phase intervals isolate the measured work inside that lifetime.
    pub elapsed_ns: u64,
    pub statement_timeline: Vec<StatementTimeline>,
    pub query_metadata: Vec<QueryMetadata>,
    pub phases: Vec<Phase>,
    pub plans: Vec<Plan>,
    pub succeeded: bool,
    pub rows: usize,
}

struct Request {
    options: Options,
    results: Mutex<Vec<Diagnostic>>,
}

#[derive(Default)]
struct State {
    diagnostic: Diagnostic,
    active: Option<(usize, Instant)>,
    // Attribute completion to the phase that started the statement, even if
    // SQLx resets a partially consumed statement after its await completes.
    statements: HashMap<usize, RunningStatement>,
}

struct RunningStatement {
    phase_index: usize,
    timeline_index: usize,
    vm_before: i32,
    cpu_before: Option<u64>,
}

struct Observation {
    origin: Instant,
    state: Mutex<State>,
    detached: AtomicBool,
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            state: Mutex::default(),
            detached: AtomicBool::default(),
        }
    }
}

fn worker_cpu_ns() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the timespec on success. This is
        // sampled inside SQLite callbacks, on the same connection worker.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, clock.as_mut_ptr()) } != 0 {
            return None;
        }
        let clock = unsafe { clock.assume_init() };
        u64::try_from(clock.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(clock.tv_nsec).ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

tokio::task_local! {
    static REQUEST: Arc<Request>;
    static ACTIVE: Arc<Observation>;
}

pub(crate) async fn with_link_read_diagnostics<F: std::future::Future>(
    options: Options,
    work: F,
) -> (F::Output, Vec<Diagnostic>) {
    let request = Arc::new(Request {
        options,
        results: Mutex::new(Vec::new()),
    });
    let result = REQUEST.scope(request.clone(), work).await;
    let diagnostics =
        std::mem::take(&mut *request.results.lock().unwrap_or_else(|p| p.into_inner()));
    (result, diagnostics)
}

pub(super) fn enabled() -> bool {
    REQUEST.try_with(|_| ()).is_ok()
}

fn finish_phase(state: &mut State, origin: Instant) {
    if let Some((index, started)) = state.active.take() {
        let now = Instant::now();
        state.diagnostic.phases[index].elapsed_us += now.duration_since(started).as_micros() as u64;
        state.diagnostic.phases[index]
            .intervals
            .push(PhaseInterval {
                started_ns: started.duration_since(origin).as_nanos() as u64,
                finished_ns: now.duration_since(origin).as_nanos() as u64,
            });
    }
}

pub(crate) fn phase(name: &'static str) {
    let _ = ACTIVE.try_with(|observation| {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        finish_phase(&mut state, observation.origin);
        let index = state
            .diagnostic
            .phases
            .iter()
            .position(|p| p.phase == name)
            .unwrap_or_else(|| {
                state.diagnostic.phases.push(Phase {
                    phase: name,
                    ..Default::default()
                });
                state.diagnostic.phases.len() - 1
            });
        state.active = Some((index, Instant::now()));
    });
}

pub(super) fn returned_rows(rows: usize) {
    let _ = ACTIVE.try_with(|observation| {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((index, _)) = state.active {
            state.diagnostic.phases[index].returned_rows += rows as u64;
        }
    });
}

pub(super) async fn explain_bound(
    conn: &mut SqliteConnection,
    name: &'static str,
    sql: &str,
    homes: &str,
    principal: &str,
    anchors: &str,
) -> Result<()> {
    if !REQUEST
        .try_with(|request| request.options.explain)
        .unwrap_or(false)
    {
        return Ok(());
    }
    phase("explain");
    let rows = sqlx::query(&format!("EXPLAIN QUERY PLAN {sql}"))
        .persistent(false)
        .bind(homes)
        .bind(principal)
        .bind(anchors)
        .fetch_all(&mut *conn)
        .await?;
    let rows = rows
        .into_iter()
        .map(|row| {
            Ok(PlanRow {
                id: row.try_get(0)?,
                parent: row.try_get(1)?,
                detail: row.try_get(3)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let bytecode_ops = sqlx::query(&format!("EXPLAIN {sql}"))
        .persistent(false)
        .bind(homes)
        .bind(principal)
        .bind(anchors)
        .fetch_all(conn)
        .await?
        .len();
    let _ = ACTIVE.try_with(|observation| {
        observation
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .diagnostic
            .plans
            .push(Plan {
                phase: name,
                rows,
                bytecode_ops,
            });
    });
    Ok(())
}

struct Trace {
    observation: Arc<Observation>,
    connection: usize,
}

unsafe extern "C" fn trace(
    event: u32,
    context: *mut c_void,
    statement: *mut c_void,
    detail: *mut c_void,
) -> i32 {
    if event == libsqlite3_sys::SQLITE_TRACE_CLOSE as u32 {
        // SAFETY: SQLite owns one Arc until explicit detach or close. Close
        // can precede SQLITE_BUSY, so unregister before releasing that Arc.
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(statement.cast(), 0, None, std::ptr::null_mut());
        }
        let observation = unsafe { Arc::from_raw(context.cast::<Observation>()) };
        observation.detached.store(true, Ordering::Relaxed);
        return 0;
    }
    // SAFETY: the callback's SQLite-owned Arc and live statement outlast this
    // call, including cancellation of the Rust future owning the other Arc.
    let observation = unsafe { &*context.cast::<Observation>() };
    let event_ns = observation.origin.elapsed().as_nanos() as u64;
    let cpu_ns = if event == libsqlite3_sys::SQLITE_TRACE_STMT as u32
        || event == libsqlite3_sys::SQLITE_TRACE_PROFILE as u32
    {
        worker_cpu_ns()
    } else {
        None
    };
    let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
    let key = statement as usize;
    if event == libsqlite3_sys::SQLITE_TRACE_STMT as u32 {
        // SQLite can emit STMT again while automatically recompiling the
        // same execution. Retain its first counter/CPU baseline and timeline;
        // replacing it would leave an unfinished phantom execution behind.
        if let Some(running) = state.statements.get(&key) {
            let timeline_index = running.timeline_index;
            state.diagnostic.statement_timeline[timeline_index].stmt_events += 1;
            return 0;
        }
        if let Some((index, _)) = state.active {
            let before = unsafe {
                libsqlite3_sys::sqlite3_stmt_status(
                    statement.cast(),
                    libsqlite3_sys::SQLITE_STMTSTATUS_VM_STEP,
                    0,
                )
            };
            let timeline_index = state.diagnostic.statement_timeline.len();
            let name = state.diagnostic.phases[index].phase;
            state.diagnostic.statement_timeline.push(StatementTimeline {
                phase: name,
                started_ns: event_ns,
                first_row_ns: None,
                finished_ns: None,
                worker_cpu_ns: None,
                vm_steps: 0,
                sqlite_rows: 0,
                sqlite_profile_ns: None,
                stmt_events: 1,
            });
            state.statements.insert(
                key,
                RunningStatement {
                    phase_index: index,
                    timeline_index,
                    vm_before: before,
                    cpu_before: cpu_ns,
                },
            );
            state.diagnostic.phases[index].statements += 1;
        }
    } else if event == libsqlite3_sys::SQLITE_TRACE_ROW as u32 {
        if let Some(running) = state.statements.get(&key) {
            let (index, timeline_index) = (running.phase_index, running.timeline_index);
            state.diagnostic.phases[index].sqlite_rows += 1;
            let timeline = &mut state.diagnostic.statement_timeline[timeline_index];
            timeline.sqlite_rows += 1;
            timeline.first_row_ns.get_or_insert(event_ns);
        }
    } else if event == libsqlite3_sys::SQLITE_TRACE_PROFILE as u32 {
        if let Some(running) = state.statements.remove(&key) {
            let index = running.phase_index;
            let after = unsafe {
                libsqlite3_sys::sqlite3_stmt_status(
                    statement.cast(),
                    libsqlite3_sys::SQLITE_STMTSTATUS_VM_STEP,
                    0,
                )
            };
            let vm_steps = after.saturating_sub(running.vm_before).max(0) as u64;
            let profile_ns = if detail.is_null() {
                None
            } else {
                Some(unsafe { *detail.cast::<u64>() })
            };
            state.diagnostic.phases[index].vm_steps += vm_steps;
            state.diagnostic.phases[index].sqlite_profile_ns += profile_ns.unwrap_or(0);
            let timeline = &mut state.diagnostic.statement_timeline[running.timeline_index];
            timeline.finished_ns = Some(event_ns);
            timeline.worker_cpu_ns = running
                .cpu_before
                .zip(cpu_ns)
                .and_then(|(before, after)| after.checked_sub(before));
            timeline.vm_steps = vm_steps;
            timeline.sqlite_profile_ns = profile_ns;
        }
    }
    0
}

impl Trace {
    async fn install(conn: &mut SqliteConnection, observation: Arc<Observation>) -> Result<Self> {
        let mut handle = conn.lock_handle().await?;
        let raw = handle.as_raw_handle().as_ptr();
        let context = Arc::into_raw(observation.clone());
        // SAFETY: locked handle excludes concurrent connection work. SQLite
        // owns the transferred Arc until finish or the close callback.
        let status = unsafe {
            libsqlite3_sys::sqlite3_trace_v2(
                raw,
                (libsqlite3_sys::SQLITE_TRACE_STMT
                    | libsqlite3_sys::SQLITE_TRACE_PROFILE
                    | libsqlite3_sys::SQLITE_TRACE_ROW
                    | libsqlite3_sys::SQLITE_TRACE_CLOSE) as u32,
                Some(trace),
                context.cast_mut().cast(),
            )
        };
        if status != libsqlite3_sys::SQLITE_OK {
            drop(unsafe { Arc::from_raw(context) });
            return Err(Error::engine(format!(
                "link diagnostic trace installation failed: {status}"
            )));
        }
        Ok(Self {
            observation,
            connection: raw as usize,
        })
    }

    async fn finish(self, conn: &mut SqliteConnection) -> Result<()> {
        let mut handle = conn.lock_handle().await?;
        let raw = handle.as_raw_handle().as_ptr();
        if raw as usize != self.connection || self.observation.detached.load(Ordering::Relaxed) {
            return Err(Error::engine("link diagnostic trace connection changed"));
        }
        // SAFETY: the original locked connection is idle. Detach first, then
        // reclaim exactly the Arc reference transferred during installation.
        unsafe {
            libsqlite3_sys::sqlite3_trace_v2(raw, 0, None, std::ptr::null_mut());
            drop(Arc::from_raw(Arc::as_ptr(&self.observation)));
        }
        self.observation.detached.store(true, Ordering::Relaxed);
        Ok(())
    }
}

pub(super) async fn measure(
    conn: &mut SqliteConnection,
    principal: &str,
    anchors: &[String],
) -> Result<Vec<serde_json::Value>> {
    let request = REQUEST.with(Clone::clone);
    let mut diagnostic = Diagnostic::default();
    if let Some(barrier) = &request.options.before_batch {
        let started = Instant::now();
        let wait = tokio::time::timeout(Duration::from_secs(2), barrier.wait()).await;
        diagnostic.barrier_wait_us = started.elapsed().as_micros() as u64;
        if wait.is_err() {
            request
                .results
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(diagnostic);
            return Err(Error::engine("link diagnostic barrier deadline exceeded"));
        }
    }
    let observation = Arc::new(Observation {
        state: Mutex::new(State {
            diagnostic,
            ..Default::default()
        }),
        ..Default::default()
    });
    let observer = Trace::install(conn, observation.clone()).await?;
    let result = ACTIVE
        .scope(
            observation.clone(),
            super::visible_link_rows_for_on_inner(conn, principal, anchors),
        )
        .await;
    {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        finish_phase(&mut state, observation.origin);
    }
    let cleanup = observer.finish(conn).await;
    let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
    state.diagnostic.elapsed_ns = observation.origin.elapsed().as_nanos() as u64;
    state.diagnostic.succeeded = result.is_ok() && cleanup.is_ok();
    state.diagnostic.rows = result.as_ref().map_or(0, Vec::len);
    request
        .results
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(state.diagnostic.clone());
    // Preserve the original reader error if observer cleanup also failed.
    result.and_then(|rows| cleanup.map(|()| rows))
}

/// Direct probes use the caller's pinned connection and existing guard. They
/// neither acquire a pool slot nor install/reset a progress handler or barrier.
pub(crate) async fn measure_readiness(conn: &mut SqliteConnection) -> (Result<()>, Diagnostic) {
    measure_direct(conn, None).await
}

pub(crate) async fn measure_dispatch_control(
    conn: &mut SqliteConnection,
    statements: usize,
) -> (Result<()>, Diagnostic) {
    measure_direct(conn, Some(statements)).await
}

/// Three scalar executions with the same three bound argument shapes as the
/// link batch. Both modes execute this exact SQL through query_scalar.
pub(crate) async fn measure_preparation_control(
    conn: &mut SqliteConnection,
    mode: QueryPreparation,
    invalidate_temp: bool,
) -> (Result<()>, Diagnostic) {
    let observation = Arc::new(Observation::default());
    let observer = match Trace::install(conn, observation.clone()).await {
        Ok(observer) => observer,
        Err(error) => return (Err(error), Diagnostic::default()),
    };
    let result = ACTIVE
        .scope(
            observation.clone(),
            with_link_query_preparation(mode, invalidate_temp, async {
                // Three distinct cache keys match the link batch's three
                // distinct SQL texts; these still control only trivial work.
                for (lane, sql) in [
                    ("control_generic", "SELECT 1 WHERE ?1 IS NOT NULL AND ?2 IS NOT NULL AND ?3 IS NOT NULL /* generic */"),
                    ("control_legacy", "SELECT 1 WHERE ?1 IS NOT NULL AND ?2 IS NOT NULL AND ?3 IS NOT NULL /* legacy */"),
                    ("control_provider", "SELECT 1 WHERE ?1 IS NOT NULL AND ?2 IS NOT NULL AND ?3 IS NOT NULL /* provider */"),
                ] {
                    before_query(conn, lane, sql).await?;
                    let value: i64 = sqlx::query_scalar(sql)
                        .bind("[]")
                        .bind("diagnostic:principal")
                        .bind("[]")
                        .fetch_one(&mut *conn)
                        .await?;
                    if value != 1 {
                        return Err(Error::engine(
                            "link preparation control returned an unexpected value",
                        ));
                    }
                    returned_rows(1);
                    after_query(conn, lane, sql).await?;
                }
                Ok(())
            }),
        )
        .await;
    {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        finish_phase(&mut state, observation.origin);
    }
    let cleanup = observer.finish(conn).await;
    let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
    state.diagnostic.elapsed_ns = observation.origin.elapsed().as_nanos() as u64;
    state.diagnostic.succeeded = result.is_ok() && cleanup.is_ok();
    (result.and(cleanup), state.diagnostic.clone())
}

async fn measure_direct(
    conn: &mut SqliteConnection,
    control: Option<usize>,
) -> (Result<()>, Diagnostic) {
    let observation = Arc::new(Observation::default());
    let observer = match Trace::install(conn, observation.clone()).await {
        Ok(observer) => observer,
        Err(error) => return (Err(error), Diagnostic::default()),
    };
    let result = ACTIVE
        .scope(observation.clone(), async {
            if let Some(statements) = control {
                phase("dispatch_control");
                for _ in 0..statements {
                    let _: i64 = sqlx::query_scalar("SELECT 1").fetch_one(&mut *conn).await?;
                }
                Ok(())
            } else {
                phase("readiness");
                super::super::provider_link_reads::require_ready_on(&mut *conn).await
            }
        })
        .await;
    {
        let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
        finish_phase(&mut state, observation.origin);
    }
    let cleanup = observer.finish(conn).await;
    let mut state = observation.state.lock().unwrap_or_else(|p| p.into_inner());
    state.diagnostic.elapsed_ns = observation.origin.elapsed().as_nanos() as u64;
    state.diagnostic.succeeded = result.is_ok() && cleanup.is_ok();
    (result.and(cleanup), state.diagnostic.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    async fn raw_probe_counters(conn: &mut SqliteConnection, sql: &str) -> (i32, i32) {
        let mut handle = conn.lock_handle().await.unwrap();
        let db = handle.as_raw_handle().as_ptr();
        let mut statement = std::ptr::null_mut();
        loop {
            // SAFETY: the idle SQLx handle is exclusively locked throughout
            // enumeration, SQL comparison and the independent status reads.
            statement = unsafe { libsqlite3_sys::sqlite3_next_stmt(db, statement) };
            assert!(!statement.is_null(), "cached probe statement disappeared");
            let original = unsafe { libsqlite3_sys::sqlite3_sql(statement) };
            if !original.is_null()
                && unsafe { CStr::from_ptr(original) }.to_bytes() == sql.as_bytes()
            {
                return unsafe {
                    (
                        libsqlite3_sys::sqlite3_stmt_status(
                            statement,
                            libsqlite3_sys::SQLITE_STMTSTATUS_RUN,
                            0,
                        ),
                        libsqlite3_sys::sqlite3_stmt_status(
                            statement,
                            libsqlite3_sys::SQLITE_STMTSTATUS_REPREPARE,
                            0,
                        ),
                    )
                };
            }
        }
    }

    async fn observed_probe_query(conn: &mut SqliteConnection, sql: &str) -> Diagnostic {
        let observation = Arc::new(Observation::default());
        let observer = Trace::install(conn, observation.clone()).await.unwrap();
        with_link_statement_metadata(ACTIVE.scope(observation.clone(), async {
            before_query(conn, "generic", sql).await.unwrap();
            let rows: Vec<i64> = sqlx::query_scalar(sql)
                .bind(1_i64)
                .fetch_all(&mut *conn)
                .await
                .unwrap();
            assert_eq!(rows, [7]);
            returned_rows(rows.len());
            after_query(conn, "generic", sql).await.unwrap();
        }))
        .await;
        {
            let mut state = observation.state.lock().unwrap();
            finish_phase(&mut state, observation.origin);
        }
        observer.finish(conn).await.unwrap();
        let diagnostic = observation.state.lock().unwrap().diagnostic.clone();
        diagnostic
    }

    #[tokio::test]
    async fn statement_metadata_matches_raw_counters_across_reuse_and_temp_invalidation() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE diag_stmt_source(x)")
            .persistent(false)
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO diag_stmt_source VALUES(7)")
            .persistent(false)
            .execute(&mut conn)
            .await
            .unwrap();
        const SQL: &str = "SELECT x FROM diag_stmt_source WHERE ?1 IS NOT NULL";
        let _: Vec<i64> = sqlx::query_scalar(SQL)
            .bind(1_i64)
            .fetch_all(&mut conn)
            .await
            .unwrap();
        let identity = connection_identity(&mut conn).await.unwrap();
        for invalidate_temp in [false, true] {
            let before = raw_probe_counters(&mut conn, SQL).await;
            if invalidate_temp {
                sqlx::query("CREATE TEMP TABLE diag_stmt_cookie_change(x)")
                    .persistent(false)
                    .execute(&mut conn)
                    .await
                    .unwrap();
                sqlx::query("DROP TABLE temp.diag_stmt_cookie_change")
                    .persistent(false)
                    .execute(&mut conn)
                    .await
                    .unwrap();
            }
            let diagnostic = observed_probe_query(&mut conn, SQL).await;
            let after = raw_probe_counters(&mut conn, SQL).await;
            assert_eq!(diagnostic.query_metadata.len(), 1);
            let metadata = &diagnostic.query_metadata[0];
            let start = &metadata.before.matching_statements[0];
            let end = &metadata.after.as_ref().unwrap().matching_statements[0];
            assert_eq!((start.runs, start.reprepares), before);
            assert_eq!((end.runs, end.reprepares), after);
            assert_eq!(metadata.before.connection_id, identity);
            assert_eq!(metadata.after.as_ref().unwrap().connection_id, identity);
            assert_eq!(
                metadata.before.main_cookie,
                metadata.after.as_ref().unwrap().main_cookie
            );
            assert_eq!(
                metadata.before.temp_cookie,
                metadata.after.as_ref().unwrap().temp_cookie
            );
            assert_eq!(
                metadata.before.cached_statements,
                metadata.after.as_ref().unwrap().cached_statements
            );
            let delta = &metadata.deltas[0];
            assert_eq!(delta.continuity, "same_token_monotonic_counters");
            assert_eq!(delta.runs, Some((after.0 - before.0) as u64));
            assert_eq!(delta.reprepares, Some((after.1 - before.1) as u64));
            assert!(after.0 > before.0);
            if invalidate_temp {
                assert!(
                    after.1 > before.1,
                    "TEMP invalidation must reprepare the cached table query"
                );
            } else {
                assert_eq!(after.1, before.1);
            }
            let query_timelines: Vec<_> = diagnostic
                .statement_timeline
                .iter()
                .filter(|s| s.phase == "generic_query")
                .collect();
            assert_eq!(
                query_timelines.len(),
                1,
                "repeated STMT must not invent another execution"
            );
            assert!(query_timelines[0].stmt_events >= 1);
            assert!(diagnostic
                .statement_timeline
                .iter()
                .all(|s| s.finished_ns.is_some()));
        }
        conn.close().await.unwrap();
        let mut another = SqliteConnection::connect(":memory:").await.unwrap();
        assert_ne!(connection_identity(&mut another).await.unwrap(), identity);
        another.close().await.unwrap();
    }

    #[tokio::test]
    async fn trace_counts_reused_statements_rows_and_detaches() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let observation = Arc::new(Observation::default());
        let observer = Trace::install(&mut conn, observation.clone())
            .await
            .unwrap();
        ACTIVE
            .scope(observation.clone(), async {
                phase("query");
                let mut previous_steps = 0;
                let mut first_steps = None;
                for _ in 0..2 {
                    let rows = sqlx::query("SELECT 1 UNION ALL SELECT 2")
                        .fetch_all(&mut conn)
                        .await
                        .unwrap();
                    returned_rows(rows.len());
                    let steps = observation.state.lock().unwrap().diagnostic.phases[0].vm_steps;
                    let delta = steps - previous_steps;
                    assert!(delta > 0);
                    if let Some(first) = first_steps {
                        assert_eq!(delta, first, "cached execution must count its own VM work");
                    } else {
                        first_steps = Some(delta);
                    }
                    previous_steps = steps;
                }
            })
            .await;
        observer.finish(&mut conn).await.unwrap();
        {
            let state = observation.state.lock().unwrap();
            let query = &state.diagnostic.phases[0];
            assert_eq!(query.statements, 2);
            assert_eq!(query.sqlite_rows, 4);
            assert_eq!(query.returned_rows, 4);
            assert!(query.vm_steps > 0);
            let timeline = &state.diagnostic.statement_timeline;
            assert_eq!(timeline.len(), 2);
            for statement in timeline {
                assert_eq!(statement.phase, "query");
                let first_row = statement.first_row_ns.unwrap();
                let finished = statement.finished_ns.unwrap();
                assert!(statement.started_ns <= first_row && first_row <= finished);
                assert_eq!(statement.sqlite_rows, 2);
                assert!(statement.vm_steps > 0);
                if let Some(cpu) = statement.worker_cpu_ns {
                    assert!(cpu > 0, "completed SQLite work consumes worker CPU");
                }
            }
            assert!(timeline[0].finished_ns.unwrap() <= timeline[1].started_ns);
            assert_eq!(
                timeline.iter().map(|s| s.vm_steps).sum::<u64>(),
                query.vm_steps
            );
        }
        sqlx::query("SELECT 3").fetch_all(&mut conn).await.unwrap();
        assert_eq!(
            observation.state.lock().unwrap().diagnostic.phases[0].statements,
            2
        );
    }

    #[tokio::test]
    async fn direct_dispatch_probe_reports_timeline_and_detaches() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let (result, diagnostic) = measure_dispatch_control(&mut conn, 3).await;
        result.unwrap();
        assert!(diagnostic.succeeded);
        assert_eq!(diagnostic.statement_timeline.len(), 3);
        let phase = &diagnostic.phases[0];
        assert_eq!(phase.phase, "dispatch_control");
        assert_eq!(phase.statements, 3);
        assert_eq!(phase.intervals.len(), 1);
        let interval = &phase.intervals[0];
        for statement in &diagnostic.statement_timeline {
            assert!(interval.started_ns <= statement.started_ns);
            assert!(statement.started_ns <= statement.finished_ns.unwrap());
            assert!(statement.finished_ns.unwrap() <= diagnostic.elapsed_ns);
            assert_eq!(statement.sqlite_rows, 1);
        }
        assert!(interval.finished_ns <= diagnostic.elapsed_ns);
        // A subsequent call owns a fresh observer and restarts its counters.
        let (result, next) = measure_dispatch_control(&mut conn, 1).await;
        result.unwrap();
        assert_eq!(next.statement_timeline.len(), 1);
        assert_eq!(diagnostic.statement_timeline.len(), 3);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_control_separates_invalidation_and_keeps_bound_results() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        for mode in [QueryPreparation::Ordinary, QueryPreparation::PrepareFirst] {
            for invalidate_temp in [false, true] {
                let (result, diagnostic) =
                    measure_preparation_control(&mut conn, mode, invalidate_temp).await;
                result.unwrap();
                assert!(diagnostic.succeeded);
                let queries: Vec<_> = diagnostic
                    .phases
                    .iter()
                    .filter(|phase| phase.phase.ends_with("_query"))
                    .collect();
                assert_eq!(queries.len(), 3);
                for query in queries {
                    assert_eq!(query.returned_rows, 1);
                    assert_eq!(query.sqlite_rows, 1);
                    assert!(query.vm_steps > 0);
                }
                assert_eq!(
                    diagnostic
                        .phases
                        .iter()
                        .filter(|p| p.phase.ends_with("_prepare"))
                        .count(),
                    if matches!(mode, QueryPreparation::PrepareFirst) {
                        3
                    } else {
                        0
                    }
                );
                assert_eq!(
                    diagnostic
                        .phases
                        .iter()
                        .filter(|p| p.phase.ends_with("_invalidation"))
                        .count(),
                    if invalidate_temp { 3 } else { 0 }
                );
                let scratch: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_schema WHERE name='_native_diag_link_prepare_invalidation'")
                    .fetch_one(&mut conn).await.unwrap();
                assert_eq!(scratch, 0);
            }
        }
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_control_refuses_scratch_collision_without_removing_it() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::query("CREATE TEMP TABLE _native_diag_link_prepare_invalidation(x)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO temp._native_diag_link_prepare_invalidation VALUES(17)")
            .execute(&mut conn)
            .await
            .unwrap();
        let (result, diagnostic) =
            measure_preparation_control(&mut conn, QueryPreparation::PrepareFirst, true).await;
        assert!(result.is_err());
        assert!(!diagnostic.succeeded);
        let retained: i64 =
            sqlx::query_scalar("SELECT x FROM temp._native_diag_link_prepare_invalidation")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(retained, 17);
        // Normal failure detached the first observer; the next owns fresh state.
        let (result, diagnostic) =
            measure_preparation_control(&mut conn, QueryPreparation::Ordinary, false).await;
        result.unwrap();
        assert_eq!(diagnostic.statement_timeline.len(), 3);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn preparation_control_keeps_existing_progress_guard_after_failure() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, || false);
        let (result, diagnostic) =
            measure_preparation_control(&mut conn, QueryPreparation::PrepareFirst, false).await;
        let error = result.unwrap_err();
        assert!(error.to_string().contains("interrupted"), "{error}");
        assert!(!diagnostic.succeeded);
        let error = sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&mut conn)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("9")
        );
        conn.lock_handle().await.unwrap().remove_progress_handler();
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn trace_preserves_existing_progress_deadline() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(100, || false);
        let observation = Arc::new(Observation::default());
        let observer = Trace::install(&mut conn, observation.clone())
            .await
            .unwrap();
        let query = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n";
        let error = ACTIVE
            .scope(observation.clone(), async {
                phase("query");
                sqlx::query(query)
                    .fetch_all(&mut conn)
                    .await
                    .err()
                    .expect("progress deadline must interrupt")
            })
            .await;
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("9")
        );
        observer.finish(&mut conn).await.unwrap();
        let statements = observation.state.lock().unwrap().diagnostic.phases[0].statements;
        let error = sqlx::query(query)
            .fetch_all(&mut conn)
            .await
            .err()
            .expect("progress deadline remains installed");
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("9")
        );
        assert_eq!(
            observation.state.lock().unwrap().diagnostic.phases[0].statements,
            statements
        );
        conn.lock_handle().await.unwrap().remove_progress_handler();
    }

    #[tokio::test]
    async fn abandoned_observer_lives_until_connection_close() {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        let observation = Arc::new(Observation::default());
        let weak = Arc::downgrade(&observation);
        let observer = Trace::install(&mut conn, observation.clone())
            .await
            .unwrap();
        // Cancellation can drop both Rust-owned references before the scoped
        // connection closes. SQLite's separate Arc keeps callback state live.
        drop(observer);
        drop(observation);
        assert!(weak.upgrade().is_some());
        sqlx::query("SELECT 1").fetch_all(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        assert!(weak.upgrade().is_none());
    }
}
