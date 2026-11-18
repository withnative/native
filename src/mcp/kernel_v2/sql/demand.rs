//! Demand-scoped staging for the two hottest point reads (design 73ad275 §6,
//! slice S1): an exact record read (`exact_body`) and a record read with its
//! logical home chain (`docs_page`). Staging evaluates only the homes those
//! records can depend on (`kernel::demand_visibility`) instead of the
//! workspace census. The record predicate, value cells and caller SQL are
//! unchanged.
//!
//! A per-request [`Plan`] says which shapes may use this path. It is decided
//! once, before scope planning, so every later step of the same request sees
//! the same decision.
use super::*;

/// Which demand-scoped shapes this request may use, plus whether its finite
/// scope accepted a closed home-ID self-join chain (which then must be staged
/// to its logical-placement fixpoint).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    pub exact_body: bool,
    pub docs_page: bool,
    pub home_chain: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    ExactBody,
    DocsPage,
}

impl Plan {
    pub(crate) fn allows(&self, shape: Shape) -> bool {
        match shape {
            Shape::ExactBody => self.exact_body,
            Shape::DocsPage => self.docs_page,
        }
    }
}

tokio::task_local! { static PLAN: Plan; }

pub(super) fn current() -> Plan {
    PLAN.try_with(|plan| *plan).unwrap_or_default()
}

/// Boxed: the wrapped staging futures are large, and callers sit deep in
/// un-boxed async chains whose stack depth tests already bound.
pub(super) async fn scoped<F: std::future::Future>(plan: Plan, work: F) -> F::Output {
    PLAN.scope(plan, Box::pin(work)).await
}

#[cfg(test)]
tokio::task_local! { static TEST_ENABLED: Plan; }

/// Test-only: serve both shapes through the demand-scoped path.
#[cfg(test)]
pub(crate) async fn with_enabled_for_test<F: std::future::Future>(work: F) -> F::Output {
    TEST_ENABLED
        .scope(
            Plan {
                exact_body: true,
                docs_page: true,
                home_chain: false,
            },
            work,
        )
        .await
}

/// Startup settings. Both shapes ship ON; a manual disable takes effect
/// after restart. Invalid values conservatively select the old path.
fn startup_plan() -> Plan {
    static STARTUP: std::sync::OnceLock<Plan> = std::sync::OnceLock::new();
    *STARTUP.get_or_init(|| {
        settings_plan(
            std::env::var("NATIVE_DEMAND_EXACT_BODY").ok().as_deref(),
            std::env::var("NATIVE_DEMAND_DOCS_PAGE").ok().as_deref(),
        )
    })
}
pub(crate) fn settings_plan(exact_body: Option<&str>, docs_page: Option<&str>) -> Plan {
    let enabled = |value: Option<&str>| matches!(value, None | Some("1" | "true" | "on"));
    Plan {
        exact_body: enabled(exact_body),
        docs_page: enabled(docs_page),
        home_chain: false,
    }
}

pub(super) fn plan_for(_db: &Db) -> Plan {
    if legacy() {
        return Plan::default();
    }
    #[cfg(test)]
    if let Ok(plan) = TEST_ENABLED.try_with(|plan| *plan) {
        return plan;
    }
    startup_plan()
}

#[cfg(test)]
pub(crate) async fn with_plan_for_test<F: std::future::Future>(plan: Plan, work: F) -> F::Output {
    TEST_ENABLED.scope(plan, work).await
}

tokio::task_local! {
    static LEGACY: ();
    static ATTEMPTED: std::sync::Arc<std::sync::atomic::AtomicU8>;
}
pub(super) fn legacy() -> bool {
    LEGACY.try_with(|_| ()).is_ok()
}
pub(super) async fn with_legacy<F: std::future::Future>(work: F) -> F::Output {
    LEGACY
        .scope((), Box::pin(scoped(Plan::default(), work)))
        .await
}
pub(super) fn selected(_shape: Shape) {
    let _ =
        ATTEMPTED.try_with(|attempted| attempted.fetch_or(3, std::sync::atomic::Ordering::Relaxed));
}
pub(super) fn served() -> bool {
    ATTEMPTED
        .try_with(|attempted| attempted.load(std::sync::atomic::Ordering::Relaxed) & 2 != 0)
        .unwrap_or(false)
}
pub(super) fn caller_started() {
    let _ = ATTEMPTED.try_with(|a| a.fetch_or(4, std::sync::atomic::Ordering::Relaxed));
}

// Caller resource-limit errors describe the caller's SQL, not admission.
// Retrying them changes their budget and can execute expensive SQL twice.
// The root Error facade erases QueryError::Sql to Engine(String), so there
// is no typed category left here; match the stable public wire category.
pub(super) fn retry_caller(error: &Error) -> bool {
    !is_timeout(error)
        && !error
            .to_string()
            .starts_with("query_sql [result_too_large]")
}
pub(super) fn mark_attempt() {
    let _ =
        ATTEMPTED.try_with(|attempted| attempted.fetch_or(1, std::sync::atomic::Ordering::Relaxed));
}
pub(super) async fn attempt<F: std::future::Future>(work: F) -> (F::Output, bool, bool) {
    let attempted = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let result = ATTEMPTED.scope(attempted.clone(), Box::pin(work)).await;
    (
        result,
        attempted.load(std::sync::atomic::Ordering::Relaxed) & 1 != 0,
        attempted.load(std::sync::atomic::Ordering::Relaxed) & 4 != 0,
    )
}

tokio::task_local! { static ROOT_ALIASES: kernel::demand_root_aliases::State; }

pub(super) fn root_aliases() -> kernel::demand_root_aliases::State {
    ROOT_ALIASES.try_with(|state| *state).unwrap_or_default()
}
pub(super) async fn scoped_for_db<F: std::future::Future>(
    db: &Db,
    plan: Plan,
    work: F,
) -> F::Output {
    kernel::demand_root_aliases::Check::start(db);
    ROOT_ALIASES
        .scope(
            db.demand_root_aliases.state(),
            Box::pin(scoped(plan, Box::pin(work))),
        )
        .await
}

/// Structural logical-placement closure: the demanded IDs plus every record
/// their `home_id` cells can name, to the fixpoint. Candidates only nominate;
/// the unchanged visibility predicate still admits every staged record.
///
/// `None` means the chain did not close within the depth cap.
pub(super) async fn placement_closure(
    tx: &mut sqlx::SqliteConnection,
    ids: &[String],
) -> Result<Option<Vec<String>>> {
    let mut all: BTreeSet<String> = ids.iter().cloned().collect();
    let mut frontier: Vec<String> = all.iter().cloned().collect();
    let mut closed = false;
    for _ in 0..=kernel::demand_visibility::MAX_DEMANDED {
        if frontier.is_empty() {
            closed = true;
            break;
        }
        let found = placement_step(tx, &frontier, true).await?;
        frontier = found
            .into_iter()
            .filter(|id| all.insert(id.clone()))
            .collect();
        if all.len() > kernel::demand_visibility::MAX_DEMANDED {
            break;
        }
    }
    Ok(closed.then(|| all.into_iter().collect()))
}

/// Every placement dependency the logical-home cell of `ids` can read: one
/// structural placement level, as staging's dependency admission computes it
/// over admitted rows (a subset of `ids`). Includes candidates that are not
/// records, whose own home row the cell may consult. Staging must load these
/// candidates' authority homes and cover them in the Message proof, or a
/// finite read can mask a visible home or skip the guard on an admitted one.
pub(super) async fn placement_dependencies(
    tx: &mut sqlx::SqliteConnection,
    ids: &[String],
) -> Result<Vec<String>> {
    placement_step(tx, ids, false).await
}

/// One level of the records cell's own placement expression over scratch
/// rows in the request's TEMP tables, emptied again before returning.
async fn placement_step(
    tx: &mut sqlx::SqliteConnection,
    frontier: &[String],
    records_only: bool,
) -> Result<Vec<String>> {
    let placement = if records_only {
        format!(
            "SELECT DISTINCT p.candidate FROM ({}) p CROSS JOIN main.kernel_records r ON r.id=p.candidate",
            logical_home_placement_sql()
        )
    } else {
        format!(
            "SELECT DISTINCT p.candidate FROM ({}) p WHERE p.candidate IS NOT NULL",
            logical_home_placement_sql()
        )
    };
    sqlx::query("DELETE FROM temp._v2_visible; DELETE FROM temp._v2_home_map")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO temp._v2_visible(id,home_id) SELECT r.id,r.home_id FROM json_each(?1) d CROSS JOIN main.kernel_records r ON r.id=d.value")
        .bind(serde_json::to_string(frontier)?)
        .execute(&mut *tx)
        .await?;
    // HOME_MAP_SQL's binding, driven from these homes rather than from the
    // scope table, which is not staged yet. The demand loader stages every
    // one of these homes, so ordinary staging recomputes the same bindings.
    sqlx::query("INSERT OR IGNORE INTO temp._v2_home_map SELECT e.record_id,json_extract(e.payload,'$.source_record_id') FROM (SELECT DISTINCT home_id FROM temp._v2_visible) h CROSS JOIN main.content_events e ON e.record_id=h.home_id AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') WHERE json_extract(e.payload,'$.source_record_id') IS NOT NULL ORDER BY e.seq")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT OR IGNORE INTO temp._v2_home_map SELECT ?1,'native:root' WHERE EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') OR EXISTS(SELECT 1 FROM main.content_events WHERE record_id=?1 AND type='kernel.import_home_policy.v1')")
        .bind(crate::events::KERNEL_ROOT_ID)
        .execute(&mut *tx)
        .await?;
    let found: Vec<String> = sqlx::query_scalar(&placement).fetch_all(&mut *tx).await?;
    sqlx::query("DELETE FROM temp._v2_visible; DELETE FROM temp._v2_home_map")
        .execute(&mut *tx)
        .await?;
    Ok(found)
}

/// The census probe proves "no Message exists anywhere" so staging may omit
/// the per-row Message guard. Its `primary_type` arm has no index and scans
/// every record. For a finite candidate set the same decision is available
/// without the scan: the guard can only remove rows, so if no row staging can
/// admit is removed by it, staging with or without it is identical. Only when some
/// candidate would be removed does the full probe decide. `candidates` must
/// therefore hold every row staging can admit with this decision: the demand,
/// its active successors and its placement dependencies.
pub(super) async fn has_messages_for(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    candidates: &[String],
    homes: &str,
) -> Result<bool> {
    let indexed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
        .fetch_one(&mut *tx)
        .await?;
    if indexed {
        return Ok(true);
    }
    let guard = kernel::messaging::sql_guard("r", "?1", homes, true);
    let guarded: bool = sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM json_each(?2) d CROSS JOIN main.kernel_records r ON r.id=d.value WHERE NOT ({guard}))"))
        .bind(actor)
        .bind(serde_json::to_string(candidates)?)
        .fetch_one(&mut *tx)
        .await?;
    if !guarded {
        return Ok(false);
    }
    Ok(sqlx::query_scalar(HAS_MESSAGES_SQL)
        .fetch_one(&mut *tx)
        .await?)
}

pub(super) const HAS_MESSAGES_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')";

/// Independent point-read admission, on the same snapshot. Check every staged
/// record, including the dependencies whose existence masks returned cells.
/// No row is silently deleted: a disagreement forces the complete old answer.
pub(super) async fn recheck(conn: &mut sqlx::SqliteConnection, actor: &str) -> Result<()> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM temp._v2_visible ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    #[cfg(test)]
    let checked = ids.len();
    for id in ids {
        // This is read_record_on's existing admission path, without body or
        // field hydration: rechecking existence must not decode cells the
        // caller did not request, or turn unrelated malformed data into errors.
        if !kernel::kernel_effective_capability_on(conn, actor, &id)
            .await?
            .allows(Capability::View)
        {
            #[cfg(test)]
            let _ = STATS.try_with(|s| s.borrow_mut().demand_recheck_rejections += 1);
            tracing::debug!(target: "native_ce::read_staging", rejected_rows = 1, "demand admission recheck disagreed; falling back");
            return Err(Error::engine("demand admission recheck disagreed"));
        }
    }
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().demand_rechecked += checked as u64);
    Ok(())
}

#[cfg(test)]
tokio::task_local! { static BROKEN_ADMISSION: (); }
#[cfg(test)]
pub(super) fn broken_admission() -> bool {
    BROKEN_ADMISSION.try_with(|_| ()).is_ok()
}
#[cfg(test)]
pub(crate) async fn with_broken_admission<F: std::future::Future>(work: F) -> F::Output {
    BROKEN_ADMISSION.scope((), work).await
}

#[cfg(test)]
tokio::task_local! { static FAIL_CALLER: (); }
#[cfg(test)]
pub(super) fn fail_caller() -> bool {
    FAIL_CALLER.try_with(|_| ()).is_ok()
}
#[cfg(test)]
pub(crate) async fn with_failed_caller<F: std::future::Future>(work: F) -> F::Output {
    FAIL_CALLER.scope((), work).await
}

#[cfg(test)]
tokio::task_local! { static FAIL_RESTAGE: (); }
#[cfg(test)]
pub(super) fn fail_restage() -> bool {
    FAIL_RESTAGE.try_with(|_| ()).is_ok()
}
#[cfg(test)]
pub(crate) async fn with_failed_restage<F: std::future::Future>(work: F) -> F::Output {
    FAIL_RESTAGE.scope((), work).await
}

/// Exercise the bundled engine's SELECT-interrupt semantics, including its
/// query-only state and an expired worker handler. The bound fallback must
/// clear that handler and retain the pinned main snapshot and savepoint.
#[cfg(test)]
pub(super) async fn injected_caller_error(conn: &mut sqlx::SqliteConnection) -> Result<Value> {
    sqlx::query("PRAGMA query_only=ON")
        .execute(&mut *conn)
        .await?;
    conn.lock_handle().await?.set_progress_handler(1, || false);
    let error = sqlx::query("SELECT 1")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    let mut handle = conn.lock_handle().await?;
    // SAFETY: the handle is exclusively locked and live. A read-only SELECT
    // interrupt must leave the main transaction active (design E2).
    assert_eq!(
        unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) },
        0
    );
    Err(error.into())
}
