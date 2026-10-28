//! Probe-only public SQL over a single kernel authority snapshot.
//!
//! Only TEMP state is written. The physical connection is discarded even on
//! cancellation, so neither scoped rows nor VM guards can reach another caller.
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

mod activity;
mod connection;
mod facet_times;
mod facets;
mod lifecycle;
mod named_views;
mod predicates;
mod record_classes;
mod record_scope;

#[cfg(test)]
pub(crate) async fn with_full_record_scope_staging<F: std::future::Future>(work: F) -> F::Output {
    record_scope::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_facet_staging<F: std::future::Future>(work: F) -> F::Output {
    facets::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_lifecycle_staging<F: std::future::Future>(work: F) -> F::Output {
    lifecycle::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_record_class_staging<F: std::future::Future>(work: F) -> F::Output {
    predicates::with_full_staging(work).await
}

use futures::TryStreamExt;

use serde_json::{json, Map, Value};
use sqlx::{Column, Row};

use super::parse;
use crate::authorization::Capability;
use crate::query::{sql as guard, sql_contract as contract};
use crate::{db::Db, kernel, Error, Result};

#[cfg(test)]
pub(super) fn columns_for_test(relation: &str) -> bool {
    columns(relation).is_some()
}

pub(crate) fn columns(relation: &str) -> Option<&'static [&'static str]> {
    if relation == "bindings" {
        return Some(&["record_id", "system", "identifier", "is_canonical"]);
    }
    if [
        "records",
        "blobs",
        "links",
        "runs",
        "run_intents",
        "actors",
        "comment_anchors",
        "vocabularies",
        "vocabulary_values",
        "record_lifecycle_interpretations",
        "agent_activity",
        "agent_activity_claims",
        "facet_values",
        "facet_observations",
        "facet_times",
        "bindings",
        "message_reactions",
        "my_mentions",
        "my_message_state",
        "messages_awaiting_reply",
        "catalog_relations",
        "catalog_columns",
        "catalog_view_definitions",
    ]
    .contains(&relation)
    {
        return contract::LOGICAL_RELATIONS
            .iter()
            .find(|r| r.name == relation)
            .map(|r| r.columns);
    }
    if relation == "content_events" {
        return Some(&[
            "local_seq",
            "id",
            "record_id",
            "type",
            "actor",
            "run_key",
            "parent_key",
            "channel_kind",
            "created_at",
            "created_at_ms",
        ]);
    }
    None
}
fn unsupported(relation: &str, column: &str) -> Error {
    contract::categorized_error(
        contract::QuerySqlErrorCategory::UnauthorizedRelation,
        format!(
            "{} not yet supported on v2. Supported columns: {}. See catalog_columns.",
            if column.is_empty() {
                format!("relation '{relation}'")
            } else {
                format!("column '{relation}.{column}'")
            },
            columns(relation)
                .map(|cols| cols.join(", "))
                .unwrap_or_else(|| "none for this relation".into())
        ),
    )
}

// Internal composed reads may share one scoped authority snapshot. The session
// is task-local, handle/caller-bound, never cached across requests, and its
// physical connection is discarded on cancellation just like ordinary SQL.
struct ReadSession {
    db: Db,
    actor: String,
    connection: connection::ReadConnection,
    reads: BTreeSet<(String, String)>,
    as_of_seq: i64,
    cache_identity: Option<kernel::read_cache::Key>,
}
tokio::task_local! {
    static READ_SESSION: std::sync::Arc<tokio::sync::Mutex<ReadSession>>;
}

pub(super) async fn with_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(db, actor, reads, LinkScope::All, None, None, work).await
}

/// Share staging for a closed count/page pair. Hydration runs after this
/// selection session ends, so it retains its independent live View recheck.
pub(super) async fn with_query_read_session<T>(
    db: &Db,
    actor: &str,
    statements: &[&str],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if READ_SESSION.try_with(|_| ()).is_ok() {
        return work.await;
    }
    let mut reads = BTreeSet::new();
    for statement in statements {
        reads.extend(guard::public_reads_ad_hoc(statement)?);
    }
    let reads = reads
        .iter()
        .map(|(r, c)| (r.as_str(), c.as_str()))
        .collect::<Vec<_>>();
    with_read_session(db, actor, &reads, work).await
}

/// Get's composed SQL only consumes part_of edges for annotation windows.
/// Its complete link envelope still uses the kernel's subject-scoped reader.
pub(super) async fn with_part_of_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    ids: &[String],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(db, actor, reads, LinkScope::PartOf, Some(ids), None, work).await
}

/// Only the closed renderer lookup may use this narrowed relation.
pub(super) async fn with_renderer_read_session<T>(
    db: &Db,
    actor: &str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "name"),
            ("links", "source_id"),
            ("links", "target_id"),
            ("links", "relationship"),
        ],
        LinkScope::Renderers,
        None,
        None,
        work,
    )
    .await
}

#[derive(Clone, Copy)]
pub(super) struct HistoryWindow {
    pub after: Option<i64>,
    pub newest: bool,
    pub limit: usize,
}

pub(super) async fn with_history_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    window: HistoryWindow,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(db, actor, reads, LinkScope::All, None, Some(window), work).await
}

/// Hydration and SQL enrichment borrow the same caller-bound read snapshot.
/// The closure must only use connection-scoped kernel helpers.
pub(super) async fn in_snapshot<T>(
    db: &Db,
    actor: &str,
    work: impl for<'a> FnOnce(
        &'a mut sqlx::SqliteConnection,
    ) -> futures::future::BoxFuture<'a, Result<T>>,
) -> Result<T> {
    if let Ok(session) = READ_SESSION.try_with(Clone::clone) {
        let mut session = session.lock().await;
        if !session.db.same_handle(db) || session.actor != actor {
            return Err(Error::engine("read snapshot caller/database mismatch"));
        }
        // Hydration is bounded per subject, not by time already spent on
        // other ids. Keep the transaction and staging, reset only the VM
        // work budget; composed SQL independently applies the same deadline.
        let started = Instant::now();
        session
            .connection
            .lock_handle()
            .await?
            .set_progress_handler(guard::PROGRESS_OPS, move || {
                started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
            });
        let identity = session.cache_identity.clone();
        kernel::read_cache::in_pinned_snapshot(
            identity,
            kernel::read_cache::connection_id(&mut session.connection),
            work(&mut session.connection),
        )
        .await
    } else {
        let mut tx = db.write_pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        let identity = kernel::read_cache::key_on(&mut tx, actor, "read_snapshot").await?;
        let result = kernel::read_cache::in_pinned_snapshot(
            identity,
            kernel::read_cache::connection_id(&mut tx),
            work(&mut tx),
        )
        .await;
        tx.rollback().await?;
        result
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkScope {
    All,
    PartOf,
    Renderers,
}

async fn with_scoped_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    link_scope: LinkScope,
    candidate_ids: Option<&[String]>,
    history_window: Option<HistoryWindow>,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    // Retain the governed slot, not an ordinary write-pool slot: enrichment
    // borrows ordinary connections too. Concurrent batches must not each hold
    // one ordinary slot while all wait for a second one.
    let mut connection = connection::ReadConnection::new(db.governed_pool().acquire().await?);
    sqlx::query("BEGIN").execute(&mut *connection).await?;
    kernel::app_installs::admit_dispatched_on(&mut connection, actor).await?;
    let as_of_seq = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
        .fetch_one(&mut *connection)
        .await?;
    let reads: BTreeSet<_> = reads
        .iter()
        .map(|(r, c)| (r.to_string(), c.to_string()))
        .collect();
    let started = Instant::now();
    {
        let mut handle = connection.lock_handle().await?;
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    }
    let cache_identity =
        kernel::read_cache::key_on(&mut connection, actor, "pinned_snapshot").await?;
    kernel::read_cache::in_pinned_snapshot(
        cache_identity.clone(),
        kernel::read_cache::connection_id(&mut connection),
        install_relations(
            &mut connection,
            actor,
            &reads,
            link_scope,
            candidate_ids,
            history_window,
            None,
            None,
            None,
            chrono::Utc::now().timestamp_millis(),
            false,
        ),
    )
    .await?;
    let materialization_started = Instant::now();
    // Composed enrichment consumes a closed metadata column set many times.
    // Materialize it once and index filing; otherwise each child count would
    // reevaluate lazy placement for every visible record, despite shared ACLs.
    let record_columns = reads
        .iter()
        .filter(|(r, c)| r == "records" && !c.is_empty())
        .map(|(_, c)| c.as_str())
        .collect::<Vec<_>>();
    if !record_columns.is_empty() {
        if record_columns
            .iter()
            .any(|c| !columns("records").unwrap().contains(c))
        {
            return Err(Error::engine("invalid composed record column"));
        }
        // Names and source birth clocks are only consumed by returned pages.
        // Keep them lazy instead of decoding them for every visible record.
        let lazy_pages = record_columns.contains(&"id");
        let lazy =
            |column: &&str| lazy_pages && ["name", "created_at", "created_at_ms"].contains(column);
        let eager_columns = record_columns
            .iter()
            .copied()
            .filter(|c| !lazy(c))
            .collect::<Vec<_>>();
        sqlx::query(&format!(
            "CREATE TEMP TABLE _v2_composed_records AS SELECT {} FROM temp.records",
            eager_columns.join(",")
        ))
        .persistent(false)
        .execute(&mut *connection)
        .await?;
        let projection = record_columns.iter().map(|column| {
            if lazy(column) {
                format!("(SELECT v.{column} FROM temp._v2_record_values v WHERE v.id=c.id) AS {column}")
            } else {
                format!("c.{column}")
            }
        }).collect::<Vec<_>>().join(",");
        sqlx::query(&format!("DROP VIEW temp.records; CREATE TEMP VIEW records AS SELECT {projection} FROM temp._v2_composed_records c"))
            .persistent(false).execute(&mut *connection).await?;
        if record_columns.contains(&"type") && record_columns.contains(&"kind") {
            sqlx::query("CREATE INDEX _v2_composed_kind ON _v2_composed_records(type,kind)")
                .execute(&mut *connection)
                .await?;
        }
        for column in ["id", "home_id"] {
            if record_columns.contains(&column) {
                sqlx::query(&format!(
                    "CREATE INDEX _v2_composed_{column} ON _v2_composed_records({column})"
                ))
                .persistent(false)
                .execute(&mut *connection)
                .await?;
            }
        }
    }

    tracing::debug!(target: "native_ce::read_staging", phase = "composed_records", elapsed_us = materialization_started.elapsed().as_micros() as u64);
    if started.elapsed() >= Duration::from_millis(contract::QUERY_DEADLINE_MS) {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "SQL relation staging exceeded query deadline",
        ));
    }
    let session = std::sync::Arc::new(tokio::sync::Mutex::new(ReadSession {
        db: db.clone(),
        actor: actor.into(),
        connection,
        reads,
        as_of_seq,
        cache_identity,
    }));
    let result = READ_SESSION.scope(session.clone(), work).await;
    // Roll back TEMP state explicitly on success/error; cancellation closes the
    // owned physical connection, so no TEMP state or VM guard can be borrowed.
    let mut session = session.lock().await;
    sqlx::query("ROLLBACK")
        .execute(&mut *session.connection)
        .await?;
    session.connection.finish().await;
    result
}

struct PreparedRead {
    statement: String,
    persistent: bool,
    parameters: Vec<contract::QuerySqlParameter>,
    output_columns: Vec<String>,
    now_ms_ms: Option<i64>,
    time_dependent: bool,
    assumed_order: Option<contract::AssumedOrder>,
}

/// A conservative closed prefix: no caller predicate, expression, alias,
/// join, offset or alternate ordering may move through the visibility barrier.
/// Narrow only the admitted ID prefix; caller SQL still reads a materialized
/// visible relation and retains its own LIMIT and SQL value/error guards.
fn id_ordered_record_limit(statement: &str) -> Option<i64> {
    static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let captures = PREFIX.get_or_init(|| regex::Regex::new(r"(?i)\A\s*SELECT\s+(?:id|name)(?:\s*,\s*(?:id|name))*\s+FROM\s+records\s+ORDER\s+BY\s+id(?:\s+ASC)?\s+LIMIT\s+([0-9]+)\s*;?\s*\z").expect("closed record prefix")).captures(statement)?;
    captures[1]
        .parse::<i64>()
        .ok()
        .filter(|n| (1..=1000).contains(n))
}

/// Only the shell's closed revision/metadata pulses can push its ID set through staging.
/// The caller statement still runs unchanged over the same live visibility gate.
/// Every other expression, relation, alias or predicate falls back to full staging.
fn metadata_pulse_ids(
    statement: &str,
    parameters: &[contract::QuerySqlParameter],
) -> Option<Vec<String>> {
    static PULSE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let captures = PULSE.get_or_init(|| regex::Regex::new(
        r"(?i-u)\A\s*SELECT\s+(?:id\s*,\s*updated_at|id\s*,\s*type\s*,\s*kind\s*,\s*name\s*,\s*summary\s*,\s*home_id\s*,\s*lifecycle\s*,\s*maturity\s*,\s*updated_at\s*,\s*last_activity_at)\s+FROM\s+records\s+WHERE\s+(?:deleted_at\s+IS\s+NULL\s+AND\s+)?id\s+IN\s*\(\s*(\?[1-9][0-9]*(?:\s*,\s*\?[1-9][0-9]*)*)\s*\)\s*;?\s*\z"
    ).expect("closed metadata pulse")).captures(statement)?;
    let mut ids = BTreeSet::new();
    for placeholder in captures[1].split(',') {
        let index = placeholder
            .trim()
            .strip_prefix('?')?
            .parse::<usize>()
            .ok()?;
        match parameters.get(index.checked_sub(1)?)? {
            contract::QuerySqlParameter::Text { value: Some(id) } => {
                ids.insert(id.clone());
            }
            contract::QuerySqlParameter::Text { value: None } => {}
            _ => return None,
        }
    }
    Some(ids.into_iter().collect())
}

pub(crate) async fn query_sql(db: &Db, actor: &str, args: Value) -> Result<Value> {
    execute(db, actor, args, false)
        .await
        .map_err(contract::ensure_categorized)
}
/// Called only after inspection of an existing governed definition and its
/// artifact port pins. Ordinary callers cannot select the stored SQL allowance.
pub(super) async fn query_stored_saved_sql(db: &Db, actor: &str, args: Value) -> Result<Value> {
    // Trusted saved definitions may race transient VM/staging contention. Retry
    // once, with the original per-attempt budget and a new authority snapshot.
    // Ad hoc SQL and every non-timeout refusal retain their existing behavior.
    match stored_attempt(db, actor, args.clone()).await {
        Err(error) if is_timeout(&error) => stored_attempt(db, actor, args).await,
        result => result,
    }
}

fn is_timeout(error: &Error) -> bool {
    error.to_string().starts_with("query_sql [timeout]")
}

// Only a pinned saved definition or a freshly admitted installed-app dispatch
// can use this preparation allowance. Visibility/provenance staging is adapter work;
// it must not consume the v1 caller SQL VM budget. Both phases remain bounded.
const NATIVE_INPUT_STAGING_MS: u64 = 4 * contract::QUERY_DEADLINE_MS;

#[cfg(test)]
tokio::task_local! {
    static TEST_ELAPSED: (Duration, Duration);
}

#[cfg(test)]
pub(crate) async fn with_elapsed<T>(
    staging: Duration,
    caller_vm: Duration,
    work: impl std::future::Future<Output = T>,
) -> T {
    TEST_ELAPSED.scope((staging, caller_vm), work).await
}

async fn stored_attempt(db: &Db, actor: &str, args: Value) -> Result<Value> {
    #[cfg(test)]
    if STORED_TIMEOUT_TEST
        .try_with(|state| {
            let mut state = state.borrow_mut();
            state.attempts += 1;
            let timeout = state.remaining > 0;
            state.remaining = state.remaining.saturating_sub(1);
            timeout
        })
        .unwrap_or(false)
    {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "injected stored query deadline",
        ));
    }
    execute(db, actor, args, true)
        .await
        .map_err(contract::ensure_categorized)
}

#[cfg(test)]
struct StoredTimeoutTest {
    remaining: usize,
    attempts: usize,
}
#[cfg(test)]
tokio::task_local! { static STORED_TIMEOUT_TEST: std::cell::RefCell<StoredTimeoutTest>; }
#[cfg(test)]
pub(crate) async fn with_stored_timeouts<T>(
    remaining: usize,
    work: impl std::future::Future<Output = T>,
) -> (T, usize) {
    STORED_TIMEOUT_TEST
        .scope(
            std::cell::RefCell::new(StoredTimeoutTest {
                remaining,
                attempts: 0,
            }),
            async {
                let result = work.await;
                (
                    result,
                    STORED_TIMEOUT_TEST.with(|state| state.borrow().attempts),
                )
            },
        )
        .await
}

// Shared parser, statement guard, parameter binding and clock rewriting for
// ordinary reads and effect membership on the caller's writer snapshot.
fn prepare_read(
    actor: &str,
    args: Value,
    stored: bool,
) -> Result<(PreparedRead, BTreeSet<(String, String)>)> {
    prepare_read_with_views(actor, args, stored, None)
}

fn prepare_read_with_views(
    actor: &str,
    args: Value,
    stored: bool,
    registry: Option<&named_views::Registry>,
) -> Result<(PreparedRead, BTreeSet<(String, String)>)> {
    let validators = registry.and_then(|r| r.validators.as_ref());
    let request: contract::QuerySqlRequest = parse("query_sql", args).map_err(|error| {
        contract::categorized_error(
            contract::QuerySqlErrorCategory::InvalidArguments,
            error.to_string(),
        )
    })?;
    request.validate()?;
    if crate::query::turso_ast_rules::named_view_references(&request.sql)
        .is_ok_and(|r| r.iter().any(|n| n.starts_with("_native_view_")))
    {
        return Err(Error::engine(
            "internal named-view aliases are not caller relations",
        ));
    }

    let profile = contract::QuerySqlProfile::SqliteLocal;
    let (statement, assumed_order, reads, output_columns) = if stored {
        let statement = contract::classify_stored_saved_sql(profile, &request.sql)?;
        let (reads, labels) = match validators {
            Some(v) => v.inspect_saved(&statement)?,
            None => guard::inspect_kernel_v2_stored_saved_sql(&statement)?,
        };
        (statement, None, reads, labels)
    } else {
        let statement = contract::classify_sqlite_ad_hoc_statement(&request.sql)?;
        let (statement, assumed_order) = match validators {
            Some(v) => v.default_order(&statement)?,
            None => guard::apply_kernel_v2_default_order(&statement)?,
        };
        let (reads, labels) = match validators {
            Some(v) => v.inspect(&statement)?,
            None => {
                let reads = guard::public_reads_ad_hoc(&statement)?;
                guard::validate_kernel_v2_ad_hoc(&statement)?;
                (
                    reads,
                    guard::validated_kernel_v2_output_columns(&statement)?,
                )
            }
        };
        (statement, assumed_order, reads, labels)
    };
    let activity_clock = reads
        .iter()
        .any(|(relation, _)| relation == "agent_activity");
    for (relation, column) in &reads {
        if let Some(view) = registry.and_then(|r| r.views.get(relation)) {
            if !column.is_empty()
                && !view
                    .definition
                    .output
                    .columns
                    .iter()
                    .any(|c| c.name == *column)
            {
                return Err(unsupported(relation, column));
            }
            continue;
        }
        if let Some(node) = registry
            .and_then(|r| r.retained.as_ref())
            .and_then(|p| p.nodes.iter().find(|n| &n.alias == relation))
        {
            if !column.is_empty()
                && !node
                    .definition
                    .query
                    .output
                    .columns
                    .iter()
                    .any(|c| &c.name == column)
            {
                return Err(unsupported(relation, column));
            }
            continue;
        }
        let Some(supported) = columns(relation) else {
            return Err(unsupported(relation, ""));
        };
        if !column.is_empty() && !supported.contains(&column.as_str()) {
            return Err(unsupported(relation, column));
        }
    }
    if output_columns.len() > contract::MAX_COLUMNS {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::ResultTooLarge,
            "result exceeds column limit",
        ));
    }
    let mut unique = BTreeSet::new();
    if let Some(duplicate) = output_columns
        .iter()
        .find(|label| !unique.insert(label.as_str()))
    {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::DuplicateColumns,
            format!("duplicate output column label '{duplicate}'"),
        ));
    }
    contract::check_positional_arguments(profile, &statement, request.parameters.len())?;
    contract::validate_regexp_bound_patterns(profile, &statement, &request.parameters)?;
    if !stored {
        contract::validate_ad_hoc_clock_bound_args(profile, &statement, &request.parameters)?;
    }
    contract::validate_utc_date_label_bound_args(profile, &statement, &request.parameters)?;
    let (statement, clock_uses) = contract::rewrite_now_ms_calls(
        profile,
        &statement,
        &format!("?{}", request.parameters.len() + 1),
    )?;
    let now_ms_ms =
        (clock_uses > 0 || activity_clock).then(|| chrono::Utc::now().timestamp_millis());
    let (statement, principal_uses) = contract::rewrite_current_principal_calls(
        profile,
        &statement,
        &format!(
            "?{}",
            request.parameters.len() + 1 + usize::from(clock_uses > 0)
        ),
    )?;
    let (statement, _) = contract::rewrite_utc_date_label_calls(
        profile,
        &statement,
        contract::UtcDateLabelEngine::Sqlite,
    )?;
    let mut parameters = request.parameters;
    if let Some(now) = now_ms_ms.filter(|_| clock_uses > 0) {
        parameters.push(contract::QuerySqlParameter::Integer {
            value: Some(now.to_string()),
        });
    }
    if principal_uses > 0 {
        parameters.push(contract::QuerySqlParameter::Text {
            value: Some(actor.into()),
        });
    }
    contract::check_positional_arguments(profile, &statement, parameters.len())?;

    let prepared = PreparedRead {
        statement,
        persistent: registry.is_none(),
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent: clock_uses > 0 || activity_clock,
        assumed_order,
    };
    Ok((prepared, reads))
}

/// Guarded SQL on the already admitted writer snapshot. TEMP staging is scoped
/// to a savepoint and discarded before any kernel mutation; invocation SQL is
/// never accepted by the caller of this seam.
/// Cancellation drops the enclosing write transaction. The write pool's
/// sanitize_released_write_connection removes progress handlers and closes
/// connections with unrolled-back transactions before reuse.
pub(super) async fn query_sql_on(
    connection: &mut sqlx::SqliteConnection,
    actor: &str,
    args: Value,
    row_limit: usize,
) -> Result<Value> {
    let (prepared, reads) = prepare_read(actor, args, false)?;
    let was_query_only: bool = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(&mut *connection)
        .await?;
    sqlx::query("SAVEPOINT v2_effect_read")
        .execute(&mut *connection)
        .await?;
    let started = Instant::now();
    connection
        .lock_handle()
        .await?
        .set_progress_handler(guard::PROGRESS_OPS, move || {
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    let outcome = async {
        install(connection, actor, &reads).await?;
        let seq = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
            .fetch_one(&mut *connection)
            .await?;
        execute_prepared_mode(
            connection,
            prepared,
            seq,
            Instant::now(),
            true,
            row_limit.clamp(1, contract::MAX_ROWS),
        )
        .await
    }
    .await;
    connection.lock_handle().await?.remove_progress_handler();
    // Restore even on a statement error, before the enclosing native effect
    // writes. Cancellation drops its transaction; pool release sanitizes the
    // connection (or discards it) before another request can use it.
    let reset = sqlx::query(if was_query_only {
        "PRAGMA query_only=ON"
    } else {
        "PRAGMA query_only=OFF"
    })
    .execute(&mut *connection)
    .await;
    let cleanup = sqlx::query("ROLLBACK TO v2_effect_read; RELEASE v2_effect_read")
        .execute(connection)
        .await;
    reset?;
    cleanup?;
    outcome
}

async fn execute(db: &Db, actor: &str, args: Value, stored: bool) -> Result<Value> {
    let pinned = if stored {
        args.get("_named_view_pins").cloned().map(serde_json::from_value::<std::collections::BTreeMap<String,crate::named_views::Pin>>).transpose()?
    } else {
        None
    };
    let mut args = args;
    if stored {
        args.as_object_mut()
            .ok_or_else(|| Error::engine("query arguments must be an object"))?
            .remove("_named_view_pins");
    }
    if pinned.is_some()
        && (db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite
            || READ_SESSION.try_with(|_| ()).is_ok())
    {
        return Err(Error::engine(
            "view_profile_unsupported: exact views require standalone hosted writer reads",
        ));
    }
    let request_started = Instant::now();
    let preflight = prepare_read(actor, args.clone(), stored);
    if preflight
        .as_ref()
        .is_ok_and(|(_, reads)| reads.iter().any(|(r, _)| r == "catalog_view_definitions"))
        && (db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite
            || READ_SESSION.try_with(|_| ()).is_ok())
    {
        return Err(Error::engine("view_profile_unsupported: catalog_view_definitions requires standalone hosted writer reads"));
    }
    if stored
        && preflight
            .as_ref()
            .is_ok_and(|(_, reads)| reads.iter().any(|(r, _)| r == "catalog_view_definitions"))
    {
        return Err(Error::engine("saved governed SQL cannot read 'catalog_view_definitions': caller-relative detail rows require standalone hosted ad-hoc query_sql"));
    }
    let registry_needed = (!stored || pinned.is_some())
        && db.open_mode() == crate::db::DatabaseOpenMode::ReadWrite
        && (pinned.as_ref().is_some_and(|pins| !pins.is_empty())
            || named_views::needed(&preflight, &args));
    // Preserve the original early refusal and all narrowing on static reads.
    let preflight = match preflight {
        Err(error) if !registry_needed => return Err(error),
        other => other,
    };
    if let Ok(session) = READ_SESSION.try_with(Clone::clone) {
        let (prepared, reads) = preflight?;
        let mut session = session.lock().await;
        if !session.db.same_handle(db) || session.actor != actor {
            return Err(Error::engine("composed SQL read caller/database differs"));
        }
        if reads.iter().any(|(r, c)| {
            !session.reads.contains(&(r.clone(), c.clone()))
                && !(c.is_empty() && session.reads.iter().any(|(sr, _)| sr == r))
        }) {
            return Err(Error::engine(
                "composed SQL read exceeds declared relations/columns",
            ));
        }
        let as_of_seq = session.as_of_seq;
        return execute_prepared(&mut session.connection, prepared, as_of_seq, Instant::now())
            .await;
    }

    // An ordinary pool slot, exclusively held and armed for physical close.
    // Only a verified clean rollback allows reuse; cancellation still closes.
    // A render may already hold a snapshot on the shared read pool. Use the
    // dedicated SQL tier so concurrent renders cannot exhaust that pool while
    // each waits for a second slot, and never borrow an ordinary writer slot.
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_validation", elapsed_us = request_started.elapsed().as_micros() as u64);
    let acquire_started = Instant::now();
    let mut connection = connection::ReadConnection::new(db.governed_pool().acquire().await?);
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_pool_wait", elapsed_us = acquire_started.elapsed().as_micros() as u64);
    let admission_started = Instant::now();
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    let admitted_app = crate::kernel::app_installs::admit_dispatched_on(&mut tx, actor)
        .await?
        .is_some();
    let as_of_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
        .fetch_one(&mut *tx)
        .await?;
    let registry_started = Instant::now();
    if registry_needed {
        tx.lock_handle()
            .await?
            .set_progress_handler(guard::PROGRESS_OPS, move || {
                admission_started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
            });
    }
    let mut registry = if registry_needed {
        named_views::Registry::load_retained(
            &mut tx,
            actor,
            &args,
            pinned,
            admission_started + Duration::from_millis(contract::QUERY_DEADLINE_MS),
        )
        .await
        .map_err(named_views::map_setup_error)?
    } else {
        named_views::Registry::default()
    };
    #[cfg(test)]
    if registry_needed && !registry.views.is_empty() {
        if let Ok((arrived, resume)) = NAMED_READ_PAUSE.try_with(Clone::clone) {
            arrived.wait().await;
            resume.wait().await;
        }
    }
    if registry_needed && preflight.is_err() {
        registry.unavailable(&args)?;
    }
    let deadline = admission_started + Duration::from_millis(contract::QUERY_DEADLINE_MS);
    let (mut registry, mut prepared, reads) = if registry.retained.is_some() && preflight.is_err() {
        let worker_actor = actor.to_owned();
        crate::query::sql::view_validation::run(deadline, move || {
            registry.validators = Some(guard::NamedViewValidators::from_closure(
                registry.retained.as_ref().unwrap(),
            )?);
            let (prepared, mut reads) =
                prepare_read_with_views(&worker_actor, args, stored, Some(&registry))?;
            registry.expand(&mut reads)?;
            registry.validators = None;
            Ok((registry, prepared, reads))
        })
        .await?
    } else {
        let (prepared, mut reads) = if registry_needed
            && registry.retained.is_none()
            && (!registry.views.is_empty() || !registry.invalid.is_empty())
        {
            prepare_read_with_views(actor, args, stored, Some(&registry))?
        } else {
            preflight?
        };
        registry.expand(&mut reads)?;
        registry.validators = None;
        (registry, prepared, reads)
    };
    if reads.iter().any(|(r, _)| r == "agent_activity") {
        prepared
            .now_ms_ms
            .get_or_insert_with(|| chrono::Utc::now().timestamp_millis());
        prepared.time_dependent = true;
    }
    let view_bearing = !registry.selected.is_empty();
    if view_bearing {
        prepared.persistent = false;
    }
    let registry_elapsed = registry_started.elapsed();
    if registry_needed && registry_elapsed >= Duration::from_millis(contract::QUERY_DEADLINE_MS) {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "named view registry exceeded query deadline",
        ));
    }
    // Exclude pool queue delay. Ad hoc callers retain their shared deadline;
    // verified saved inputs and installed-app dispatches get separately bounded
    // native preparation. The app claim alone grants nothing: the receipt above
    // rechecks current account membership, source pins and consent on this read
    // snapshot. JSON arguments cannot create that internal dispatch context.
    let separate_staging = !view_bearing && (stored || admitted_app);
    let started = if registry_needed {
        admission_started
    } else {
        Instant::now() - registry_elapsed
    };
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_admission", elapsed_us = admission_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let started = started
        - TEST_ELAPSED
            .try_with(|elapsed| elapsed.0)
            .unwrap_or_default();
    let staging_budget = Duration::from_millis(if separate_staging {
        NATIVE_INPUT_STAGING_MS
    } else {
        contract::QUERY_DEADLINE_MS
    });
    #[cfg(test)]
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let mut handle = tx.lock_handle().await?;
        #[cfg(test)]
        let progress = progress.clone();
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            #[cfg(test)]
            progress.fetch_add(
                guard::PROGRESS_OPS as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            started.elapsed() < staging_budget
        });
    }
    let pulse_ids = if view_bearing || record_scope::full_staging() {
        None
    } else {
        record_scope::ids(&prepared.statement, &prepared.parameters, &reads)
            .or_else(|| metadata_pulse_ids(&prepared.statement, &prepared.parameters))
    };
    let class_scope = if view_bearing || record_scope::full_staging() {
        None
    } else {
        record_classes::plan(&prepared.statement, &prepared.parameters, &reads)
    };
    let staging_started = Instant::now();
    install_relations(
        &mut tx,
        actor,
        &reads,
        LinkScope::All,
        None,
        None,
        if view_bearing || record_scope::full_staging() {
            None
        } else {
            id_ordered_record_limit(&prepared.statement)
        },
        pulse_ids.as_deref(),
        class_scope.as_ref(),
        prepared
            .now_ms_ms
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        !view_bearing,
    )
    .await
    .map_err(|error| {
        let error = match error {
            crate::Error::Sqlx(error) => guard::map_stream_error(error),
            error => error,
        };
        if is_timeout(&error) {
            contract::categorized_error(
                contract::QuerySqlErrorCategory::Timeout,
                "SQL relation staging exceeded query deadline",
            )
        } else {
            error
        }
    })?;
    #[cfg(test)]
    let _ = STATS
        .try_with(|s| s.borrow_mut().staging_us = staging_started.elapsed().as_micros() as u64);
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_staging", elapsed_us = staging_started.elapsed().as_micros() as u64);
    // A link join revisits record identity metadata once per edge. Decode the
    // caller's closed scalar column set once per visible record instead. Bodies
    // and other potentially large values retain their existing lazy path.
    let metadata_started = Instant::now();
    let joined_columns: Vec<_> = reads
        .iter()
        .filter(|(relation, column)| relation == "records" && !column.is_empty())
        .map(|(_, column)| column.as_str())
        .collect();
    if !view_bearing
        && reads.iter().any(|(relation, _)| relation == "links")
        && !joined_columns.is_empty()
        && joined_columns
            .iter()
            .all(|c| ["id", "type", "kind", "name"].contains(c))
    {
        sqlx::query(&format!(
            "CREATE TEMP TABLE _v2_joined_records AS SELECT {} FROM temp.records",
            joined_columns.join(",")
        ))
        .persistent(false)
        .execute(&mut *tx)
        .await?;
        if joined_columns.contains(&"id") {
            sqlx::query("CREATE INDEX temp._v2_joined_id ON _v2_joined_records(id)")
                .execute(&mut *tx)
                .await?;
        }
        let projection = columns("records")
            .expect("records contract")
            .iter()
            .map(|c| {
                if joined_columns.contains(c) {
                    format!("r.{c}")
                } else {
                    format!("NULL AS {c}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!("DROP VIEW temp.records; CREATE TEMP VIEW records AS SELECT {projection} FROM temp._v2_joined_records r"))
            .persistent(false).execute(&mut *tx).await?;
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_join_metadata", elapsed_us = metadata_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let _ = STATS.try_with(|s| {
        s.borrow_mut().staging_vm_ops = progress.load(std::sync::atomic::Ordering::Relaxed)
    });
    // Many individually small SQL statements (or provider decoding in Rust)
    // may never invoke the VM callback. They still consume the same budget.
    if started.elapsed() >= staging_budget {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "SQL relation staging exceeded query deadline",
        ));
    }
    let caller_started = if separate_staging {
        Instant::now()
    } else {
        started
    };
    registry
        .append_catalog(&mut tx, &reads)
        .await
        .map_err(named_views::map_setup_error)?;
    registry
        .register(&mut tx)
        .await
        .map_err(named_views::map_setup_error)?;
    #[cfg(test)]
    if !registry.views.is_empty() {
        if let Ok((arrived, resume)) = NAMED_REGISTER_PAUSE.try_with(Clone::clone) {
            arrived.wait().await;
            resume.wait().await;
        }
    }
    if started.elapsed() >= staging_budget {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "named view compilation exceeded query deadline",
        ));
    }
    let execution_started = Instant::now();
    let mut result = execute_prepared(&mut tx, prepared, as_of_seq, caller_started).await?;
    if !registry.generated_drift.is_empty() {
        result["view_provenance"] = json!({"generated_source_drift":registry.generated_drift,"generated_unknown_reason":registry.generated_unknown_reason});
    }
    if let Some(message) = registry.omission {
        result["notices"] = json!([{"code":"view_catalog_incomplete","message":message}]);
    }
    if let Some(plan) = &registry.retained {
        let static_relations: std::collections::BTreeMap<_, _> = reads
            .iter()
            .filter_map(|(name, _)| {
                contract::LOGICAL_RELATIONS
                    .iter()
                    .find(|r| r.name == name)
                    .map(|r| {
                        (
                            name.clone(),
                            json!({"identity":r.identity,"semantic_version":r.semantic_version}),
                        )
                    })
            })
            .collect();
        // Catalog candidates are discovery metadata, never dependencies of the
        // executed statement. Version/diagnostics come only from this closure.
        let drift: std::collections::BTreeMap<_, _> = plan
            .generated_drift
            .iter()
            .map(|(p, d)| (p.revision_id.clone(), *d))
            .collect();
        let reasons: std::collections::BTreeMap<_, _> = plan
            .generated_unknown_reason
            .iter()
            .map(|(p, r)| (p.revision_id.clone(), *r))
            .collect();
        let generated = plan.retained.values().any(|revision| revision.v == 2);
        let summaries = crate::named_views::receipt::generated_summaries(plan)?;
        result["view_provenance"] = json!({"roots":registry.pins,"closure_digest":plan.digest,"static_relations":static_relations,"has_generated_nodes":generated,"generated_diagnostics":summaries,"generated_source_drift":drift,"generated_unknown_reason":reasons});
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_caller", elapsed_us = execution_started.elapsed().as_micros() as u64);
    let cleanup_started = Instant::now();
    tx.rollback().await?;
    connection.finish().await;
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_cleanup", elapsed_us = cleanup_started.elapsed().as_micros() as u64);
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_total", elapsed_us = request_started.elapsed().as_micros() as u64);
    Ok(result)
}

async fn execute_prepared(
    connection: &mut sqlx::SqliteConnection,
    prepared: PreparedRead,
    as_of_seq: i64,
    started: Instant,
) -> Result<Value> {
    execute_prepared_mode(
        connection,
        prepared,
        as_of_seq,
        started,
        true,
        contract::MAX_ROWS,
    )
    .await
}

async fn execute_prepared_mode(
    connection: &mut sqlx::SqliteConnection,
    prepared: PreparedRead,
    as_of_seq: i64,
    started: Instant,
    query_only: bool,
    row_limit: usize,
) -> Result<Value> {
    let PreparedRead {
        statement,
        persistent,
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent,
        assumed_order,
    } = prepared;
    #[cfg(test)]
    let started = started
        - TEST_ELAPSED
            .try_with(|elapsed| elapsed.1)
            .unwrap_or_default();
    {
        let mut handle = connection.lock_handle().await?;
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    }
    if query_only {
        sqlx::query("PRAGMA query_only=ON")
            .execute(&mut *connection)
            .await?;
    }
    let previous_value_limit = {
        let mut handle = connection.lock_handle().await?;
        // SAFETY: exclusive SQLite handle lock, connection never returns to pool.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                guard::MAX_SQLITE_VALUE_BYTES,
            )
        }
    };
    let result = async {
        let capped = guard::cap_statement(&statement, row_limit as i64);
        #[cfg(test)]
        if !persistent {
            let _ = STATS.try_with(|s| s.borrow_mut().uncached_caller_statements += 1);
        }
        let query =
            guard::bind_parameters(sqlx::query(&capped).persistent(persistent), &parameters)?;
        let mut stream = query.fetch(&mut *connection);
        let mut rows = Vec::new();
        let mut bytes = serde_json::to_vec(&output_columns)?.len() + 2;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(guard::map_stream_error)? {
            if rows.len() == row_limit {
                truncated = true;
                break;
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().into(), guard::json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            bytes += serde_json::to_vec(&value)?.len() + 1;
            if bytes > contract::MAX_RESULT_ENCODED_BYTES {
                return Err(contract::categorized_error(
                    contract::QuerySqlErrorCategory::ResultTooLarge,
                    "encoded result exceeds byte limit",
                ));
            }
            rows.push(value);
        }
        drop(stream);
        Ok(json!(contract::QuerySqlResult {
            columns: output_columns,
            row_count: rows.len(),
            rows,
            truncated,
            truncation_hint: contract::truncation_hint_for(truncated),
            as_of_seq,
            now_ms_ms,
            time_dependent,
            assumed_order,
        }))
    }
    .await;
    // SQL's cell ceiling must not persist into closed kernel hydration: an
    // ordinary Get may legitimately return a body larger than a SQL cell.
    // Cancellation discards this session's owned physical connection.
    {
        let mut handle = connection.lock_handle().await?;
        // SAFETY: the exclusive handle lock owns this connection.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
    }
    result
}

#[cfg(test)]
#[derive(Default, Debug)]
pub(crate) struct Stats {
    pub staging_vm_ops: u64,
    pub named_registry_loads: usize,
    pub uncached_caller_statements: usize,
    pub staging_us: u64,
    pub installations: usize,
    pub home_checks: usize,
    pub failed_homes: usize,
    pub staged_records: u64,
    pub staged_metadata_records: u64,
    pub staged_relations: usize,
    pub provider_states_decoded: usize,
    pub invalid_facet_time_rows: usize,
}
#[cfg(test)]
tokio::task_local! { static STATS: std::cell::RefCell<Stats>; }
#[cfg(test)]
pub(crate) async fn measured<T>(work: impl std::future::Future<Output = T>) -> (T, Stats) {
    STATS
        .scope(std::cell::RefCell::new(Stats::default()), async {
            let result = work.await;
            (result, STATS.with(|s| s.take()))
        })
        .await
}

// Values are scalar lookups driven ONLY by staged visible IDs. User predicates
// cannot reach a hidden value, even when SQLite pushes them through the view.
fn field(name: &str) -> String {
    format!("(SELECT json_extract(value_json,'$') FROM main.kernel_record_fields f WHERE f.record_id=r.id AND f.name='{name}')")
}
fn millis(expression: &str) -> String {
    format!("(CAST(strftime('%s',{expression}) AS INTEGER)*1000 + CAST(substr(strftime('%f',{expression}),4,3) AS INTEGER))")
}
fn records_ddl() -> String {
    let activity =
        "(SELECT last_activity_at FROM main.kernel_record_metadata m WHERE m.record_id=r.id)";
    let updated = kernel::record_metadata::updated_clock_sql("r.id");
    let created = "coalesce((SELECT m.created_at FROM main.kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='snapshot_provenance' ORDER BY m.seq DESC LIMIT 1),r.created_at)";
    // Same immutable carrier binding as v1_type_and_kind; column values remain lazy.
    let carrier = format!(
        "r.pin_family='{}' AND r.pin_version=1",
        crate::v2_standard::v1_compat::FAMILY
    );
    let values = format!(
        r#"CREATE TEMP VIEW _v2_record_values AS SELECT r.id,
 CASE WHEN {carrier} THEN {v1_type} ELSE r.primary_type END AS type,
 CASE WHEN {carrier} THEN {v1_kind} ELSE r.kind END AS kind,
 -- V1 records.name is NOT NULL DEFAULT ''. Import carriers intentionally
 -- omit empty titles. This fallback is inside the visible-record relation:
 -- an unmatched caller LEFT JOIN still has SQL NULLs for the absent row.
 coalesce({title},{name},'') AS name,
 coalesce((SELECT body FROM main.kernel_record_bodies b WHERE b.record_id=r.id),{body}) AS body,
 {summary} AS summary,
 (SELECT home_id FROM temp._v2_record_homes h WHERE h.id=r.id) AS home_id,
 CASE WHEN (SELECT count(*) FROM main.kernel_generic_links l WHERE l.active=1 AND l.target_id=r.id AND l.relationship='supersedes' AND EXISTS(SELECT 1 FROM temp._v2_visible s WHERE s.id=l.source_id))=0 THEN 1 ELSE NULL END AS is_current,
 (SELECT count(*) FROM main.kernel_generic_links l WHERE l.active=1 AND l.target_id=r.id AND l.relationship='supersedes' AND EXISTS(SELECT 1 FROM temp._v2_visible s WHERE s.id=l.source_id)) AS successor_count,
 coalesce((SELECT value FROM main.kernel_facets f WHERE f.record_id=r.id AND f.key='lifecycle'),{lifecycle}) AS lifecycle,
 {persistence} AS persistence, {maturity} AS maturity,
 coalesce((SELECT archived FROM main.kernel_lifecycle l WHERE l.record_id=r.id),0) AS archived,
 strftime('%Y-%m-%dT%H:%M:%fZ',{created}) AS created_at, {created_ms} AS created_at_ms,
 strftime('%Y-%m-%dT%H:%M:%fZ',{updated}) AS updated_at, {updated_ms} AS updated_at_ms,
 {activity} AS last_activity_at, {activity_ms} AS last_activity_at_ms,
 (SELECT json_extract(e.payload,'$.evidence.deleted_at') FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record' ORDER BY e.seq DESC LIMIT 1) AS deleted_at,
 (SELECT CAST(unixepoch(json_extract(e.payload,'$.evidence.deleted_at'),'subsec')*1000 AS INTEGER) FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record' ORDER BY e.seq DESC LIMIT 1) AS deleted_at_ms FROM temp._v2_visible r"#,
        v1_type = field("v1_type"),
        v1_kind = field("v1_kind"),
        title = field("title"),
        name = field("name"),
        body = field("body"),
        summary = field("summary"),
        lifecycle = field("lifecycle"),
        persistence =
            "(SELECT persistence FROM main.kernel_record_metadata m WHERE m.record_id=r.id)",
        maturity = "(SELECT maturity FROM main.kernel_record_metadata m WHERE m.record_id=r.id)",
        activity_ms = millis(activity),
        created_ms = millis(created),
        updated_ms = millis(&updated)
    );
    format!(
        "{values}; CREATE TEMP VIEW records AS SELECT {} FROM temp._v2_record_values",
        columns("records").expect("records contract").join(",")
    )
}
const DDL: &str = r#"
CREATE TEMP TABLE _v2_scopes(home_id TEXT PRIMARY KEY, valid INTEGER, policy_view INTEGER, home_view INTEGER);
CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY, home_id TEXT, primary_type TEXT, kind TEXT, pin_family TEXT, pin_version INTEGER, created_at TEXT);
CREATE TEMP TABLE _v2_home_map(home_id TEXT PRIMARY KEY,record_id TEXT);
-- Only populated when the statement reads home_id. No caller expression can
-- force a retained body through the metadata/provenance lookup.
CREATE TEMP TABLE _v2_record_homes(id TEXT PRIMARY KEY,home_id TEXT);
CREATE TEMP TABLE catalog_relations(relation_name TEXT, identity TEXT, semantic_version INTEGER, caller_relative INTEGER, completeness TEXT, profiles TEXT, comment TEXT);
CREATE TEMP TABLE catalog_columns(relation_name TEXT,column_name TEXT,column_position INTEGER);
CREATE TEMP TABLE catalog_view_definitions(relation_name TEXT,view_id TEXT,revision_id TEXT,definition_sha256 TEXT,schema_sha256 TEXT,origin TEXT,description TEXT,scope_json TEXT,source_pins_json TEXT,dependencies_json TEXT,columns_json TEXT);
CREATE TEMP TABLE _v2_facet_rows(id TEXT,record_id TEXT,key TEXT,value TEXT,value_num REAL,vocab_ref TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_facet_record_key ON _v2_facet_rows(record_id,key);
CREATE INDEX _v2_facet_key_value ON _v2_facet_rows(key,value);
CREATE INDEX _v2_facet_key_num ON _v2_facet_rows(key,value_num) WHERE value_num IS NOT NULL;
CREATE TEMP VIEW facet_values AS SELECT * FROM temp._v2_facet_rows;
CREATE TEMP TABLE facet_observations(id TEXT,record_id TEXT,key TEXT,value TEXT,op TEXT,vocab_ref TEXT,as_of TEXT,observed_at TEXT,observed_at_ms INTEGER,event_seq INTEGER);
CREATE INDEX _v2_observation_series ON facet_observations(record_id,key,as_of);
CREATE INDEX _v2_observation_key ON facet_observations(key,as_of);
CREATE TEMP TABLE _v2_provider_links(source_id TEXT,target_id TEXT);
CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY);
-- All edge sources pass the same endpoint fence. New sources belong here.
CREATE TEMP VIEW _v2_link_sources AS
 SELECT printf('v2:link:%s:%s:%s',l.source_id,l.target_id,l.relationship) AS id,l.source_id,l.target_id,l.relationship,NULL AS note,e.created_at FROM main.kernel_links l LEFT JOIN main.content_events e INDEXED BY idx_kernel_event_birth ON e.seq=l.created_seq
 UNION ALL SELECT l.edge_id,l.source_id,l.target_id,l.predicate,NULL,e.created_at FROM main.kernel_link4_edges l LEFT JOIN main.content_events e INDEXED BY idx_kernel_event_birth ON e.seq=l.created_seq
 UNION ALL SELECT link_id,source_id,target_id,relationship,note,created_at FROM main.kernel_generic_links WHERE active=1
;
CREATE TEMP VIEW _v2_link_endpoints AS
 SELECT printf('v2:link:%s:%s:%s',source_id,target_id,relationship) AS id,source_id,target_id,relationship,NULL AS note FROM main.kernel_links
 UNION ALL SELECT edge_id,source_id,target_id,predicate,NULL FROM main.kernel_link4_edges
 UNION ALL SELECT link_id,source_id,target_id,relationship,note FROM main.kernel_generic_links WHERE active=1
;
CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_link_target ON _v2_link_rows(target_id,relationship);
CREATE INDEX _v2_link_source ON _v2_link_rows(source_id,relationship,target_id);
CREATE TEMP VIEW links AS SELECT * FROM temp._v2_link_rows;
CREATE TEMP TABLE _v2_event_disclosure(actor TEXT,root_visible INTEGER);
CREATE TEMP TABLE _v2_disclosed_legacy_actors(actor TEXT PRIMARY KEY);
CREATE TEMP TABLE _v2_event_ids(seq INTEGER PRIMARY KEY);
CREATE TEMP TABLE runs(run_key TEXT PRIMARY KEY,principal_person_id TEXT,started_at_ms INTEGER,ended_at_ms INTEGER,reported_model TEXT,reported_client TEXT,model_assurance TEXT);
CREATE TEMP TABLE run_intents(run_key TEXT,ordinal INTEGER,intent TEXT,declared_at_ms INTEGER);
CREATE TEMP TABLE vocabularies(id TEXT,name TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP TABLE vocabulary_values(id TEXT,vocabulary_id TEXT,value TEXT,gloss TEXT,status TEXT,ordinal REAL,terminality TEXT,metadata TEXT,alias_of TEXT);
CREATE TEMP TABLE record_lifecycle_interpretations(record_id TEXT,status TEXT,raw TEXT,axis_key TEXT,axis_label TEXT,vocabulary_id TEXT,vocabulary_name TEXT,value_id TEXT,canonical TEXT,terminality TEXT,reason TEXT);
CREATE TEMP TABLE agent_activity(activity_id TEXT,run_key TEXT,principal_ref TEXT,principal_display_name TEXT,started_at TEXT,started_at_ms INTEGER,ended_at TEXT,ended_at_ms INTEGER,last_observed_activity_at TEXT,last_observed_activity_at_ms INTEGER,active_until TEXT,active_until_ms INTEGER,appears_active INTEGER,declared_intent TEXT,declared_intent_state TEXT);
CREATE TEMP TABLE agent_activity_claims(claim_id TEXT,activity_id TEXT,record_id TEXT,claimed_at TEXT,claimed_at_ms INTEGER,released_at TEXT,released_at_ms INTEGER,is_current INTEGER);

CREATE TEMP TABLE _v2_runs(id TEXT PRIMARY KEY,run_key TEXT,owner TEXT);
CREATE TEMP TABLE _v2_imported_accounts(principal_id TEXT PRIMARY KEY);
CREATE TEMP TABLE my_message_state(message_id TEXT PRIMARY KEY,stage TEXT,unread INTEGER,is_own INTEGER,mentioned INTEGER,flagged INTEGER,muted INTEGER,archived INTEGER,snoozed_until TEXT,snoozed_until_ms INTEGER,reactable INTEGER);
CREATE TEMP TABLE messages_awaiting_reply(message_id TEXT PRIMARY KEY);
CREATE TEMP TABLE bindings(record_id TEXT,system TEXT,identifier TEXT,is_canonical INTEGER);
CREATE TEMP TABLE message_reactions(reaction_id TEXT PRIMARY KEY,message_id TEXT,emoji TEXT,actor_record_id TEXT,actor_name TEXT,executor_kind TEXT,reacted_at TEXT,reacted_at_ms INTEGER,viewer INTEGER);
CREATE TEMP TABLE my_mentions(source_id TEXT,source_kind TEXT,via TEXT,own_source INTEGER,mentioned_at TEXT,mentioned_at_ms INTEGER,seen INTEGER);

"#;

// Trusted snapshot preparation extracts only the authorized logical home.
// The thin legacy header finds provenance without searching body envelopes;
// caller VM value limits apply after this metadata has been materialized.
fn logical_home_placement_sql() -> String {
    format!(
        r#" SELECT r.id,m.record_id,{direct_home} AS direct_home,
 coalesce(json_extract(move.payload,'$.logical_home_id'), {direct_home}, CASE WHEN m.record_id=r.id AND json_extract(e.payload,'$.legacy.payload.policy_anchor')=r.id
 THEN json_extract(e.payload,'$.legacy.payload.original_home') ELSE coalesce(m.record_id,r.home_id) END) AS candidate
 FROM temp._v2_visible r LEFT JOIN temp._v2_home_map m ON m.home_id=r.home_id
 LEFT JOIN main.kernel_messages message ON message.message_id=r.id
 LEFT JOIN main.content_events move ON move.seq=(SELECT max(seq) FROM (SELECT max(p.seq) AS seq FROM main.content_events p WHERE p.record_id=r.id AND p.type='kernel.record_rehomed.v1' UNION ALL SELECT max(p.seq) AS seq FROM main.content_events p WHERE p.record_id=r.id AND p.type='kernel.record_rehomed.v2'))
 LEFT JOIN main.content_events e ON e.seq=CASE WHEN m.record_id=r.id THEN (SELECT seq FROM main.kernel_legacy_sql_events p WHERE p.record_id=r.id AND p.source_stream='snapshot_provenance' ORDER BY seq DESC LIMIT 1) END"#,
        direct_home = kernel::messaging::LOGICAL_DIRECT_HOME_SQL
    )
}

pub(super) fn logical_home_rows_sql() -> String {
    format!(
        r#"INSERT INTO temp._v2_record_homes WITH placement AS ({placement})
 SELECT p.id,CASE WHEN (p.candidate='native:unfiled' AND p.direct_home='native:unfiled')
 OR EXISTS(SELECT 1 FROM temp._v2_visible v WHERE v.id=p.candidate)
 OR (p.candidate='native:root' AND NOT EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') AND EXISTS(SELECT 1 FROM temp._v2_home_map m JOIN temp._v2_scopes h ON h.home_id=m.home_id WHERE m.record_id='native:root' AND h.home_view))
 OR (NOT EXISTS(SELECT 1 FROM main.kernel_records hidden WHERE hidden.id=p.candidate) AND EXISTS(SELECT 1 FROM temp._v2_scopes h WHERE h.home_id=p.candidate AND h.home_view)) THEN p.candidate ELSE NULL END AS home_id FROM placement p"#,
        placement = logical_home_placement_sql()
    )
}

const FACET_ROWS: &str = r#"INSERT INTO temp._v2_facet_rows SELECT printf('v2:facet:%s:%s',f.record_id,f.key),
 f.record_id,f.key,f.value,f.value_num,f.vocab_ref,strftime('%Y-%m-%dT%H:%M:%fZ',f.as_of),
 CAST(strftime('%s',f.as_of) AS INTEGER)*1000+CAST(substr(strftime('%f',f.as_of),4,3) AS INTEGER)
 FROM main.kernel_facets f JOIN temp._v2_visible v ON v.id=f.record_id WHERE f.value IS NOT NULL"#;
// v1's projector stores one observation per (record,key,as_of), replacing
// equal-time observations in source order. Only the public cell is projected;
// actor, app origin, and the rest of the retained envelope never enter SQL.
// Legacy event_seq follows the public v2 content_events namespace, so joins
// remain exact. IDs and all other fields retain their v1 representation.
const FACET_OBSERVATION_ROWS: &str = r#"INSERT INTO temp.facet_observations
WITH candidates AS (
 SELECT h.record_id,json_extract(e.payload,'$.legacy.payload.key') AS key,
 CASE h.event_type WHEN 'facet.set' THEN json_extract(e.payload,'$.legacy.payload.value') END AS value,
 CASE h.event_type WHEN 'facet.set' THEN 'set' ELSE 'unset' END AS op,
 CASE h.event_type WHEN 'facet.set' THEN json_extract(e.payload,'$.legacy.payload.vocab_ref') END AS vocab_ref,
 coalesce(json_extract(e.payload,'$.legacy.payload.as_of'),h.created_at) AS as_of,
 h.created_at AS observed_at,h.seq AS event_seq,0 AS native,
 json_extract(e.payload,'$.legacy.source.metadata.seq') AS ordering
 FROM main.kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq
 JOIN temp._v2_visible v ON v.id=h.record_id
 WHERE h.source_stream='content_events' AND h.event_type IN ('facet.set','facet.unset')
 AND json_type(e.payload,'$.legacy.payload.key')='text'
 AND json_type(e.payload,'$.legacy.source.metadata.seq')='integer'
 UNION ALL
 SELECT e.record_id,json_extract(e.payload,'$.key'),json_extract(e.payload,'$.value'),
 CASE WHEN json_extract(e.payload,'$.value') IS NULL THEN 'unset' ELSE 'set' END,
 json_extract(e.payload,'$.vocab_ref'),json_extract(e.payload,'$.as_of'),e.created_at,e.seq,1,e.seq
 FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id
 WHERE e.type='kernel.facet_observed.v1'
 UNION ALL
 SELECT e.record_id,'archived',CASE WHEN json_extract(e.payload,'$.archived') THEN 'true' END,
 CASE WHEN json_extract(e.payload,'$.archived') THEN 'set' ELSE 'unset' END,
 NULL,e.created_at,e.created_at,e.seq,1,e.seq
 FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id
 WHERE e.type='kernel.archive_changed.v1'
), latest AS (
 SELECT *,row_number() OVER(PARTITION BY record_id,key,as_of ORDER BY native DESC,ordering DESC,event_seq DESC) AS rank
 FROM candidates WHERE key NOT IN ('lifecycle','owner','persistence','maturity') AND as_of IS NOT NULL
)
SELECT 'fo:'||record_id||':'||key||':'||as_of,record_id,key,value,op,vocab_ref,as_of,
 strftime('%Y-%m-%dT%H:%M:%fZ',observed_at),(CAST(strftime('%s',observed_at) AS INTEGER)*1000+CAST(substr(strftime('%f',observed_at),4,3) AS INTEGER)),event_seq
 FROM latest WHERE rank=1"#;

fn events_ddl() -> String {
    format!(
        r#"
CREATE TEMP TABLE _v2_event_rows(local_seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,actor TEXT,run_key TEXT,parent_key TEXT,channel_kind TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP VIEW content_events AS
 SELECT local_seq,id,record_id,type,actor,run_key,parent_key,channel_kind,
 strftime('%Y-%m-%dT%H:%M:%fZ',created_at) AS created_at,
 CAST(strftime('%s',created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',created_at),4,3) AS INTEGER) AS created_at_ms
 FROM temp._v2_event_rows;
CREATE TEMP VIEW actors AS SELECT DISTINCT e.actor,r.id AS person_id,coalesce(json_extract(n.value_json,'$'),p.display_label) AS display_name
 FROM temp.content_events e LEFT JOIN main.kernel_principals p ON p.principal_id=e.actor OR 'v1:'||p.auth_binding=e.actor
 LEFT JOIN main.kernel_v1_state d ON d.section='account_directory' AND d.account_principal=p.principal_id
 LEFT JOIN main.kernel_message_people mp ON mp.principal_id=p.principal_id
 LEFT JOIN temp._v2_visible v ON v.id=coalesce(d.record_id,mp.person_id)
 LEFT JOIN main.kernel_records r ON r.id=v.id
 LEFT JOIN main.kernel_record_fields n ON n.record_id=r.id AND n.name='title'
 WHERE e.actor IS NOT NULL;
CREATE TEMP VIEW comment_anchors AS SELECT a.annotation_id,a.target_record_id,a.purpose,a.selectors,a.body_revision AS source_event_seq,a.body_sha256 AS source_sha256
 FROM main.kernel_comment_anchors a JOIN temp._v2_visible c ON c.id=a.annotation_id JOIN temp._v2_visible t ON t.id=a.target_record_id JOIN main.kernel_records r ON r.id=a.annotation_id
 WHERE a.source_slot='body' AND {};
"#,
        kernel::comments_v2::sql_is_comment("r")
    )
}

// Keep every retained-header join after the tiny selected-position set.
// Fencing only a/m lets SQLite move the JSON subject scan ahead of both.
pub(super) const LEGACY_ADMISSION_SQL: &str = "INSERT INTO temp._v2_legacy_admitted SELECT m.seq FROM temp._v2_event_ids a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq CROSS JOIN temp._v2_visible r ON r.id=m.record_id WHERE m.source_stream='content_events' AND NOT h.hidden AND (?1 OR NOT h.restricted OR h.owner=?2) AND NOT EXISTS(SELECT 1 FROM json_each(h.subjects) subject WHERE NOT EXISTS(SELECT 1 FROM temp._v2_legacy_visible_subjects visible WHERE visible.id=subject.value))";

/// Share W5 disclosure checks. Only replayed header facts are read here;
/// source bodies and immutable retained envelopes stay outside ordinary SQL.
async fn install_events(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    bounded: bool,
) -> Result<()> {
    let logical_types = super::LOGICAL_EVENT_TYPES
        .iter()
        .map(|(native, logical)| format!("WHEN '{native}' THEN '{logical}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let imported = super::IMPORTED_EVENTS
        .iter()
        .map(|event| format!("'{event}'"))
        .collect::<Vec<_>>()
        .join(",");
    let native_sql = format!(
        r#"INSERT INTO temp._v2_event_rows
 SELECT e.seq,e.id,e.record_id,
 CASE e.type {logical_types} ELSE e.type END,
 CASE WHEN ?1 OR e.actor=?2 OR EXISTS(SELECT 1 FROM main.kernel_message_people mp JOIN temp._v2_visible v ON v.id=mp.person_id WHERE mp.principal_id=e.actor) THEN e.actor END,
 CASE WHEN ?1 THEN e.run_key END,CASE WHEN ?1 THEN e.parent_key END,
 CASE WHEN ?1 OR e.actor=?2 THEN 'unknown' END,
 e.created_at,NULL
 FROM temp._v2_event_ids a CROSS JOIN main.content_events e ON e.seq=a.seq
 WHERE e.type!='kernel.legacy_recorded.v1' AND e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT GLOB 'kernel.import_*' AND e.type NOT IN ({imported})"#
    );
    sqlx::query(&native_sql)
        .bind(root_visible)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    install_reaction_headers(tx, actor, root_visible, bounded).await?;
    let headers: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='kernel_legacy_sql_events')").fetch_one(&mut *tx).await?;
    if !headers {
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_legacy_history)")
                .fetch_one(&mut *tx)
                .await?;
        if retained {
            return Err(Error::engine(
                "kernel-v2 logical history needs import projection upgrade",
            ));
        }
        return Ok(());
    }
    let binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(&mut *tx)
            .await?;
    let admin =
        kernel::kernel_effective_capability_on(&mut *tx, actor, crate::events::KERNEL_ROOT_ID)
            .await?
            .allows(Capability::Manage);
    let subject_sets: Vec<String> = sqlx::query_scalar("SELECT DISTINCT h.subjects FROM temp._v2_event_ids a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq CROSS JOIN temp._v2_visible r ON r.id=m.record_id WHERE m.source_stream='content_events' AND NOT h.hidden AND (?1 OR NOT h.restricted OR h.owner=?2)")
        .bind(admin).bind(&binding).fetch_all(&mut *tx).await?;
    let mut visibility = std::collections::BTreeMap::new();
    // Reuse current record visibility already established by S7, including
    // terminal-bearer authorization for derived records. Comments retain W5's
    // additional anchor check; homes and other subjects use its shared helper.
    let mut subjects = BTreeSet::<String>::new();
    for row in &subject_sets {
        subjects.extend(serde_json::from_str::<Vec<String>>(row)?);
    }
    let ordinary = format!(
        "SELECT v.id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id WHERE v.id IN (SELECT value FROM json_each(?1)) AND NOT {}",
        kernel::comments_v2::sql_is_comment("r")
    );
    for id in sqlx::query_scalar::<_, String>(&ordinary)
        .bind(serde_json::to_string(&subjects)?)
        .fetch_all(&mut *tx)
        .await?
    {
        visibility.insert(id, true);
    }
    // Resolve each subject once, with the same W5 helper as before. Admission
    // of the many historical rows is then a set operation inside this exact
    // authority snapshot, rather than decoding/inserting each row in Rust.
    for subjects in subject_sets {
        for subject in serde_json::from_str::<Vec<String>>(&subjects)? {
            kernel::legacy_history_visible(&mut *tx, actor, &subject, &mut visibility).await?;
        }
    }
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _v2_legacy_visible_subjects(id TEXT PRIMARY KEY); DELETE FROM temp._v2_legacy_visible_subjects; CREATE TEMP TABLE IF NOT EXISTS _v2_legacy_admitted(seq INTEGER PRIMARY KEY); DELETE FROM temp._v2_legacy_admitted")
        .execute(&mut *tx).await?;
    let visible: Vec<&str> = visibility
        .iter()
        .filter_map(|(id, allowed)| allowed.then_some(id.as_str()))
        .collect();
    for chunk in visible.chunks(500) {
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_legacy_visible_subjects(id) ",
        );
        insert.push_values(chunk, |mut row, id| {
            row.push_bind(*id);
        });
        insert.build().execute(&mut *tx).await?;
    }
    sqlx::query(LEGACY_ADMISSION_SQL)
        .bind(admin)
        .bind(&binding)
        .execute(&mut *tx)
        .await?;
    // Same v1 rule as get_history: self, or an actor's verified Person
    // visible under current policy. Root visibility is not a substitute.
    for principal in kernel::v1_state::disclosed_accounts_on(tx, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_disclosed_legacy_actors SELECT 'v1:'||auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(principal).execute(&mut *tx).await?;
    }
    // SQL uses one verified principal identity across imported and native
    // activity. Otherwise apps mistake a source alias and that principal's
    // first native event for two different accounts bound to the same Person.
    // Disclosure still gates the source actor first; retained headers and raw
    // history keep the exact v1 actor. Never coalesce accounts by Person/name.
    // Copy admitted headers in one set operation, never one round trip per
    // historical event. No source payload enters the ordinary SQL surface.
    sqlx::query(r#"INSERT INTO temp._v2_event_rows
      SELECT m.seq,m.source_id,m.record_id,
       CASE WHEN m.event_type='receipt.committed.v1' THEN 'record.updated' ELSE m.event_type END,
       CASE WHEN d.actor IS NOT NULL THEN coalesce(p.principal_id,m.actor) END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.run_key END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.parent_key END,
       CASE WHEN d.actor IS NOT NULL THEN 'unknown' END,
       m.created_at,NULL
      FROM temp._v2_legacy_admitted a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq
      CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq
      LEFT JOIN temp._v2_disclosed_legacy_actors d ON d.actor=m.actor
      LEFT JOIN main.kernel_principals p ON p.auth_binding=substr(m.actor,4) AND m.actor LIKE 'v1:%' AND p.kind='account'"#)
        .bind(&binding).execute(&mut *tx).await?;
    Ok(())
}

async fn select_event_ids(tx: &mut sqlx::SqliteConnection, bounded: bool) -> Result<()> {
    let candidate = if bounded {
        " AND e.seq IN (SELECT seq FROM temp._v2_history_candidates)"
    } else {
        ""
    };
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id WHERE e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT IN ('kernel.identity_binding_added.v1','kernel.account_config_bound.v1','kernel.app_state_imported.v1','kernel.import_receipt.v1','kernel.v1_state_imported.v1','kernel.message_state.v1','kernel.notification_preference_set.v1','kernel.message_command_committed.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1','kernel.provider_outcome.v1','kernel.link_added.v2','kernel.link_added.v1','kernel.link_removed.v1') AND e.type NOT LIKE 'kernel.generic_link_%'{candidate}")).execute(&mut *tx).await?;

    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN main.kernel_link4_edges l ON l.created_seq=e.seq JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE e.type='kernel.link_added.v2'{candidate}")).execute(&mut *tx).await?;
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible s ON s.id=e.record_id JOIN temp._v2_visible t ON t.id=json_extract(e.payload,'$.target_id') WHERE e.type IN ('kernel.link_added.v1','kernel.link_removed.v1'){candidate}")).execute(&mut *tx).await?;
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN main.kernel_generic_links l ON l.link_id=json_extract(e.payload,'$.link_id') JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE e.type LIKE 'kernel.generic_link_%'{candidate}")).execute(&mut *tx).await?;
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible anchor ON anchor.id=e.record_id WHERE e.type='kernel.provider_outcome.v1' AND EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id) AND NOT EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id AND s.subject_id NOT IN (SELECT id FROM temp._v2_visible)){candidate}")).execute(&mut *tx).await?;
    Ok(())
}

/// Structural subjects for a closed history window, followed by the SAME
/// live record gate as full staging. Accumulate admitted subjects across
/// windows; all event selectors/redactors still run unchanged afterwards.
async fn stage_history_subjects(tx: &mut sqlx::SqliteConnection, actor: &str) -> Result<()> {
    let visibility = kernel::sql_record_visible(
        "r",
        "?1",
        "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
        true,
    );
    let subjects = r#"WITH candidates AS MATERIALIZED (SELECT e.seq,e.record_id,e.type,e.actor,CASE WHEN e.type IN ('kernel.link_added.v1','kernel.link_removed.v1') OR e.type LIKE 'kernel.generic_link_%' THEN e.payload END AS payload FROM temp._v2_history_candidates c CROSS JOIN main.content_events e ON e.seq=c.seq),
    subjects(id) AS (
      SELECT record_id FROM candidates
      UNION SELECT m.record_id FROM candidates c JOIN main.kernel_legacy_sql_events m ON m.seq=c.seq
      UNION SELECT j.value FROM candidates c JOIN main.kernel_legacy_history h ON h.seq=c.seq JOIN json_each(h.subjects) j
      UNION SELECT l.source_id FROM candidates c JOIN main.kernel_generic_links l ON l.link_id=json_extract(c.payload,'$.link_id') WHERE c.type LIKE 'kernel.generic_link_%'
      UNION SELECT l.target_id FROM candidates c JOIN main.kernel_generic_links l ON l.link_id=json_extract(c.payload,'$.link_id') WHERE c.type LIKE 'kernel.generic_link_%'
      UNION SELECT l.source_id FROM candidates c JOIN main.kernel_link4_edges l ON l.created_seq=c.seq WHERE c.type='kernel.link_added.v2'
      UNION SELECT l.target_id FROM candidates c JOIN main.kernel_link4_edges l ON l.created_seq=c.seq WHERE c.type='kernel.link_added.v2'
      UNION SELECT json_extract(payload,'$.target_id') FROM candidates WHERE type IN ('kernel.link_added.v1','kernel.link_removed.v1')
      UNION SELECT s.subject_id FROM candidates c JOIN main.kernel_provider_subjects s ON s.aggregate_id=c.record_id WHERE c.type='kernel.provider_outcome.v1'
      UNION SELECT p.person_id FROM main.kernel_message_people p
    )"#;
    // Payloads only supply native edge ids/endpoints. Retained payloads stay
    // opaque; their already projected subject headers are the authority input.
    sqlx::query(&format!("{subjects} INSERT OR IGNORE INTO temp._v2_visible SELECT r.id,r.home_id,NULL,NULL,NULL,NULL,NULL FROM main.kernel_records r WHERE r.id IN (SELECT id FROM subjects) AND ({visibility})"))
        .bind(actor).execute(tx).await?;
    Ok(())
}

/// Candidate positions carry no authority. Every window still passes the
/// unchanged native/legacy disclosure selectors and retained header gates.
async fn install_history_window(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    window: HistoryWindow,
) -> Result<()> {
    sqlx::query("CREATE TEMP TABLE _v2_history_candidates(seq INTEGER PRIMARY KEY)")
        .execute(&mut *tx)
        .await?;
    let imported = super::IMPORTED_EVENTS
        .iter()
        .map(|event| format!("'{event}'"))
        .collect::<Vec<_>>()
        .join(",");
    let direction = if window.newest { "DESC" } else { "ASC" };
    let mut cursor = window
        .after
        .unwrap_or(if window.newest { i64::MAX } else { 0 });
    let mut inclusive = window.newest && window.after.is_none();
    let mut admitted_count = 0usize;
    let mut fetch = window.limit.saturating_add(1).clamp(16, 256);
    loop {
        let comparison = if window.newest {
            if inclusive {
                "<="
            } else {
                "<"
            }
        } else {
            ">"
        };
        inclusive = false;
        let positions: Vec<i64> = sqlx::query_scalar(&format!(
            "SELECT e.seq FROM main.content_events e WHERE e.seq{comparison}?1 AND e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT GLOB 'kernel.import_*' AND e.type NOT IN ({imported},'kernel.identity_binding_added.v1','kernel.account_config_bound.v1','kernel.app_state_imported.v1','kernel.v1_state_imported.v1','kernel.notification_preference_set.v1','kernel.message_command_committed.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1') AND (e.type!='kernel.legacy_recorded.v1' OR EXISTS(SELECT 1 FROM main.kernel_legacy_sql_events m WHERE m.seq=e.seq AND m.source_stream='content_events')) ORDER BY e.seq {direction} LIMIT {fetch}"
        )).bind(cursor).fetch_all(&mut *tx).await?;
        if positions.is_empty() {
            break;
        }
        cursor = *positions.last().expect("nonempty candidate window");
        sqlx::query("DELETE FROM temp._v2_history_candidates; DELETE FROM temp._v2_event_ids")
            .execute(&mut *tx)
            .await?;
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_history_candidates(seq) ",
        );
        insert.push_values(&positions, |mut row, seq| {
            row.push_bind(*seq);
        });
        insert.build().execute(&mut *tx).await?;
        stage_history_subjects(tx, actor).await?;
        select_event_ids(tx, true).await?;
        install_events(tx, actor, root_visible, true).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_event_rows")
            .fetch_one(&mut *tx)
            .await?;
        if count > window.limit as i64 || positions.len() < fetch {
            break;
        }
        // Fetch only the remaining page/lookahead when making progress. A
        // hidden or private-only window uses the old full stride next time.
        fetch = if count as usize == admitted_count {
            256
        } else {
            window
                .limit
                .saturating_add(1)
                .saturating_sub(count as usize)
                .clamp(16, 256)
        };
        admitted_count = count as usize;
    }
    Ok(())
}

// Drive immutable home-event lookup from the already evaluated scopes. Letting
// SQLite reorder an ordinary join scans every retained content-event row before
// probing the tiny scope set, even though the existing record/type index can
// answer these exact lookups. No authority predicate or source data changes.
pub(super) const HOME_MAP_SQL: &str = "INSERT INTO temp._v2_home_map SELECT e.record_id,json_extract(e.payload,'$.source_record_id') FROM temp._v2_scopes h CROSS JOIN main.content_events e ON e.record_id=h.home_id AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') WHERE json_extract(e.payload,'$.source_record_id') IS NOT NULL";

/// Frozen app bundles use the v1-versioned public headers for counts and invalidation.
/// Derive them from adjacent authoritative states, never from private-lane
/// writes. No replacement payload enters TEMP SQL or the ordinary event feed.
async fn install_reaction_headers(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    bounded: bool,
) -> Result<()> {
    let candidate = if bounded {
        " AND seq IN (SELECT seq FROM temp._v2_history_candidates)"
    } else {
        ""
    };
    sqlx::query(&format!(r#"WITH states AS (
      SELECT e.seq,e.id,e.record_id,e.type,e.actor,e.run_key,e.parent_key,e.created_at,
       json_extract({state_json},'$.reactions') AS reactions
      FROM main.kernel_messages m JOIN temp._v2_visible v ON v.id=m.message_id
      CROSS JOIN main.content_events e
      WHERE e.record_id=m.message_id AND e.type IN {state_events}
       AND json_type({state_json})='object'
     ), transitions AS (
      SELECT *,lag(reactions) OVER (PARTITION BY record_id ORDER BY seq) AS previous FROM states
     ), changes AS (
      SELECT *,
       EXISTS(SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji
        EXCEPT SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji) AS added,
       EXISTS(SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji
        EXCEPT SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji) AS removed
      FROM transitions WHERE type='kernel.message_state.v1' AND previous IS NOT NULL
     )
     INSERT INTO temp._v2_event_rows
     SELECT seq,id,record_id,
      CASE WHEN added THEN 'message.reaction.added.v1' ELSE 'message.reaction.removed.v1' END,
      CASE WHEN ?1 OR actor=?2 OR EXISTS(SELECT 1 FROM main.kernel_message_people mp JOIN temp._v2_visible v ON v.id=mp.person_id WHERE mp.principal_id=changes.actor) THEN actor END,
      CASE WHEN ?1 THEN run_key END,CASE WHEN ?1 THEN parent_key END,
      CASE WHEN ?1 OR actor=?2 THEN 'unknown' END,
      created_at,NULL
     FROM changes WHERE (added OR removed){candidate}"#, state_json=kernel::messaging::STATE_JSON_SQL, state_events=kernel::messaging::STATE_EVENTS_SQL))
        .bind(root_visible).bind(actor).execute(tx).await?;
    Ok(())
}

pub(crate) async fn install(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    install_relations(
        tx,
        actor,
        reads,
        LinkScope::All,
        None,
        None,
        None,
        None,
        None,
        chrono::Utc::now().timestamp_millis(),
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn install_relations(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
    link_scope: LinkScope,
    candidate_ids: Option<&[String]>,
    history_window: Option<HistoryWindow>,
    record_limit: Option<i64>,
    exact_record_ids: Option<&[String]>,
    class_scope: Option<&record_classes::Plan>,
    observed_ms: i64,
    project_facet_columns: bool,
) -> Result<()> {
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().installations += 1);
    let schema_started = Instant::now();
    sqlx::query(DDL).persistent(false).execute(&mut *tx).await?;
    sqlx::query(&records_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    sqlx::query(&events_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_temp_schema", elapsed_us = schema_started.elapsed().as_micros() as u64);
    let needs = |relation: &str| reads.iter().any(|(r, _)| r == relation);
    if needs("bindings") {
        // Keep main's caller-scoped portable/catalog aliases. The native
        // principal is also a verified alias for current_principal(), as the
        // typed Messages feed expects; never stage another member's bindings.
        let mut bindings = super::identity_read::sql_bindings_on(tx, actor).await?;
        if let Some((person, _)) = bindings.first() {
            let native = (person.clone(), actor.to_owned());
            if !bindings.contains(&native) {
                bindings.push(native);
            }
        }
        for (person, identifier) in bindings {
            // This caller-relative view has one canonical native identifier.
            // Portable/catalog identifiers remain verified lookup aliases;
            // they are not fabricated canonical native principals.
            let canonical = i64::from(identifier == actor);
            sqlx::query("INSERT INTO temp.bindings VALUES(?,'account',?,?)")
                .bind(person)
                .bind(identifier)
                .bind(canonical)
                .execute(&mut *tx)
                .await?;
        }
    }
    let column = |name: &str| reads.contains(&("records".into(), name.into()));
    let needs_events = needs("content_events") || needs("actors");
    let needs_records = [
        "records",
        "blobs",
        "links",
        "facet_values",
        "facet_observations",
        "facet_times",
        "content_events",
        "actors",
        "comment_anchors",
        "record_lifecycle_interpretations",
        "agent_activity_claims",
        "bindings",
        "message_reactions",
        "my_mentions",
        "my_message_state",
        "messages_awaiting_reply",
    ]
    .iter()
    .any(|r| needs(r));
    let needs_runs = needs("runs") || needs("run_intents") || needs("agent_activity_claims");
    let mut root_visible = false;
    if needs_records {
        // Authorize requested anchors in this same snapshot before their raw
        // structural relations can influence staging (including timing).
        let candidate_ids = if let Some(ids) = candidate_ids {
            let mut allowed = BTreeSet::new();
            for id in ids.iter().collect::<BTreeSet<_>>() {
                let root = [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id.as_str());
                let visible = kernel::read_record_on(tx, actor, id).await?.is_some()
                    || (root
                        && kernel::kernel_effective_capability_on(
                            tx,
                            actor,
                            crate::events::KERNEL_ROOT_ID,
                        )
                        .await?
                        .allows(Capability::View));
                if visible {
                    allowed.insert(id.clone());
                    if root {
                        allowed.extend([
                            crate::events::KERNEL_ROOT_ID.to_owned(),
                            "native:root".to_owned(),
                        ]);
                    }
                }
            }
            Some(serde_json::to_string(&allowed)?)
        } else {
            None
        };
        // A pre-upgrade importer may append while this handle stays open.
        // Never serve incomplete logical headers or invented birth times.
        let frontier_started = Instant::now();
        kernel::legacy_history::require_sql_frontier_on(&mut *tx).await?;
        tracing::debug!(target: "native_ce::read_staging", phase = "legacy_frontier", elapsed_us = frontier_started.elapsed().as_micros() as u64);

        let scopes_started = Instant::now();
        let scope = kernel::visible_home_anchors_as(tx, actor).await?;
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            let mut s = s.borrow_mut();
            s.home_checks = scope.homes.len();
            s.failed_homes = scope.failed_homes;
        });
        let mut home_rows = Vec::with_capacity(scope.homes.len());
        for home in scope.homes {
            if home.home_id == crate::events::KERNEL_ROOT_ID {
                root_visible = home.home_view;
            }
            home_rows.push((
                home.home_id,
                home.policy_valid,
                home.policy_view,
                home.home_view,
            ));
        }
        for batch in home_rows.chunks(256) {
            sqlx::query("INSERT INTO temp._v2_scopes SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]') FROM json_each(?)")
                .bind(serde_json::to_string(batch)?).execute(&mut *tx).await?;
        }
        tracing::debug!(target: "native_ce::read_staging", phase = "scopes", elapsed_us = scopes_started.elapsed().as_micros() as u64);
        let visible_started = Instant::now();
        let map_started = Instant::now();
        if column("home_id")
            || (exact_record_ids.is_some() && needs("record_lifecycle_interpretations"))
        {
            sqlx::query(HOME_MAP_SQL).execute(&mut *tx).await?;
            // The importer does not create a record for the structural v1 root;
            // its sealed root policy import witnesses that logical home mapping.
            sqlx::query("INSERT OR IGNORE INTO temp._v2_home_map SELECT ?1,'native:root' WHERE EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') OR EXISTS(SELECT 1 FROM main.content_events WHERE record_id=?1 AND type='kernel.import_home_policy.v1')").bind(crate::events::KERNEL_ROOT_ID).execute(&mut *tx).await?;
        }
        tracing::debug!(target:"native_ce::read_staging",phase="home_map",elapsed_us=map_started.elapsed().as_micros() as u64);
        // Single set operation; no per-record authority, field reads or inserts.
        let identity = column("type") || column("kind") || needs("my_mentions") || needs("blobs");
        let creation = column("created_at") || column("created_at_ms") || needs("my_mentions");
        let projection = if identity {
            "r.primary_type,r.kind,r.pin_family,r.pin_version"
        } else {
            "NULL,NULL,NULL,NULL"
        };
        let creation = if creation {
            "COALESCE((SELECT json_extract(m.state,'$.created_at') FROM kernel_messages m WHERE m.message_id=r.id),r.created_at)"
        } else {
            "NULL"
        };
        // Omit the recursive per-row Message gate only when this same read
        // snapshot proves there are no sealed OR unsealed Message records.
        // The second probe preserves fail-closed reads of missing audience
        // state; it is intentionally independent of the public type carrier.
        let has_messages: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
            .fetch_one(&mut *tx).await?;
        let visibility = kernel::sql_record_visible(
            "r",
            "?1",
            "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
            has_messages,
        );
        // This is a structural superset for Get's closed enrichment queries,
        // not an authorization gate. Annotation windows only consume direct
        // part_of sources of requested subjects, not unrelated annotations.
        // All candidates pass the unchanged kernel
        // visibility predicates below. Include every self-home and moved row
        // so private filing and logical relocation remain exact.
        let candidates = if exact_record_ids.is_some() {
            "r.id IN (SELECT value FROM json_each(?2))"
        } else if candidate_ids.is_some() {
            "r.id IN (SELECT value FROM json_each(?2) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT value FROM json_each(?2)) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT home_id FROM temp._v2_home_map WHERE record_id IN (SELECT value FROM json_each(?2))) UNION SELECT record_id FROM temp._v2_home_map UNION SELECT root_id FROM main.kernel_roots UNION SELECT id FROM main.kernel_records WHERE primary_type='Collection' UNION SELECT record_id FROM main.kernel_record_fields WHERE name='v1_type' AND value_json IN ('\"Annotation\"','\"Collection\"') AND value_json='\"Collection\"' UNION SELECT source_id FROM main.kernel_generic_links WHERE active=1 AND relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_links WHERE relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_link4_edges WHERE predicate='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT record_id FROM main.content_events INDEXED BY idx_kernel_record_moves WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2'))"
        } else if let Some(scope) = class_scope {
            &scope.predicate
        } else {
            "1"
        };
        let prefix = record_limit
            .map(|n| format!(" ORDER BY r.id LIMIT {n}"))
            .unwrap_or_default();
        let staging = format!("INSERT INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE ({candidates}) AND ({visibility}){prefix}");
        let mut query = sqlx::query(&staging).bind(actor);
        if let Some(ids) = exact_record_ids {
            query = query.bind(serde_json::to_string(ids)?);
        } else if let Some(ids) = candidate_ids {
            query = query.bind(ids);
        } else if let Some(scope) = class_scope {
            for parameter in &scope.parameters {
                query = query.bind(parameter);
            }
        }
        let staging_started = Instant::now();
        // Global history stages only each candidate window's direct subjects
        // below. Its closed callback consumes event headers, never records.
        let count = if history_window.is_some() {
            0
        } else {
            query.execute(&mut *tx).await?.rows_affected()
        };
        // The wide pulse also discloses logical placement. Admit only its
        // direct placement dependencies with the SAME kernel endpoint gate.
        // They cannot become caller rows: the original IN predicate remains.
        let dependency_count = if exact_record_ids.is_some()
            && (column("home_id") || needs("record_lifecycle_interpretations"))
        {
            // Lifecycle interpretation also needs the source record bearing
            // the policy home, even when its logical folder differs.
            let policy_bearers = if needs("record_lifecycle_interpretations") {
                " UNION SELECT h.record_id FROM temp._v2_visible v JOIN temp._v2_home_map h ON h.home_id=v.home_id"
            } else {
                ""
            };
            sqlx::query(&format!("CREATE TEMP TABLE _v2_home_candidates AS SELECT DISTINCT candidate AS id FROM ({}){policy_bearers}", logical_home_placement_sql()))
                .execute(&mut *tx).await?;
            sqlx::query(&format!("INSERT OR IGNORE INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE r.id IN (SELECT id FROM temp._v2_home_candidates) AND ({visibility})"))
                .bind(actor).execute(&mut *tx).await?.rows_affected()
        } else {
            0
        };
        let count = count + dependency_count;
        tracing::debug!(target:"native_ce::read_staging",phase="visibility_gate",elapsed_us=staging_started.elapsed().as_micros() as u64,records=count);
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            let mut s = s.borrow_mut();
            s.staged_records = count;
            s.staged_metadata_records = if identity || creation != "NULL" {
                count
            } else {
                0
            };
        });
        #[cfg(not(test))]
        let _ = count;
        tracing::debug!(target: "native_ce::read_staging", phase = "visible_records", elapsed_us = visible_started.elapsed().as_micros() as u64);
    } else if needs_runs {
        root_visible =
            kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap_or(Capability::None)
                .allows(Capability::View);
    }
    let relations_started = Instant::now();
    if column("home_id") {
        sqlx::query(&logical_home_rows_sql())
            .execute(&mut *tx)
            .await?;
    }
    if (needs("links") && link_scope == LinkScope::All)
        || (needs_events && history_window.is_none())
    {
        stage_visible_providers(tx).await?;
    }
    if needs("facet_values") {
        // Internal readers may declare only relation dependencies. Only SQL
        // admission supplies an authoritative set of consumed columns.
        let rows = if project_facet_columns {
            facets::rows_sql(reads)
        } else {
            FACET_ROWS.to_owned()
        };
        sqlx::query(&rows).execute(&mut *tx).await?;
    }
    if needs("facet_observations") {
        sqlx::query(FACET_OBSERVATION_ROWS)
            .execute(&mut *tx)
            .await?;
    }
    if needs("facet_times") {
        facet_times::stage(tx).await?;
    }
    if needs("links") {
        install_link_view(tx, reads, link_scope).await?;
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "home_links", elapsed_us = relations_started.elapsed().as_micros() as u64);
    if needs_events {
        sqlx::query("INSERT INTO temp._v2_event_disclosure VALUES(?,?)")
            .bind(actor)
            .bind(root_visible)
            .execute(&mut *tx)
            .await?;
        if let Some(window) = history_window {
            install_history_window(tx, actor, root_visible, window).await?;
        } else {
            select_event_ids(tx, false).await?;
            install_events(tx, actor, root_visible, false).await?;
        }
        sqlx::query(
            "CREATE INDEX temp._v2_event_record_type ON _v2_event_rows(record_id,type,local_seq)",
        )
        .execute(&mut *tx)
        .await?;
    }
    if needs("blobs") {
        // A byte handle is public only through a visible, live Document
        // attachment with its exact engine-owned blob_ref. Group references
        // before joining bytes: metadata-only needs never materialize blobs.
        sqlx::query("CREATE TEMP VIEW blobs AS SELECT a.handle AS id,b.bytes,json_extract(a.metadata,'$.mime') AS mime,b.size_bytes,b.sha256,json_extract(a.metadata,'$.original_filename') AS original_filename,json_extract(a.metadata,'$.storage_tier') AS storage_tier,NULL AS external_ref,json_extract(a.metadata,'$.created_at') AS created_at,CAST((julianday(json_extract(a.metadata,'$.created_at'))-2440587.5)*86400000 AS INTEGER) AS created_at_ms FROM (SELECT json_extract(a.metadata,'$.id') AS handle,a.metadata,a.sha256 FROM main.kernel_attachment_blobs a JOIN temp.records r ON r.id=a.record_id JOIN main.kernel_facets f ON f.record_id=a.record_id AND f.key='blob_ref' AND f.value=json_extract(a.metadata,'$.id') WHERE r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL GROUP BY json_extract(a.metadata,'$.id')) a JOIN main.kernel_blobs b ON b.sha256=a.sha256")
            .execute(&mut *tx).await?;
    }
    install_imported_catalogue(tx, actor, reads).await?;
    if needs("my_message_state")
        || needs("messages_awaiting_reply")
        || needs("message_reactions")
        || needs("my_mentions")
    {
        install_messaging(
            tx,
            actor,
            needs("my_message_state"),
            needs("messages_awaiting_reply"),
            needs("message_reactions"),
            needs("my_mentions"),
        )
        .await?;
    }

    if needs("agent_activity") {
        activity::install(tx, actor, observed_ms).await?;
    }
    if needs_runs {
        install_runs(tx, actor, root_visible, needs("run_intents")).await?;
        install_imported_runs(
            tx,
            actor,
            root_visible,
            needs("run_intents"),
            needs("agent_activity_claims"),
        )
        .await?;
    }
    #[cfg(test)]
    let _ = STATS.try_with(|s| {
        s.borrow_mut().staged_relations = [
            "records",
            "links",
            "facet_values",
            "facet_observations",
            "facet_times",
            "content_events",
            "agent_activity",
            "runs",
            "run_intents",
            "vocabularies",
            "vocabulary_values",
            "record_lifecycle_interpretations",
            "agent_activity_claims",
        ]
        .iter()
        .filter(|r| needs(r))
        .count()
    });
    if needs("catalog_relations") || needs("catalog_columns") || needs("catalog_view_definitions") {
        for relation in contract::LOGICAL_RELATIONS {
            let Some(supported) = columns(relation.name) else {
                continue;
            };
            sqlx::query("INSERT INTO temp.catalog_relations VALUES(?,?,?,?,?,?,?)")
                .bind(relation.name).bind(relation.identity).bind(relation.semantic_version as i64).bind(relation.caller_relative)
                .bind("best_effort").bind("sqlite-local-v2")
                .bind("v2 probe; catalog_columns lists the supported columns. Bindings expose only the caller's visible verified Person with its portable account and stored H3 catalogue aliases; email, canonical flags and provider timestamps are not represented. Bodies lazy. Home is the visible logical folder, or native home id. Currency counts visible active supersedes sources; is_current is 1 or NULL. Generic links retain ids/notes/times; provider links are symmetric with NULL note/time: an aggregate may combine directed legacy sources with different original notes and claimed timestamps; no single source is chosen. Facet value timestamps use as_of; facet_times follows v1 current typed writes and excludes observation-only writes. Native event attribution uses self/root-directory admission; legacy attribution requires self or View on the verified Person and retains v1:. Logical create/update types and retained content headers are exposed; migration receipts are omitted. channel_kind is unknown until provenance admission. Actor names/person IDs use visible verified imported Persons when available, otherwise labels may be placeholders. Anchor positions retain their source namespace without a coedit cut proof. Native runs use self/root-directory admission and NULL person/model/client fields. Imported runs/intents require self or a visible verified imported Person; known principal_person_id is retained; imported runs preserve declarations, use model_assurance imported_historical and ended_at_ms at the source close or snapshot boundary. Imported claims are historical, is_current=0 and released at the source release or snapshot boundary; they never occupy the live claims lane. Imported creation times retain source birth; native creation time stays separate; deletion times NULL.")
                .execute(&mut *tx).await?;
            for (position, column) in supported.iter().enumerate() {
                sqlx::query("INSERT INTO temp.catalog_columns VALUES(?,?,?)")
                    .bind(relation.name)
                    .bind(*column)
                    .bind(position as i64)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    Ok(())
}

// The subject table is keyed by (subject_id,aggregate_id). Group once in
// this authority snapshot; a correlated aggregate_id probe per provider would
// scan the entire subject table repeatedly. A provider with no subjects is
// absent, and one hidden endpoint excludes the whole provider, as before.
async fn stage_visible_providers(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    sqlx::query("INSERT INTO temp._v2_visible_providers SELECT s.aggregate_id FROM main.kernel_provider_subjects s LEFT JOIN temp._v2_visible v ON v.id=s.subject_id GROUP BY s.aggregate_id HAVING count(v.id)=count(*)")
        .execute(tx).await?;
    Ok(())
}

/// Keep the disclosure barrier, but let SQLite build its narrow ephemeral
/// rows once for the caller statement. Eagerly copying every link into another
/// TEMP table plus two indexes dominated joins which only consume endpoints.
/// MATERIALIZED prevents caller expressions from moving below the live gates.
async fn install_link_view(
    tx: &mut sqlx::SqliteConnection,
    reads: &BTreeSet<(String, String)>,
    scope: LinkScope,
) -> Result<()> {
    // Composed Get/render sessions consume the same closed relation repeatedly.
    // Keep their one-time materialization instead of rebuilding a CTE per id.
    if scope != LinkScope::All {
        let predicate = if scope == LinkScope::PartOf {
            "l.relationship='part_of'"
        } else {
            "l.relationship='renders'"
        };
        sqlx::query(&format!("INSERT INTO temp._v2_link_rows SELECT l.id,l.source_id,l.target_id,l.relationship,l.note,strftime('%Y-%m-%dT%H:%M:%fZ',l.created_at),CAST(strftime('%s',l.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',l.created_at),4,3) AS INTEGER) FROM temp._v2_link_sources l JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE {predicate}")).execute(tx).await?;
        return Ok(());
    }
    let used = |column: &str| reads.contains(&("links".into(), column.into()));
    let native = |column: &str| {
        if used(column) {
            format!("l.{column}")
        } else {
            "NULL".into()
        }
    };
    let native_clock = if used("created_at") {
        "strftime('%Y-%m-%dT%H:%M:%fZ',l.created_at)"
    } else {
        "NULL"
    };
    let native_ms = if used("created_at_ms") {
        "CAST(strftime('%s',l.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',l.created_at),4,3) AS INTEGER)"
    } else {
        "NULL"
    };
    let predicate = match scope {
        LinkScope::PartOf => " WHERE l.relationship='part_of'",
        LinkScope::Renderers => " WHERE l.relationship='renders'",
        LinkScope::All => "",
    };
    // An unused birth clock must not retain joins to the canonical event log.
    let source_view = if used("created_at") || used("created_at_ms") {
        "temp._v2_link_sources"
    } else {
        "temp._v2_link_endpoints"
    };
    let ordinary=format!("SELECT {} id,{} source_id,{} target_id,{} relationship,{} note,{native_clock} created_at,{native_ms} created_at_ms FROM {source_view} l JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id{predicate}",native("id"),native("source_id"),native("target_id"),native("relationship"),native("note"));
    let provider = if scope == LinkScope::All {
        let readiness_started = Instant::now();
        kernel::provider_link_reads::require_ready_on(tx).await?;
        tracing::debug!(target: "native_ce::read_staging", phase = "provider_readiness", elapsed_us = readiness_started.elapsed().as_micros() as u64);
        let duplicates:bool=sqlx::query_scalar("SELECT EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)").fetch_one(&mut *tx).await?;
        let from = if duplicates {
            stage_projected_provider_rows(tx).await?;
            "temp._v2_link_rows l"
        } else {
            "main.kernel_provider_link_rows l JOIN temp._v2_visible_providers p ON p.id=l.aggregate_id"
        };
        let relationship = if used("relationship") {
            "'relates_to'"
        } else {
            "NULL"
        };
        format!("SELECT {} id,{} source_id,{} target_id,{relationship} relationship,{} note,{} created_at,{} created_at_ms FROM {from} JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id UNION ALL ",native("id"),native("source_id"),native("target_id"),native("note"),native("created_at"),native("created_at_ms"))
    } else {
        String::new()
    };
    if reads.iter().any(|(relation, _)| relation == "records") {
        // Joins reuse the same disclosed endpoints. Persist only consumed
        // columns and one driving index rather than rebuilding a CTE and its
        // automatic index inside caller execution. No caller expression can
        // run until this live-gated materialization has finished.
        let selected: Vec<_> = columns("links")
            .expect("links contract")
            .iter()
            .copied()
            .filter(|c| used(c))
            .collect();
        let selected_sql = if selected.is_empty() {
            "1 AS _row".into()
        } else {
            selected.join(",")
        };
        sqlx::query(&format!("CREATE TEMP TABLE _v2_selected_links AS SELECT {selected_sql} FROM ({provider}{ordinary})"))
            .persistent(false).execute(&mut *tx).await?;
        for index in ["source_id", "target_id"].into_iter().filter(|c| used(c)) {
            sqlx::query(&format!(
                "CREATE INDEX temp._v2_selected_link_{index} ON _v2_selected_links({index})"
            ))
            .persistent(false)
            .execute(&mut *tx)
            .await?;
        }
        let projection = columns("links")
            .expect("links contract")
            .iter()
            .map(|c| {
                if used(c) {
                    format!("l.{c}")
                } else {
                    format!("NULL AS {c}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!("DROP VIEW temp.links; CREATE TEMP VIEW links AS SELECT {projection} FROM temp._v2_selected_links l"))
            .persistent(false).execute(tx).await?;
    } else {
        sqlx::query(&format!("DROP VIEW temp.links; CREATE TEMP VIEW links AS WITH disclosed AS MATERIALIZED ({provider}{ordinary}) SELECT * FROM disclosed"))
            .persistent(false).execute(tx).await?;
    }
    Ok(())
}

// Interpretations are projected at commit/preparation time. Ranking retains
// the old BTreeMap semantics: native rows only fill an absent id; retained
// sources must agree with the first row, including the original timestamp.
// Both provider admission and the endpoint gate are evaluated live here.
async fn stage_projected_provider_rows(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    // Most workspaces have globally unique link ids. Prove that fact from the
    // interpreted identity index before choosing the direct path; duplicates
    // retain the complete native/retained conflict and first-row semantics.
    let duplicates: bool = sqlx::query_scalar("SELECT EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)").fetch_one(&mut *tx).await?;
    if !duplicates {
        sqlx::query("INSERT INTO temp._v2_link_rows SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,r.created_at,r.created_at_ms FROM main.kernel_provider_link_rows r JOIN temp._v2_visible_providers p ON p.id=r.aggregate_id JOIN temp._v2_visible s ON s.id=r.source_id JOIN temp._v2_visible t ON t.id=r.target_id").execute(tx).await?;
        return Ok(());
    }
    let cte = "WITH admitted AS MATERIALIZED (SELECT r.* FROM main.kernel_provider_link_rows r JOIN temp._v2_visible_providers p ON p.id=r.aggregate_id), ranked AS (SELECT *,first_value(raw_json) OVER (PARTITION BY id ORDER BY aggregate_id,ordinal) first_json,row_number() OVER (PARTITION BY id ORDER BY aggregate_id,ordinal) position FROM admitted)";
    let conflict: bool = sqlx::query_scalar(&format!(
        "{cte} SELECT EXISTS(SELECT 1 FROM ranked WHERE if_absent=0 AND raw_json<>first_json)"
    ))
    .fetch_one(&mut *tx)
    .await?;
    if conflict {
        return Err(Error::engine(
            "provider source identity has conflicting link metadata",
        ));
    }
    sqlx::query(&format!("{cte} INSERT INTO temp._v2_link_rows SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,r.created_at,r.created_at_ms FROM ranked r JOIN temp._v2_visible s ON s.id=r.source_id JOIN temp._v2_visible t ON t.id=r.target_id WHERE r.position=1"))
        .execute(tx).await?;
    Ok(())
}

// Batch trusted projection rows, retaining both endpoint checks. A workspace
// with thousands of provider links must not pay one async SQL round trip per
// pair before its actual query can start. No source state enters the public tier.
/// Imported assertions retain each original directional link, including its
/// identity, note and birth time. Native assertions without legacy sources
/// expose the symmetric pair at the host-attested assertion time.
#[cfg(test)]
async fn stage_provider_rows(
    tx: &mut sqlx::SqliteConnection,
    states: &[crate::v2_standard::relates_to::State],
) -> Result<()> {
    let mut rows = BTreeMap::new();
    for state in states {
        for assertion in state.assertions.iter().filter(|a| !a.retracted) {
            if assertion.sources.is_empty() {
                for (from, to) in [(&state.left, &state.right), (&state.right, &state.left)] {
                    let id = format!("v2:relates_to:{from}:{to}");
                    rows.entry(id.clone()).or_insert_with(|| {
                        json!([id, from, to, Value::Null, assertion.asserted_at])
                    });
                }
            } else {
                for source in &assertion.sources {
                    let row = json!([
                        source.source_id,
                        source.from,
                        source.to,
                        source.note,
                        source
                            .claimed_timestamp
                            .as_deref()
                            .unwrap_or(&assertion.asserted_at)
                    ]);
                    if rows
                        .insert(source.source_id.clone(), row.clone())
                        .is_some_and(|previous| previous != row)
                    {
                        return Err(Error::engine(
                            "provider source identity has conflicting link metadata",
                        ));
                    }
                }
            }
        }
    }
    let rows: Vec<Value> = rows.into_values().collect();
    for chunk in rows.chunks(500) {
        sqlx::query(r#"WITH rows AS (
 SELECT json_extract(value,'$[0]') id,json_extract(value,'$[1]') source_id,
 json_extract(value,'$[2]') target_id,json_extract(value,'$[3]') note,
 json_extract(value,'$[4]') created_at FROM json_each(?1)
)
INSERT INTO temp._v2_link_rows
 SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,
 strftime('%Y-%m-%dT%H:%M:%fZ',r.created_at),
 CAST(strftime('%s',r.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',r.created_at),4,3) AS INTEGER)
 FROM rows r JOIN temp._v2_visible s ON s.id=r.source_id
 JOIN temp._v2_visible t ON t.id=r.target_id"#)
            .bind(serde_json::to_string(chunk)?).execute(&mut *tx).await?;
    }
    Ok(())
}

#[cfg(test)]
async fn stage_provider_pairs(
    tx: &mut sqlx::SqliteConnection,
    pairs: &[(String, String)],
) -> Result<()> {
    for chunk in pairs.chunks(500) {
        sqlx::query(
            r#"WITH pairs AS (
 SELECT json_extract(p.value,'$[0]') AS source_id,json_extract(p.value,'$[1]') AS target_id
 FROM json_each(?1) p
), admitted AS (
 SELECT p.source_id,p.target_id FROM pairs p
 JOIN temp._v2_visible s ON s.id=p.source_id JOIN temp._v2_visible t ON t.id=p.target_id
)
INSERT INTO temp._v2_provider_links SELECT source_id,target_id FROM admitted
UNION ALL SELECT target_id,source_id FROM admitted"#,
        )
        .bind(serde_json::to_string(chunk)?)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

async fn install_messaging(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    private: bool,
    awaiting: bool,
    reactions: bool,
    mentions: bool,
) -> Result<()> {
    let rows:Vec<(String,String)>=sqlx::query_as("SELECT m.message_id,m.state FROM kernel_messages m JOIN temp._v2_visible v ON v.id=m.message_id ORDER BY m.message_id LIMIT 10001").fetch_all(&mut *conn).await?;
    if rows.len() > 10_000 {
        return Err(Error::engine(
            "messaging SQL exceeds the bounded 10000 Message selection",
        ));
    }
    let person: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *conn)
            .await?;
    for (id, raw) in rows {
        let state: kernel::MessageState = serde_json::from_str(&raw)?;
        if reactions {
            let mut withheld = std::collections::BTreeMap::<String, usize>::new();
            for (principal, emojis) in &state.reactions {
                let face: Option<(String, Option<String>)> = sqlx::query_as("SELECT p.person_id,json_extract(n.value_json,'$') FROM main.kernel_message_people p JOIN temp._v2_visible v ON v.id=p.person_id LEFT JOIN main.kernel_record_fields n ON n.record_id=p.person_id AND n.name='title' WHERE p.principal_id=?")
                    .bind(principal).fetch_optional(&mut *conn).await?;
                for emoji in emojis {
                    // A public digest must never encode a withheld principal:
                    // known account IDs would make that digest an identity oracle.
                    let hidden_slot = if face.is_none() && principal != actor {
                        let n = withheld.entry(emoji.clone()).or_default();
                        *n += 1;
                        Some(*n)
                    } else {
                        None
                    };
                    let key = crate::canonical_json::digest_json(&json!([
                        id,
                        emoji,
                        face.as_ref().map(|f| &f.0),
                        principal == actor,
                        hidden_slot
                    ]));
                    sqlx::query(
                        "INSERT INTO temp.message_reactions VALUES(?,?,?,?,?,NULL,NULL,NULL,?)",
                    )
                    .bind(key)
                    .bind(&id)
                    .bind(emoji)
                    .bind(face.as_ref().map(|f| f.0.as_str()))
                    .bind(face.as_ref().and_then(|f| f.1.as_deref()))
                    .bind(principal == actor)
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
        if private || mentions {
            let value = super::messaging::private_fields(actor, person.as_deref(), &state);
            if mentions && value["mention"]["principal"] == true {
                let at: Option<String> =
                    sqlx::query_scalar("SELECT created_at FROM temp.records WHERE id=?")
                        .bind(&id)
                        .fetch_one(&mut *conn)
                        .await?;
                let ms = at
                    .as_deref()
                    .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.timestamp_millis());
                let seen = matches!(
                    value["human"]["stage"].as_str(),
                    Some("opened" | "acknowledged")
                );
                sqlx::query("INSERT INTO temp.my_mentions VALUES(?,'message','principal',?,?,?,?)")
                    .bind(&id)
                    .bind(state.author.as_deref() == Some(actor) && state.speaker.is_none())
                    .bind(at)
                    .bind(ms)
                    .bind(seen)
                    .execute(&mut *conn)
                    .await?;
            }
            if private {
                let pref = state
                    .private
                    .get(actor)
                    .and_then(|p| p.get("preference"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let bool_value = |key: &str| {
                    pref[key]
                        .as_bool()
                        .unwrap_or_else(|| pref[key].as_i64() == Some(1))
                };
                let snoozed = pref["snoozed_until"].as_str();
                let snoozed_ms = snoozed
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.timestamp_millis());
                sqlx::query("INSERT INTO temp.my_message_state VALUES(?,?,?,?,?,?,?,?,?,?,?)")
                    .bind(&id)
                    .bind(value["human"]["stage"].as_str())
                    .bind(value["attention"]["unread"].as_bool().unwrap_or(false))
                    .bind(state.author.as_deref() == Some(actor) && state.speaker.is_none())
                    .bind(value["mention"]["principal"].as_bool().unwrap_or(false))
                    .bind(bool_value("attention_flag"))
                    .bind(bool_value("muted"))
                    .bind(bool_value("archived"))
                    .bind(snoozed)
                    .bind(snoozed_ms)
                    .bind(true)
                    .execute(&mut *conn)
                    .await?;
            }
        }
        if awaiting
            && state.expectation.as_deref() == Some("reply")
            && person
                .as_ref()
                .is_some_and(|p| state.addressed_to.contains(p))
        {
            let expectation = super::messaging::expectation_value(conn, actor, &id, &state).await?;
            if expectation["state"] == "open" {
                sqlx::query("INSERT INTO temp.messages_awaiting_reply VALUES(?)")
                    .bind(&id)
                    .execute(&mut *conn)
                    .await?;
            }
        }
    }
    if mentions {
        install_reference_mentions(conn, actor, person.as_deref()).await?;
    }
    Ok(())
}

async fn install_runs(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    intents: bool,
) -> Result<()> {
    // The kernel directory replaces v1's disclosable Person/account binding:
    // ordinary principals see their own runs, directory viewers may see all.
    let admission = if root_visible {
        "1"
    } else {
        "r.owner_principal=?"
    };
    let sql=format!("INSERT INTO temp._v2_runs SELECT r.id,CASE WHEN p.auth_binding LIKE 'mcp-run:%' THEN substr(p.auth_binding,9) ELSE r.id END,r.owner_principal FROM main.kernel_runs r JOIN main.kernel_principals p ON p.principal_id=r.run_principal WHERE {admission}");
    let mut query = sqlx::query(&sql);
    if !root_visible {
        query = query.bind(actor);
    }
    query.execute(&mut *tx).await?;
    sqlx::query("INSERT INTO temp.runs SELECT v.run_key,NULL,CAST(strftime('%s',e.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',e.created_at),4,3) AS INTEGER),(SELECT CAST(strftime('%s',c.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',c.created_at),4,3) AS INTEGER) FROM main.content_events c WHERE c.record_id=r.id AND c.type='kernel.run_closed.v1' ORDER BY seq DESC LIMIT 1),NULL,NULL,'self_declared' FROM temp._v2_runs v JOIN main.kernel_runs r ON r.id=v.id JOIN main.content_events e ON e.seq=r.opened_seq").execute(&mut *tx).await?;
    if intents {
        let sql=format!("INSERT INTO temp.run_intents SELECT v.run_key,row_number() OVER(PARTITION BY v.id ORDER BY e.seq),CASE WHEN octet_length(json_extract(e.payload,'$.intent'))>{} THEN NULL ELSE json_extract(e.payload,'$.intent') END,CAST(strftime('%s',e.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',e.created_at),4,3) AS INTEGER) FROM temp._v2_runs v CROSS JOIN main.content_events e INDEXED BY idx_content_events_record WHERE e.record_id=v.id AND e.type='kernel.run_intent_set.v1' AND e.actor=v.owner",guard::MAX_RUN_INTENT_BYTES);
        sqlx::query(&sql).execute(&mut *tx).await?;
    }
    Ok(())
}

async fn install_imported_catalogue(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    let needs = |name: &str| reads.iter().any(|(r, _)| r == name);
    if needs("vocabularies") {
        sqlx::query("INSERT INTO temp.vocabularies SELECT json_extract(payload,'$.id'),json_extract(payload,'$.name'),strftime('%Y-%m-%dT%H:%M:%fZ',json_extract(payload,'$.created_at')),(CAST(strftime('%s',json_extract(payload,'$.created_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(payload,'$.created_at')),4,3) AS INTEGER)) FROM main.kernel_v1_state WHERE section='vocabularies'").execute(&mut *tx).await?;
    }
    if needs("vocabulary_values") {
        sqlx::query("INSERT INTO temp.vocabulary_values SELECT json_extract(payload,'$.id'),json_extract(payload,'$.vocabulary_id'),json_extract(payload,'$.value'),json_extract(payload,'$.gloss'),json_extract(payload,'$.status'),CASE WHEN json_type(payload,'$.ordinal') IN ('integer','real') THEN json_extract(payload,'$.ordinal') END,json_extract(payload,'$.terminality'),json_extract(payload,'$.metadata'),json_extract(payload,'$.alias_of') FROM main.kernel_v1_state WHERE section='vocabulary_values'").execute(&mut *tx).await?;
    }
    if needs("record_lifecycle_interpretations") {
        lifecycle::install(tx, actor).await?;
    }
    Ok(())
}
async fn install_imported_runs(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    _root_visible: bool,
    intents: bool,
    claims: bool,
) -> Result<()> {
    sqlx::query("INSERT INTO temp._v2_imported_accounts VALUES(?)")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    for account in kernel::v1_state::disclosed_accounts_on(tx, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_imported_accounts VALUES(?)")
            .bind(account)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO temp.runs SELECT json_extract(s.payload,'$.run_key'),(SELECT d.record_id FROM main.kernel_v1_state d WHERE d.section='account_directory' AND d.account_principal=s.account_principal LIMIT 1),(CAST(strftime('%s',json_extract(s.payload,'$.started_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(s.payload,'$.started_at')),4,3) AS INTEGER)),(CAST(strftime('%s',coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at)) AS INTEGER)*1000+CAST(substr(strftime('%f',coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at)),4,3) AS INTEGER)),json_extract(s.payload,'$.reported_model'),CASE WHEN json_extract(s.payload,'$.reported_mcp_client_name') IS NULL THEN NULL WHEN json_extract(s.payload,'$.reported_mcp_client_version') IS NULL THEN json_extract(s.payload,'$.reported_mcp_client_name') ELSE json_extract(s.payload,'$.reported_mcp_client_name')||'/'||json_extract(s.payload,'$.reported_mcp_client_version') END,'imported_historical' FROM main.kernel_v1_state s WHERE s.section='runs' AND s.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts) AND NOT EXISTS(SELECT 1 FROM temp.runs r WHERE r.run_key=json_extract(s.payload,'$.run_key'))")
        .execute(&mut *tx).await?;
    if intents {
        let sql=format!("WITH numbered AS (SELECT i.source_id,json_extract(i.payload,'$.run_key') AS run_key,row_number() OVER(PARTITION BY json_extract(i.payload,'$.run_key') ORDER BY json_extract(i.payload,'$.source_seq'),i.source_id) AS ordinal FROM main.kernel_v1_state i WHERE i.section='run_intents' AND i.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts) AND EXISTS(SELECT 1 FROM temp.runs r WHERE r.run_key=json_extract(i.payload,'$.run_key'))) INSERT INTO temp.run_intents SELECT n.run_key,n.ordinal,CASE WHEN octet_length(json_extract(i.payload,'$.intent'))>{} THEN NULL ELSE json_extract(i.payload,'$.intent') END,(CAST(strftime('%s',json_extract(i.payload,'$.declared_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(i.payload,'$.declared_at')),4,3) AS INTEGER)) FROM numbered n JOIN main.kernel_v1_state i ON i.section='run_intents' AND i.source_id=n.source_id",guard::MAX_RUN_INTENT_BYTES);

        sqlx::query(&sql).execute(&mut *tx).await?;
    }
    if claims {
        sqlx::query("INSERT INTO temp.agent_activity_claims SELECT json_extract(c.payload,'$.id'),json_extract(r.payload,'$.activity_id'),c.record_id,json_extract(c.payload,'$.claimed_at'),(CAST(strftime('%s',json_extract(c.payload,'$.claimed_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(c.payload,'$.claimed_at')),4,3) AS INTEGER)),coalesce(json_extract(c.payload,'$.released_at'),c.observed_at),(CAST(strftime('%s',coalesce(json_extract(c.payload,'$.released_at'),c.observed_at)) AS INTEGER)*1000+CAST(substr(strftime('%f',coalesce(json_extract(c.payload,'$.released_at'),c.observed_at)),4,3) AS INTEGER)),0 FROM main.kernel_v1_state c LEFT JOIN main.kernel_v1_state r ON r.section='runs' AND json_extract(r.payload,'$.run_key')=json_extract(c.payload,'$.run_key') AND +r.account_principal=c.account_principal JOIN temp._v2_visible v ON v.id=c.record_id WHERE c.section='claims' AND c.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts)")
            .execute(&mut *tx).await?;
    }
    Ok(())
}

/// Rebuild this caller's reference rows from current visible bodies. First
/// narrow by the caller's six-hex prefix in SQLite; never scan hidden bodies
/// or use hidden look-alikes to resolve a reference.
async fn install_reference_mentions(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    person: Option<&str>,
) -> Result<()> {
    let Some(person) =
        person.filter(|id| uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == *id))
    else {
        return Ok(());
    };
    let visible: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?)")
            .bind(person)
            .fetch_one(&mut *conn)
            .await?;
    if !visible {
        return Ok(());
    }
    let canonical = person.to_ascii_lowercase();
    let hex = canonical.replace('-', "");
    let rivals: Vec<String> =
        sqlx::query_scalar("SELECT id FROM temp._v2_visible WHERE id>=? AND id<? AND id!=?")
            .bind(&hex[..6])
            .bind(format!("{}g", &hex[..6]))
            .bind(person)
            .fetch_all(&mut *conn)
            .await?;
    let rivals: Vec<String> = rivals
        .into_iter()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .map(|id| id.replace('-', "").to_ascii_lowercase())
        .collect();
    type MentionSource = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<MentionSource> = sqlx::query_as("SELECT r.id,r.body,r.type,k.owner_id,coalesce(e.created_at,r.created_at) FROM temp.records r JOIN main.kernel_records k ON k.id=r.id LEFT JOIN main.kernel_record_bodies b ON b.record_id=r.id LEFT JOIN main.content_events e ON e.seq=b.event_seq WHERE instr(lower(r.body),?)>0 ORDER BY r.id LIMIT 10001")
        .bind(&hex[..6]).fetch_all(&mut *conn).await?;
    if rows.len() > 10000 || rows.iter().map(|r| r.1.len()).sum::<usize>() > 128 * 1024 * 1024 {
        return Err(Error::engine(
            "mention SQL exceeds bounded visible body selection",
        ));
    }
    for (id, body, kind, owner, at) in rows {
        let matched = crate::mentions::scan_body(&body).iter().any(|mention| {
            let key = &mention.lookup_key;
            if key == &canonical {
                return true;
            }
            let prefix = key.replace('-', "");
            (6..32).contains(&prefix.len())
                && (key == &prefix || canonical.starts_with(key))
                && prefix.bytes().all(|b| b.is_ascii_hexdigit())
                && hex.starts_with(&prefix)
                && !rivals.iter().any(|r| r.starts_with(&prefix))
        });
        if !matched {
            continue;
        }
        let ms = at
            .as_deref()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|v| v.timestamp_millis());
        let own: bool = if kind.as_deref() == Some("Message") {
            sqlx::query_scalar("SELECT coalesce(json_extract(state,'$.author')=? AND json_extract(state,'$.speaker') IS NULL,0) FROM main.kernel_messages WHERE message_id=?").bind(actor).bind(&id).fetch_optional(&mut *conn).await?.unwrap_or(false)
        } else {
            owner.as_deref() == Some(actor)
        };
        sqlx::query("INSERT INTO temp.my_mentions VALUES(?,?,'reference',?,?,?,NULL)")
            .bind(id)
            .bind(if kind.as_deref() == Some("Message") {
                "message"
            } else {
                "record"
            })
            .bind(own)
            .bind(at)
            .bind(ms)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod prefix_tests {
    use super::id_ordered_record_limit;
    #[test]
    fn metadata_pulse_refuses_to_narrow_other_sql_or_parameter_types() {
        use crate::query::sql_contract::QuerySqlParameter;
        let parameters = [QuerySqlParameter::Text {
            value: Some("id".into()),
        }];
        assert_eq!(
            super::metadata_pulse_ids(
                "SELECT id, updated_at FROM records WHERE id IN (?1)",
                &parameters
            ),
            Some(vec!["id".into()])
        );
        for sql in [
            "ſELECT id, updated_at FROM records WHERE id IN (?1)",
            "SELECT\u{a0}id, updated_at FROM records WHERE id IN (?1)",
            "SELECT id, type, Kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE deleted_at IS NULL AND id IN (?1)",
            "SELECT id, updated_at FROM records WHERE id IN (?1) OR 1",
            "SELECT id, updated_at FROM records WHERE id IN (?1) UNION SELECT id, updated_at FROM records",
            "SELECT id, updated_at FROM records WHERE id IN (SELECT id FROM records)",
            "SELECT id, updated_at FROM records WHERE id IN (?1 COLLATE NOCASE)",
            "SELECT id, updated_at FROM records WHERE id IN (?2)",
            "SELECT id, updated_at FROM records WHERE id IN (?0)",
            "SELECT id, updated_at FROM records WHERE id IN ('id')",
        ] { assert_eq!(super::metadata_pulse_ids(sql, &parameters), None, "{sql}"); }
        assert_eq!(
            super::metadata_pulse_ids(
                "SELECT id, updated_at FROM records WHERE id IN (?1)",
                &[QuerySqlParameter::Integer {
                    value: Some("1".into())
                }]
            ),
            None
        );
    }
    #[test]
    fn only_closed_id_ordered_prefixes_narrow_staging() {
        for (sql, limit) in [
            ("SELECT id,name FROM records ORDER BY id LIMIT 20", 20),
            ("select name from records order by id asc limit 1;", 1),
        ] {
            assert_eq!(id_ordered_record_limit(sql), Some(limit));
        }
        for sql in [
            "SELECT name AS id FROM records ORDER BY id LIMIT 20",
            "SELECT id,name FROM records WHERE id>'a' ORDER BY id LIMIT 20",
            "SELECT id,name FROM records ORDER BY name LIMIT 20",
            "SELECT id,name FROM records ORDER BY id COLLATE NOCASE LIMIT 20",
            "SELECT id,name FROM records ORDER BY id LIMIT 20 OFFSET 1",
            "SELECT id,name FROM records ORDER BY id LIMIT 1001",
            "SELECT id,name FROM records ORDER BY id LIMIT ?1",
            "SELECT id,name FROM records ORDER BY id LIMIT 20 UNION SELECT id,name FROM records",
            "SELECT (SELECT name FROM records LIMIT 1) AS id FROM records ORDER BY id LIMIT 20",
        ] {
            assert_eq!(id_ordered_record_limit(sql), None, "{sql}");
        }
    }
}

#[cfg(test)]
mod html_input_tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn provider_link_batches_keep_both_endpoint_visibility_and_revocation() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_provider_links(source_id TEXT,target_id TEXT)")
            .execute(&mut db).await.unwrap();
        sqlx::query("INSERT INTO _v2_visible VALUES('source')")
            .execute(&mut db)
            .await
            .unwrap();
        let mut pairs = Vec::new();
        for i in 0..501 {
            let target = format!("target-{i}");
            sqlx::query("INSERT INTO _v2_visible VALUES(?)")
                .bind(&target)
                .execute(&mut db)
                .await
                .unwrap();
            pairs.push(("source".into(), target));
        }
        sqlx::query("CREATE TABLE kernel_provider_subjects(subject_id TEXT,aggregate_id TEXT,PRIMARY KEY(subject_id,aggregate_id)); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); INSERT INTO kernel_provider_subjects VALUES('source','shared'),('target-0','shared'),('source','private'),('hidden','private')")
            .execute(&mut db).await.unwrap();
        stage_visible_providers(&mut db).await.unwrap();
        let admitted: Vec<String> =
            sqlx::query_scalar("SELECT id FROM _v2_visible_providers ORDER BY id")
                .fetch_all(&mut db)
                .await
                .unwrap();
        assert_eq!(admitted, vec!["shared"]);
        pairs.extend([
            ("source".into(), "hidden".into()),
            ("hidden".into(), "target-0".into()),
            ("hidden".into(), "also-hidden".into()),
        ]);
        stage_provider_pairs(&mut db, &pairs).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 1002);
        let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links WHERE source_id='hidden' OR target_id='hidden' OR target_id='also-hidden'")
            .fetch_one(&mut db).await.unwrap();
        assert_eq!(hidden, 0);
        sqlx::query("DELETE FROM _v2_visible WHERE id='source'; DELETE FROM _v2_provider_links")
            .execute(&mut db)
            .await
            .unwrap();
        stage_provider_pairs(&mut db, &pairs).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 0, "next snapshot must respect the lost endpoint");
        sqlx::query("DELETE FROM _v2_visible_providers")
            .execute(&mut db)
            .await
            .unwrap();
        stage_visible_providers(&mut db).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_visible_providers")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[tokio::test]
    async fn provider_link_projection_matches_each_retained_interpreter_prefix() {
        use crate::kernel::provider_catalogue::{self as catalogue, FoldInput, StoredState};
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE kernel_provider_state(id TEXT PRIMARY KEY,provider_key TEXT,head INTEGER); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,created_at TEXT); CREATE TABLE kernel_record_fields(record_id TEXT,name TEXT,value_json TEXT)").execute(&mut db).await.unwrap();
        kernel::provider_link_reads::ensure_schema_on(&mut db)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)").execute(&mut db).await.unwrap();
        for bytes in [
            include_str!("../../kernel/fixtures/relates_to_v1.golden.json"),
            include_str!("../../kernel/fixtures/relates_to_v2.golden.json"),
            include_str!("../../kernel/fixtures/relates_to_v3.golden.json"),
        ] {
            let vector: Value = serde_json::from_str(bytes).unwrap();
            let mut current: Option<StoredState> = None;
            for event in vector["events"].as_array().unwrap() {
                let entry = catalogue::recorded(&event["payload"]).unwrap();
                let decoded = (entry.decode)(&event["payload"]).unwrap();
                let input = FoldInput {
                    decoded: &decoded,
                    principal: event["actor"].as_str().unwrap(),
                    timestamp: event["created_at"].as_str().unwrap(),
                    event_seq: event["seq"].as_i64().unwrap(),
                };
                let folded = (entry.fold)(&input, current.as_ref()).unwrap();
                let stored = StoredState {
                    pins: (entry.pins)(),
                    state: folded.state,
                    attribution: folded.attribution,
                };
                let state: crate::v2_standard::relates_to::State =
                    serde_json::from_value(stored.view().unwrap()).unwrap();
                sqlx::query("DELETE FROM kernel_provider_link_rows; DELETE FROM kernel_provider_link_heads; DELETE FROM _v2_visible; DELETE FROM _v2_visible_providers; DELETE FROM _v2_link_rows").execute(&mut db).await.unwrap();
                sqlx::query("INSERT INTO _v2_visible VALUES(?),(?)")
                    .bind(&state.left)
                    .bind(&state.right)
                    .execute(&mut db)
                    .await
                    .unwrap();
                sqlx::query("INSERT INTO _v2_visible_providers VALUES(?)")
                    .bind(&decoded.facts.aggregate_id)
                    .execute(&mut db)
                    .await
                    .unwrap();
                kernel::provider_link_reads::store_on(
                    &mut db,
                    &decoded.facts.aggregate_id,
                    input.event_seq,
                    &stored.pins,
                    entry.link_read.unwrap()(stored.view().unwrap()).unwrap(),
                )
                .await
                .unwrap();
                stage_provider_rows(&mut db, std::slice::from_ref(&state))
                    .await
                    .unwrap();
                let select = "SELECT json_array(id,source_id,target_id,relationship,note,created_at,created_at_ms) FROM _v2_link_rows ORDER BY id";
                let expected: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                sqlx::query("DELETE FROM _v2_link_rows")
                    .execute(&mut db)
                    .await
                    .unwrap();
                stage_projected_provider_rows(&mut db).await.unwrap();
                let projected: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                assert_eq!(
                    projected, expected,
                    "retained codec prefix {}",
                    input.event_seq
                );
                // Two admitted aggregates can carry the same source/native id.
                // Aggregate order, not insertion order, determines the first row.
                let mut first = state.clone();
                let mut native = first.assertions[0].clone();
                native.sources.clear();
                native.retracted = false;
                first.assertions.push(native);
                kernel::provider_link_reads::store_on(
                    &mut db,
                    &decoded.facts.aggregate_id,
                    input.event_seq,
                    &stored.pins,
                    entry.link_read.unwrap()(serde_json::to_value(&first).unwrap()).unwrap(),
                )
                .await
                .unwrap();
                let later_id = format!("~{}", decoded.facts.aggregate_id);
                sqlx::query("INSERT INTO _v2_visible_providers VALUES(?)")
                    .bind(&later_id)
                    .execute(&mut db)
                    .await
                    .unwrap();
                for variant in 0..3 {
                    let mut later = first.clone();
                    for assertion in &mut later.assertions {
                        if variant == 1 && assertion.sources.is_empty() {
                            assertion.asserted_at = "2030-01-01T00:00:00Z".into();
                        }
                        if variant == 2 {
                            for source in &mut assertion.sources {
                                source.note = Some("conflicting second aggregate".into());
                            }
                        }
                    }
                    kernel::provider_link_reads::store_on(
                        &mut db,
                        &later_id,
                        input.event_seq,
                        &stored.pins,
                        entry.link_read.unwrap()(serde_json::to_value(&later).unwrap()).unwrap(),
                    )
                    .await
                    .unwrap();
                    sqlx::query("DELETE FROM _v2_link_rows")
                        .execute(&mut db)
                        .await
                        .unwrap();
                    let oracle = stage_provider_rows(&mut db, &[first.clone(), later]).await;
                    assert_eq!(
                        oracle.is_err(),
                        variant == 2,
                        "retained conflict versus native first-row ranking"
                    );
                    let expected: Vec<String> =
                        sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                    sqlx::query("DELETE FROM _v2_link_rows")
                        .execute(&mut db)
                        .await
                        .unwrap();
                    let projected = stage_projected_provider_rows(&mut db).await;
                    assert_eq!(
                        projected.is_ok(),
                        oracle.is_ok(),
                        "two aggregates, prefix {}, variant {variant}",
                        input.event_seq
                    );
                    match (oracle, projected) {
                        (Ok(()), Ok(())) => {
                            let actual: Vec<String> =
                                sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                            assert_eq!(actual, expected, "first aggregate wins, variant {variant}");
                        }
                        (Err(old), Err(new)) => assert_eq!(old.to_string(), new.to_string()),
                        _ => unreachable!(),
                    }
                }
                sqlx::query("DELETE FROM _v2_link_rows; DELETE FROM _v2_visible")
                    .execute(&mut db)
                    .await
                    .unwrap();
                // Provider admission would drop the aggregate after revocation.
                sqlx::query("DELETE FROM _v2_visible_providers")
                    .execute(&mut db)
                    .await
                    .unwrap();
                stage_projected_provider_rows(&mut db).await.unwrap();
                let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_link_rows")
                    .fetch_one(&mut db)
                    .await
                    .unwrap();
                assert_eq!(hidden, 0);
                current = Some(stored);
            }
        }
    }

    #[tokio::test]
    async fn provider_link_projection_preserves_source_shapes_and_conflict_refusals() {
        use crate::v2_standard::relates_to::{Assertion, Source, State};
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE kernel_provider_state(id TEXT PRIMARY KEY,provider_key TEXT,head INTEGER); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,created_at TEXT); CREATE TABLE kernel_record_fields(record_id TEXT,name TEXT,value_json TEXT)").execute(&mut db).await.unwrap();
        kernel::provider_link_reads::ensure_schema_on(&mut db)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); INSERT INTO _v2_visible VALUES('a'),('b'); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); INSERT INTO _v2_visible_providers VALUES('pair'); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)").execute(&mut db).await.unwrap();
        let native = Assertion {
            id: "native".into(),
            sources: vec![],
            retracted: false,
            asserted_by: Some("member".into()),
            asserted_at: "2026-01-01T00:00:00Z".into(),
            asserted_seq: 1,
            retracted_by: None,
            retracted_at: None,
            retracted_seq: None,
        };
        let source = Source {
            source_id: "retained".into(),
            from: "b".into(),
            to: "a".into(),
            claimed_author: Some("source-author".into()),
            claimed_timestamp: None,
            note: Some("source note".into()),
        };
        let retained = Assertion {
            id: "retained-assertion".into(),
            sources: vec![source.clone()],
            ..native.clone()
        };
        let mut reverse = source.clone();
        reverse.source_id = "reverse".into();
        reverse.from = "a".into();
        reverse.to = "b".into();
        reverse.claimed_timestamp = Some("2025-12-31T23:00:00+01:00".into());
        let mut invalid_time = source.clone();
        invalid_time.source_id = "invalid-time".into();
        invalid_time.claimed_timestamp = Some("unknown".into());
        let mut conflict_source = source.clone();
        conflict_source.note = Some("different".into());
        let cases = vec![
            vec![],
            vec![native.clone()],
            vec![retained.clone()],
            vec![
                retained.clone(),
                Assertion {
                    id: "other".into(),
                    sources: vec![reverse, invalid_time, source.clone()],
                    ..native.clone()
                },
            ],
            vec![
                native.clone(),
                Assertion {
                    id: "native-later".into(),
                    asserted_at: "2026-02-01T00:00:00Z".into(),
                    ..native.clone()
                },
            ],
            vec![
                retained.clone(),
                Assertion {
                    retracted: true,
                    ..native.clone()
                },
            ],
            vec![Assertion {
                retracted: true,
                ..retained.clone()
            }],
            vec![
                retained.clone(),
                Assertion {
                    sources: vec![conflict_source],
                    ..retained
                },
            ],
        ];
        let entry = &crate::v2_standard::relates_to_retained::V3;
        for assertions in cases {
            let state = State {
                left: "a".into(),
                right: "b".into(),
                assertions,
            };
            sqlx::query("DELETE FROM _v2_link_rows")
                .execute(&mut db)
                .await
                .unwrap();
            let old = stage_provider_rows(&mut db, std::slice::from_ref(&state)).await;
            let select="SELECT json_array(id,source_id,target_id,relationship,note,created_at,created_at_ms) FROM _v2_link_rows ORDER BY id";
            let expected: Vec<String> =
                sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
            sqlx::query("DELETE FROM _v2_link_rows")
                .execute(&mut db)
                .await
                .unwrap();
            kernel::provider_link_reads::store_on(
                &mut db,
                "pair",
                1,
                &(entry.pins)(),
                entry.link_read.unwrap()(serde_json::to_value(&state).unwrap()).unwrap(),
            )
            .await
            .unwrap();
            let projected = stage_projected_provider_rows(&mut db).await;
            assert_eq!(old.is_err(), projected.is_err());
            if let (Err(old), Err(projected)) = (old, projected) {
                assert_eq!(old.to_string(), projected.to_string());
            } else {
                let actual: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[tokio::test]
    async fn provider_sql_retains_imported_link_identity_note_and_birth_time() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); INSERT INTO _v2_visible VALUES('a'),('b'); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)")
            .execute(&mut db).await.unwrap();
        let state: crate::v2_standard::relates_to::State =
            serde_json::from_value(json!({"left":"a","right":"b","assertions":[{
                "id":"assertion","sources":[
                    {"source_id":"original","from":"a","to":"b","claimed_author":null,
                     "claimed_timestamp":"2026-01-01T00:00:00Z","note":"retained note"}
                ],"retracted":false,"asserted_by":"importer","asserted_at":"2026-02-01T00:00:00Z",
                "asserted_seq":1,"retracted_by":null,"retracted_at":null,"retracted_seq":null
            }]}))
            .unwrap();
        let mut hidden = state.clone();
        hidden.right = "hidden".into();
        hidden.assertions[0].sources[0].source_id = "hidden-link".into();
        hidden.assertions[0].sources[0].to = "hidden".into();
        stage_provider_rows(&mut db, &[state, hidden])
            .await
            .unwrap();
        let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
            "SELECT id,source_id,target_id,note,created_at,created_at_ms FROM _v2_link_rows",
        )
        .fetch_all(&mut db)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![(
                "original".into(),
                "a".into(),
                "b".into(),
                "retained note".into(),
                "2026-01-01T00:00:00.000Z".into(),
                1767225600000
            )]
        );
    }

    #[test]
    fn provider_batch_decodes_each_row_and_keeps_exact_retained_pins() {
        use crate::kernel::provider_catalogue::StoredState;
        let old = StoredState {
            pins: crate::v2_standard::relates_to_v1::pins(),
            state: json!({"left":"a","right":"b","assertions":[]}),
            attribution: json!({}),
        };
        let active = StoredState {
            pins: crate::v2_standard::relates_to_v3::pins(),
            state: json!({"left":"a","right":"b","assertions":[{
                "id":"assertion","sources":[],"retracted":false,
                "asserted_by":"actor","asserted_at":"2026-01-01T00:00:00Z","asserted_seq":1,
                "retracted_by":null,"retracted_at":null,"retracted_seq":null
            }]}),
            attribution: Value::Null,
        };
        let states = vec![
            serde_json::to_string(&old).unwrap(),
            serde_json::to_string(&active).unwrap(),
        ];
        let expected: Vec<_> = states
            .iter()
            .filter_map(|state| kernel::relates_to_port::active_pair_from_state(state).unwrap())
            .collect();
        assert_eq!(
            kernel::relates_to_port::active_pairs_from_states(&states).unwrap(),
            expected
        );
        assert_eq!(expected, vec![("a".into(), "b".into())]);
        let mut bad_pin = active.clone();
        bad_pin.pins.relationship.digest = "unattested".into();
        assert!(kernel::relates_to_port::active_pairs_from_states(&[
            states[1].clone(),
            serde_json::to_string(&bad_pin).unwrap()
        ])
        .is_err());
        let mut bad_row = active;
        bad_row.state["assertions"] = json!("malformed");
        assert!(
            kernel::relates_to_port::active_pairs_from_states(&[
                states[1].clone(),
                serde_json::to_string(&bad_row).unwrap()
            ])
            .is_err(),
            "a cached interpreter must still decode every row"
        );
    }

    #[test]
    fn stored_sql_keeps_v1_rules_without_allowing_physical_reads() {
        let stored = "SELECT round(1.234,2) AS n FROM records LIMIT 1";
        assert!(guard::inspect_kernel_v2_stored_saved_sql(stored).is_ok());
        assert!(guard::validate_kernel_v2_ad_hoc(stored).is_err());
        for sql in [
            "SELECT * FROM main.records",
            "SELECT * FROM main.kernel_records",
            "SELECT * FROM policy_entries",
            "SELECT load_extension('untrusted')",
        ] {
            assert!(
                guard::inspect_kernel_v2_stored_saved_sql(sql).is_err(),
                "{sql}"
            );
        }
    }
}

#[cfg(test)]
mod effect_read_tests {
    use super::*;

    #[tokio::test]
    async fn declared_effect_read_restores_query_only_on_success_and_statement_error() {
        let dir = tempfile::tempdir().unwrap();
        let (db, actor) = kernel::create_v2_database(
            dir.path().join("query.db").to_str().unwrap(),
            "account",
            "Owner",
            "fixture-owner",
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("CREATE TEMP TABLE fence_probe(value INTEGER)")
            .execute(&mut *tx)
            .await
            .unwrap();
        for (sql, ok) in [
            ("SELECT id FROM records ORDER BY id", true),
            ("SELECT json_extract('not-json', '$') AS broken", false),
        ] {
            let result = query_sql_on(&mut tx, &actor, json!({"sql":sql}), 2).await;
            assert_eq!(result.is_ok(), ok, "{result:?}");
            let fenced: bool = sqlx::query_scalar("PRAGMA query_only")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert!(!fenced, "the enclosing effect must remain writable");
            sqlx::query("INSERT INTO fence_probe VALUES(1)")
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.rollback().await.unwrap();
        db.close().await;
    }
}

#[cfg(test)]
tokio::task_local! {
    static NAMED_READ_PAUSE: (std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>);
    static NAMED_REGISTER_PAUSE: (std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>);
}
#[cfg(test)]
pub(crate) async fn with_named_read_pause<T>(
    arrived: std::sync::Arc<tokio::sync::Barrier>,
    resume: std::sync::Arc<tokio::sync::Barrier>,
    work: impl std::future::Future<Output = T>,
) -> T {
    NAMED_READ_PAUSE.scope((arrived, resume), work).await
}

#[cfg(test)]
pub(crate) async fn with_named_registered_pause<T>(
    arrived: std::sync::Arc<tokio::sync::Barrier>,
    resume: std::sync::Arc<tokio::sync::Barrier>,
    work: impl std::future::Future<Output = T>,
) -> T {
    NAMED_REGISTER_PAUSE.scope((arrived, resume), work).await
}

/// Test-only connection adapter into the real caller-relative installer,
/// registry expansion/registration and result executor. It neither loads nor
/// enables a v2 revision. The fixture owns the snapshot and rolls it back.
#[cfg(test)]
pub(crate) async fn generated_checkpoint_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    name: &str,
    definition: &crate::named_views::contract::Definition,
    outer: &crate::named_views::contract::SavedSqlV12,
    deadline: Instant,
) -> Result<Value> {
    outer.validate_current()?;
    let started = deadline - Duration::from_millis(contract::QUERY_DEADLINE_MS);
    conn.lock_handle()
        .await?
        .set_progress_handler(guard::PROGRESS_OPS, move || Instant::now() < deadline);
    let roots = outer.roots();
    let pin = roots
        .get(name)
        .ok_or_else(|| Error::engine("checkpoint root missing"))?;
    let mut registry = named_views::Registry::generated_checkpoint(name, definition, pin)?;
    let (mut prepared, mut reads) = prepare_read_with_views(
        actor,
        json!({"sql":outer.sql,"parameters":outer.parameters}),
        true,
        Some(&registry),
    )?;
    registry.expand(&mut reads)?;
    prepared.persistent = false;
    install_relations(
        conn,
        actor,
        &reads,
        LinkScope::All,
        None,
        None,
        None,
        None,
        None,
        chrono::Utc::now().timestamp_millis(),
        false,
    )
    .await?;
    registry.register(conn).await?;
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
        .fetch_one(&mut *conn)
        .await?;
    execute_prepared(conn, prepared, head, started).await
}
