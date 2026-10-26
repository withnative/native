//! Caller-filtered, validated read-only SQL (tool 18, `query_sql`).
//!
//! User SQL never reaches a physical content or policy relation. Every call is
//! prepared twice against the public logical contract, then executed on one
//! explicitly acquired connection from the dedicated governed-SQL pool whose
//! portable principal exists only inside a rolled-back transaction. The TEMP
//! schema is connection-local; pool release removes both principal state and
//! the progress handler. The governed pool is never shared with ordinary
//! writes or with the physically read-only observation tier, so a burst of
//! governed reads can saturate only its own bounded slots — never the
//! writer's connections — and retained TEMP state there cannot shadow the
//! unqualified names `bootstrap` and `get_structure` rely on.

#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod named_views;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod view_validation;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use named_views::NamedViewValidators;

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures::TryStreamExt;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use sqlx::query::Query;
use sqlx::sqlite::SqliteArguments;
use sqlx::sqlite::SqliteRow;
use sqlx::{Acquire, Column, Row, Sqlite, TypeInfo, ValueRef};

use super::principal::QueryPrincipal;
use super::sql_contract::{
    self, QuerySqlErrorCategory, QuerySqlParameter, QuerySqlRequest, QuerySqlResult,
};
use crate::db::Db;
use crate::error::Result;
use crate::schema::DDL_STATEMENTS;

use super::error::contract_violation;

const CONTROLLED_ACCESSORS: [&str; 57] = [
    "_query_sql_bearer_walk",
    "_query_sql_authorization_subjects",
    "_query_sql_visible_records",
    "records",
    "record_lifecycle_interpretations",
    "content_events",
    "body_blocks",
    "body_block_headings",
    "links",
    "facet_values",
    "facet_value_json_nodes",
    "content_event_apps",
    "facet_observations",
    "facet_observation_json_nodes",
    "record_body_json_nodes",
    "bindings",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "vocabulary_value_json_nodes",
    "schema_config_json_nodes",
    "schema_config",
    "effective_relationships",
    "effective_relationship_endpoints",
    "agent_activity",
    "agent_activity_claims",
    "_query_sql_activity_observations",
    "_query_sql_activity_capture",
    "_query_sql_agent_activity_durable",
    "_query_sql_agent_activity_admitted",
    "_query_sql_agent_activity_claim_events",
    "actors",
    "_query_sql_disclosable_persons",
    "_query_sql_visible_person",
    "_query_sql_run_principals",
    "runs",
    "run_intents",
    "_query_sql_run_declarations",
    "messages_awaiting_reply",
    "facet_times",
    "facet_keys",
    "_query_sql_my_person",
    "my_message_state",
    "my_participants",
    "message_speakers",
    "deleted_messages",
    "my_mentions",
    "comment_anchors",
    "message_reactions",
    "_query_sql_mention_visible",
    "_query_sql_mention_self",
    "_query_sql_mention_prefix",
    "_query_sql_mention_key",
    "_query_sql_mention_rivals",
    "_query_sql_mention_reference",
    "_query_sql_mention_rows",
    "body_task_items",
];

const MAX_ROWS: i64 = sql_contract::MAX_ROWS as i64;
/// Lifecycle meaning is caller-relative and currently projected for the full
/// visible set before SQL execution. Refuse larger dependent snapshots until
/// a keyed/lazy projection can preserve the same governance semantics.
const MAX_LIFECYCLE_VISIBLE_RECORDS: i64 = 20_000;
// Engineering admission bounds, not product-ratified limits. The borrowed
// freshness budget counts ALL visible records and inspected source events,
// independently of the reaction-only window budget below.
const MAX_REACTION_HEAD_RECORDS: usize = 20_000;
const MAX_REACTION_HEAD_EVENTS: i64 = 100_000;
/// Reaction-only admission, distinct from the all-record freshness budget.
/// Only viewer-visible live Messages and their reaction history count.
const MAX_REACTION_MESSAGES: i64 = 20_000;
const MAX_REACTION_SOURCE_EVENTS: i64 = 100_000;
const MAX_REACTION_METADATA_BYTES: i64 = 16 * 1024 * 1024;
const MAX_REACTION_WINNERS: i64 = 20_000;
/// Longest declared intent `run_intents` returns as text. A declaration over
/// it reads as NULL, so one oversized `set_intent` cannot fail a statement at
/// the caller value ceiling. Well under the cell cap even after worst-case
/// JSON escaping.
pub const MAX_RUN_INTENT_BYTES: usize = 16 * 1024;
#[cfg(test)]
const MAX_SQL_BYTES: usize = sql_contract::MAX_SQL_BYTES;
const MAX_COLUMNS: usize = sql_contract::MAX_COLUMNS;
const MAX_CELL_ENCODED_BYTES: usize = sql_contract::MAX_CELL_ENCODED_BYTES;
const MAX_RESULT_ENCODED_BYTES: usize = sql_contract::MAX_RESULT_ENCODED_BYTES;
// SQLite's TEXT/BLOB and record ceiling, distinct from JSON-encoded result
// budgets. Schema-config projection admission shares this exact execution cap.
pub(crate) const MAX_SQLITE_VALUE_BYTES: i32 = 256 * 1024;
pub(crate) const PROGRESS_OPS: i32 = 1_000;

/// Member `query_sql` served relations (contract c323277 rev 8 §2.3(a)
/// `query_sql` row + 1e5d802 §2a catalogs). Every other logical relation —
/// including log-position views, actors, agent_activity*, messages, runs,
/// run_intents, body_task_items and effective_relationships — raises typed
/// `UnavailableOffline` at prepare. Mirrors
/// `crate::mcp::member_scope::QUERY_SQL_SERVED_RELATIONS`; keep both lists
/// aligned when changing the member contract.
pub(crate) const MEMBER_QUERY_SQL_SERVED_RELATIONS: &[&str] = &[
    "records",
    "links",
    "facet_values",
    "facet_times",
    "facet_keys",
    "bindings",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "catalog_relations",
    "catalog_columns",
];

/// Member replacement for the shared `records` governed view: identical
/// columns in identical order, with the dropped physical currency columns
/// derived over the slice (visible incoming `supersedes` only, the R1
/// carve-out). Installed with `DROP VIEW IF EXISTS` + `CREATE` after the
/// shared contract, connection-local only, never shipped.
const MEMBER_RECORDS_VIEW_DDL: &str = r#"
DROP VIEW IF EXISTS temp.records;
CREATE TEMP VIEW records AS
SELECT r.id, r.type, r.kind, r.name, r.body,
       CASE WHEN EXISTS (
         SELECT 1 FROM temp._query_sql_visible_ids AS parent_visible
         WHERE parent_visible.id = r.home_id
       ) THEN r.home_id ELSE NULL END AS home_id,
       r.lifecycle, r.persistence, r.maturity, r.summary,
       CASE WHEN (
         SELECT COUNT(*) FROM main.links AS s
         JOIN temp._query_sql_visible_ids AS sv ON sv.id = s.source_id
         WHERE s.target_id = r.id AND s.relationship = 'supersedes'
       ) = 0 THEN 1 ELSE NULL END AS is_current,
       (SELECT COUNT(*) FROM main.links AS s
        JOIN temp._query_sql_visible_ids AS sv ON sv.id = s.source_id
        WHERE s.target_id = r.id AND s.relationship = 'supersedes') AS successor_count,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.last_activity_at) AS last_activity_at,
       CAST(strftime('%s', r.last_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.last_activity_at), 4, 3) AS INTEGER) AS last_activity_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.created_at) AS created_at,
       CAST(strftime('%s', r.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.created_at), 4, 3) AS INTEGER) AS created_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.updated_at) AS updated_at,
       CAST(strftime('%s', r.updated_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.updated_at), 4, 3) AS INTEGER) AS updated_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.deleted_at) AS deleted_at,
       CAST(strftime('%s', r.deleted_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.deleted_at), 4, 3) AS INTEGER) AS deleted_at_ms,
       r.archived
FROM main.records AS r
JOIN temp._query_sql_visible_ids AS visible ON visible.id = r.id
"#;

/// Member replacement for the shared `facet_values` governed view: identical
/// columns in identical order, with the `VIRTUAL` generated `value_num`
/// recomputed locally from `value` by the exact engine generation expression
/// (`ddl.rs` `facet_values`), because the member profile ships the value but
/// not the generated projection.
const MEMBER_FACET_VALUES_VIEW_DDL: &str = r#"
DROP VIEW IF EXISTS temp.facet_values;
CREATE TEMP VIEW facet_values AS
SELECT f.id, f.record_id, f.key, f.value,
       CASE WHEN json_valid(f.value) THEN
         CASE WHEN json_type(f.value) IN ('integer','real')
              THEN CAST(f.value AS REAL) END
       END AS value_num,
       f.vocab_ref,
       strftime('%Y-%m-%dT%H:%M:%fZ', f.created_at) AS created_at,
       CAST(strftime('%s', f.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', f.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.facet_values AS f
JOIN temp._query_sql_visible_ids AS visible ON visible.id = f.record_id
"#;

/// First denied dependency in sorted order, if any. Pure authorizer
/// observation result check: denied before any storage access, even for
/// zero-row statements. Returns the relation name for the typed requirement.
pub(crate) fn member_query_sql_denied(
    dependencies: &std::collections::BTreeSet<String>,
) -> Option<String> {
    dependencies
        .iter()
        .find(|name| !MEMBER_QUERY_SQL_SERVED_RELATIONS.contains(&name.as_str()))
        .cloned()
}

/// Private probe source for a forbidden logical relation in the member
/// preflight validator. Never shipped, never installed on a copy: a
/// throwaway in-memory staging name only, so it cannot masquerade as a
/// served excluded relation. No canonical policy/history table is faked.
fn member_probe_source(relation: &str) -> String {
    format!("_member_probe_{relation}")
}

/// Authorizer for the member preflight validator: like `authorize_strict`
/// plus the private probe sources. Records nothing itself; the observation
/// closure wraps it.
fn authorize_member_preflight(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp")
                && (sql_contract::is_logical_relation(table_name)
                    || table_name.starts_with("_member_probe_")
                    || strict_task_source_read(&context, table_name)) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name }
            if sql_contract::is_portable_function(function_name)
                || function_name.eq_ignore_ascii_case("like") =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

/// Build the throwaway member-preflight validator: the strict public schema
/// with every forbidden logical relation replaced by a view over its private
/// probe source (`SELECT *` keeps columns in lockstep with the contract).
/// Served relations stay plain tables. Real reads — column, column-less
/// `COUNT(*)`/`EXISTS`, `WHERE 0`, `LIMIT 0` — open the probe source;
/// same-named CTEs, comments and literals never do (verified against SQLite
/// authorizer behavior). Body-task items keep the existing private-source
/// pattern instead of a second wrapping.
fn build_member_preflight_validator(gate_schema_config: bool) -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(
        "ALTER TABLE temp.body_task_items RENAME TO _query_sql_task_item_source;
         CREATE TEMP VIEW body_task_items AS
         SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset
         FROM _query_sql_task_item_source",
    )
    .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    for relation in sql_contract::LOGICAL_RELATIONS {
        let name = relation.name;
        if name == "body_task_items" || MEMBER_QUERY_SQL_SERVED_RELATIONS.contains(&name) {
            // `schema_config` is normally served, but a generation that withheld
            // a schema row (`schema_incomplete_for`, §3.3 rule 6) makes the
            // shipped relation non-authoritative; then it is probed like an
            // excluded relation so a statement reading it refuses, while a
            // same-named CTE/comment/literal never opens the probe.
            if !(matches!(name, "schema_config" | "facet_keys") && gate_schema_config) {
                continue;
            }
        }
        let probe = member_probe_source(name);
        let ddl = format!(
            "ALTER TABLE temp.\"{name}\" RENAME TO \"{probe}\"; \
             CREATE TEMP VIEW \"{name}\" AS SELECT * FROM \"{probe}\";"
        );
        conn.execute_batch(&ddl)
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    }
    register_regexp_function(&conn)?;
    register_now_ms_stub(&conn)?;
    register_current_principal_stub(&conn)?;
    register_utc_date_label_stub(&conn)?;
    Ok(conn)
}

/// CTE-safe forbidden-relation observation over an already-validated portable
/// statement. No validation gates run here — shapes are preserved exactly as
/// the existing two-phase validator accepted them. Only authorizer-observed
/// private-probe opens are reported; CTE aliases, comments and literals never
/// touch a probe source. Covers column reads and column-less `COUNT(*)` /
/// `EXISTS` alike, including `WHERE 0` / `LIMIT 0`.
pub(crate) fn member_forbidden_observation(
    portable_statement: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let conn = build_member_preflight_validator(false)?;
    let found = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::BTreeSet::<String>::new(),
    ));
    let observed = found.clone();
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if let AuthAction::Read { table_name, .. } = context.action {
            if let Some(relation) = table_name.strip_prefix("_member_probe_") {
                observed
                    .lock()
                    .expect("member probe lock")
                    .insert(relation.to_owned());
            } else if table_name == "_query_sql_task_item_source" {
                observed
                    .lock()
                    .expect("member probe lock")
                    .insert("body_task_items".to_owned());
            }
        }
        authorize_member_preflight(context)
    }));
    let prepared = conn.prepare(portable_statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let prepared = prepared.map_err(|error| {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    })?;
    if !prepared.readonly() {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "read-only statement writes",
        ));
    }
    drop(prepared);
    Ok(std::sync::Arc::try_unwrap(found)
        .expect("validator releases member probe observer")
        .into_inner()
        .expect("member probe lock"))
}

/// Member denial for an already-validated portable statement: first sorted
/// probe-observed forbidden relation, `None` serves. The probe covers column
/// reads and column-less `COUNT(*)`/`EXISTS` alike (even `WHERE 0`/`LIMIT 0`)
/// and never mistakes a same-named CTE, comment or literal. It runs without
/// validation gates so shapes stay exactly as the existing two-phase
/// validator accepted them; the existing column-read observer is not
/// consulted here because it errors (rather than observes) on some
/// column-less forbidden reads such as `messages_awaiting_reply`, which must
/// still deny with the typed requirement instead of that error.
pub(crate) fn member_denied_requirement(portable_statement: &str) -> Result<Option<String>> {
    let observed = member_forbidden_observation(portable_statement)?;
    Ok(member_query_sql_denied(&observed))
}

/// §3.3 rule 6 carry for `query_sql` (C5): when the admitted generation
/// withheld a schema row (`schema_incomplete_for` non-empty), the shipped
/// `schema_config` relation is not authoritative — reading it is a partial
/// interpretation. This observes a real read of `schema_config` through the
/// same probe machinery as an excluded relation, so a same-named CTE, comment
/// or literal never denies and column-less `COUNT(*)` / `EXISTS` and
/// `WHERE 0` / `LIMIT 0` still do. The caller decides applicability from the
/// generation markers before calling this.
pub(crate) fn member_reads_schema_config(portable_statement: &str) -> Result<bool> {
    let conn = build_member_preflight_validator(true)?;
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = seen.clone();
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if let AuthAction::Read { table_name, .. } = context.action {
            if matches!(
                table_name,
                "_member_probe_schema_config" | "_member_probe_facet_keys"
            ) {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        authorize_member_preflight(context)
    }));
    let prepared = conn.prepare(portable_statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let prepared = prepared.map_err(|error| {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    })?;
    if !prepared.readonly() {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "read-only statement writes",
        ));
    }
    drop(prepared);
    Ok(seen.load(std::sync::atomic::Ordering::SeqCst))
}

/// Restrict the cost proxy to the caller statement's VM work. The governed
/// connection's progress handler stays installed for its deadline across
/// setup and error diagnosis; those phases are outside the measured query.
struct QueryVmWorkPhase(Option<Arc<AtomicBool>>);

impl QueryVmWorkPhase {
    fn start(active: Option<Arc<AtomicBool>>) -> Self {
        if let Some(active) = &active {
            active.store(true, Ordering::Release);
        }
        Self(active)
    }
}

impl Drop for QueryVmWorkPhase {
    fn drop(&mut self) {
        if let Some(active) = &self.0 {
            active.store(false, Ordering::Release);
        }
    }
}
const QUERY_DEADLINE: Duration = Duration::from_millis(sql_contract::QUERY_DEADLINE_MS);

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct Slice1PhaseCpu {
    stage_ns: u128,
    caller_ns: u128,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Slice1Phase {
    Stage,
    Caller,
}

#[cfg(test)]
tokio::task_local! {
    static SLICE1_PHASE_CPU: Arc<std::sync::Mutex<Slice1PhaseCpu>>;
}

#[cfg(test)]
fn slice1_cpu_ns() -> u128 {
    let mut total = 0u128;
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            if let Ok(text) = std::fs::read_to_string(task.path().join("schedstat")) {
                if let Some(first) = text.split_whitespace().next() {
                    total += first.parse::<u128>().unwrap_or(0);
                }
            }
        }
    }
    total
}

#[cfg(test)]
fn slice1_phase_cpu_before() -> Option<u128> {
    SLICE1_PHASE_CPU.try_with(|_| slice1_cpu_ns()).ok()
}

#[cfg(test)]
fn slice1_phase_cpu_after(before: Option<u128>, phase: Slice1Phase) {
    if let Some(before) = before {
        let elapsed = slice1_cpu_ns().saturating_sub(before);
        let _ = SLICE1_PHASE_CPU.try_with(|timings| {
            let mut timings = timings.lock().unwrap();
            match phase {
                Slice1Phase::Stage => timings.stage_ns += elapsed,
                Slice1Phase::Caller => timings.caller_ns += elapsed,
            }
        });
    }
}

const MAX_AWAITING_REPLY_CANDIDATES: i64 = 10_000;
/// Failure-path SQLITE_TOOBIG probe only. Twelve named rows bounds the
/// error while leaving headroom above the exclusion hint's 10-id display
/// cap, so the "(first 10 of N oversized rows)" count is reachable through
/// the wired path. 16384
/// candidate rowids covers the live workspace (~4.5k records) with headroom.
/// 500ms is well under QUERY_DEADLINE_MS so the probe cannot consume the
/// caller's budget; incremental blob reads never copy the oversized payload.
const MAX_TOOBIG_NAMED: usize = 12;
const MAX_TOOBIG_PROBE_ROWS: i64 = 16_384;
const TOOBIG_PROBE_BUDGET: Duration = Duration::from_millis(500);

/// A single governed visibility evaluation and its database snapshot fences.
/// The caller may intersect these ids with an index only when all fences match.
/// The set is reference-counted so cache hits share it without copying.
pub(crate) struct WorkspaceVisibleSet {
    pub ids: std::sync::Arc<HashSet<String>>,
    pub content_seq: i64,
    pub relationship_seq: i64,
    pub authorization_epoch: i64,
    pub unit_seq_max: i64,
}

/// Evaluate the same private visibility view that backs governed `query_sql`.
/// No caller SQL, row cap, or second authorization algorithm is involved.
pub(crate) async fn workspace_visible_set(
    db: &Db,
    principal: QueryPrincipal,
) -> Result<WorkspaceVisibleSet> {
    let mut connection = db.governed_pool().acquire().await?;
    if let Err(error) = install_temp_contract(&mut connection).await {
        connection.close_on_drop();
        return Err(error.into());
    }
    // Clearing outside the transaction prevents rollback from restoring an
    // earlier principal on a reused governed connection.
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    let mut tx = connection.begin().await?;
    let result: Result<WorkspaceVisibleSet> = async {
        sqlx::query(
            "INSERT INTO temp._query_sql_principal \
             (singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at) \
             VALUES (1, ?, ?, ?, ?, ?)",
        )
        .bind(principal.credential())
        .bind(principal.trusted_local_bypass())
        .bind(principal.activity_read())
        .bind(principal.is_member())
        .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .execute(&mut *tx)
        .await?;
        workspace_visible_set_in_tx(db, &mut tx, &principal).await
    }
    .await;
    let rollback = tx.rollback().await;
    if result.is_err() || rollback.is_err() {
        connection.close_on_drop();
    }
    rollback?;
    result
}

/// Slice 1 (task 77bd40a): cache-consulting visible-set evaluation against
/// an already-open read transaction whose principal row is already
/// installed and whose snapshot is already fixed. Shared by
/// [`workspace_visible_set`] (own connection) and the governed `query_sql`
/// owned path (the read transaction itself), so the read path never needs
/// a second governed slot and always evaluates at its own snapshot — no
/// cross-snapshot fence comparison. Fences are sampled here, inside the
/// caller's snapshot, exactly as before.
async fn workspace_visible_set_in_tx(
    db: &Db,
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<WorkspaceVisibleSet> {
    let fence_result: Result<WorkspaceVisibleSet> = async {
        // Fix the main database snapshot before installing request-local state.
        let content_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
                .fetch_one(&mut **tx)
                .await?;
        let relationship_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.relationship_events")
                .fetch_one(&mut **tx)
                .await?;
        let authorization_epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM main.authorization_revision WHERE id = 1")
                .fetch_one(&mut **tx)
                .await?;
        // Second fence (Tier 1.4, record fd6c1f2): unit-created projections
        // move the visible set without moving the epoch, so the key carries
        // both. The UNIQUE index makes this one cheap scalar probe in the
        // same snapshot as the evaluation below.
        let unit_seq_max: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(creation_event_seq), 0) FROM main.semantic_units",
        )
        .fetch_one(&mut **tx)
        .await?;
        let cache_key = crate::visible_set_cache::VisibleSetCacheKey {
            credential: principal.credential().to_string(),
            trusted_local_bypass: principal.trusted_local_bypass(),
            activity_read: principal.activity_read(),
            is_member: principal.is_member(),
            authorization_epoch,
            unit_seq_max,
        };
        if let Some(ids) = db.visible_set_cache_get(&cache_key) {
            crate::mcp::request_timing::record_visible_set_lookup(true);
            // Hit: fences match, so the stored set equals a fresh evaluation;
            // content/relationship stamps are current by construction. M2's
            // own live-triple gate still applies downstream.
            return Ok(WorkspaceVisibleSet {
                ids,
                content_seq,
                relationship_seq,
                authorization_epoch,
                unit_seq_max,
            });
        }
        crate::mcp::request_timing::record_visible_set_lookup(false);
        db.visible_set_cache_record_miss();
        let mut ids = HashSet::new();
        let mut rows =
            sqlx::query("SELECT id FROM temp._query_sql_visible_records").fetch(&mut **tx);
        while let Some(row) = rows.try_next().await? {
            ids.insert(row.try_get(0)?);
        }
        let evaluated = WorkspaceVisibleSet {
            ids: std::sync::Arc::new(ids),
            content_seq,
            relationship_seq,
            authorization_epoch,
            unit_seq_max,
        };
        // Refusal keeps the just-computed live answer; the cache never holds
        // a subset. The caller's rollback (if any) affects connection reuse,
        // not the reads above, so storing before it returns is sound.
        db.visible_set_cache_insert(cache_key, evaluated.ids.clone());
        Ok(evaluated)
    }
    .await;
    fence_result
}

/// In-transaction installer for the governed visibility view.
///
/// For hosts that already hold a snapshot transaction (e.g. the
/// `do_live_read` gate tx). Installs ONLY the principal table plus the
/// bearer-walk and visible-records views — never the public logical
/// `records` etc. views, which would shadow unqualified main-table reads
/// later in the same transaction. The caller supplies a narrowly
/// constructed `QueryPrincipal`; this function never widens it and never
/// reads the hosted activity roster (the visible view ignores the roster).
pub(crate) async fn install_visible_records_in(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
) -> Result<()> {
    for stmt in frozen_temp_contract_batch()
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // `contains`, not `starts_with`: the bearer-walk chunk carries its
        // leading `--` comment block, so the CREATE is not first. The
        // CREATE-prefixed literals occur only in TEMP_CONTRACT, so no
        // public logical view can match.
        if stmt.contains("CREATE TEMP TABLE IF NOT EXISTS _query_sql_principal")
            || stmt.contains("CREATE TEMP VIEW IF NOT EXISTS _query_sql_authorization_subjects")
            || stmt.contains("CREATE TEMP VIEW IF NOT EXISTS _query_sql_visible_records")
        {
            sqlx::query(stmt).execute(&mut **tx).await?;
        }
    }
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at) VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Slice 1 (task 77bd40a): evaluate the visibility walk once per read
/// transaction, in this same transaction and under this same principal row,
/// and stage the ids in `_query_sql_visible_ids`. Snapshot-sound by
/// construction. The owned path prefers the shared cache via
/// [`populate_visible_ids_owned`]; this is its race fallback and the
/// caller-transaction path's only source.
async fn populate_visible_ids_live(tx: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO temp._query_sql_visible_ids(id) \
         SELECT id FROM temp._query_sql_visible_records",
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Slice 1 (task 77bd40a): stage the viewer-visible set for the owned path.
///
/// The set comes through [`workspace_visible_set_in_tx`] against this read
/// transaction itself, which consults and populates the shared cache on a
/// miss so later statements in the same request hit it. One governed slot,
/// one snapshot, this caller's principal — per-viewer narrowing holds and
/// no cross-snapshot fence comparison is needed.
async fn populate_visible_ids_owned(
    db: &Db,
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<()> {
    let visible = workspace_visible_set_in_tx(db, tx, principal).await?;
    insert_visible_ids(tx, &visible.ids).await
}

/// Bulk load of one viewer-visible set as a single `json_each` statement
/// with one bind. Binding every id as its own SQLite variable costs roughly
/// as much as the walk it replaces (measured ~100 ms per 20k-id statement
/// in the dev profile); the JSON form parses in C and keeps staging near
/// free on cache hits. `OR IGNORE` keeps a double-populate (never expected;
/// the table is cleared per read) to a no-op instead of a failure. An empty
/// set binds `[]`, which selects no rows.
async fn insert_visible_ids(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    ids: &HashSet<String>,
) -> Result<()> {
    let payload = serde_json::to_string(ids)?;
    sqlx::query(
        "INSERT OR IGNORE INTO temp._query_sql_visible_ids(id) \
         SELECT value FROM json_each(?)",
    )
    .bind(payload)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Deliberately conservative: every callable function is denied unless it is
/// in the shared portable subset (`sql_contract::is_portable_function`,
/// plus function-form `like`), whose output is intrinsically small or a
/// familiar numeric/min/max aggregate. The SQLite runtime value ceiling is
/// still mandatory for min/max over text. Operators and CAST remain
/// available. Dropped names never reach the authorizer: the classifier
/// rejects them first with the portable replacement, so a deny here means
/// an unknown function. Blob constructors, other value-returning
/// string/JSON/window functions, concatenating aggregates, extension
/// loaders, and introspection helpers never prepare.
/// The connection-local contract. `_query_sql_visible_records` is an internal
/// helper, absent from the strict public schema, so caller SQL cannot name it.
/// A routed credential resolves with its folded catalog footing for this
/// request; membership alone matters only when the explicit anchor grants
/// `native:members`, and guests never match that subject.
const TEMP_CONTRACT: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS catalog_view_definitions AS SELECT CAST(NULL AS TEXT) AS relation_name,CAST(NULL AS TEXT) AS view_id,CAST(NULL AS TEXT) AS revision_id,CAST(NULL AS TEXT) AS definition_sha256,CAST(NULL AS TEXT) AS schema_sha256,CAST(NULL AS TEXT) AS origin,CAST(NULL AS TEXT) AS description,CAST(NULL AS TEXT) AS scope_json,CAST(NULL AS TEXT) AS source_pins_json,CAST(NULL AS TEXT) AS dependencies_json,CAST(NULL AS TEXT) AS columns_json WHERE 1=0;

CREATE TEMP TABLE IF NOT EXISTS _query_sql_principal (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  account_id          TEXT NOT NULL,
  trusted_local_bypass INTEGER NOT NULL CHECK (trusted_local_bypass IN (0, 1)),
  activity_read        INTEGER NOT NULL CHECK (activity_read IN (0, 1)),
  is_member            INTEGER NOT NULL CHECK (is_member IN (0, 1)),
  observed_at         TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_messages_awaiting_reply (
  message_id TEXT PRIMARY KEY
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_lifecycle_interpretations (
  record_id TEXT PRIMARY KEY, status TEXT NOT NULL, raw TEXT,
  axis_key TEXT, axis_label TEXT, vocabulary_id TEXT, vocabulary_name TEXT,
  value_id TEXT, canonical TEXT, terminality TEXT, reason TEXT
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_observations (
  run_key TEXT PRIMARY KEY,
  last_observed_at TEXT NOT NULL,
  declared_intent TEXT
);
-- Whether the disposable read-log capture contributed to this observation.
-- The activity helper sets exactly one row per governed execution. Zero means
-- the `read_log_calls` table was absent. A standby export strips read-log
-- rows but keeps the tables, so a stripped-but-present read log still reads
-- one and its empty rows report `none`, not `unavailable`. That conflation is
-- a known gap, closing it needs a durable capture-removed signal the export
-- writes, and table existence cannot carry it. The `agent_activity` view reads
-- this flag to report an unavailable disclosure state rather than a silent
-- empty column, and `unavailable` shadows `withheld` by design, since there
-- is nothing to withhold when capture contributed nothing
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_capture (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  available INTEGER NOT NULL CHECK (available IN (0, 1))
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_members (
  account_id TEXT PRIMARY KEY,
  member_ref TEXT NOT NULL UNIQUE
);
-- Claim and claim-clear candidate rows, populated by the engine-owned
-- prepared step before the caller value ceiling is lowered (same precedent
-- as `_query_sql_activity_observations`). The claims view reads only these
-- narrow projected columns and never opens `content_events.payload`, so an
-- over-limit payload cannot fail the relation however the planner orders the
-- view. Shape matching happens once at population time at the full limit.
-- TEMP_CONTRACT statements are split on semicolons by the installers, so no
-- comment in this contract may contain one.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_claim_candidates (
  seq INTEGER PRIMARY KEY,
  claim_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  run_key TEXT,
  claim_actor TEXT,
  claimed_by_account TEXT,
  claimed_at TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_claim_releases (
  seq INTEGER PRIMARY KEY,
  record_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL
);
-- Actors one governed execution may attribute: the caller account plus
-- accounts bound to a caller-visible person record. Populated per request by
-- the engine-owned prepared step next to the claim candidates, so the
-- content_events view joins a plain table and never a compound view. Person
-- lookup reads main bindings directly because the governed bindings view is
-- caller-filtered and would make every other actor undisclosable.
-- `person_id` is filled only when caller SQL reads `actors`, and only from
-- the caller-visible record bound to the account. It stays NULL when there
-- is none (the caller's own account may have no binding, or a binding the
-- caller cannot see). `actor` is never NULL but is deliberately not declared
-- NOT NULL: see the `actors` view below.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_disclosable_actors (
  actor TEXT,
  person_id TEXT
);
-- Slice 1 staging (task 77bd40a): materialized viewer-visible set, one row
-- per visible record id. Populated inside the read transaction and cleared
-- outside the transaction like the principal row. No semicolons in comments.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_visible_ids (
  id TEXT PRIMARY KEY
);
-- Exact winning additions, populated once only for a resolved dependency.
-- event_seq and actor never become public columns. NULL legacy partitions
-- are preserved by the metadata-only window before this stage is filled.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_reaction_winners (
  event_seq INTEGER PRIMARY KEY,
  message_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  emoji TEXT NOT NULL,
  executor_kind TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TEMP VIEW IF NOT EXISTS message_reactions AS
SELECT identity.id AS reaction_id, winner.message_id, winner.emoji,
       visible_actor.id AS actor_record_id, person.name AS actor_name,
       CASE WHEN principal.trusted_local_bypass = 1
                  OR winner.actor = principal.account_id
                  OR visible_actor.id IS NOT NULL
            THEN winner.executor_kind ELSE NULL END AS executor_kind,
       strftime('%Y-%m-%dT%H:%M:%fZ', winner.created_at) AS reacted_at,
       CAST(strftime('%s', winner.created_at) AS INTEGER) * 1000
         + CAST(substr(strftime('%f', winner.created_at), 4, 3) AS INTEGER) AS reacted_at_ms,
       winner.actor = principal.account_id AS viewer
  FROM temp._query_sql_reaction_winners AS winner
  CROSS JOIN main.content_events AS identity
  CROSS JOIN temp._query_sql_principal AS principal
  LEFT JOIN main.bindings AS actor_binding
    ON actor_binding.system = 'account' AND actor_binding.identifier = winner.actor
  LEFT JOIN temp._query_sql_visible_ids AS visible_actor
    ON visible_actor.id = actor_binding.record_id
  LEFT JOIN main.records AS person ON person.id = visible_actor.id
 -- Keep these narrow reads in the controlled accessor even for COUNT(*).
 -- Both columns are stored NOT NULL TEXT, so these predicates also retain
 -- empty and Unicode values without excluding a winning row.
 WHERE identity.seq = winner.event_seq
   AND length(identity.id) >= 0 AND length(principal.account_id) >= 0;

-- Derived artifacts do not carry independent visibility in v1. Each live
-- record resolves through a chain of exactly-one outgoing part_of links until
-- the first ordinary live bearer. Missing/multiple bearers, tombstones,
-- cycles, and chains longer than the defensive recursion ceiling produce no
-- subject row.
--
-- The walk runs *bearer-first* (subject -> derived artifact) rather than
-- artifact-first. Both directions describe the same relation, because the
-- exactly-one-outgoing-part_of rule makes every derived artifact's bearer
-- chain a single deterministic path: seeding at the ordinary terminals and
-- descending the reverse edges visits each derived artifact exactly once.
-- The artifact-first form re-walked the whole remaining chain from every
-- origin, so a chain of D edges cost O(D^2) walk rows and, because the
-- artifact-first cycle guard rescanned a growing json path per step, O(D^3)
-- json_each iterations. The `records` view alone references
-- `_query_sql_visible_records` twice (once for the row, once through the
-- home_id LEFT JOIN that preceded the slice-1 staging), and a
-- non-materialized view is re-evaluated per reference — EXPLAIN QUERY PLAN
-- shows the walk twice — so that cost was paid twice per statement on every
-- projection of `records`. That is the mechanism that put this
-- query at the edge of the QUERY_DEADLINE_MS budget on the qualification
-- fixtures, which deliberately contain a MAX_DERIVED_BEARER_DEPTH-long chain.
--
-- Bearer-first has no such term: the row count is bounded by the number of
-- live records, independent of chain depth, and no per-row cycle guard is
-- needed because an unresolvable cycle is simply never reachable from an
-- ordinary terminal. Measured on the query_sql parity fixture (119 records,
-- 113 links, one 101-edge chain) with the system SQLite 3.45.1: 93ms -> 0.8ms
-- for one evaluation of this view, i.e. roughly two orders of magnitude of
-- headroom against the 2s deadline instead of the previous single order.
-- `depth` is still counted and still bounded, so an over-depth artifact stays
-- invisible exactly as before.
CREATE TEMP VIEW IF NOT EXISTS _query_sql_authorization_subjects AS
WITH RECURSIVE _query_sql_bearer_walk(record_id, subject_id, depth) AS (
  SELECT ordinary.id, ordinary.id, 0
  FROM main.records AS ordinary
  WHERE ordinary.deleted_at IS NULL
    AND NOT (ordinary.type = 'Annotation'
             OR (ordinary.type = 'Document' AND ordinary.kind IS 'attachment'))
  UNION ALL
  SELECT derived.id, walk.subject_id, walk.depth + 1
  FROM _query_sql_bearer_walk AS walk
  JOIN main.links AS part
    ON part.target_id = walk.record_id AND part.relationship = 'part_of'
  JOIN main.records AS derived ON derived.id = part.source_id
  WHERE derived.deleted_at IS NULL
    AND (derived.type = 'Annotation'
         OR (derived.type = 'Document' AND derived.kind IS 'attachment'))
    AND (SELECT COUNT(*) FROM main.links AS all_parts
         WHERE all_parts.source_id = derived.id
           AND all_parts.relationship = 'part_of') = 1
    AND walk.depth < __MAX_DERIVED_BEARER_DEPTH__
)
SELECT walk.record_id AS record_id, walk.subject_id AS subject_id
FROM _query_sql_bearer_walk AS walk;

CREATE TEMP VIEW IF NOT EXISTS _query_sql_visible_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._query_sql_authorization_subjects AS resolved
  ON resolved.record_id = r.id
JOIN main.records AS authorization_subject
  ON authorization_subject.id = resolved.subject_id
CROSS JOIN temp._query_sql_principal AS principal
WHERE r.deleted_at IS NULL
  -- Governed attribution annotations are intentionally absent from every
  -- generic surface. Their bearer-derived authorization is consumed only by
  -- the dedicated attribution reader and must not admit the hidden record or
  -- its events through query_sql's shared visibility relation.
  AND NOT (r.type = 'Annotation' AND r.kind IN ('attribution','acknowledgement'))
  -- Units and derived artefacts resolving to Units are subordinate to the
  -- dedicated/direct surfaces, and cannot be admitted on envelope policy.
  AND NOT (r.type = 'Entity' AND r.kind IS 'semantic-unit')
  AND NOT EXISTS (
        SELECT 1 FROM main.semantic_units AS semantic_subject
        WHERE semantic_subject.unit_id = authorization_subject.id
      )
  AND EXISTS (
       SELECT 1 FROM main.record_policies AS explicit_policy
       WHERE explicit_policy.record_id = authorization_subject.policy_anchor_id
     )
   AND (principal.trusted_local_bypass = 1 OR (EXISTS (
         SELECT 1 FROM main.bindings AS owner_account
         WHERE owner_account.record_id = authorization_subject.owner_id
           AND owner_account.system = 'account'
           AND owner_account.identifier = principal.account_id
           AND owner_account.is_canonical = 1
       )
    -- Per-anchor decision: the caller-visible anchor set depends only on the
    -- principal row, so it is computed once per statement and probed per
    -- record, instead of re-matching all of the caller's entries for every
    -- record. Membership is unchanged: for a non-null anchor this admits
    -- exactly the anchors the former correlated EXISTS matched, and a null
    -- anchor admits nothing under either form
    OR authorization_subject.policy_anchor_id IN (
         SELECT entry.policy_anchor_id
         FROM main.policy_entries AS entry
         CROSS JOIN temp._query_sql_principal AS anchor_principal
         WHERE entry.effect = 'allow'
           AND entry.capability IN ('view', 'edit', 'manage')
           AND (
             (entry.subject_kind = 'members'
              AND entry.subject_id = 'native:members'
              AND anchor_principal.is_member = 1)
             OR
             (entry.subject_kind = 'account'
              AND entry.subject_id = anchor_principal.account_id)
           )
       )));

-- Slice 1 (task 77bd40a): `records` joins the materialized
-- `_query_sql_visible_ids` table instead of re-walking
-- `_query_sql_visible_records` per reference. The table is populated once per
-- read transaction on every path, so an empty table here always means an
-- empty visible set, never a skipped step. The parent probe is a projected
-- scalar expression so count/page statements that do not return home_id do
-- not pay one extra lookup per row.
CREATE TEMP VIEW IF NOT EXISTS records AS
SELECT r.id, r.type, r.kind, r.name, r.body,
       CASE WHEN EXISTS (
         SELECT 1 FROM temp._query_sql_visible_ids AS parent_visible
         WHERE parent_visible.id = r.home_id
       ) THEN r.home_id ELSE NULL END AS home_id,
       r.lifecycle, r.persistence, r.maturity, r.summary,
       r.is_current, r.successor_count,
       -- Portable value model (E1 M1 slice B): every engine-managed
       -- timestamp presents fixed UTC millis text plus an integer
       -- epoch-millis companion, so date maths is portable integer
       -- arithmetic. SQLite's default text ordering is already BINARY.
       strftime('%Y-%m-%dT%H:%M:%fZ', r.last_activity_at) AS last_activity_at,
       CAST(strftime('%s', r.last_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.last_activity_at), 4, 3) AS INTEGER) AS last_activity_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.created_at) AS created_at,
       CAST(strftime('%s', r.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.created_at), 4, 3) AS INTEGER) AS created_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.updated_at) AS updated_at,
       CAST(strftime('%s', r.updated_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.updated_at), 4, 3) AS INTEGER) AS updated_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.deleted_at) AS deleted_at,
       CAST(strftime('%s', r.deleted_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.deleted_at), 4, 3) AS INTEGER) AS deleted_at_ms,
       r.archived
FROM main.records AS r
JOIN temp._query_sql_visible_ids AS visible ON visible.id = r.id;

-- Actor and run lineage are disclosed under exactly the `get_history` rule:
-- the actor travels when the disclosure table populated per request holds
-- it (trusted-local callers see all and a NULL actor discloses nothing),
-- and `run_key`/`parent_key` additionally stay NULL on claim-shaped
-- payloads unless the caller is the actor. Claim shape comes from the
-- trigger-maintained `content_event_claim_meta` side table, never from the
-- payload. Opening any payload here would run under the caller's lowered
-- value ceiling and fail oversized rows. The LEFT JOIN keeps every event
-- visible. A missing metadata row degrades to shaped (hidden run), never
-- to disclosed. Payloads and intent stay out of
-- this relation. Transport (`channel_kind`) is viewer-visible only: it
-- travels exactly when the actor gate above discloses the actor, and is
-- NULL otherwise — never the built-in unknown-fallback on hidden rows.
-- On disclosed rows an invalidated or absent attestation reads 'unknown',
-- matching the built-in row label for unattested transport.
CREATE TEMP VIEW IF NOT EXISTS content_events AS
SELECT e.seq AS local_seq, e.id, e.record_id,
       CASE WHEN e.type='receipt.committed.v1' THEN 'record.updated' ELSE e.type END AS type,
       CASE WHEN (SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                 OR e.actor = (SELECT account_id FROM temp._query_sql_principal)
                 OR EXISTS (SELECT 1 FROM temp._query_sql_disclosable_actors AS disclosed
                            WHERE disclosed.actor = e.actor)
            THEN e.actor ELSE NULL END AS actor,
       CASE WHEN ((SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                 OR e.actor = (SELECT account_id FROM temp._query_sql_principal)
                 OR EXISTS (SELECT 1 FROM temp._query_sql_disclosable_actors AS disclosed
                            WHERE disclosed.actor = e.actor))
                AND ((SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                     OR NOT ((COALESCE(claim_meta.has_claimed_by, 1) = 1
                              OR COALESCE(claim_meta.has_claimed_run, 1) = 1
                              OR COALESCE(claim_meta.has_released_from, 1) = 1)
                             AND e.actor IS NOT (SELECT account_id FROM temp._query_sql_principal)))
            THEN e.run_key ELSE NULL END AS run_key,
       CASE WHEN ((SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                 OR e.actor = (SELECT account_id FROM temp._query_sql_principal)
                 OR EXISTS (SELECT 1 FROM temp._query_sql_disclosable_actors AS disclosed
                            WHERE disclosed.actor = e.actor))
                AND ((SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                     OR NOT ((COALESCE(claim_meta.has_claimed_by, 1) = 1
                              OR COALESCE(claim_meta.has_claimed_run, 1) = 1
                              OR COALESCE(claim_meta.has_released_from, 1) = 1)
                             AND e.actor IS NOT (SELECT account_id FROM temp._query_sql_principal)))
             THEN e.parent_key ELSE NULL END AS parent_key,
        CASE WHEN (SELECT trusted_local_bypass FROM temp._query_sql_principal) = 1
                  OR e.actor = (SELECT account_id FROM temp._query_sql_principal)
                  OR EXISTS (SELECT 1 FROM temp._query_sql_disclosable_actors AS disclosed
                             WHERE disclosed.actor = e.actor)
             THEN COALESCE((SELECT CASE WHEN EXISTS (
                                          SELECT 1 FROM main.provenance_attestation_validity_events AS v
                                           WHERE v.attestation_id = first_att.attestation_id
                                             AND v.status = 'invalidated'
                                             AND v.ordinal = (SELECT MAX(v2.ordinal)
                                                                FROM main.provenance_attestation_validity_events AS v2
                                                               WHERE v2.attestation_id = v.attestation_id))
                                        THEN 'unknown' ELSE first_att.channel END
                              FROM (SELECT a.channel AS channel, a.id AS attestation_id, 0 AS src
                                      FROM main.provenance_action_outputs AS o
                                      JOIN main.provenance_action_attestations AS a
                                        ON a.id = o.action_attestation_id
                                     WHERE o.output_domain = 'content' AND o.output_event_id = e.id
                                     UNION ALL
                                    SELECT a.channel, a.id, 1 AS src
                                      FROM main.provenance_action_events AS ev
                                      JOIN main.provenance_action_attestations AS a
                                        ON a.id = ev.action_attestation_id
                                     WHERE ev.output_event_id = e.id
                                     ORDER BY 3 LIMIT 1) AS first_att), 'unknown')
             ELSE NULL END AS channel_kind,
         strftime('%Y-%m-%dT%H:%M:%fZ', e.created_at) AS created_at,
        CAST(strftime('%s', e.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', e.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.content_events AS e
LEFT JOIN main.content_event_claim_meta AS claim_meta ON claim_meta.event_seq = e.seq
JOIN temp._query_sql_visible_ids AS visible ON visible.id = e.record_id
WHERE e.type NOT IN (
    'reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1'
);

-- App contract v2 attribution (task 50f5aca): one row per visible content
-- event produced by a call a host-asserted v2 app made. Content-only:
-- relationship outputs have no caller-visible event relation here, so the
-- engine-side selector app_attribution::app_action_outputs covers both
-- domains for undo. It is driven from the
-- caller-filtered content_events view, and only where that view discloses the
-- actor, so which app someone used travels exactly as far as who they are.
-- An invalidated attestation attributes nothing.
CREATE TEMP VIEW IF NOT EXISTS content_event_apps AS
SELECT e.id AS event_id, e.record_id, app.package, app.version,
       app.install_event_id, app.assertion
FROM main.provenance_action_app_attributions AS app
JOIN main.provenance_action_outputs AS o
  ON o.action_attestation_id = app.action_attestation_id
 AND o.output_domain = 'content'
JOIN temp.content_events AS e ON e.id = o.output_event_id
WHERE e.actor IS NOT NULL
  AND NOT EXISTS (
        SELECT 1 FROM main.provenance_attestation_validity_events AS v
         WHERE v.attestation_id = app.action_attestation_id
           AND v.status = 'invalidated'
           AND v.ordinal = (SELECT MAX(v2.ordinal)
                              FROM main.provenance_attestation_validity_events AS v2
                             WHERE v2.attestation_id = v.attestation_id));

-- The physical projection carries the exact source event for replay, but
-- caller SQL receives only current content chunks. Record visibility uses
-- the same staged snapshot as `records`, so deleted and hidden bodies stay out.
CREATE TEMP VIEW IF NOT EXISTS body_blocks AS
SELECT b.record_id, b.block_index, b.chunk_index, b.chunk_count,
       b.heading_path, b.block_kind, b.text, b.start_offset, b.end_offset
FROM main.body_blocks AS b
JOIN temp._query_sql_visible_ids AS visible ON visible.id = b.record_id;

-- Expand only the already governed chunk path, never caller-supplied JSON.
-- HeadingSegment is an object, and its block_index is revision-local identity.
CREATE TEMP VIEW IF NOT EXISTS body_block_headings AS
SELECT b.record_id, b.block_index, b.chunk_index,
       CAST(h.key AS INTEGER) AS heading_index,
       CAST(json_extract(h.value, '$.depth') AS INTEGER) AS depth,
       json_extract(h.value, '$.title') AS title,
       CAST(json_extract(h.value, '$.title_truncated') AS INTEGER) AS title_truncated,
       CAST(json_extract(h.value, '$.block_index') AS INTEGER) AS heading_block_index
FROM temp.body_blocks AS b, json_each(b.heading_path) AS h
-- Keep population-only reads attributed to this controlled view: SQLite
-- otherwise reports a column-less json_each read without an accessor.
WHERE h.type = 'object';

CREATE TEMP VIEW IF NOT EXISTS links AS
SELECT l.id, l.source_id, l.target_id, l.relationship, l.note,
       strftime('%Y-%m-%dT%H:%M:%fZ', l.created_at) AS created_at,
       CAST(strftime('%s', l.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', l.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.links AS l
JOIN temp._query_sql_visible_ids AS source_visible
  ON source_visible.id = l.source_id
JOIN temp._query_sql_visible_ids AS target_visible
  ON target_visible.id = l.target_id;

-- Passage anchors of comment roots, under the comments' own visibility: a
-- comment is a derived artifact visible exactly when its bearer is, and the
-- anchor names that bearer, so both ends must be visible (as for `links`).
-- Body anchors only. The scoped capture provenance travels with the row:
-- `source_event_seq` is the stored content-events MAX at capture (metadata
-- included) and `source_sha256` the captured body digest, so a later live
-- reopen can prove the same recorded range (stored body seq at or before the
-- capture seq with equal SHA) while any later body write invalidates it,
-- even an equal-bytes restore. No other sequence travels here.
CREATE TEMP VIEW IF NOT EXISTS comment_anchors AS
SELECT t.annotation_id, t.target_record_id, t.purpose, t.selectors, t.source_event_seq, t.source_sha256
FROM main.annotation_targets AS t
JOIN temp._query_sql_visible_ids AS comment_visible
  ON comment_visible.id = t.annotation_id
JOIN temp._query_sql_visible_ids AS bearer_visible
  ON bearer_visible.id = t.target_record_id
JOIN main.records AS comment
  ON comment.id = t.annotation_id
WHERE t.source_slot = 'body'
  AND comment.type = 'Annotation' AND comment.kind = 'comment'
  AND comment.deleted_at IS NULL;

CREATE TEMP VIEW IF NOT EXISTS facet_values AS
SELECT f.id, f.record_id, f.key, f.value, f.value_num, f.vocab_ref,
       strftime('%Y-%m-%dT%H:%M:%fZ', f.created_at) AS created_at,
       CAST(strftime('%s', f.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', f.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.facet_values AS f
JOIN temp._query_sql_visible_ids AS visible ON visible.id = f.record_id;

CREATE TEMP VIEW IF NOT EXISTS facet_observations AS
SELECT f.id, f.record_id, f.key, f.value, f.op, f.vocab_ref,
       f.as_of,
       strftime('%Y-%m-%dT%H:%M:%fZ', f.observed_at) AS observed_at,
       CAST(strftime('%s', f.observed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', f.observed_at), 4, 3) AS INTEGER) AS observed_at_ms,
       f.event_seq
FROM main.facet_observations AS f
JOIN temp._query_sql_visible_ids AS visible ON visible.id = f.record_id;

-- Occurrence nodes for facet values whose stored text parses as a JSON object
-- or array. Joining main.facet_value_json_nodes to the caller-filtered
-- temp.facet_values view inherits that view's visibility fence exactly: a node
-- is visible iff its facet row is. `interpretation` is the constant
-- `parsed_text_candidate` because stored text records syntax, not authored type.
CREATE TEMP VIEW IF NOT EXISTS facet_value_json_nodes AS
SELECT n.facet_id, n.ordinal, n.path, n.parent_path, n.parent_ordinal,
       n.member_key, n.array_index, n.depth, n.node_type,
       n.text_value, n.number_text, n.bool_value,
       'parsed_text_candidate' AS interpretation
FROM main.facet_value_json_nodes AS n
JOIN temp.facet_values AS f ON f.id = n.facet_id;

-- Occurrence nodes for facet observations whose stored text parses as a JSON
-- object or array. Joining main.facet_observation_json_nodes to the
-- caller-filtered temp.facet_observations view inherits that view's visibility
-- fence exactly: a node is visible iff its observation row is. The joining
-- observation's identifying `record_id`, `key` and `as_of` are projected onto
-- every node. `interpretation` is the constant `parsed_text_candidate` because
-- stored text records syntax, not authored type.
CREATE TEMP VIEW IF NOT EXISTS facet_observation_json_nodes AS
SELECT n.observation_id, o.record_id, o.key, o.as_of,
       n.ordinal, n.path, n.parent_path, n.parent_ordinal,
       n.member_key, n.array_index, n.depth, n.node_type,
       n.text_value, n.number_text, n.bool_value,
       'parsed_text_candidate' AS interpretation
FROM main.facet_observation_json_nodes AS n
JOIN temp.facet_observations AS o ON o.id = n.observation_id;

-- Occurrence nodes for record bodies whose stored text parses as a JSON
-- object or array. Joining main.record_body_json_nodes to the caller-filtered
-- temp.records view inherits that view's visibility fence exactly: a node is
-- visible iff its record is, so hidden and tombstoned records contribute no
-- rows even though their nodes are retained physically. `interpretation` is
-- the constant `parsed_text_candidate` because stored text records syntax,
-- not authored type.
CREATE TEMP VIEW IF NOT EXISTS record_body_json_nodes AS
SELECT n.record_id, n.ordinal, n.path, n.parent_path, n.parent_ordinal,
       n.member_key, n.array_index, n.depth, n.node_type,
       n.text_value, n.number_text, n.bool_value,
       'parsed_text_candidate' AS interpretation
FROM main.record_body_json_nodes AS n
JOIN temp.records AS r ON r.id = n.record_id;

-- Account/email bindings are caller-owned. No non-identity system has yet
-- completed the explicit exposure audit, so unknown systems fail closed.
CREATE TEMP VIEW IF NOT EXISTS bindings AS
SELECT b.record_id, b.system, b.identifier, b.is_canonical,
       b.url, b.etag,
       strftime('%Y-%m-%dT%H:%M:%fZ', b.last_seen_at) AS last_seen_at,
       CAST(strftime('%s', b.last_seen_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', b.last_seen_at), 4, 3) AS INTEGER) AS last_seen_at_ms
FROM main.bindings AS b
CROSS JOIN temp._query_sql_principal AS principal
JOIN temp._query_sql_visible_ids AS visible ON visible.id = b.record_id
WHERE b.system IN ('account', 'email')
  AND EXISTS (
        SELECT 1 FROM main.bindings AS own_account
        WHERE own_account.record_id = b.record_id
          AND own_account.system = 'account'
          AND own_account.identifier = principal.account_id
          AND own_account.is_canonical = 1
      );

CREATE TEMP VIEW IF NOT EXISTS blobs AS
SELECT blob.id, blob.bytes, blob.mime, blob.size_bytes, blob.sha256,
       blob.original_filename, blob.storage_tier, blob.external_ref,
       strftime('%Y-%m-%dT%H:%M:%fZ', blob.created_at) AS created_at,
       CAST(strftime('%s', blob.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', blob.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.blobs AS blob
WHERE EXISTS (
  SELECT 1
  FROM main.records AS attachment
  JOIN temp._query_sql_visible_ids AS attachment_visible
    ON attachment_visible.id = attachment.id
  JOIN main.facet_values AS blob_ref
    ON blob_ref.record_id = attachment.id
   AND blob_ref.key = 'blob_ref'
   AND blob_ref.value = blob.id
  JOIN main.links AS bearer
    ON bearer.source_id = attachment.id
   AND bearer.relationship = 'part_of'
  JOIN temp._query_sql_visible_ids AS bearer_visible
    ON bearer_visible.id = bearer.target_id
  WHERE attachment.type = 'Document' AND attachment.kind = 'attachment'
);

CREATE TEMP VIEW IF NOT EXISTS vocabularies AS
SELECT id, name,
       strftime('%Y-%m-%dT%H:%M:%fZ', created_at) AS created_at,
       CAST(strftime('%s', created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.vocabularies;

CREATE TEMP VIEW IF NOT EXISTS vocabulary_values AS
SELECT id, vocabulary_id, value, gloss, status, ordinal, terminality,
       metadata, alias_of
FROM main.vocabulary_values;

CREATE TEMP VIEW IF NOT EXISTS vocabulary_value_json_nodes AS
SELECT value_id, ordinal, path, parent_path, parent_ordinal, member_key,
       array_index, depth, node_type, text_value, number_text, bool_value
FROM main.vocabulary_value_json_nodes;

CREATE TEMP VIEW IF NOT EXISTS schema_config AS
SELECT config.id, config.layer, config.name, config.data,
       config.applies_to_collection_id, config.version_lineage,
       strftime('%Y-%m-%dT%H:%M:%fZ', config.created_at) AS created_at,
       CAST(strftime('%s', config.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', config.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.schema_config AS config
WHERE config.applies_to_collection_id IS NULL
   OR EXISTS (
         SELECT 1 FROM temp._query_sql_visible_ids AS visible
         WHERE visible.id = config.applies_to_collection_id
      );

CREATE TEMP VIEW IF NOT EXISTS schema_config_json_nodes AS
SELECT n.config_id, n.ordinal, n.path, n.parent_path, n.parent_ordinal,
       n.member_key, n.array_index, n.depth, n.node_type,
       n.text_value, n.number_text, n.bool_value
FROM main.schema_config_json_nodes AS n
JOIN temp.schema_config AS config ON config.id = n.config_id;

-- Governed receiver-local reduction, deliberately excluding assertion and
-- evidence rows. Every endpoint must resolve to a caller-visible local record;
-- otherwise the relationship is absent, matching the dedicated read surface.
CREATE TEMP VIEW IF NOT EXISTS effective_relationships AS
SELECT rel.relationship_origin_db_id, rel.relationship_id,
       rel.relationship_type, rel.type_definition_id, rel.endpoint_semantics,
       (SELECT json_group_array(json_object(
            'ordinal', ordered.ordinal, 'role', ordered.role,
            'portable_ref', ordered.portable_ref,
            'record_type', ordered.record_type, 'record_kind', ordered.record_kind,
            'record_id', ordered.record_id))
          FROM (SELECT ep.ordinal, ep.role, ep.portable_ref, ep.record_type,
                       ep.record_kind, ep.record_id
                  FROM main.relationship_endpoints ep
                 WHERE ep.relationship_origin_db_id=rel.relationship_origin_db_id
                   AND ep.relationship_id=rel.relationship_id
                 ORDER BY ep.ordinal) AS ordered) AS endpoints,
       eff.effective_state, eff.epistemic_state, eff.support_count,
       eff.contest_count,
       strftime('%Y-%m-%dT%H:%M:%fZ', eff.recomputed_at) AS recomputed_at,
       CAST(strftime('%s', eff.recomputed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', eff.recomputed_at), 4, 3) AS INTEGER) AS recomputed_at_ms
  FROM main.relationships rel
  JOIN main.effective_relationships eff
    ON eff.relationship_origin_db_id=rel.relationship_origin_db_id
   AND eff.relationship_id=rel.relationship_id
 WHERE NOT EXISTS (
       SELECT 1 FROM main.relationship_endpoints hidden
        WHERE hidden.relationship_origin_db_id=rel.relationship_origin_db_id
          AND hidden.relationship_id=rel.relationship_id
          AND (hidden.record_id IS NULL OR NOT EXISTS (
              SELECT 1 FROM temp._query_sql_visible_ids visible
               WHERE visible.id=hidden.record_id)))
   AND EXISTS (
       SELECT 1 FROM main.relationship_endpoints present
        WHERE present.relationship_origin_db_id=rel.relationship_origin_db_id
          AND present.relationship_id=rel.relationship_id);

-- One row per endpoint of a relationship present in the caller's
-- effective_relationships view. Joining on both key columns inherits that
-- view's all-endpoints-visible fence exactly, so an endpoint of a hidden
-- relationship is never exposed and a relationship with any hidden endpoint
-- yields no rows. `ordinal` is the endpoint order.
CREATE TEMP VIEW IF NOT EXISTS effective_relationship_endpoints AS
SELECT rel.relationship_origin_db_id, rel.relationship_id,
       ep.ordinal, ep.role, ep.portable_ref, ep.record_type, ep.record_kind,
       ep.record_id
  FROM temp.effective_relationships AS rel
  JOIN main.relationship_endpoints AS ep
    ON ep.relationship_origin_db_id = rel.relationship_origin_db_id
   AND ep.relationship_id = rel.relationship_id;

-- Caller-relative actor directory. Rows are the actors this execution may
-- attribute under the `get_history` rule who also appear, disclosed, in the
-- caller's own history: the relation never lists a member who has not acted
-- where the caller can see it, so it names nobody `content_events.actor`
-- does not already disclose. The person and
-- name travel only through a caller-visible record bound to the account. The
-- name is read here, at query time, under the caller's deadline and value
-- ceiling, never copied during preparation. The table is filled only when
-- this relation is a statement dependency, so a statement that reads no
-- column of `actors` (`count(*)`) sees it empty (task d8d7e9b).
-- Human versus agent is a property of each event (`channel_kind`, `run_key`),
-- not of the actor, so this relation carries no kind.
-- The WHERE term is load-bearing, not a filter. SQLite flattens this view into
-- the caller's statement and then authorizes any table none of whose columns
-- is used, outside the view's accessor context, which the view-expansion
-- authorizer refuses. Referencing `actor` here keeps a column in use for every
-- statement shape (`count(*)`, self-joins, cross joins), and the column is
-- declared nullable above so the planner cannot drop the term as always true.
-- The history term is an uncorrelated IN list that SQLite materializes once
-- per reference to this view in a statement (a self-join builds it twice).
-- It runs under the caller's deadline and value ceiling like any other read.
CREATE TEMP VIEW IF NOT EXISTS actors AS
SELECT disclosed.actor, disclosed.person_id, person.name AS display_name
  FROM temp._query_sql_disclosable_actors AS disclosed
  LEFT JOIN main.records AS person ON person.id = disclosed.person_id
 WHERE disclosed.actor IS NOT NULL
   AND disclosed.actor IN (SELECT history.actor FROM temp.content_events AS history);

-- Every account this execution may attribute under the `get_history` rule,
-- with the caller-visible person bound to it: the caller's own account, plus
-- each account bound to a person record the caller can see. This is the rule
-- `prepare_disclosable_actors` materialises for `actors`, stated once so the
-- directory and the run relations below cannot disagree. `(system,
-- identifier)` is unique in `bindings`, so an account names at most one
-- person and both UNION arms yield the same pair for a caller bound to a
-- visible person. `person_id` is NULL only for the caller's own account when
-- it has no binding the caller can see. Evaluated at query time, under the
-- caller's deadline and value ceiling, once per reference in a statement.
CREATE TEMP VIEW IF NOT EXISTS _query_sql_disclosable_persons AS
WITH _query_sql_visible_person AS MATERIALIZED (
  SELECT actor_binding.identifier AS actor,
         actor_binding.record_id AS person_id
    FROM main.bindings AS actor_binding
    JOIN temp._query_sql_visible_ids AS person_visible
      ON person_visible.id = actor_binding.record_id
   WHERE actor_binding.system = 'account'
)
SELECT principal.account_id AS actor, own.person_id AS person_id
  FROM temp._query_sql_principal AS principal
  LEFT JOIN _query_sql_visible_person AS own ON own.actor = principal.account_id
UNION
SELECT actor, person_id FROM _query_sql_visible_person;

-- The accounts whose runs this execution may list: every account the
-- `get_history` rule above discloses, except that a guest (`is_member = 0`,
-- the membership fact `agent_activity` admits on) keeps only their own
-- account for now. Another person's runs are member-only, even when the
-- guest can see that person. This narrows the run relations alone. The
-- shared disclosure view, and so `actors`, is unchanged.
CREATE TEMP VIEW IF NOT EXISTS _query_sql_run_principals AS
SELECT disclosed.actor AS account_id, disclosed.person_id
  FROM temp._query_sql_disclosable_persons AS disclosed
  CROSS JOIN temp._query_sql_principal AS principal
 WHERE principal.is_member = 1 OR disclosed.actor = principal.account_id;

-- Durable agent runs of every age, one row per run of an admitted account
-- above, so a hidden run contributes no row and no count. There is no time
-- window and no presence inference (`agent_activity` owns that), and no
-- observation clock is read, so the relation depends only on durable state.
-- The owner travels only as the caller-visible person, never as a raw
-- account id. `reported_model` and `reported_client` are the run's own
-- unverified claims, clamped at admission, and `model_assurance` says so on
-- every row. They are never merged with the attested
-- `content_events.channel_kind`. No sequence or `activity_id` is exposed:
-- tabs page by keyset on (started_at_ms, run_key). Reads nothing but short
-- `agent_runs` columns, never an event payload.
-- Work scales with what the caller may see (anchor lesson 6): the CROSS JOIN
-- keeps the admitted accounts outside, and each account's runs are fetched
-- through `idx_agent_runs_account_started` (pinned with `INDEXED BY`, as in
-- `run_intents` below), so a hidden account's runs are never visited and
-- cannot show in timing or reach the deadline.
CREATE TEMP VIEW IF NOT EXISTS runs AS
SELECT run.run_key,
       admitted.person_id AS principal_person_id,
       CAST(strftime('%s', run.started_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', run.started_at), 4, 3) AS INTEGER) AS started_at_ms,
       CAST(strftime('%s', run.ended_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', run.ended_at), 4, 3) AS INTEGER) AS ended_at_ms,
       run.reported_model,
       CASE WHEN run.reported_mcp_client_name IS NULL THEN NULL
            WHEN run.reported_mcp_client_version IS NULL THEN run.reported_mcp_client_name
            ELSE run.reported_mcp_client_name || '/' || run.reported_mcp_client_version
       END AS reported_client,
       'self_declared' AS model_assurance
  FROM temp._query_sql_run_principals AS admitted
  CROSS JOIN main.agent_runs AS run INDEXED BY idx_agent_runs_account_started
 WHERE run.account_id = admitted.account_id;

-- Each run's `set_intent` declarations in order, for exactly the runs in
-- `runs` (the same admitted accounts): the owner's successful declarations on
-- that run, read the way the `set_intent` briefing lists them (read-log
-- order, declared at the call's start). `ordinal` counts from 1 within a
-- run, so it is a per-run position and never a global sequence. A
-- declaration longer than __MAX_RUN_INTENT_BYTES__ bytes reads as a NULL
-- intent: its size is taken with `octet_length`, which does not load the
-- value, so an oversized declaration can neither fail the statement at the
-- caller value ceiling nor overflow a cell, and its ordinal is still counted.
-- `ordinal` is one linear window pass per run: every declaration of an
-- admitted run is admitted, since admission depends on the run alone, so
-- numbering the admitted rows numbers the whole run. The window sorts only
-- (seq, run_key), and the text is read back by primary key afterwards: a
-- window copies the raw columns its result needs into its sort, which would
-- load an oversized intent before the size check could cap it. The
-- redundant `run_key` join term is load-bearing: `seq` is the rowid alias,
-- which SQLite does not count as a used column, so without a real column in
-- use a column-less statement (`count(*)`) would authorize the read log
-- outside this view's accessor context and be refused. As in `runs`, the
-- CROSS JOIN order keeps work to what the caller may see: admitted accounts,
-- then their runs by `idx_agent_runs_account_started`, then each run's
-- declarations by `idx_read_log_calls_run`, and the text by primary key. The
-- read log is never scanned, so hidden declarations are never visited.
-- `INDEXED BY` is load-bearing: left free, the planner prefers an automatic
-- covering index on the read log, whose construction scans every row. Both
-- indexes are in the canonical DDL and no migration drops them. A read log
-- without its run index reads as empty, like an absent log
-- (`guard_run_intents_source`), and the account index is checked at open.
-- The read log is optional state. When `read_log_calls` or its run index is
-- absent the engine replaces this view, inside the rolled-back governed
-- transaction, with an empty one of the same shape
-- (`guard_run_intents_source`), and the catalog declares the relation
-- best-effort because a standby export strips the log.
CREATE TEMP VIEW IF NOT EXISTS run_intents AS
WITH _query_sql_run_declarations AS (
  SELECT declaration.seq,
         declaration.run_key,
         row_number() OVER (PARTITION BY declaration.run_key
                            ORDER BY declaration.seq) AS ordinal
    FROM temp._query_sql_run_principals AS admitted
    CROSS JOIN main.agent_runs AS run INDEXED BY idx_agent_runs_account_started
    CROSS JOIN main.read_log_calls AS declaration INDEXED BY idx_read_log_calls_run
   WHERE run.account_id = admitted.account_id
     AND declaration.run_key = run.run_key
     AND declaration.actor = run.account_id
     AND declaration.tool = 'set_intent'
     AND declaration.outcome = 'ok'
     AND declaration.intent IS NOT NULL
)
SELECT numbered.run_key,
       numbered.ordinal,
       CASE WHEN octet_length(declared.intent) > __MAX_RUN_INTENT_BYTES__ THEN NULL
            ELSE declared.intent END AS intent,
       CAST(strftime('%s', declared.started_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', declared.started_at), 4, 3) AS INTEGER) AS declared_at_ms
  FROM _query_sql_run_declarations AS numbered
  CROSS JOIN main.read_log_calls AS declared
 WHERE declared.seq = numbered.seq
   AND declared.run_key = numbered.run_key;

-- Minimal run presence derives from durable lifecycle and content evidence.
-- The protected helper contributes disposable capture when it is available;
-- its absence leaves the durable subset intact. Claim tuple updates are
-- excluded here so hiding a claim can never alter presence or ordering.
-- Declared intent is caller-authored disclosure, not verified fact: the view
-- surfaces the latest `set_intent` text only to the declaring account and
-- reports an engine-authored disclosure state beside it, so a withheld intent
-- never reads as an absent one.
CREATE TEMP VIEW IF NOT EXISTS agent_activity AS
WITH _query_sql_agent_activity_durable AS (
  SELECT run.activity_id, run.run_key, run.account_id, run.started_at, run.ended_at,
         observed.declared_intent,
         max(run.started_at,
             coalesce(run.ended_at, run.started_at),
               coalesce((SELECT max(event.created_at)
                           FROM main.content_events event
                           LEFT JOIN main.content_event_claim_meta AS claim_meta
                             ON claim_meta.event_seq = event.seq
                          WHERE event.run_key=run.run_key
                            AND event.actor=run.account_id
                            AND NOT (event.type='record.updated'
                                     AND (COALESCE(claim_meta.has_claimed_by, 1) = 1
                                          OR COALESCE(claim_meta.has_claimed_run, 1) = 1))
                           AND (run.ended_at IS NULL
                                OR julianday(event.created_at)<=julianday(run.ended_at))),
                       run.started_at),
             coalesce(observed.last_observed_at, run.started_at)) AS last_observed_activity_at
    FROM main.agent_runs run
    LEFT JOIN temp._query_sql_activity_observations observed ON observed.run_key=run.run_key
), _query_sql_agent_activity_admitted AS (
  SELECT durable.*,
         member.member_ref,
         principal.account_id AS viewer_account_id,
         principal.observed_at,
         principal.trusted_local_bypass
    FROM _query_sql_agent_activity_durable durable
    CROSS JOIN temp._query_sql_principal principal
    LEFT JOIN temp._query_sql_activity_members member
      ON member.account_id=durable.account_id
   WHERE principal.activity_read=1
      AND principal.is_member=1
      AND (member.member_ref IS NOT NULL
           OR (principal.trusted_local_bypass=1
               AND durable.account_id=principal.account_id))
)
SELECT activity_id,
       run_key,
       coalesce(member_ref, 'native:local-operator') AS principal_ref,
       NULL AS principal_display_name,
       strftime('%Y-%m-%dT%H:%M:%fZ', started_at) AS started_at,
       CAST(strftime('%s', started_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', started_at), 4, 3) AS INTEGER) AS started_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', ended_at) AS ended_at,
       CAST(strftime('%s', ended_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', ended_at), 4, 3) AS INTEGER) AS ended_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at) AS last_observed_activity_at,
       CAST(strftime('%s', last_observed_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at), 4, 3) AS INTEGER) AS last_observed_activity_at_ms,
        strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at, '+5 minutes') AS active_until,
        CAST(strftime('%s', last_observed_activity_at, '+5 minutes') AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at, '+5 minutes'), 4, 3) AS INTEGER) AS active_until_ms,
        CASE WHEN ended_at IS NULL
                   AND julianday(observed_at) < julianday(last_observed_activity_at, '+5 minutes')
             THEN 1 ELSE 0 END AS appears_active,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN NULL
             WHEN account_id = viewer_account_id THEN declared_intent
             ELSE NULL END AS declared_intent,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN 'unavailable'
             WHEN account_id != viewer_account_id THEN 'withheld'
             WHEN declared_intent IS NULL THEN 'none'
             ELSE 'disclosed' END AS declared_intent_state
   FROM _query_sql_agent_activity_admitted
  WHERE julianday(last_observed_activity_at) >= julianday(observed_at, '-24 hours');

-- One caller-visible durable claim event. Release is the first subsequent
-- engine-owned claim-clear update. Exclusive claim state prevents another
-- claim from interleaving before it. Visibility is applied before rows reach
-- logical SQL and never feeds the independent presence relation above.
--
-- Both CTE inputs are engine-populated narrow projections (see the
-- `_query_sql_claim_candidates` contract note). The CTE itself opens no
-- payload: every column it reads is a short identity or timestamp value.
-- The joined `agent_activity` relation is outside that guarantee: its
-- durable CTE still reads `content_events.payload` for run-scoped events
-- under the caller ceiling, so a run-stamped over-limit payload can fail
-- this view through that join. That sibling defect is tracked separately
-- and is out of scope here.
-- The window and records terms below re-apply the population filter on
-- those narrow columns. They disclose exactly what the previous
-- payload-reading form disclosed: NULL-actor rows could never join
-- `agent_runs` and NULL-actor releases could never satisfy the actor
-- disjunction.
CREATE TEMP VIEW IF NOT EXISTS agent_activity_claims AS
WITH _query_sql_agent_activity_claim_events AS (
   SELECT candidate.claim_id, candidate.record_id, candidate.run_key,
          candidate.claim_actor,
          candidate.claimed_by_account,
          candidate.claimed_at,
          (SELECT rc.created_at
             FROM temp._query_sql_claim_releases rc
            WHERE rc.record_id=candidate.record_id AND rc.seq>candidate.seq
              AND ((rc.actor=candidate.claim_actor)
                   OR rc.actor='local')
             ORDER BY rc.seq
             LIMIT 1) AS released_at
     FROM temp._query_sql_claim_candidates candidate
     CROSS JOIN temp._query_sql_principal principal
    WHERE (julianday(candidate.claimed_at)>=julianday(principal.observed_at,'-24 hours')
           OR EXISTS (
                SELECT 1 FROM main.records current
                 WHERE current.id=candidate.record_id
                   AND current.claimed_run_key=candidate.run_key
                   AND current.claimed_at=candidate.claimed_at
           ))
)
SELECT claim.claim_id, run.activity_id, claim.record_id,
       strftime('%Y-%m-%dT%H:%M:%fZ', claim.claimed_at) AS claimed_at,
       CAST(strftime('%s', claim.claimed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', claim.claimed_at), 4, 3) AS INTEGER) AS claimed_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', claim.released_at) AS released_at,
       CAST(strftime('%s', claim.released_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', claim.released_at), 4, 3) AS INTEGER) AS released_at_ms,
       CASE WHEN claim.released_at IS NULL THEN 1 ELSE 0 END AS is_current
  FROM _query_sql_agent_activity_claim_events claim
   JOIN main.agent_runs run ON run.run_key=claim.run_key
                            AND run.account_id=claim.claim_actor
                            AND run.account_id=claim.claimed_by_account
  JOIN temp.agent_activity activity ON activity.activity_id=run.activity_id
  JOIN temp._query_sql_visible_ids visible ON visible.id=claim.record_id
 WHERE run.ended_at IS NULL OR julianday(claim.claimed_at)<=julianday(run.ended_at);

-- This narrow negative-state relation is populated lazily by the Rust
-- expectation evaluator only when caller SQL actually depends on it. The
-- public row intentionally carries no evidence id, count, or diagnostic.
CREATE TEMP VIEW IF NOT EXISTS messages_awaiting_reply AS
SELECT message_id FROM temp._query_sql_messages_awaiting_reply;

-- Materialized only for a statement that reads it, from the same governed
-- snapshot as that statement. No unfiltered meta version or basis is exposed.
-- The non-null predicate is true for every inserted record ID. It keeps a
-- column-less COUNT(*) read inside this view's authorization context.
CREATE TEMP VIEW IF NOT EXISTS record_lifecycle_interpretations AS
SELECT record_id,status,raw,axis_key,axis_label,vocabulary_id,
       vocabulary_name,value_id,canonical,terminality,reason
FROM temp._query_sql_lifecycle_interpretations
WHERE record_id IS NOT NULL;

-- Snapshot-local discovery rows, populated only for a real dependency.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_facet_keys (
  scope_id TEXT, type TEXT, kind TEXT, key TEXT, record_count INTEGER,
  declared INTEGER, value_type TEXT, vocab_ref TEXT, required INTEGER
);
CREATE TEMP VIEW IF NOT EXISTS facet_keys AS
SELECT scope_id,type,kind,key,record_count,declared,value_type,vocab_ref,required
FROM temp._query_sql_facet_keys WHERE type IS NOT NULL;

-- Typed time values: floating dates or UTC epoch millis, end exclusive.
CREATE TEMP VIEW IF NOT EXISTS facet_times AS
SELECT t.record_id, t.key, t.kind, t.all_day, t.start_date, t.end_date,
       t.start_ms, t.end_ms, t.tz, t.tzdb_version
FROM main.facet_times AS t
JOIN temp._query_sql_visible_ids AS visible ON visible.id = t.record_id;

-- Design D6 (task b2583dc). The caller's own live bound Person, resolved as
-- the messaging inbox resolves it (`attention_person_id_in`): the canonical
-- account binding to a live Entity/person, with no View gate. The id only
-- ever meets `owner_id` and mention targets inside the relations below and
-- is never output, so it discloses nothing. Exactly one row, NULL when the
-- caller has no person. `(system, identifier)` is unique in `bindings`, so
-- an account names at most one person.
CREATE TEMP VIEW IF NOT EXISTS _query_sql_my_person AS
SELECT (SELECT account.record_id
          FROM main.bindings AS account
          JOIN main.records AS person ON person.id = account.record_id
         WHERE account.system = 'account'
           AND account.identifier = principal.account_id
           AND account.is_canonical = 1
           AND person.type = 'Entity' AND person.kind = 'person'
           AND person.deleted_at IS NULL
         ORDER BY account.record_id LIMIT 1) AS person_id
  FROM temp._query_sql_principal AS principal;

-- The caller's own state for each Message the caller can see (D6 3.1),
-- private to the caller. One row per visible live Message. Awareness and
-- preferences are read by primary key (caller account, message), so another
-- account's rows are never visited, and the relation has no account,
-- subject, sequence or version column: no join, aggregate or count over it
-- can reach another viewer's state. Work is driven by the visible Messages
-- and scales with nothing the caller cannot see.
-- `stage` is the human lane (`unsurfaced` when the caller has none).
-- `unread` is 1 until the caller opens or acknowledges an unarchived Message
-- whose speaker is not the caller. `is_own` requires the caller's owner Person
-- and no separate speaker fact. `mentioned` is an effective principal @-mention of
-- the caller, the same predicate the inbox uses, read by the mention primary
-- key for this Message alone (the unary plus keeps the planner off the target
-- index, whose leading column would visit every principal mention in the
-- workspace, hidden ones included). `reactable` is 0 for a
-- federated Message, which cannot take reactions. The account is read
-- through scalar subqueries rather than a joined principal row, so every
-- joined table keeps a column in use in every statement shape (`count(*)`).
CREATE TEMP VIEW IF NOT EXISTS my_participants AS
SELECT 'persona:' || p.persona_id AS participant_address, 'persona' AS kind,
       p.persona_id, r.name AS display_name, p.state
  FROM main.personas p
  JOIN main.records r ON r.id=p.persona_id
  JOIN temp._query_sql_visible_ids visible ON visible.id=p.persona_id
 WHERE p.owner_person_id=(SELECT person_id FROM temp._query_sql_my_person) AND r.deleted_at IS NULL;

CREATE TEMP VIEW IF NOT EXISTS message_speakers AS
SELECT s.message_id, s.speaker_kind, 'persona:' || s.persona_id AS speaker_address,
       r.name AS display_name, s.assurance
  FROM temp._query_sql_visible_ids visible
  JOIN main.message_speakers s ON s.message_id=visible.id
  JOIN main.records message ON message.id=s.message_id AND message.type='Message' AND message.deleted_at IS NULL
  LEFT JOIN main.records r ON r.id=s.persona_id;

CREATE TEMP VIEW IF NOT EXISTS deleted_messages AS
SELECT parent.id AS message_id, reply.source_id AS reply_id,
       strftime('%Y-%m-%dT%H:%M:%fZ', parent.deleted_at) AS deleted_at,
       CAST(strftime('%s', parent.deleted_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', parent.deleted_at), 4, 3) AS INTEGER) AS deleted_at_ms
  FROM main.links reply
  JOIN temp._query_sql_visible_ids visible ON visible.id=reply.source_id
  JOIN main.records source ON source.id=reply.source_id AND source.type='Message' AND source.deleted_at IS NULL
  JOIN main.records parent ON parent.id=reply.target_id AND parent.type='Message' AND parent.deleted_at IS NOT NULL
 CROSS JOIN temp._query_sql_principal principal
 WHERE reply.relationship='reply_to'
   -- Seeing the reply is not enough: the parent must itself have been visible
   -- to the caller before the tombstone. A Message is its own authorization
   -- subject, so this is `_query_sql_visible_records` evaluated for the
   -- parent without its `deleted_at IS NULL` term.
   AND EXISTS (SELECT 1 FROM main.record_policies AS explicit_policy
                WHERE explicit_policy.record_id = parent.policy_anchor_id)
   AND (principal.trusted_local_bypass = 1
        OR EXISTS (SELECT 1 FROM main.bindings AS owner_account
                    WHERE owner_account.record_id = parent.owner_id
                      AND owner_account.system = 'account'
                      AND owner_account.identifier = principal.account_id
                      AND owner_account.is_canonical = 1)
        OR parent.policy_anchor_id IN (
             SELECT entry.policy_anchor_id
               FROM main.policy_entries AS entry
              CROSS JOIN temp._query_sql_principal AS anchor_principal
              WHERE entry.effect = 'allow'
                AND entry.capability IN ('view', 'edit', 'manage')
                AND ((entry.subject_kind = 'members'
                      AND entry.subject_id = 'native:members'
                      AND anchor_principal.is_member = 1)
                     OR (entry.subject_kind = 'account'
                         AND entry.subject_id = anchor_principal.account_id))));

CREATE TEMP VIEW IF NOT EXISTS my_message_state AS
SELECT message.id AS message_id,
       COALESCE(awareness.stage, 'unsurfaced') AS stage,
       CASE WHEN message.owner_id = (SELECT me.person_id FROM temp._query_sql_my_person AS me) AND NOT EXISTS(SELECT 1 FROM main.message_speakers s WHERE s.message_id=message.id) THEN 0
            WHEN preference.archived = 1 THEN 0
            WHEN preference.unread_override IS NOT NULL THEN preference.unread_override
            WHEN awareness.stage IN ('opened', 'acknowledged') THEN 0
            ELSE 1 END AS unread,
       CASE WHEN message.owner_id = (SELECT me.person_id FROM temp._query_sql_my_person AS me) AND NOT EXISTS(SELECT 1 FROM main.message_speakers s WHERE s.message_id=message.id)
            THEN 1 ELSE 0 END AS is_own,
       EXISTS (SELECT 1
                 FROM main.message_mentions AS mention
                 JOIN main.bindings AS target
                   ON target.record_id = mention.target_record_id
                  AND target.system = 'account'
                  AND target.is_canonical = 1
                WHERE mention.message_id = message.id
                  AND +mention.target_kind = 'principal'
                  AND +mention.effective = 1
                  AND target.identifier = (SELECT account_id FROM temp._query_sql_principal)) AS mentioned,
       COALESCE(preference.attention_flag, 0) AS flagged,
       COALESCE(preference.muted, 0) AS muted,
       COALESCE(preference.archived, 0) AS archived,
       strftime('%Y-%m-%dT%H:%M:%fZ', preference.snoozed_until) AS snoozed_until,
       CAST(strftime('%s', preference.snoozed_until) AS INTEGER) * 1000 + CAST(substr(strftime('%f', preference.snoozed_until), 4, 3) AS INTEGER) AS snoozed_until_ms,
       NOT EXISTS (SELECT 1 FROM main.destination_message_ingest AS ingest
                    WHERE ingest.message_id = message.id) AS reactable
  FROM temp._query_sql_visible_ids AS visible
  CROSS JOIN main.records AS message
  LEFT JOIN main.human_message_awareness AS awareness
         ON awareness.subject_account_id = (SELECT account_id FROM temp._query_sql_principal)
        AND awareness.message_id = message.id
  LEFT JOIN main.message_preferences AS preference
         ON preference.subject_account_id = (SELECT account_id FROM temp._query_sql_principal)
        AND preference.message_id = message.id
 WHERE message.id = visible.id
   AND message.type = 'Message' AND message.deleted_at IS NULL;

-- Sources that mention the caller (D6 3.2), private to the caller, one row
-- per (source, via). `principal` rows are effective principal @-mentions of
-- the caller on visible live Messages, the inbox predicate again, with
-- `seen` 1 once the caller has opened or acknowledged the Message.
-- `reference` rows reuse the `record_mentions` projection: a body reference
-- counts exactly when `get_record` would resolve it to the caller, that is
-- when its lookup key is one of the caller person's incoming keys
-- (`mention_incoming_lookup_keys`: the canonical id plus every undashed and
-- dashed 6 to 31 hex prefix) and it has exactly one caller-visible
-- candidate (`finish_mentions`). The caller's person must itself be visible
-- to the caller, and a hidden record sharing the prefix is never a rival.
-- Native tracks no seen state for references, so `seen` is NULL there.
-- `mentioned_at` is the Message's creation, or the body version that wrote
-- the reference (the `record_id` term on that read is load-bearing, as in
-- `run_intents`). Both arms are driven from the caller-visible set, which is
-- already materialized in the indexed TEMP visible-id table and kept
-- outermost by CROSS JOIN (otherwise the planner
-- may start from every Message and test visibility last, visiting a hidden
-- Message's mentions first): mentions are read per visible source by index, and
-- rival candidates for a prefix come from the visible set alone, so hidden
-- sources, hidden mentions and hidden look-alike ids are never visited.
-- The visible CTE stays NOT MATERIALIZED: copying the indexed TEMP table
-- into an unindexed CTE forces correlated page probes to scan every visible
-- id once per row. The underlying table already freezes visibility for the
-- request, while its primary key lets source-id predicates stay selective.
-- The final WHERE term is load-bearing, as in `actors`: the two arms form a
-- compound that SQLite cannot flatten into an aggregate (`count(*)`), and a
-- FROM item none of whose columns is used is authorized outside this view's
-- accessor context, so the outer select keeps a column of it in use.
CREATE TEMP VIEW IF NOT EXISTS my_mentions AS
WITH RECURSIVE
_query_sql_mention_visible(id) AS NOT MATERIALIZED (
  SELECT id FROM temp._query_sql_visible_ids
),
_query_sql_mention_self(person_id) AS MATERIALIZED (
  SELECT me.person_id
    FROM temp._query_sql_my_person AS me
   WHERE me.person_id GLOB '__CANONICAL_UUID_GLOB__'
     AND me.person_id IN (SELECT id FROM _query_sql_mention_visible)
),
_query_sql_mention_prefix(len) AS (
  SELECT 6 UNION ALL SELECT len + 1 FROM _query_sql_mention_prefix WHERE len < 31
),
_query_sql_mention_key(lookup_key, range_start) AS MATERIALIZED (
  SELECT self.person_id, NULL FROM _query_sql_mention_self AS self
  UNION
  SELECT substr(replace(self.person_id, '-', ''), 1, prefix.len),
         substr(self.person_id, 1, prefix.len + (prefix.len > 8) + (prefix.len > 12)
                                   + (prefix.len > 16) + (prefix.len > 20))
    FROM _query_sql_mention_self AS self
    CROSS JOIN _query_sql_mention_prefix AS prefix
  UNION
  SELECT substr(self.person_id, 1, prefix.len + (prefix.len > 8) + (prefix.len > 12)
                                   + (prefix.len > 16) + (prefix.len > 20)),
         substr(self.person_id, 1, prefix.len + (prefix.len > 8) + (prefix.len > 12)
                                   + (prefix.len > 16) + (prefix.len > 20))
    FROM _query_sql_mention_self AS self
    CROSS JOIN _query_sql_mention_prefix AS prefix
),
_query_sql_mention_rivals(id) AS MATERIALIZED (
  SELECT rival.id
    FROM _query_sql_mention_visible AS rival
    CROSS JOIN _query_sql_mention_self AS self
   WHERE rival.id >= substr(self.person_id, 1, 6)
     AND rival.id < substr(self.person_id, 1, 6) || 'g'
     AND rival.id <> self.person_id
     AND rival.id GLOB '__CANONICAL_UUID_GLOB__'
),
_query_sql_mention_reference(source_id, source_event_seq) AS (
  SELECT reference.source_id, max(reference.source_event_seq)
    FROM _query_sql_mention_visible AS visible_source
    CROSS JOIN main.record_mentions AS reference INDEXED BY idx_record_mentions_source
    JOIN _query_sql_mention_key AS mention_key ON mention_key.lookup_key = reference.lookup_key
   WHERE reference.source_id = visible_source.id
     AND (mention_key.range_start IS NULL
          OR NOT EXISTS (SELECT 1 FROM _query_sql_mention_rivals AS rival
                          WHERE rival.id >= mention_key.range_start
                            AND rival.id < mention_key.range_start || 'g'))
   GROUP BY reference.source_id
),
_query_sql_mention_rows(source_id, source_kind, via, own_source, mentioned_at, mentioned_at_ms, seen) AS (
SELECT message.id AS source_id,
       'message' AS source_kind,
       'principal' AS via,
       CASE WHEN message.owner_id = (SELECT me.person_id FROM temp._query_sql_my_person AS me)
                 AND NOT EXISTS(SELECT 1 FROM main.message_speakers s WHERE s.message_id=message.id)
            THEN 1 ELSE 0 END AS own_source,
       strftime('%Y-%m-%dT%H:%M:%fZ', message.created_at) AS mentioned_at,
       CAST(strftime('%s', message.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', message.created_at), 4, 3) AS INTEGER) AS mentioned_at_ms,
       CASE WHEN awareness.stage IN ('opened', 'acknowledged') THEN 1 ELSE 0 END AS seen
  FROM _query_sql_mention_visible AS visible_message
  CROSS JOIN main.records AS message
  LEFT JOIN main.human_message_awareness AS awareness
         ON awareness.subject_account_id = (SELECT account_id FROM temp._query_sql_principal)
        AND awareness.message_id = message.id
 WHERE message.id = visible_message.id
   AND message.type = 'Message' AND message.deleted_at IS NULL
   AND EXISTS (SELECT 1
                 FROM main.message_mentions AS mention
                 JOIN main.bindings AS target
                   ON target.record_id = mention.target_record_id
                  AND target.system = 'account'
                  AND target.is_canonical = 1
                WHERE mention.message_id = message.id
                  AND +mention.target_kind = 'principal'
                  AND +mention.effective = 1
                  AND target.identifier = (SELECT account_id FROM temp._query_sql_principal))
UNION ALL
SELECT source.id AS source_id,
       CASE WHEN source.type = 'Message' THEN 'message' ELSE 'record' END AS source_kind,
       'reference' AS via,
       CASE WHEN source.owner_id = (SELECT me.person_id FROM temp._query_sql_my_person AS me)
                 AND (source.type <> 'Message' OR NOT EXISTS(SELECT 1 FROM main.message_speakers s WHERE s.message_id=source.id))
            THEN 1 ELSE 0 END AS own_source,
       strftime('%Y-%m-%dT%H:%M:%fZ', written.created_at) AS mentioned_at,
       CAST(strftime('%s', written.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', written.created_at), 4, 3) AS INTEGER) AS mentioned_at_ms,
       NULL AS seen
  FROM _query_sql_mention_reference AS referenced
  JOIN main.records AS source ON source.id = referenced.source_id
  LEFT JOIN main.content_events AS written
         ON written.seq = referenced.source_event_seq
        AND written.record_id = referenced.source_id
 WHERE source.deleted_at IS NULL
)
SELECT mention_row.source_id, mention_row.source_kind, mention_row.via, mention_row.own_source,
       mention_row.mentioned_at, mention_row.mentioned_at_ms, mention_row.seen
  FROM _query_sql_mention_rows AS mention_row
 WHERE mention_row.source_id IS NOT NULL;

-- Current GFM task-list items are visible only with their owning record.
-- Keep checked, quoted and ordered rows so callers can decide which task
-- shapes they need. The physical source-event coordinate never travels.
CREATE TEMP VIEW IF NOT EXISTS body_task_items AS
SELECT t.record_id, t.item_index, t.marker, t.checked, t.in_quote,
       t.start_offset, t.end_offset
FROM main.body_task_items AS t
JOIN temp._query_sql_visible_ids AS visible ON visible.id = t.record_id;

-- Serving executor catalogue rows for catalog_operations. Populated once
-- per execution from the trusted request snapshot (ad-hoc online executor
-- query_sql only). Every other entry point refuses the relation before
-- reading it, so an empty table here is never served as an empty success.
-- A table (not a view) so every read shape fires a table-read callback.
-- Named-column reads observe and populate, while column-less aggregates
-- meet the same validator refusal as the other staged temp tables.
CREATE TEMP TABLE IF NOT EXISTS catalog_operations (
  executor TEXT, operation TEXT, surface TEXT, access TEXT,
  plan_required INTEGER, direct_execution_enabled INTEGER,
  contract_version TEXT, contract_digest TEXT, source_tool TEXT,
  selector_field TEXT, selector_value TEXT, advertised_directly INTEGER
);
"#;

/// GLOB pattern matching exactly `record_ref::is_canonical_uuid`: 36 bytes,
/// lowercase hex, dashes at 8, 13, 18 and 23.
fn canonical_uuid_glob() -> String {
    [8, 4, 4, 4, 12]
        .iter()
        .map(|len| "[0-9a-f]".repeat(*len))
        .collect::<Vec<_>>()
        .join("-")
}

fn temp_contract() -> String {
    let mut contract = TEMP_CONTRACT
        .replace(
            "__MAX_DERIVED_BEARER_DEPTH__",
            &crate::authorization::MAX_DERIVED_BEARER_DEPTH.to_string(),
        )
        .replace(
            "__MAX_RUN_INTENT_BYTES__",
            &MAX_RUN_INTENT_BYTES.to_string(),
        )
        .replace("__CANONICAL_UUID_GLOB__", &canonical_uuid_glob());
    // The served catalog is generated from LOGICAL_RELATIONS (E2 I-2), so
    // the rows an agent reads always match the admission catalog.
    for statement in sql_contract::catalog_view_statements(true, false) {
        contract.push_str(&statement);
        contract.push_str(";\n");
    }
    contract
}

/// Install the governed TEMP contract as one script rather than one call per
/// statement (task `9be4011`). SQLite prepares and runs the statements one at
/// a time, in order, and stops at the first failure, so a failed install has
/// applied exactly the statements before the failing one, as the call-per-
/// statement loop did. One script spares 88 separate prepares, statement-cache
/// entries and connection round trips, which measured as most of a governed
/// read's cost.
async fn install_temp_contract(connection: &mut sqlx::SqliteConnection) -> sqlx::Result<()> {
    sqlx::query(frozen_temp_contract_batch())
        .persistent(false)
        .execute(connection)
        .await?;
    Ok(())
}

/// How one governed execution in a caller's transaction treats the TEMP
/// contract.
#[derive(Clone, Copy)]
enum ContractMode<'db> {
    /// Install before the statement and drop after it (every caller except
    /// a [`GovernedSqlSession`]).
    PerCall,
    /// Already installed by a [`GovernedSqlSession`], which drops it once.
    Session(&'db Db),
}

/// Every table of the TEMP contract, emptied at the start of each execution
/// in a session. A per-call install starts from freshly created, empty
/// tables; a session's later executions must start from the same state.
const SESSION_EXECUTION_RESET: &str = "\
DELETE FROM temp._query_sql_principal;
DELETE FROM temp.catalog_operations;
DELETE FROM temp._query_sql_visible_ids;
DELETE FROM temp._query_sql_messages_awaiting_reply;
DELETE FROM temp._query_sql_lifecycle_interpretations;
DELETE FROM temp._query_sql_facet_keys;
DELETE FROM temp._query_sql_activity_members;
DELETE FROM temp._query_sql_activity_observations;
DELETE FROM temp._query_sql_activity_capture;
DELETE FROM temp._query_sql_claim_candidates;
DELETE FROM temp._query_sql_claim_releases;
DELETE FROM temp._query_sql_disclosable_actors;
DELETE FROM temp._query_sql_reaction_winners;
";

/// One governed transaction running several SQL executions under a single
/// TEMP contract install (task `9be4011`). Installing and dropping the
/// contract is most of a governed execution's cost, so a caller with
/// several statements for one snapshot pays it once.
///
/// The contract's views shadow main table names for unqualified SQL, so
/// while it is installed no domain read may run on the transaction. The
/// session enforces that by owning the transaction: nothing but
/// [`execute`](Self::execute) can reach it until [`finish`](Self::finish)
/// drops the contract and hands it back. Run gate and other domain reads
/// before [`begin`](Self::begin) or after `finish`.
///
/// If the session is dropped instead (an error or a cancelled future), the
/// transaction rolls back, which undoes the contract's in-transaction
/// creation, and the governed pool's release hook drops anything left on
/// the connection before it is reused.
pub(crate) struct GovernedSqlSession<'db, 't> {
    db: &'db Db,
    transaction: sqlx::Transaction<'t, Sqlite>,
}

impl<'db, 't> GovernedSqlSession<'db, 't> {
    /// Install the contract on `transaction` and take it over.
    pub(crate) async fn begin(
        db: &'db Db,
        mut transaction: sqlx::Transaction<'t, Sqlite>,
    ) -> Result<Self> {
        install_temp_contract(&mut transaction).await?;
        Ok(Self { db, transaction })
    }

    /// One governed execution, exactly as
    /// [`query_sql_request_in_with_row_limit_observed`] runs it, without
    /// installing or dropping the contract.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute(
        &mut self,
        principal: QueryPrincipal,
        request: QuerySqlRequest,
        row_limit: i64,
        allowance: sql_contract::FunctionAllowance,
        replay_clock: Option<i64>,
        vm_callbacks: Option<Arc<AtomicU64>>,
        apply_default_order: bool,
    ) -> Result<(SqlResult, GovernedSqlObservation)> {
        query_sql_request_in_with_row_limit_scoped(
            &mut self.transaction,
            principal,
            request,
            row_limit,
            allowance,
            replay_clock,
            vm_callbacks,
            apply_default_order,
            &[],
            ContractMode::Session(self.db),
        )
        .await
    }

    /// Drop the contract and hand the transaction back for ordinary reads.
    pub(crate) async fn finish(mut self) -> Result<sqlx::Transaction<'t, Sqlite>> {
        cleanup_query_sql_temp_contract(&mut self.transaction).await?;
        Ok(self.transaction)
    }

    /// End the transaction without reading through it again, after an
    /// execution failed. The rollback undoes the contract's creation, which
    /// happened inside this transaction; the release hook covers the rest.
    pub(crate) async fn abandon(self) {
        let _ = self.transaction.rollback().await;
    }

    /// The transaction with the contract installed, for tests that show
    /// what an unqualified read would see during a session.
    #[cfg(test)]
    pub(crate) fn transaction_for_test(&mut self) -> &mut sqlx::Transaction<'t, Sqlite> {
        &mut self.transaction
    }
}

/// [`cleanup_query_sql_temp_contract`]'s drops, in its order, as one script.
fn temp_contract_teardown_script() -> &'static str {
    static SCRIPT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| {
        // `catalog_operations` stages per-execution snapshot rows in a
        // table (so column-less shapes meet the staged-table refusal
        // instead of constant-folding past observation); dropping it as a
        // view would fail, so it is excluded from the view loop and
        // dropped with the tables below.
        let views = sql_contract::LOGICAL_RELATIONS
            .iter()
            .rev()
            .map(|relation| relation.name)
            .filter(|name| *name != "catalog_operations")
            .chain([
                "_query_sql_my_person",
                "_query_sql_run_principals",
                "_query_sql_disclosable_persons",
                "_query_sql_visible_records",
                "_query_sql_authorization_subjects",
            ])
            .map(|name| format!("DROP VIEW IF EXISTS temp.{name};\n"));
        let tables = [
            "catalog_operations",
            "_query_sql_messages_awaiting_reply",
            "_query_sql_lifecycle_interpretations",
            "_query_sql_facet_keys",
            "_query_sql_principal",
            "_query_sql_activity_observations",
            "_query_sql_activity_capture",
            "_query_sql_activity_members",
            "_query_sql_claim_candidates",
            "_query_sql_claim_releases",
            "_query_sql_disclosable_actors",
            "_query_sql_visible_ids",
            "_query_sql_reaction_winners",
        ]
        .map(|name| format!("DROP TABLE IF EXISTS temp.{name};\n"));
        views.chain(tables).collect()
    })
}

fn facet_key_groups_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let excluded = crate::schema::SPINE_FACET_KEYS
            .iter()
            .chain(crate::schema::ENGINE_RESERVED_FACET_KEYS.iter())
            .map(|key| format!("'{}'", key.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "SELECT r.type,r.kind,
            CASE WHEN r.home_id IN (
                SELECT applies_to_collection_id FROM temp.schema_config
                WHERE applies_to_collection_id IS NOT NULL
            ) THEN r.home_id END AS scope_home_id,
            f.key,count(DISTINCT f.record_id) AS n
            FROM temp.facet_values f JOIN temp.records r ON r.id=f.record_id
            WHERE f.key NOT IN ({excluded})
            GROUP BY r.type,r.kind,scope_home_id,f.key LIMIT 50001"
        )
    })
}

#[cfg(test)]
tokio::task_local! {
    static FACET_TEST_EXHAUST_AFTER_POPULATION: bool;
}

fn check_facet_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(governed_sql_timeout())
    } else {
        Ok(())
    }
}

/// Build discovery from this execution's logical views, after visibility (and
/// any alpha-tab record scope) has been applied. Never read physical facets.
async fn populate_facet_keys(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    deadline: Instant,
) -> Result<()> {
    // Population precedes the statement's own handler on every entry path.
    // Bound aggregate work too, including work before the first grouped row.
    transaction
        .lock_handle()
        .await?
        .set_progress_handler(PROGRESS_OPS, move || Instant::now() < deadline);
    let result = populate_facet_keys_inner(transaction, deadline).await;
    transaction.lock_handle().await?.remove_progress_handler();
    #[cfg(test)]
    if result.is_ok()
        && FACET_TEST_EXHAUST_AFTER_POPULATION
            .try_with(|enabled| *enabled)
            .unwrap_or(false)
    {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    }
    match result {
        Err(error)
            if error
                .to_string()
                .to_ascii_lowercase()
                .contains("interrupted") =>
        {
            Err(governed_sql_timeout())
        }
        other => other,
    }
}

async fn populate_facet_keys_inner(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    deadline: Instant,
) -> Result<()> {
    use super::field_definitions::{build_fields, BuildError, BuildLimits};
    let limits = BuildLimits::default();
    let too_large = || {
        sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            "facet_keys discovery snapshot exceeds its input budget",
        )
    };
    // Bound raw cells before parsing/cloning the schema snapshot. This also
    // keeps unrelated oversized schema data from exhausting adapter memory.
    let (n, bytes, cell): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(length(CAST(data AS BLOB))),0),
                coalesce(max(length(CAST(data AS BLOB))),0) FROM temp.schema_config",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if n > limits.input_rows as i64
        || bytes > limits.input_bytes as i64
        || cell > limits.cell_bytes as i64
    {
        return Err(too_large());
    }
    let rows = super::cascade::schema_config_rows_in(transaction).await?;
    let fields = build_fields(&rows, &[], &[], limits, deadline).map_err(|error| match error {
        BuildError::Timeout => sql_contract::categorized_error(
            QuerySqlErrorCategory::Timeout,
            "facet_keys discovery timed out",
        ),
        BuildError::ResultTooLarge(_) => too_large(),
        BuildError::InvalidInput(reason) => contract_violation(format!("facet_keys: {reason}")),
    })?;
    type Key = (Option<String>, String, Option<String>, String);
    type Metadata = (Option<String>, Option<String>, Option<bool>);
    let allowed = |key: &str| {
        !crate::schema::SPINE_FACET_KEYS.contains(&key)
            && !crate::schema::ENGINE_RESERVED_FACET_KEYS.contains(&key)
    };
    let mut discovered: BTreeMap<Key, (i64, Metadata)> = BTreeMap::new();
    for field in fields.definitions {
        if !allowed(&field.key) {
            continue;
        }
        discovered.insert(
            (
                field.context.scope_id,
                field.context.r#type,
                field.context.kind,
                field.key,
            ),
            (
                0,
                (
                    field.constraint.declared_type,
                    field.constraint.vocab_ref,
                    Some(field.constraint.required),
                ),
            ),
        );
    }
    // Group by home so an anchored declaration counts only direct members.
    // NULL kind in discovery deliberately means a type-wide aggregate, not
    // only records whose stored kind happens to be NULL.
    let mut groups = sqlx::query(facet_key_groups_sql()).fetch(&mut **transaction);
    let mut group_count = 0;
    let mut input_bytes = 0;
    let mut type_counts: BTreeMap<(String, String), i64> = BTreeMap::new();
    while let Some(row) = groups.try_next().await? {
        group_count += 1;
        if group_count > limits.input_rows || discovered.len() > limits.emitted_rows {
            return Err(too_large());
        }
        if Instant::now() >= deadline {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "facet_keys discovery timed out",
            ));
        }
        let key: String = row.try_get("key")?;
        if !allowed(&key) {
            continue;
        }
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let home: Option<String> = row.try_get("scope_home_id")?;
        let n: i64 = row.try_get("n")?;
        input_bytes += record_type.len()
            + kind.as_ref().map_or(0, String::len)
            + home.as_ref().map_or(0, String::len)
            + key.len()
            + 64;
        if input_bytes > limits.input_bytes {
            return Err(too_large());
        }
        let global = (None, record_type.clone(), kind.clone(), key.clone());
        let wildcard = (None, record_type.clone(), None, key.clone());
        *type_counts
            .entry((record_type.clone(), key.clone()))
            .or_default() += n;
        let metadata = discovered
            .get(&global)
            .or_else(|| discovered.get(&wildcard))
            .map(|(_, metadata)| metadata.clone())
            .unwrap_or((None, None, None));
        discovered.entry(global.clone()).or_insert((0, metadata)).0 += n;
        if let Some(home) = home {
            let scoped = (Some(home), record_type, kind.clone(), key);
            if let Some(row) = discovered.get_mut(&scoped) {
                row.0 += n;
            }
            if kind.is_some() {
                let wildcard = (scoped.0, scoped.1, None, scoped.3);
                if let Some(row) = discovered.get_mut(&wildcard) {
                    row.0 += n;
                }
            }
        }
    }
    drop(groups);
    for ((record_type, key), count) in type_counts {
        discovered
            .entry((None, record_type, None, key))
            .or_insert((0, (None, None, None)))
            .0 = count;
    }
    if discovered.len() > limits.emitted_rows {
        return Err(too_large());
    }
    let mut emitted_bytes = 0;
    for ((scope, record_type, kind, key), (count, (value_type, vocab_ref, required))) in discovered
    {
        emitted_bytes += scope.as_ref().map_or(0, String::len)
            + record_type.len()
            + kind.as_ref().map_or(0, String::len)
            + key.len()
            + value_type.as_ref().map_or(0, String::len)
            + vocab_ref.as_ref().map_or(0, String::len)
            + 64;
        if emitted_bytes > limits.emitted_bytes {
            return Err(too_large());
        }
        if Instant::now() >= deadline {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "facet_keys discovery timed out",
            ));
        }
        sqlx::query("INSERT INTO temp._query_sql_facet_keys(scope_id,type,kind,key,record_count,declared,value_type,vocab_ref,required) VALUES (?,?,?,?,?,?,?,?,?)")
            .bind(scope).bind(record_type).bind(kind).bind(key).bind(count)
            .bind(required.is_some()).bind(value_type).bind(vocab_ref).bind(required)
            .execute(&mut **transaction).await?;
    }
    Ok(())
}

/// Populate caller-relative lifecycle meaning from the same pinned SQLite
/// transaction as the eventual SQL statement. Recompute per referenced read:
/// no global meta sequence, policy version, or hidden schema hash is served.
async fn populate_lifecycle_interpretations(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<()> {
    use super::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};

    let visible_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM temp._query_sql_visible_ids")
        .fetch_one(&mut **transaction)
        .await?;
    if visible_count > MAX_LIFECYCLE_VISIBLE_RECORDS {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!(
                "record_lifecycle_interpretations requires materializing {visible_count} visible records, above its {MAX_LIFECYCLE_VISIBLE_RECORDS}-record limit; use get_record for a specific record"
            ),
        ));
    }
    // temp.schema_config is already filtered by this read's staged visible
    // IDs. Running the ordinary authorization resolver a second time here
    // would resolve through TEMP logical shadows and incorrectly discard an
    // owner-visible anchored row.
    let schema_rows = super::cascade::schema_config_rows_in(transaction).await?;
    let interpreter = LifecycleInterpreter::load_from_connection(transaction, schema_rows).await?;
    type LifecycleRecordRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let records: Vec<LifecycleRecordRow> = sqlx::query_as(
        "SELECT r.id,r.type,r.kind,r.home_id,r.lifecycle
               FROM main.records AS r
               JOIN temp._query_sql_visible_records AS visible ON visible.id=r.id
              ORDER BY r.id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    for (record_id, record_type, kind, home_id, raw) in records {
        let (
            status,
            raw,
            axis_key,
            axis_label,
            vocabulary_id,
            vocabulary_name,
            value_id,
            canonical,
            terminality,
            reason,
        ) = match interpreter.interpret(
            &record_type,
            kind.as_deref(),
            home_id.as_deref(),
            raw.as_deref(),
        ) {
            LifecycleInterpretation::Governed(value) => (
                "governed",
                Some(value.value.raw),
                Some(value.axis.key),
                Some(value.axis.label),
                Some(value.vocabulary.id),
                Some(value.vocabulary.name),
                Some(value.value.id),
                Some(value.value.canonical),
                Some(value.terminality),
                None,
            ),
            LifecycleInterpretation::Absent(value) => {
                let (axis_key, axis_label) = value
                    .axis
                    .map(|axis| (Some(axis.key), Some(axis.label)))
                    .unwrap_or((None, None));
                let (vocabulary_id, vocabulary_name) = value
                    .vocabulary
                    .map(|vocabulary| (Some(vocabulary.id), Some(vocabulary.name)))
                    .unwrap_or((None, None));
                (
                    "absent",
                    None,
                    axis_key,
                    axis_label,
                    vocabulary_id,
                    vocabulary_name,
                    None,
                    None,
                    None,
                    None,
                )
            }
            LifecycleInterpretation::Unclassified(value) => (
                "unclassified",
                Some(value.raw),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(value.reason.to_string()),
            ),
        };
        sqlx::query(
            "INSERT INTO temp._query_sql_lifecycle_interpretations
             (record_id,status,raw,axis_key,axis_label,vocabulary_id,vocabulary_name,
              value_id,canonical,terminality,reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(record_id)
        .bind(status)
        .bind(raw)
        .bind(axis_key)
        .bind(axis_label)
        .bind(vocabulary_id)
        .bind(vocabulary_name)
        .bind(value_id)
        .bind(canonical)
        .bind(terminality)
        .bind(reason)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Remove the governed projection before a caller-owned transaction resumes
/// ordinary domain reads, including when lifecycle admission fails early.
async fn cleanup_query_sql_temp_contract(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<()> {
    // One script, stopping at the first failure like the old per-statement
    // loop (see `install_temp_contract`).
    sqlx::query(temp_contract_teardown_script())
        .persistent(false)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// The second prepare contains only public names and columns in TEMP. It has
/// no main schema at all, structurally rejecting `main.records`, raw relations,
/// and the colliding-CTE accessor spoof that defeats a view-aware callback.
pub(crate) const STRICT_LOGICAL_SCHEMA: &str = r#"
CREATE TEMP TABLE catalog_view_definitions(relation_name TEXT,view_id TEXT,revision_id TEXT,definition_sha256 TEXT,schema_sha256 TEXT,origin TEXT,description TEXT,scope_json TEXT,source_pins_json TEXT,dependencies_json TEXT,columns_json TEXT);

CREATE TEMP TABLE records (
  id TEXT, type TEXT, kind TEXT, name TEXT, body TEXT, home_id TEXT,
  lifecycle TEXT, persistence TEXT, maturity TEXT, summary TEXT,
  is_current INTEGER, successor_count INTEGER,
  last_activity_at TEXT, last_activity_at_ms INTEGER,
  created_at TEXT, created_at_ms INTEGER,
  updated_at TEXT, updated_at_ms INTEGER,
  deleted_at TEXT, deleted_at_ms INTEGER, archived INTEGER
);
CREATE TEMP TABLE record_lifecycle_interpretations (
  record_id TEXT, status TEXT, raw TEXT, axis_key TEXT, axis_label TEXT,
  vocabulary_id TEXT, vocabulary_name TEXT, value_id TEXT, canonical TEXT,
  terminality TEXT, reason TEXT
);
CREATE TEMP TABLE content_events (
  local_seq INTEGER, id TEXT, record_id TEXT, type TEXT,
  actor TEXT, run_key TEXT, parent_key TEXT, channel_kind TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE content_event_apps (
  event_id TEXT, record_id TEXT, package TEXT, version TEXT,
  install_event_id TEXT, assertion TEXT
);
CREATE TEMP TABLE body_blocks (
  record_id TEXT, block_index INTEGER, chunk_index INTEGER, chunk_count INTEGER,
  heading_path TEXT, block_kind TEXT, text TEXT,
  start_offset INTEGER, end_offset INTEGER
);
CREATE TEMP TABLE body_block_headings (
  record_id TEXT, block_index INTEGER, chunk_index INTEGER, heading_index INTEGER,
  depth INTEGER, title TEXT, title_truncated INTEGER, heading_block_index INTEGER
);
CREATE TEMP TABLE links (
  id TEXT, source_id TEXT, target_id TEXT, relationship TEXT, note TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE facet_values (
  id TEXT, record_id TEXT, key TEXT, value TEXT, value_num REAL,
  vocab_ref TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE facet_observations (
  id TEXT, record_id TEXT, key TEXT, value TEXT, op TEXT, vocab_ref TEXT,
  as_of TEXT, observed_at TEXT, observed_at_ms INTEGER, event_seq INTEGER
);
CREATE TEMP TABLE facet_value_json_nodes (
  facet_id TEXT, ordinal INTEGER, path TEXT, parent_path TEXT,
  parent_ordinal INTEGER, member_key TEXT, array_index INTEGER, depth INTEGER,
  node_type TEXT, text_value TEXT, number_text TEXT, bool_value INTEGER,
  interpretation TEXT
);
CREATE TEMP TABLE facet_observation_json_nodes (
  observation_id TEXT, record_id TEXT, key TEXT, as_of TEXT, ordinal INTEGER,
  path TEXT, parent_path TEXT, parent_ordinal INTEGER, member_key TEXT,
  array_index INTEGER, depth INTEGER, node_type TEXT, text_value TEXT,
  number_text TEXT, bool_value INTEGER, interpretation TEXT
);
CREATE TEMP TABLE record_body_json_nodes (
  record_id TEXT, ordinal INTEGER, path TEXT, parent_path TEXT,
  parent_ordinal INTEGER, member_key TEXT, array_index INTEGER, depth INTEGER,
  node_type TEXT, text_value TEXT, number_text TEXT, bool_value INTEGER,
  interpretation TEXT
);
CREATE TEMP TABLE bindings (
  record_id TEXT, system TEXT, identifier TEXT, is_canonical INTEGER,
  url TEXT, etag TEXT, last_seen_at TEXT, last_seen_at_ms INTEGER
);
CREATE TEMP TABLE blobs (
  id TEXT, bytes BLOB, mime TEXT, size_bytes INTEGER, sha256 TEXT,
  original_filename TEXT, storage_tier TEXT, external_ref TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE vocabularies (
  id TEXT, name TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE vocabulary_values (
  id TEXT, vocabulary_id TEXT, value TEXT, gloss TEXT, status TEXT,
  ordinal REAL, terminality TEXT, metadata TEXT, alias_of TEXT
);
CREATE TEMP TABLE vocabulary_value_json_nodes (
  value_id TEXT, ordinal INTEGER, path TEXT, parent_path TEXT,
  parent_ordinal INTEGER, member_key TEXT, array_index INTEGER, depth INTEGER,
  node_type TEXT, text_value TEXT, number_text TEXT, bool_value INTEGER
);
CREATE TEMP TABLE schema_config_json_nodes (
  config_id TEXT, ordinal INTEGER, path TEXT, parent_path TEXT,
  parent_ordinal INTEGER, member_key TEXT, array_index INTEGER, depth INTEGER,
  node_type TEXT, text_value TEXT, number_text TEXT, bool_value INTEGER
);
CREATE TEMP TABLE schema_config (
  id TEXT, layer TEXT, name TEXT, data TEXT, applies_to_collection_id TEXT,
  version_lineage TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE effective_relationships (
  relationship_origin_db_id TEXT, relationship_id TEXT,
  relationship_type TEXT, type_definition_id TEXT, endpoint_semantics TEXT,
  endpoints TEXT, effective_state TEXT, epistemic_state TEXT,
  support_count INTEGER, contest_count INTEGER,
  recomputed_at TEXT, recomputed_at_ms INTEGER
);
CREATE TEMP TABLE effective_relationship_endpoints (
  relationship_origin_db_id TEXT, relationship_id TEXT, ordinal INTEGER,
  role TEXT, portable_ref TEXT, record_type TEXT, record_kind TEXT,
  record_id TEXT
);
CREATE TEMP TABLE agent_activity (
  activity_id TEXT, run_key TEXT, principal_ref TEXT, principal_display_name TEXT,
  started_at TEXT, started_at_ms INTEGER,
  ended_at TEXT, ended_at_ms INTEGER,
  last_observed_activity_at TEXT, last_observed_activity_at_ms INTEGER,
  active_until TEXT, active_until_ms INTEGER,
  appears_active INTEGER, declared_intent TEXT,
  declared_intent_state TEXT
);
CREATE TEMP TABLE agent_activity_claims (
  claim_id TEXT, activity_id TEXT, record_id TEXT,
  claimed_at TEXT, claimed_at_ms INTEGER,
  released_at TEXT, released_at_ms INTEGER, is_current INTEGER
);
CREATE TEMP TABLE actors (
  actor TEXT, person_id TEXT, display_name TEXT
);
CREATE TEMP TABLE runs (
  run_key TEXT, principal_person_id TEXT,
  started_at_ms INTEGER, ended_at_ms INTEGER,
  reported_model TEXT, reported_client TEXT, model_assurance TEXT
);
CREATE TEMP TABLE run_intents (
  run_key TEXT, ordinal INTEGER, intent TEXT, declared_at_ms INTEGER
);
CREATE TEMP TABLE messages_awaiting_reply (message_id TEXT);
CREATE TEMP TABLE my_participants (participant_address TEXT, kind TEXT, persona_id TEXT, display_name TEXT, state TEXT);
CREATE TEMP TABLE message_speakers (message_id TEXT, speaker_kind TEXT, speaker_address TEXT, display_name TEXT, assurance TEXT);
CREATE TEMP TABLE deleted_messages (message_id TEXT, reply_id TEXT, deleted_at TEXT, deleted_at_ms INTEGER);
CREATE TEMP TABLE my_message_state (
  message_id TEXT, stage TEXT, unread INTEGER, is_own INTEGER,
  mentioned INTEGER, flagged INTEGER, muted INTEGER, archived INTEGER,
  snoozed_until TEXT, snoozed_until_ms INTEGER, reactable INTEGER
);
CREATE TEMP TABLE my_mentions (
  source_id TEXT, source_kind TEXT, via TEXT, own_source INTEGER,
  mentioned_at TEXT, mentioned_at_ms INTEGER, seen INTEGER
);
CREATE TEMP TABLE comment_anchors (
  annotation_id TEXT, target_record_id TEXT, purpose TEXT,
  selectors TEXT, source_event_seq INTEGER, source_sha256 TEXT
);
CREATE TEMP TABLE message_reactions (
  reaction_id TEXT, message_id TEXT, emoji TEXT, actor_record_id TEXT,
  actor_name TEXT, executor_kind TEXT, reacted_at TEXT, reacted_at_ms INTEGER,
  viewer INTEGER
);
CREATE TEMP TABLE facet_keys (
  scope_id TEXT, type TEXT, kind TEXT, key TEXT, record_count INTEGER,
  declared INTEGER, value_type TEXT, vocab_ref TEXT, required INTEGER
);
CREATE TEMP TABLE facet_times (
  record_id TEXT, key TEXT, kind TEXT, all_day INTEGER,
  start_date TEXT, end_date TEXT, start_ms INTEGER, end_ms INTEGER,
  tz TEXT, tzdb_version TEXT
);
CREATE TEMP TABLE body_task_items (
  record_id TEXT, item_index INTEGER, marker TEXT, checked INTEGER,
  in_quote INTEGER, start_offset INTEGER, end_offset INTEGER
);
CREATE TEMP TABLE catalog_relations (
  relation_name TEXT, identity TEXT, semantic_version INTEGER,
  caller_relative INTEGER, completeness TEXT, profiles TEXT, comment TEXT
);
CREATE TEMP TABLE catalog_columns (
  relation_name TEXT, column_name TEXT, column_position INTEGER
);
CREATE TEMP TABLE catalog_operations (
  executor TEXT, operation TEXT, surface TEXT, access TEXT,
  plan_required INTEGER, direct_execution_enabled INTEGER,
  contract_version TEXT, contract_digest TEXT, source_tool TEXT,
  selector_field TEXT, selector_value TEXT, advertised_directly INTEGER
);
"#;

pub type SqlResult = QuerySqlResult;

#[derive(Clone, Debug)]
pub(crate) struct GovernedSqlObservation {
    pub observed_at: String,
    /// Highest caller-visible content event in this authorization snapshot.
    /// A hidden claim therefore cannot perturb receipt diagnostics.
    pub content_event_seq: Option<i64>,
    pub lifecycle_event_seq: Option<i64>,
    /// Opaque caller- and dependency-scoped authorization boundary. Raw
    /// database-global epochs are never exposed through governed receipts.
    pub authorization_boundary: String,
    pub transient_watermark: Option<i64>,
    pub transient_available: bool,
}

async fn prepare_activity_observations(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<(bool, Option<i64>)> {
    sqlx::query("DELETE FROM temp._query_sql_activity_observations")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_activity_capture")
        .execute(&mut **transaction)
        .await?;
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='read_log_calls')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !available {
        sqlx::query(
            "INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,0)",
        )
        .execute(&mut **transaction)
        .await?;
        return Ok((false, None));
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_activity_observations(run_key,last_observed_at,declared_intent)
         SELECT calls.run_key,max(calls.ended_at),
                (SELECT intent_calls.intent
                   FROM main.read_log_calls intent_calls
                  WHERE intent_calls.run_key=calls.run_key
                    AND intent_calls.tool='set_intent'
                    AND intent_calls.outcome='ok'
                    AND intent_calls.intent IS NOT NULL
                    AND intent_calls.actor=run.account_id
                    AND julianday(intent_calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
                    AND (run.ended_at IS NULL OR julianday(intent_calls.ended_at)<=julianday(run.ended_at))
                  ORDER BY intent_calls.seq DESC
                  LIMIT 1)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.run_key IS NOT NULL AND calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
          GROUP BY calls.run_key",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,1)")
        .execute(&mut **transaction)
        .await?;
    let watermark = sqlx::query_scalar(
        "SELECT max(calls.seq)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
            AND julianday(max(run.started_at,coalesce(run.ended_at,run.started_at),calls.ended_at))
                >=julianday((SELECT observed_at FROM temp._query_sql_principal),'-24 hours')",
    )
        .fetch_one(&mut **transaction)
        .await?;
    Ok((true, watermark))
}

/// Materialise the claim and claim-clear candidate rows before the caller
/// value ceiling is lowered. Shape matching on `content_events.payload`
/// happens here at the full limit, and only for agent-stamped
/// `record.updated` rows inside the activity window or matching the
/// still-current `records` identity. The claims view then reads the narrow
/// projected columns alone, so caller SQL can never open an over-limit
/// payload through this relation.
///
/// The `actor IS NOT NULL` term is disclosure-neutral: every engine-owned
/// claim and claim-clear event carries an actor, while a NULL-actor row
/// could never join `agent_runs` (claim) or satisfy the release actor
/// disjunction against a non-null claim actor (release).
///
/// Release completeness: a genuine release always has a higher event seq
/// than its claim, so bounding the release scan below by the oldest
/// candidate claim seq keeps every release a disclosed claim can observe.
/// Seq comparison needs no date parsing. An empty candidate set yields a
/// NULL bound and inserts no releases.
async fn prepare_claim_candidates(transaction: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_claim_releases")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_claim_candidates(seq, claim_id, record_id, run_key, claim_actor, claimed_by_account, claimed_at)
          SELECT event.seq, event.id, event.record_id, event.run_key, event.actor,
                 json_extract(event.payload,'$.claimed_by_account'), event.created_at
            FROM main.content_events event
            JOIN main.content_event_claim_meta AS claim_meta ON claim_meta.event_seq = event.seq
            CROSS JOIN temp._query_sql_principal principal
           WHERE event.type='record.updated'
             AND event.actor IS NOT NULL
             AND claim_meta.claim_class = 'claim'
             AND (julianday(event.created_at)>=julianday(principal.observed_at,'-24 hours')
                  OR EXISTS (
                       SELECT 1 FROM main.records current
                        WHERE current.id=event.record_id
                          AND current.claimed_run_key=event.run_key
                          AND current.claimed_at=event.created_at
                  ))",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_claim_releases(seq, record_id, actor, created_at)
          SELECT event.seq, event.record_id, event.actor, event.created_at
            FROM main.content_events event
            JOIN main.content_event_claim_meta AS claim_meta ON claim_meta.event_seq = event.seq
           WHERE event.type='record.updated'
             AND event.actor IS NOT NULL
             AND claim_meta.claim_class = 'release'
             AND event.seq>=(
                   SELECT min(seq)
                     FROM temp._query_sql_claim_candidates
                 )",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The complete fold reads metadata only. Emitted emoji is not the legacy
/// partition key: serde sequence payloads all share a NULL key per actor.
const REACTION_WINNER_SQL: &str = r#"
INSERT INTO temp._query_sql_reaction_winners
       (event_seq,message_id,actor,emoji,executor_kind,created_at)
WITH ranked AS MATERIALIZED (
  SELECT meta.event_seq, meta.record_id AS message_id, meta.actor, meta.emoji,
         meta.executor_kind, meta.created_at, meta.reaction_class,
         row_number() OVER (PARTITION BY meta.record_id,meta.actor,meta.legacy_emoji
                            ORDER BY meta.event_seq DESC) AS position
    FROM temp._query_sql_visible_ids AS visible
    CROSS JOIN main.records AS message
    CROSS JOIN main.content_event_reaction_meta AS meta INDEXED BY idx_content_event_reaction_meta_record
   WHERE message.id = visible.id AND message.type = 'Message'
     AND message.deleted_at IS NULL AND meta.record_id = message.id
)
SELECT event_seq,message_id,actor,emoji,executor_kind,created_at
  FROM ranked WHERE position = 1 AND reaction_class = 'added'
 LIMIT ?
"#;

// Same global envelope as MAX(seq), with a non-filtering stored-column
// read so SQLite preparation never reports a column-less source read.
// record_id is NOT NULL TEXT, including empty/Unicode/NUL values. The
// min/max optimization still inspects only the rightmost source event.
const REACTION_BORROWED_ENVELOPE_SQL: &str =
    "SELECT COALESCE(MAX(seq), 0) FROM main.content_events WHERE length(record_id)>=0";

/// Reverse walks use the full record index: the partial record_changes
/// index also excludes occurrence.bound.v1, which belongs in the old head.
const REACTION_HEAD_EVENTS_SQL: &str = "SELECT event.seq,event.type
    FROM main.content_events AS event INDEXED BY idx_content_events_record
    WHERE event.record_id=? ORDER BY event.seq DESC LIMIT 1";
const REACTION_HEAD_PREVIOUS_EVENT_SQL: &str = "SELECT event.seq,event.type
    FROM main.content_events AS event INDEXED BY idx_content_events_record
    WHERE event.record_id=? AND event.seq<? ORDER BY event.seq DESC LIMIT 1";

/// One request-local absolute deadline. Production uses exactly std::Instant;
/// the private test clock is captured once, then shared with the VM callback.
#[derive(Clone)]
struct ReactionDeadline {
    absolute: Instant,
    #[cfg(test)]
    clock: Option<Arc<ReactionTestClock>>,
}

impl ReactionDeadline {
    fn new(started: Instant) -> Self {
        #[cfg(test)]
        let clock = REACTION_TEST_CLOCK.try_with(Arc::clone).ok();
        #[cfg(test)]
        let started = clock.as_ref().map_or(started, |clock| clock.now());
        Self {
            absolute: started + QUERY_DEADLINE,
            #[cfg(test)]
            clock,
        }
    }

    #[cfg(test)]
    fn at(absolute: Instant) -> Self {
        Self {
            absolute,
            clock: None,
        }
    }

    fn expired(&self) -> bool {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return clock.now() >= self.absolute;
        }
        Instant::now() >= self.absolute
    }
}

#[cfg(test)]
struct ReactionTestClock {
    origin: Instant,
    nanos: AtomicU64,
    reads: AtomicU64,
}

#[cfg(test)]
impl ReactionTestClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            nanos: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        }
    }
    fn now(&self) -> Instant {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.origin
            .checked_add(Duration::from_nanos(self.nanos.load(Ordering::Acquire)))
            .expect("test clock advance is checked")
    }
    fn advance(&self, delta: Duration) {
        let nanos = u64::try_from(delta.as_nanos()).expect("test clock delta fits");
        self.nanos
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                let next = previous.checked_add(nanos)?;
                self.origin
                    .checked_add(Duration::from_nanos(next))
                    .map(|_| next)
            })
            .expect("test clock must not wrap or move backwards");
    }
}

#[cfg(test)]
tokio::task_local! {
    static REACTION_TEST_CLOCK: Arc<ReactionTestClock>;
}

// Owned queries start their budget at the first VM callback. Only explicitly
// scoped reaction tests substitute a clock; production keeps std::Instant.
#[cfg(test)]
fn reaction_test_budget_alive(clock: &ReactionTestClock, started: &mut Option<Instant>) -> bool {
    let now = clock.now();
    now.duration_since(*started.get_or_insert(now)) < QUERY_DEADLINE
}

/// Small indexed seeks may never reach SQLite's progress callback interval.
fn ensure_reaction_deadline(deadline: &ReactionDeadline) -> Result<()> {
    if deadline.expired() {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::Timeout,
            "message_reactions shared deadline exceeded; no partial read or receipt returned",
        ));
    }
    Ok(())
}

/// Exact equivalent of max(local_seq) over the visible content_events view.
/// Admission and every reverse walk share the caller's absolute deadline/value
/// scope. Exhaustion cannot produce a partial maximum/receipt.
async fn bounded_reaction_visible_head(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    deadline: &ReactionDeadline,
) -> Result<i64> {
    bounded_reaction_visible_head_with_bounds(
        transaction,
        MAX_REACTION_HEAD_RECORDS,
        MAX_REACTION_HEAD_EVENTS,
        deadline,
    )
    .await
}

async fn bounded_reaction_visible_head_with_bounds(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    record_bound: usize,
    event_bound: i64,
    deadline: &ReactionDeadline,
) -> Result<i64> {
    ensure_reaction_deadline(deadline)?;
    let bound_error =
        |message| sql_contract::categorized_error(QuerySqlErrorCategory::ResultTooLarge, message);
    let mut records = Vec::new();
    let mut bytes = 0_usize;
    let mut visible = sqlx::query("SELECT id FROM temp._query_sql_visible_ids ORDER BY id LIMIT ?")
        .bind((record_bound + 1) as i64)
        .fetch(&mut **transaction);
    while let Some(row) = visible.try_next().await.map_err(map_stream_error)? {
        ensure_reaction_deadline(deadline)?;
        if records.len() == record_bound {
            return Err(bound_error("message_reactions visible freshness record bound exceeded; no partial read or receipt returned"));
        }
        let id: String = row.try_get(0)?;
        bytes += id.len();
        if bytes > MAX_REACTION_METADATA_BYTES as usize {
            return Err(bound_error("message_reactions visible freshness identifier byte bound exceeded; no partial read or receipt returned"));
        }
        records.push(id);
    }
    drop(visible);
    let mut inspected = 0_i64;
    // None means no eligible event, NOT sequence zero. Negative heads remain
    // negative; only the empty eligible set has the old coalesce-to-zero.
    let mut head: Option<i64> = None;
    for record in records {
        let mut before = None;
        loop {
            ensure_reaction_deadline(deadline)?;
            // One-row keyset steps avoid SQLx stream prefetch doing an
            // uncounted excluded-tail scan after a winning row is found.
            let row = if let Some(seq) = before {
                sqlx::query(REACTION_HEAD_PREVIOUS_EVENT_SQL)
                    .bind(&record)
                    .bind(seq)
                    .fetch_optional(&mut **transaction)
                    .await
            } else {
                sqlx::query(REACTION_HEAD_EVENTS_SQL)
                    .bind(&record)
                    .fetch_optional(&mut **transaction)
                    .await
            }
            .map_err(map_stream_error)?;
            let Some(row) = row else { break };
            inspected += 1;
            if inspected > event_bound {
                return Err(bound_error("message_reactions visible freshness history bound exceeded; no partial read or receipt returned"));
            }
            let seq: i64 = row.try_get(0)?;
            let event_type: String = row.try_get(1)?;
            if !matches!(
                event_type.as_str(),
                "reconciliation.recorded.v1"
                    | "unit.superseded.v1"
                    | "receipt.dependency_audited.v1"
            ) {
                head = Some(head.map_or(seq, |previous| previous.max(seq)));
                break;
            }
            before = Some(seq);
        }
    }
    ensure_reaction_deadline(deadline)?;
    Ok(head.unwrap_or(0))
}

async fn reaction_visible_authorization_boundary(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
    relation_dependencies: &std::collections::BTreeSet<String>,
    deadline: &ReactionDeadline,
) -> Result<String> {
    // Same existing digest, deferred with the head for reaction-dependent
    // reads so an oversized visible set cannot be hashed before admission.
    let mut digest = Sha256::new();
    let prefix = serde_json::to_vec(&(
        principal.credential(),
        principal.trusted_local_bypass(),
        relation_dependencies.iter().cloned().collect::<Vec<_>>(),
    ))?;
    digest.update((prefix.len() as u64).to_be_bytes());
    digest.update(prefix);
    let mut visible = sqlx::query("SELECT id FROM temp._query_sql_visible_ids ORDER BY id")
        .fetch(&mut **transaction);
    while let Some(row) = visible.try_next().await.map_err(map_stream_error)? {
        ensure_reaction_deadline(deadline)?;
        let id: String = row.try_get(0)?;
        digest.update((id.len() as u64).to_be_bytes());
        digest.update(id.as_bytes());
    }
    ensure_reaction_deadline(deadline)?;
    Ok(format!(
        "native.authorization-snapshot.v1.{:x}",
        digest.finalize()
    ))
}

async fn populate_reaction_winners(transaction: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
    // Admission is full-snapshot and cap+1, independent of caller predicates,
    // output LIMIT, COUNT or the number of references to the public relation.
    // All three statements run under the same value ceiling and deadline.
    let messages: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (
           SELECT message.id FROM temp._query_sql_visible_ids AS visible
           CROSS JOIN main.records AS message
           WHERE message.id=visible.id AND message.type='Message' AND message.deleted_at IS NULL
           LIMIT ?)",
    )
    .bind(MAX_REACTION_MESSAGES + 1)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_stream_error)?;
    if messages > MAX_REACTION_MESSAGES {
        return Err(sql_contract::categorized_error(QuerySqlErrorCategory::ResultTooLarge,
            "message_reactions visible Message candidate bound exceeded; no partial relation returned"));
    }
    let (history, metadata_bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*),coalesce(sum(bytes),0) FROM (
           SELECT 128 + octet_length(meta.record_id) + octet_length(meta.actor)
                      + coalesce(octet_length(meta.legacy_emoji),0) + octet_length(meta.emoji)
                      + octet_length(meta.executor_kind) + octet_length(meta.created_at) AS bytes
             FROM temp._query_sql_visible_ids AS visible
             CROSS JOIN main.records AS message
             CROSS JOIN main.content_event_reaction_meta AS meta INDEXED BY idx_content_event_reaction_meta_record
            WHERE message.id=visible.id AND message.type='Message' AND message.deleted_at IS NULL
              AND meta.record_id=message.id LIMIT ?)",
    ).bind(MAX_REACTION_SOURCE_EVENTS + 1).fetch_one(&mut **transaction).await.map_err(map_stream_error)?;
    if history > MAX_REACTION_SOURCE_EVENTS {
        return Err(sql_contract::categorized_error(QuerySqlErrorCategory::ResultTooLarge,
            "message_reactions visible reaction history bound exceeded; no partial relation returned"));
    }
    if metadata_bytes > MAX_REACTION_METADATA_BYTES {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            "message_reactions visible metadata byte bound exceeded; no partial relation returned",
        ));
    }
    let winners = sqlx::query(REACTION_WINNER_SQL)
        .bind(MAX_REACTION_WINNERS + 1)
        .execute(&mut **transaction)
        .await
        .map_err(map_stream_error)?
        .rows_affected();
    if winners > MAX_REACTION_WINNERS as u64 {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            "message_reactions winning row bound exceeded; no partial relation returned",
        ));
    }
    Ok(())
}

async fn prepare_disclosable_actors(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    with_persons: bool,
) -> Result<()> {
    sqlx::query("DELETE FROM temp._query_sql_disclosable_actors")
        .execute(&mut **transaction)
        .await?;
    if !with_persons {
        // `content_events` needs only the actor set: main's exact statement.
        sqlx::query(
            "INSERT INTO temp._query_sql_disclosable_actors(actor)
             SELECT principal.account_id FROM temp._query_sql_principal AS principal
             UNION
             SELECT actor_binding.identifier
               FROM main.bindings AS actor_binding
               JOIN temp._query_sql_visible_ids AS person_visible
                 ON person_visible.id = actor_binding.record_id
              WHERE actor_binding.system = 'account'",
        )
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    // `actors` also needs each actor's visible person, by the one rule the
    // run relations read too (`_query_sql_disclosable_persons`). Only ids are
    // stored: the view reads the name at query time, under the caller's
    // deadline and value ceiling.
    sqlx::query(
        "INSERT INTO temp._query_sql_disclosable_actors(actor, person_id)
         SELECT actor, person_id FROM temp._query_sql_disclosable_persons",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// `run_intents` reads the optional read log in place. When
/// `read_log_calls` is absent, swap the view for an empty one of the same
/// shape so the relation reads as empty rather than failing to prepare. The
/// same holds when the table exists without `idx_read_log_calls_run`: the view
/// pins that index with `INDEXED BY` (so hidden declarations are never
/// scanned), and a missing pinned index would otherwise fail every statement
/// with an opaque "no such index" planner error. The account index the view
/// also pins is checked when the database opens (`control.rs`). The
/// swap runs inside the governed transaction, which the owned path always
/// rolls back and the caller-transaction path tears down with every other
/// logical view, so the real definition returns for the next execution.
/// The trigger is a textual mention, a deliberate over-approximation of the
/// dependency set: a statement that reads no `run_intents` column (`count(*)`)
/// is not a dependency but still expands the view. A mention costs one
/// catalog lookup, and the swap itself happens only when the log or its run
/// index is absent.
/// In a [`GovernedSqlSession`] a `temp.run_intents` replacement made here
/// persists into the session's later executions by design: it depends only
/// on the schema, and every statement re-runs this guard anyway.
async fn guard_run_intents_source(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    sql: &str,
) -> Result<()> {
    if !sql.to_ascii_lowercase().contains("run_intents") {
        return Ok(());
    }
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='read_log_calls')
            AND EXISTS(SELECT 1 FROM main.sqlite_master
                        WHERE type='index' AND name='idx_read_log_calls_run'
                          AND tbl_name='read_log_calls')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if available {
        return Ok(());
    }
    sqlx::query("DROP VIEW IF EXISTS temp.run_intents")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "CREATE TEMP VIEW run_intents AS
         SELECT CAST(NULL AS TEXT) AS run_key, CAST(NULL AS INTEGER) AS ordinal,
                CAST(NULL AS TEXT) AS intent, CAST(NULL AS INTEGER) AS declared_at_ms
          WHERE 0",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn populate_activity_members(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<()> {
    if principal.trusted_local_bypass() {
        let workspace_id: String =
            sqlx::query_scalar("SELECT origin_db_id FROM main.database_identity WHERE singleton=1")
                .fetch_one(&mut **transaction)
                .await?;
        let accounts: Vec<String> =
            sqlx::query_scalar("SELECT account_id FROM main.member_contexts ORDER BY account_id")
                .fetch_all(&mut **transaction)
                .await?;
        for account_id in accounts {
            sqlx::query(
                "INSERT INTO temp._query_sql_activity_members(account_id,member_ref) VALUES(?,?)",
            )
            .bind(&account_id)
            .bind(crate::identity::activity_member_ref(
                &workspace_id,
                &account_id,
            ))
            .execute(&mut **transaction)
            .await?;
        }
    } else {
        for member in principal.activity_roster() {
            sqlx::query(
                "INSERT INTO temp._query_sql_activity_members(account_id,member_ref) VALUES(?,?)",
            )
            .bind(member.account_id())
            .bind(member.member_ref())
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

/// Richard 25 Sep (Native e25665c): already-stored governed SQL
/// keeps working under the pinned engine's pre-I2 function rules, nothing
/// added: the legacy allowance is exactly the portable subset plus every
/// other name the pre-I2 SQLite authorizer admitted (`SAFE_FUNCTIONS` as of
/// the I2 base, minus the portable overlap). Before I2 `group_concat` was
/// already refused ("not authorized to use function"), so it stays refused
/// for stored definitions too. Ad-hoc `query_sql` and SQL being saved stay
/// on the portable subset.
const LEGACY_SAVED_SQL_EXTRA_FUNCTIONS: [&str; 15] = [
    "date",
    "datetime",
    "glob",
    "instr",
    "json_array_length",
    "json_type",
    "json_valid",
    "julianday",
    "strftime",
    "substring",
    "time",
    "total",
    "typeof",
    "unicode",
    "unixepoch",
];

fn is_legacy_saved_sql_function(function_name: &str) -> bool {
    sql_contract::is_portable_function(function_name)
        || function_name.eq_ignore_ascii_case("like")
        || LEGACY_SAVED_SQL_EXTRA_FUNCTIONS
            .iter()
            .any(|safe| function_name.eq_ignore_ascii_case(safe))
}

/// Task 73e5b92 carve-out: the claim-metadata side table is read only
/// through controlled views, but SQLite attributes its redundant-LEFT-JOIN
/// analysis for unreferenced join outputs outside any view context
/// (`accessor` None). Without this carve-out, any query that does not
/// select `run_key`/`parent_key` fails prepare with a denial, because the
/// analysis read has no accessor. The classifier rejects the bare table
/// name before prepare, so no caller SQL can reach it directly; default
/// deny stands for every other table.
fn is_claim_meta_side_table(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("main") && table_name == "content_event_claim_meta"
}

fn authorize_view_expansion_legacy_saved_sql(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read {
            table_name,
            column_name,
        } => {
            // A reaction winner may acquire its public history UUID, never
            // decode the source payload or read its type/actor after the fold.
            if context.database_name == Some("main")
                && table_name == "content_events"
                && context.accessor == Some("message_reactions")
                && !matches!(column_name, "id" | "seq")
            {
                return Authorization::Deny;
            }
            let public_temp = context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name);
            let through_controlled = context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view));
            if public_temp || through_controlled || is_claim_meta_side_table(&context, table_name) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        AuthAction::Function { function_name }
            if context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view))
                && !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        AuthAction::Function { function_name } if is_legacy_saved_sql_function(function_name) => {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
}

fn portable_function_allowed(function_name: &str) -> bool {
    sql_contract::is_portable_function(function_name) || function_name.eq_ignore_ascii_case("like")
}

fn no_table_functions(_: &str) -> bool {
    false
}

fn authorize_view_expansion(context: AuthContext<'_>) -> Authorization {
    authorize_view_expansion_with(context, portable_function_allowed, no_table_functions)
}

/// Ad-hoc online sqlite-local SQL (Native 702de73): the same view-expansion
/// rules with the ad-hoc function allowlist. Table reads are unchanged, so
/// `json_each`/`json_tree` open no relation the caller cannot already read.
fn authorize_view_expansion_ad_hoc(context: AuthContext<'_>) -> Authorization {
    authorize_view_expansion_with(
        context,
        sql_contract::is_sqlite_ad_hoc_function,
        sql_contract::is_sqlite_ad_hoc_table_function,
    )
}

/// Kernel SQL stages complete logical tables itself, unlike v1's observed-column
/// staging. Its column-free admission must never enter the v1 authorizer.
#[cfg(feature = "v2-kernel-probe")]
fn authorize_kernel_v2_view_expansion(context: AuthContext<'_>) -> Authorization {
    if matches!(context.action, AuthAction::Read { table_name, column_name }
        if column_name.is_empty() && sql_contract::is_logical_relation(table_name))
        && matches!(context.database_name, None | Some("main"))
    {
        return Authorization::Allow;
    }
    authorize_view_expansion_ad_hoc(context)
}

#[cfg(feature = "v2-kernel-probe")]
fn authorize_kernel_v2_portable_view_expansion(context: AuthContext<'_>) -> Authorization {
    if matches!(context.action, AuthAction::Read { table_name, column_name }
        if column_name.is_empty() && sql_contract::is_logical_relation(table_name))
        && matches!(context.database_name, None | Some("main"))
    {
        return Authorization::Allow;
    }
    authorize_view_expansion(context)
}

#[cfg(feature = "v2-kernel-probe")]
fn authorize_kernel_v2_stored_view_expansion(context: AuthContext<'_>) -> Authorization {
    if matches!(context.action, AuthAction::Read { table_name, column_name }
        if column_name.is_empty() && sql_contract::is_logical_relation(table_name))
        && matches!(context.database_name, None | Some("main"))
    {
        return Authorization::Allow;
    }
    authorize_view_expansion_legacy_saved_sql(context)
}

/// `table_function_allowed` names the table-valued functions (`json_each`,
/// `json_tree`) whose eponymous virtual table may be read. SQLite reports
/// that read against `main` with column names (`value`, `key`, ...) and no
/// accessor when it comes from the caller's own statement; no governed
/// schema holds a real table by that name, and every other table read keeps
/// the logical-relation / controlled-accessor requirement.
fn authorize_view_expansion_with(
    context: AuthContext<'_>,
    function_allowed: fn(&str) -> bool,
    table_function_allowed: fn(&str) -> bool,
) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("main") && table_function_allowed(table_name) =>
        {
            Authorization::Allow
        }
        AuthAction::Read {
            table_name,
            column_name,
        } => {
            // A reaction winner may acquire its public history UUID, never
            // decode the source payload or read its type/actor after the fold.
            if context.database_name == Some("main")
                && table_name == "content_events"
                && context.accessor == Some("message_reactions")
                && !matches!(column_name, "id" | "seq")
            {
                return Authorization::Deny;
            }
            let public_temp = context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name);
            let through_controlled = context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view));
            if public_temp || through_controlled || is_claim_meta_side_table(&context, table_name) {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        AuthAction::Function { function_name }
            if context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view))
                && !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        AuthAction::Function { function_name } if function_allowed(function_name) => {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
}

fn strict_task_source_read(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("temp")
        && table_name == "_query_sql_task_item_source"
        && context.accessor == Some("body_task_items")
}

fn strict_heading_source_read(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("temp")
        && table_name == "_query_sql_heading_source"
        && context.accessor == Some("body_block_headings")
}

fn strict_facet_keys_source_read(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("temp")
        && table_name == "_query_sql_facet_keys_source"
        && context.accessor == Some("facet_keys")
}

fn strict_lifecycle_source_read(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("temp")
        && table_name == "_query_sql_lifecycle_source"
        && context.accessor == Some("record_lifecycle_interpretations")
}

fn strict_reaction_source_read(context: &AuthContext<'_>, table_name: &str) -> bool {
    context.database_name == Some("temp")
        && table_name == "_query_sql_reaction_source"
        && context.accessor == Some("message_reactions")
}

fn authorize_strict(context: AuthContext<'_>) -> Authorization {
    authorize_strict_with(context, portable_function_allowed, no_table_functions)
}

/// Ad-hoc online sqlite-local SQL: the strict public-only schema with the
/// ad-hoc function allowlist. See [`authorize_view_expansion_ad_hoc`].
fn authorize_strict_ad_hoc(context: AuthContext<'_>) -> Authorization {
    authorize_strict_with(
        context,
        sql_contract::is_sqlite_ad_hoc_function,
        sql_contract::is_sqlite_ad_hoc_table_function,
    )
}

fn authorize_strict_with(
    context: AuthContext<'_>,
    function_allowed: fn(&str) -> bool,
    table_function_allowed: fn(&str) -> bool,
) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        // The strict schema lives wholly in `temp`; `main` holds no table,
        // so a `main` read of a table function is the eponymous virtual table.
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("main") && table_function_allowed(table_name) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp")
                && (sql_contract::is_logical_relation(table_name)
                    || strict_task_source_read(&context, table_name)
                    || strict_heading_source_read(&context, table_name)
                    || strict_reaction_source_read(&context, table_name)
                    || strict_lifecycle_source_read(&context, table_name)
                    || strict_facet_keys_source_read(&context, table_name)) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name } if function_allowed(function_name) => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn authorize_strict_legacy_saved_sql(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp")
                && (sql_contract::is_logical_relation(table_name)
                    || strict_task_source_read(&context, table_name)
                    || strict_heading_source_read(&context, table_name)
                    || strict_reaction_source_read(&context, table_name)
                    || strict_lifecycle_source_read(&context, table_name)
                    || strict_facet_keys_source_read(&context, table_name)) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name } if is_legacy_saved_sql_function(function_name) => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn prepare_under_authorizer(
    conn: &rusqlite::Connection,
    statement: &str,
    authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<()> {
    conn.authorizer(Some(authorizer));
    let prepared = conn.prepare(statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    match prepared {
        Ok(statement) if statement.readonly() => {
            let mut labels = std::collections::HashSet::new();
            if let Some(duplicate) = statement
                .column_names()
                .into_iter()
                .find(|label| !labels.insert(*label))
            {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::DuplicateColumns,
                    format!("duplicate output column label '{duplicate}'"),
                ));
            }
            Ok(())
        }
        Ok(_) => Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "read-only statement writes",
        )),
        Err(error) => {
            let detail = error.to_string();
            let category = if detail.contains("not authorized")
                || detail.contains("access to")
                || detail.contains("no such table")
            {
                QuerySqlErrorCategory::UnauthorizedRelation
            } else {
                QuerySqlErrorCategory::SyntaxOrType
            };
            if category == QuerySqlErrorCategory::UnauthorizedRelation {
                if let Some(repair) = blocked_probe_repair(statement, &detail) {
                    return Err(sql_contract::categorized_error(
                        category,
                        format!("{detail} {repair}"),
                    ));
                }
            } else if detail.contains("no such column") {
                if let Some(repair) = unknown_column_repair_for(
                    statement,
                    &detail,
                    sql_contract::QuerySqlProfile::SqliteLocal,
                ) {
                    return Err(sql_contract::categorized_error(
                        category,
                        sql_contract::join_detail_repair(&detail, &repair),
                    ));
                }
            }
            Err(sql_contract::categorized_error(category, detail))
        }
    }
}

/// E2 I-1: name the fix when a catalog probe or physical table is blocked.
/// Runs only on an already-rejected UnauthorizedRelation, so it rewords a
/// failure and never admits a statement. Function denies (e.g.
/// GROUP_CONCAT) name no table and resolve to logical targets, so they
/// fall through untouched for the function-allowlist repair to own.
fn blocked_probe_repair(statement: &str, detail: &str) -> Option<String> {
    if let Some(tail) = detail
        .find("access to ")
        .map(|index| &detail[index + "access to ".len()..])
    {
        let name = tail
            .split(['.', ' ', '\t', '\n'])
            .next()
            .unwrap_or_default();
        if let Some(repair) =
            sql_contract::blocked_relation_repair(name, sql_contract::QuerySqlProfile::SqliteLocal)
        {
            return Some(repair);
        }
    }
    if let Some(tail) = detail.find("no such table").and_then(|index| {
        detail[index..]
            .find(':')
            .map(|off| &detail[index + off + 1..])
    }) {
        let qualified = tail
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .find(|token| !token.is_empty())
            .unwrap_or_default();
        let short = qualified.rsplit('.').next().unwrap_or_default();
        // Prefer the qualified name: `information_schema.tables` is a probe
        // even though bare `tables` is not.
        if let Some(repair) = sql_contract::blocked_relation_repair(
            qualified,
            sql_contract::QuerySqlProfile::SqliteLocal,
        )
        .filter(|_| qualified != short)
        .or_else(|| {
            sql_contract::blocked_relation_repair(short, sql_contract::QuerySqlProfile::SqliteLocal)
        }) {
            return Some(repair);
        }
    }
    first_non_logical_target(statement).and_then(|name| {
        sql_contract::blocked_relation_repair(&name, sql_contract::QuerySqlProfile::SqliteLocal)
    })
}

/// E1 M2 I6: name the valid columns when a known logical relation is read
/// with an unknown column. Runs only on an already-rejected SyntaxOrType
/// failure, so it rewords a failure and never admits a statement. The column
/// spelling comes from the engine detail (`no such column: X`); the scope
/// comes from the statement's FROM/JOIN targets via the shared contract
/// scan, so the message is identical on every engine by construction.
fn unknown_column_repair_for(
    statement: &str,
    detail: &str,
    profile: sql_contract::QuerySqlProfile,
) -> Option<String> {
    let column = sql_contract::unknown_column_in_detail(detail)?;
    let scope = sql_contract::statement_scope(statement);
    let relations: Vec<&str> = sql_contract::resolve_column_scope(column.as_str(), &scope);
    sql_contract::unknown_column_repair(column.as_str(), &relations, profile)
}

/// SQLite has no dedicated unknown-column error code. Require both the
/// public refusal category and the engine's leading diagnostic, rather than
/// finding column-shaped text inside an unrelated validation error.
fn sqlite_records_facet_key_for_refusal(statement: &str, error: &crate::Error) -> Option<String> {
    let detail = error.to_string();
    detail.strip_prefix("query_sql [syntax_or_type]: no such column:")?;
    sql_contract::unknown_records_facet_key(statement, &detail)
}

/// First FROM/JOIN target that is not a logical relation, qualifiers
/// (`main.`/`temp.`) stripped. Returns `None` when every target resolves.
fn first_non_logical_target(statement: &str) -> Option<String> {
    let tokens: Vec<&str> = statement
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|token| !token.is_empty())
        .collect();
    let mut expect_table = false;
    for token in tokens {
        if token.eq_ignore_ascii_case("from") || token.eq_ignore_ascii_case("join") {
            expect_table = true;
            continue;
        }
        if expect_table {
            expect_table = false;
            let short = token.rsplit('.').next().unwrap_or(token);
            if short.eq_ignore_ascii_case("select") || short.eq_ignore_ascii_case("with") {
                continue;
            }
            if !sql_contract::is_logical_relation(&short.to_ascii_lowercase()) {
                return Some(short.to_string());
            }
        }
    }
    None
}

/// Tier 1.1: the frozen schemas are process-constant, so their batch text is
/// assembled once and each thread keeps one prepared validator connection per
/// schema. Validation itself never writes to these connections — it only sets
/// a per-call authorizer, prepares, then clears the authorizer — so reuse is
/// behavior-preserving. A global lock would serialize every caller prepare
/// across threads; thread-local reuse keeps prepares parallel while still
/// reaching zero schema rebuilds after per-thread warm-up.
static FROZEN_DDL_BATCH: OnceLock<String> = OnceLock::new();
static FROZEN_TEMP_CONTRACT_BATCH: OnceLock<String> = OnceLock::new();

thread_local! {
    static FROZEN_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    static STRICT_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    #[cfg(feature = "v2-kernel-probe")]
    static KERNEL_FROZEN_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    #[cfg(feature = "v2-kernel-probe")]
    static KERNEL_STRICT_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    /// Observability for the tier-1.1 acceptance: how many validator
    /// connections this thread built. Thread-local like the caches, so one
    /// thread's warm-up never moves another thread's count. Incremented only
    /// on the cold path, so reading it is free on every governed call.
    static FROZEN_VALIDATOR_BUILDS: Cell<usize> = const { Cell::new(0) };
    static STRICT_VALIDATOR_BUILDS: Cell<usize> = const { Cell::new(0) };
}

fn frozen_ddl_batch() -> &'static str {
    FROZEN_DDL_BATCH.get_or_init(|| {
        DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect()
    })
}

fn frozen_temp_contract_batch() -> &'static str {
    FROZEN_TEMP_CONTRACT_BATCH.get_or_init(temp_contract)
}

fn build_frozen_validator() -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    #[cfg(feature = "v2-kernel-probe")]
    view_validation::arm(&conn)?;
    conn.execute_batch(frozen_ddl_batch())
        .and_then(|_| conn.execute_batch(frozen_temp_contract_batch()))
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    register_regexp_function(&conn)?;
    register_now_ms_stub(&conn)?;
    register_current_principal_stub(&conn)?;
    register_utc_date_label_stub(&conn)?;
    FROZEN_VALIDATOR_BUILDS.with(|builds| builds.set(builds.get() + 1));
    Ok(conn)
}

fn build_strict_validator() -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    #[cfg(feature = "v2-kernel-probe")]
    view_validation::arm(&conn)?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    // Only this validator substitutes views for the writable public tables.
    // Column-less reads open their private sources and count as dependencies,
    // while same-named CTEs cannot trigger materialization.
    conn.execute_batch(
        "ALTER TABLE temp.facet_keys RENAME TO _query_sql_facet_keys_source;
         CREATE TEMP VIEW facet_keys AS SELECT * FROM _query_sql_facet_keys_source WHERE type IS NOT NULL;
         ALTER TABLE temp.body_task_items RENAME TO _query_sql_task_item_source;
         CREATE TEMP VIEW body_task_items AS
         SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset
         FROM _query_sql_task_item_source;
         ALTER TABLE temp.body_block_headings RENAME TO _query_sql_heading_source;
         CREATE TEMP VIEW body_block_headings AS
         SELECT record_id,block_index,chunk_index,heading_index,depth,title,
                title_truncated,heading_block_index
         FROM _query_sql_heading_source;
         ALTER TABLE temp.record_lifecycle_interpretations RENAME TO _query_sql_lifecycle_source;
         CREATE TEMP VIEW record_lifecycle_interpretations AS
         SELECT record_id,status,raw,axis_key,axis_label,vocabulary_id,
                vocabulary_name,value_id,canonical,terminality,reason
         FROM _query_sql_lifecycle_source WHERE record_id IS NOT NULL;
         ALTER TABLE temp.message_reactions RENAME TO _query_sql_reaction_source;
         CREATE TEMP VIEW message_reactions AS
         SELECT reaction_id,message_id,emoji,actor_record_id,actor_name,
                executor_kind,reacted_at,reacted_at_ms,viewer
         FROM _query_sql_reaction_source WHERE reaction_id IS NOT NULL",
    )
    .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    register_regexp_function(&conn)?;
    register_now_ms_stub(&conn)?;
    register_current_principal_stub(&conn)?;
    register_utc_date_label_stub(&conn)?;
    STRICT_VALIDATOR_BUILDS.with(|builds| builds.set(builds.get() + 1));
    Ok(conn)
}

/// E1 M3: `regexp(pattern, haystack)` on the rusqlite validator
/// connections. SQLite resolves functions at prepare time, so validation
/// (prepare under an authorizer — these connections are never stepped)
/// needs the name to exist; execution runs on the sqlx pool connections,
/// which carry sqlx's bundled implementation via `.with_regexp()`.
/// Semantics mirror Turso's builtin (NULL on NULL, invalid pattern, or
/// non-UTF8 blob; integers and reals coerced to text as Turso's
/// `to_text_coerced` formats them) so any future stepping agrees with
/// Turso. Compiled patterns are cached per connection and bounded.
fn register_regexp_function(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    use rusqlite::types::Value;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const CACHE_CAP: usize = 64;
    let cache: Arc<Mutex<HashMap<String, Option<regex::Regex>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    conn.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let pattern = coerce_regexp_arg(ctx.get::<Value>(0)?);
            let haystack = coerce_regexp_arg(ctx.get::<Value>(1)?);
            let (Some(pattern), Some(haystack)) = (pattern, haystack) else {
                return Ok(None::<i64>);
            };
            if pattern.len() > sql_contract::MAX_REGEXP_PATTERN_BYTES {
                return Ok(None::<i64>);
            }
            let compiled = {
                let mut cache = cache.lock().expect("regexp cache lock");
                if let Some(hit) = cache.get(&pattern) {
                    hit.clone()
                } else {
                    let compiled = regex::Regex::new(&pattern).ok();
                    if cache.len() >= CACHE_CAP {
                        cache.clear();
                    }
                    cache.insert(pattern.clone(), compiled.clone());
                    compiled
                }
            };
            Ok(compiled.map(|expression| i64::from(expression.is_match(&haystack))))
        },
    )
    .map_err(|e| contract_violation(format!("query_sql: regexp setup failed: {e}")))?;
    Ok(())
}

/// E1 M3: `now_ms()` on the rusqlite validator connections. SQLite
/// resolves functions at prepare time, so validation (prepare under an
/// authorizer — these connections are never stepped) needs the name to
/// exist; execution runs on the sqlx pool connections over rewritten text
/// (`now_ms()` becomes a hidden `?N` bound to the statement-fixed value),
/// so this stub's constant is never observed. Registered beside the
/// `regexp` validator function for the same reason.
fn register_now_ms_stub(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "now_ms",
        0,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |_ctx| Ok(0_i64),
    )
    .map_err(|e| contract_violation(format!("query_sql: now_ms setup failed: {e}")))?;
    Ok(())
}

/// `current_principal()` on the rusqlite validator connections, for the
/// same reason as the `now_ms` stub: execution rewrites it to a hidden `?N`
/// bound to the caller's principal, so this stub's NULL is never observed.
fn register_current_principal_stub(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "current_principal",
        0,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |_ctx| Ok(None::<String>),
    )
    .map_err(|e| contract_violation(format!("query_sql: current_principal setup failed: {e}")))?;
    Ok(())
}

/// The caller's principal as the hidden bind for `current_principal()`:
/// the authenticated identity stamped as `content_events.actor`, pushed
/// after the caller's parameters and any hidden clock.
fn push_current_principal_bind(
    parameters: &mut Vec<sql_contract::QuerySqlParameter>,
    principal_uses: usize,
    principal: &QueryPrincipal,
) {
    if principal_uses > 0 {
        parameters.push(sql_contract::QuerySqlParameter::Text {
            value: Some(principal.credential().to_string()),
        });
    }
}

/// Native e25665c: `utc_date_label(ms)` on the rusqlite validator
/// connections. SQLite resolves functions at prepare time, so validation
/// (prepare under an authorizer — these connections are never stepped)
/// needs the name to exist; execution runs over rewritten text (the
/// `strftime` lowering, which carries no `utc_date_label` call), so this
/// stub's NULL is never observed. Registered beside the `now_ms` stub for
/// the same reason. Deterministic +1-arg STRICT shape mirrors the rewrite.
fn register_utc_date_label_stub(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "utc_date_label",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |_ctx| Ok(None::<String>),
    )
    .map_err(|e| contract_violation(format!("query_sql: utc_date_label setup failed: {e}")))?;
    Ok(())
}

/// Turso `to_text_coerced` parity for the validator `regexp`: text as-is,
/// integers and reals in Rust display form, blobs as UTF-8, NULL as NULL.
fn coerce_regexp_arg(value: rusqlite::types::Value) -> Option<String> {
    match value {
        rusqlite::types::Value::Null => None,
        rusqlite::types::Value::Text(text) => Some(text),
        rusqlite::types::Value::Integer(number) => Some(number.to_string()),
        rusqlite::types::Value::Real(number) => Some(number.to_string()),
        rusqlite::types::Value::Blob(bytes) => String::from_utf8(bytes).ok(),
    }
}

fn with_frozen_validator<T>(
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    FROZEN_VALIDATOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(build_frozen_validator()?);
        }
        let conn = slot.as_ref().expect("validator slot populated above");
        operation(conn)
    })
}

fn with_strict_validator<T>(
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    STRICT_VALIDATOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(build_strict_validator()?);
        }
        let conn = slot.as_ref().expect("validator slot populated above");
        operation(conn)
    })
}

#[cfg(feature = "v2-kernel-probe")]
fn configure_kernel_v2_bindings(conn: &rusqlite::Connection, view_expansion: bool) -> Result<()> {
    let ddl = if view_expansion {
        "DROP VIEW temp.bindings; CREATE TEMP VIEW bindings AS SELECT record_id,system,identifier,is_canonical FROM main.bindings;"
    } else {
        "DROP TABLE temp.bindings; CREATE TEMP TABLE bindings(record_id TEXT,system TEXT,identifier TEXT,is_canonical INTEGER);"
    };
    conn.execute_batch(ddl)
        .map_err(|e| contract_violation(format!("query_sql: v2 validator setup failed: {e}")))
}

// Separate caches preserve the v1 logical schema, including its wider bindings
// relation. SQLite must expand stars and describe labels against the same
// supported v2 binding columns that the execution connection actually serves.
#[cfg(feature = "v2-kernel-probe")]
fn with_kernel_v2_validator<T>(
    view_expansion: bool,
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    let use_slot = |slot: &RefCell<Option<rusqlite::Connection>>| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            let conn = if view_expansion {
                build_frozen_validator()?
            } else {
                build_strict_validator()?
            };
            configure_kernel_v2_bindings(&conn, view_expansion)?;
            *slot = Some(conn);
        }
        operation(slot.as_ref().expect("v2 validator initialized"))
    };
    if view_expansion {
        KERNEL_FROZEN_VALIDATOR.with(use_slot)
    } else {
        KERNEL_STRICT_VALIDATOR.with(use_slot)
    }
}

fn validate_view_expansion(statement: &str) -> Result<()> {
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_view_expansion)
    })
}

/// Test-only SQLite-engine oracle for the turso differential: rusqlite
/// acceptance (syntax + schema) without any validator rule layered on.
#[cfg(test)]
pub(crate) fn strict_prepare(sql: &str) -> Result<()> {
    validate_view_expansion(sql)
}

fn validate_view_expansion_legacy_saved_sql(statement: &str) -> Result<()> {
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_view_expansion_legacy_saved_sql)
    })
}

fn validate_strict(statement: &str) -> Result<()> {
    with_strict_validator(|conn| prepare_under_authorizer(conn, statement, authorize_strict))
}

fn validate_strict_legacy_saved_sql(statement: &str) -> Result<()> {
    with_strict_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_strict_legacy_saved_sql)
    })
}

fn validate_view_expansion_ad_hoc(statement: &str) -> Result<()> {
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_view_expansion_ad_hoc)
    })
}

fn validate_strict_ad_hoc(statement: &str) -> Result<()> {
    with_strict_validator(|conn| prepare_under_authorizer(conn, statement, authorize_strict_ad_hoc))
}

/// Ad-hoc online sqlite-local `query_sql` only (Native 702de73): identical
/// gates to [`validate`] with the ad-hoc function allowance in the shared
/// classifier and in both engine authorizers. SQL being saved, stored SQL,
/// member copies, Turso and Postgres never reach this.
pub(crate) fn validate_ad_hoc(sql: &str) -> Result<()> {
    let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
    super::turso_ast_rules::check_statement(&statement)?;
    validate_view_expansion_ad_hoc(&statement)?;
    validate_strict_ad_hoc(&statement)
}

/// KernelV2-only validation. The strict pass still rejects caller-authored
/// physical reads; v1 keeps its original population-read refusal.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn validate_kernel_v2_ad_hoc(sql: &str) -> Result<()> {
    let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
    super::turso_ast_rules::check_statement(&statement)?;
    with_kernel_v2_validator(true, |conn| {
        prepare_under_authorizer(conn, &statement, authorize_kernel_v2_view_expansion)
    })?;
    with_kernel_v2_validator(false, |conn| {
        prepare_under_authorizer(conn, &statement, authorize_strict_ad_hoc)
    })
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn validated_kernel_v2_output_columns(sql: &str) -> Result<Vec<String>> {
    let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
    with_kernel_v2_validator(true, |conn| {
        prepare_under_authorizer(conn, &statement, authorize_kernel_v2_view_expansion)
    })?;
    with_kernel_v2_validator(false, |conn| {
        conn.authorizer(Some(authorize_strict_ad_hoc));
        let prepared = conn.prepare(&statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|e| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, e.to_string())
        })?;
        Ok(prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect())
    })
}

/// Internal execution of already-stored governed definitions. This keeps v1's
/// retained function/ordering allowance, with the same two physical-read gates
/// and public-column observer as ordinary kernel SQL. There is no RPC opt-in.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) type KernelSqlInspection = (BTreeSet<(String, String)>, Vec<String>);

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn inspect_kernel_v2_stored_saved_sql(sql: &str) -> Result<KernelSqlInspection> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, &statement, authorize_kernel_v2_stored_view_expansion)
    })?;
    validate_strict_legacy_saved_sql(&statement)?;
    Ok((
        public_reads_with(&statement, authorize_strict_legacy_saved_sql)?,
        describe_output_columns(&statement, authorize_strict_legacy_saved_sql)?,
    ))
}

/// Validate caller SQL against both the real view expansion and a strict
/// public-only schema. This is security enforcement, not linting.
pub fn validate(sql: &str) -> Result<()> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    // I3 (AST design): per-engine determinism rules on the shared SQLite
    // AST (unparseable statements fail open for the engine gates below,
    // counted in turso_ast_rules). SQLite/Turso text is never rewritten.
    super::turso_ast_rules::check_statement(&statement)?;
    validate_view_expansion(&statement)?;
    validate_strict(&statement)
}

/// Stored governed SQL only (Native e25665c): identical gates except
/// the I2 portable-function rules are replaced by the legacy allowance, in
/// both the shared classifier and the engine authorizers.
pub(crate) fn validate_legacy_saved_sql(sql: &str) -> Result<()> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    validate_strict_legacy_saved_sql(&statement)
}

/// Return the labels SQLite assigns to a validated statement without running
/// it. Saved SQL uses this at admission so an empty result cannot defer output
/// schema drift until a later execution happens to produce rows.
pub(crate) fn validated_output_columns(sql: &str) -> Result<Vec<String>> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    validate_view_expansion(&statement)?;
    describe_output_columns(&statement, authorize_strict)
}

/// Ad-hoc online sqlite-local form of [`validated_output_columns`].
pub(crate) fn validated_output_columns_ad_hoc(sql: &str) -> Result<Vec<String>> {
    let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
    validate_view_expansion_ad_hoc(&statement)?;
    describe_output_columns(&statement, authorize_strict_ad_hoc)
}

fn describe_output_columns(
    statement: &str,
    strict_authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<Vec<String>> {
    with_strict_validator(|conn| {
        conn.authorizer(Some(strict_authorizer));
        let prepared = conn.prepare(statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })?;
        Ok(prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect())
    })
}

/// Stored governed SQL only (Native e25665c): same labels under the
/// legacy function allowance.
pub(crate) fn validated_output_columns_legacy_saved_sql(sql: &str) -> Result<Vec<String>> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    with_strict_validator(|conn| {
        conn.authorizer(Some(authorize_strict_legacy_saved_sql));
        let prepared = conn.prepare(&statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })?;
        Ok(prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect())
    })
}

/// Resolve the logical relations actually read by a validated statement.
/// SQLite's authoritative prepare/authorizer path naturally ignores names in
/// comments and literals and does not mistake a same-named CTE for a catalog
/// dependency.
pub(crate) fn validated_relation_dependencies(
    sql: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    validate_view_expansion(&statement)?;
    observe_relation_dependencies(&statement, authorize_strict)
}

/// Ad-hoc online sqlite-local form of [`validated_relation_dependencies`].
pub(crate) fn validated_relation_dependencies_ad_hoc(
    sql: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
    validate_view_expansion_ad_hoc(&statement)?;
    observe_relation_dependencies(&statement, authorize_strict_ad_hoc)
}

fn observe_relation_dependencies(
    statement: &str,
    strict_authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<std::collections::BTreeSet<String>> {
    let dependencies = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::<
        String,
    >::new()));
    let observed = dependencies.clone();
    with_strict_validator(|conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read { table_name, .. } = context.action {
                if strict_task_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("body_task_items".to_owned());
                } else if strict_heading_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("body_block_headings".to_owned());
                } else if strict_reaction_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("message_reactions".to_owned());
                } else if strict_facet_keys_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("facet_keys".to_owned());
                } else if strict_lifecycle_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("record_lifecycle_interpretations".to_owned());
                } else if context.database_name == Some("temp")
                    && sql_contract::is_logical_relation(table_name)
                {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert(table_name.to_owned());
                }
            }
            strict_authorizer(context)
        }));
        let prepared = conn.prepare(statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })?;
        if !prepared.readonly() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "read-only statement writes",
            ));
        }
        drop(prepared);
        Ok(())
    })?;
    Ok(std::sync::Arc::try_unwrap(dependencies)
        .expect("validator releases dependency observer")
        .into_inner()
        .expect("dependency lock"))
}

/// Prepare-time public reads for adapters with a narrower logical surface.
/// SQLite observes aliases, CTEs, wildcard expansion and column-less counts.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn public_reads_ad_hoc(statement: &str) -> Result<BTreeSet<(String, String)>> {
    public_reads_with(statement, authorize_strict_ad_hoc)
}

#[cfg(feature = "v2-kernel-probe")]
fn public_reads_with(
    statement: &str,
    authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<BTreeSet<(String, String)>> {
    let reads = Arc::new(std::sync::Mutex::new(BTreeSet::new()));
    let observed = reads.clone();
    with_kernel_v2_validator(false, |conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                let relation = if strict_task_source_read(&context, table_name) {
                    "body_task_items"
                } else if strict_heading_source_read(&context, table_name) {
                    "body_block_headings"
                } else if strict_reaction_source_read(&context, table_name) {
                    "message_reactions"
                } else if strict_facet_keys_source_read(&context, table_name) {
                    "facet_keys"
                } else if strict_lifecycle_source_read(&context, table_name) {
                    "record_lifecycle_interpretations"
                } else {
                    table_name
                };
                if sql_contract::is_logical_relation(relation) {
                    observed
                        .lock()
                        .expect("reads lock")
                        .insert((relation.to_owned(), column_name.to_owned()));
                }
            }
            authorizer(context)
        }));
        let result = conn.prepare(statement).map(|_| ()).map_err(|e| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, e.to_string())
        });
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        result
    })?;
    Ok(Arc::try_unwrap(reads)
        .expect("observer released")
        .into_inner()
        .expect("reads lock"))
}

/// Check the app analyzer's read set against SQLite's prepare-time reads on
/// the strict logical schema. The analyzer must run first: it refuses CTEs
/// (including logical-name shadows), so an unqualified column-less read here
/// can only name a catalog relation. Every observed public column must be in
/// the admitted set; excess analyzer grants are conservative and harmless.
/// This supplements the shared executor's viewer fence and view-expansion
/// validation, without changing direct query_sql or legacy saved needs.
/// Returns verified output labels so empty app results retain their schema.
pub(crate) fn validate_app_sql_dependencies(
    sql: &str,
    admitted: &crate::mcp::tools::alpha_tabs::ReadsDeclaration,
) -> Result<Vec<String>> {
    let grants = admitted.grants.clone();
    let verified = with_strict_validator(|conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                // These controlled validator views use private sources.
                // Their internal reads implement the engine's logical relation,
                // not additional app grants; the public view reads below still
                // check the columns requested by the statement.
                let population_read = context.database_name.is_none() && column_name.is_empty();
                let source_relation = if strict_task_source_read(&context, table_name)
                    || (population_read && table_name == "_query_sql_task_item_source")
                {
                    Some("body_task_items")
                } else if strict_heading_source_read(&context, table_name)
                    || (population_read && table_name == "_query_sql_heading_source")
                {
                    Some("body_block_headings")
                } else if strict_facet_keys_source_read(&context, table_name)
                    || (population_read && table_name == "_query_sql_facet_keys_source")
                {
                    Some("facet_keys")
                } else if strict_lifecycle_source_read(&context, table_name)
                    || (population_read && table_name == "_query_sql_lifecycle_source")
                {
                    Some("record_lifecycle_interpretations")
                } else if strict_reaction_source_read(&context, table_name)
                    || (population_read && table_name == "_query_sql_reaction_source")
                {
                    Some("message_reactions")
                } else {
                    None
                };
                if let Some(relation) = source_relation {
                    // SQLite reports population reads of these views using
                    // the private source name and no schema/accessor. The
                    // analyzer excludes that name and CTE shadows, so this
                    // exact mapping cannot admit a caller-authored source read.
                    return if grants.iter().any(|grant| grant.relation == relation) {
                        authorize_strict(context)
                    } else {
                        Authorization::Deny
                    };
                }
                let logical = sql_contract::is_logical_relation(table_name)
                    && (context.database_name == Some("temp")
                        || (context.database_name.is_none() && column_name.is_empty()));
                let covered = logical
                    && grants.iter().any(|grant| {
                        grant.relation.eq_ignore_ascii_case(table_name)
                            && (column_name.is_empty()
                                || grant
                                    .columns
                                    .iter()
                                    .any(|column| column.eq_ignore_ascii_case(column_name)))
                    });
                if !covered {
                    return Authorization::Deny;
                }
            }
            authorize_strict(context)
        }));
        let prepared = conn.prepare(sql);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        Ok(match prepared {
            Ok(statement) if statement.readonly() => Some(
                statement
                    .column_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
            _ => None,
        })
    });
    // Neither SQL text nor SQLite's raw schema/setup diagnostics cross the
    // app boundary. This also refuses disagreement over syntax/resolution.
    if let Some(columns) = verified.ok().flatten() {
        Ok(columns)
    } else {
        Err(crate::error::Error::engine(
            "app_sql [dependency_mismatch]: statement could not be verified against admitted reads",
        ))
    }
}

/// Receipt-only, over-approximating read check (6867ce6 review). True when
/// the stored statement reads any of `names` in any way, including a
/// column-less read (`(SELECT count(*) FROM runs)`), which SQLite authorizes
/// with an empty column name outside the `temp` schema and which the
/// dependency set above therefore omits. A same-named CTE also matches.
/// Both errors only make a receipt more conservative, so this must never
/// feed saved-definition validation, port matching or authorization, which
/// keep the exact dependency set. Any failure to analyse counts as a read.
pub(crate) fn saved_sql_reads_any_relation(sql: &str, names: &[&str]) -> bool {
    let Ok(statement) =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)
    else {
        return true;
    };
    let touched = Arc::new(AtomicBool::new(false));
    let observed = touched.clone();
    let names: Vec<String> = names.iter().map(|name| name.to_ascii_lowercase()).collect();
    let prepared = with_strict_validator(|conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read { table_name, .. } = context.action {
                if names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(table_name))
                {
                    observed.store(true, Ordering::Relaxed);
                }
            }
            authorize_strict_legacy_saved_sql(context)
        }));
        let prepared = conn.prepare(&statement).map(drop);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })
    });
    prepared.is_err() || touched.load(Ordering::Relaxed)
}

/// Stored governed SQL only (Native e25665c): same relation
/// observation under the legacy function allowance.
pub(crate) fn validated_relation_dependencies_legacy_saved_sql(
    sql: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    let dependencies = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::<
        String,
    >::new()));
    let observed = dependencies.clone();
    with_strict_validator(|conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read { table_name, .. } = context.action {
                if strict_reaction_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("message_reactions".to_owned());
                } else if strict_facet_keys_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("facet_keys".to_owned());
                } else if strict_lifecycle_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("record_lifecycle_interpretations".to_owned());
                } else if strict_heading_source_read(&context, table_name) {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert("body_block_headings".to_owned());
                } else if context.database_name == Some("temp")
                    && sql_contract::is_logical_relation(table_name)
                {
                    observed
                        .lock()
                        .expect("dependency lock")
                        .insert(table_name.to_owned());
                }
            }
            authorize_strict_legacy_saved_sql(context)
        }));
        let prepared = conn.prepare(&statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })?;
        if !prepared.readonly() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "read-only statement writes",
            ));
        }
        drop(prepared);
        Ok(())
    })?;
    Ok(std::sync::Arc::try_unwrap(dependencies)
        .expect("validator releases dependency observer")
        .into_inner()
        .expect("dependency lock"))
}

/// Test-only predicate for the mechanical trigger-coverage test (slice
/// F-B): which `TEMP_CONTRACT` views belong to the authorization fence.
/// A new authorization view must either follow the
/// `_query_sql_authorization*` naming or extend this predicate — it
/// lives next to the views it governs, and the coverage accessor below
/// fails loudly if it matches nothing.
#[cfg(test)]
fn is_authorization_coverage_view(name: &str) -> bool {
    name.starts_with("_query_sql_authorization") || name == "_query_sql_visible_records"
}

/// Test-only accessor for the mechanical trigger-coverage test (slice
/// F-B): the SELECT bodies of every governed authorization view, with
/// the bearer-depth placeholder substituted exactly as the installed
/// contract does. Discovered from the live `TEMP_CONTRACT` via
/// `is_authorization_coverage_view`, so a new fence view is picked up
/// automatically and the covered column set cannot drift from the
/// served views.
#[cfg(test)]
pub(crate) fn authorization_view_coverage_selects() -> Vec<(String, String)> {
    let contract = TEMP_CONTRACT.replace(
        "__MAX_DERIVED_BEARER_DEPTH__",
        &crate::authorization::MAX_DERIVED_BEARER_DEPTH.to_string(),
    );
    let mut views = Vec::new();
    for statement in contract.split(';') {
        let Some(at) = statement.find("CREATE TEMP VIEW IF NOT EXISTS ") else {
            continue;
        };
        let after = &statement[at + "CREATE TEMP VIEW IF NOT EXISTS ".len()..];
        let end = after.find(char::is_whitespace).unwrap_or(after.len());
        let name = &after[..end];
        if !is_authorization_coverage_view(name) {
            continue;
        }
        // The contract chunk holding a view starts with its comments
        // (TEMP_CONTRACT statements split on `;`), so locate the
        // prefix inside the chunk rather than at its start.
        let prefix = format!("CREATE TEMP VIEW IF NOT EXISTS {name} AS");
        let select = statement
            .find(&prefix)
            .map(|index| statement[index + prefix.len()..].trim().to_owned())
            .unwrap_or_else(|| panic!("TEMP_CONTRACT view {name} has no body"));
        let upper = select.to_ascii_uppercase();
        assert!(
            upper.starts_with("WITH") || upper.starts_with("SELECT"),
            "{name} body is a SELECT"
        );
        views.push((name.to_owned(), select));
    }
    assert!(
        !views.is_empty(),
        "TEMP_CONTRACT contains no authorization coverage views"
    );
    views
}

/// Authorizer observation for rule inputs: (relation -> read columns) over the
/// strict public-only schema. `""` marks a column-less population read
/// (COUNT(*)/EXISTS report the table with no database and an empty column,
/// parent-reproduced); every other real read carries temp. Same-name CTE
/// fakes are impossible: the shape gate forbids them before this runs.
fn observe_rule_reads(statement: &str) -> Result<(BTreeMap<String, BTreeSet<String>>, usize)> {
    let observed = std::sync::Arc::new(std::sync::Mutex::new(
        BTreeMap::<String, BTreeSet<String>>::new(),
    ));
    let seen = observed.clone();
    let parameter_count = with_strict_validator(|conn| {
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                if strict_reaction_source_read(&context, table_name) {
                    seen.lock()
                        .expect("dependency lock")
                        .entry("message_reactions".to_owned())
                        .or_default()
                        .insert(String::new());
                } else if context.database_name.is_none()
                    && column_name.is_empty()
                    && table_name == "_query_sql_heading_source"
                {
                    seen.lock()
                        .expect("dependency lock")
                        .entry("body_block_headings".to_owned())
                        .or_default()
                        .insert(String::new());
                } else if sql_contract::is_logical_relation(table_name)
                    && (context.database_name == Some("temp")
                        || (context.database_name.is_none() && column_name.is_empty()))
                {
                    seen.lock()
                        .expect("dependency lock")
                        .entry(table_name.to_owned())
                        .or_default()
                        .insert(column_name.to_owned());
                }
            }
            authorize_strict(context)
        }));
        let prepared = conn.prepare(statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|error| {
            sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
        })?;
        if !prepared.readonly() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "read-only statement writes",
            ));
        }
        let parameter_count = prepared.parameter_count();
        drop(prepared);
        Ok(parameter_count)
    })?;
    let observed = std::sync::Arc::try_unwrap(observed)
        .expect("validator releases dependency observer")
        .into_inner()
        .expect("dependency lock");
    Ok((observed, parameter_count))
}

/// Authoritative rule-input read-set (task 81c1d95, pure slice): validated SQL
/// text in, ordered pinned relations plus parameter slots out. No caller trust
/// anywhere: classification, the fail-closed shape gate, view expansion, and
/// authorizer observation all run on the host. Unprovable shapes
/// (USING/NATURAL, `*`, logical-name CTE shadows) never reach observation;
/// best-effort relations are refused after it.
pub(crate) fn extract_rule_input_dependencies(
    sql: &str,
) -> Result<native_query_contract::rule_contract::RuleInputReadset> {
    use native_query_contract::rule_contract::{PinnedRelation, RuleInputReadset};
    let profile = sql_contract::QuerySqlProfile::SqliteLocal;
    let statement = sql_contract::classify_single_read_statement(profile, sql)?;
    // Both gates: the existing deterministic semantics (LIMIT/GROUP BY) that
    // query_sql enforces via validate(), plus the stronger fail-closed rule
    // shape gate. Anything validate() rejects stays rejected here.
    super::turso_ast_rules::check_statement(&statement)?;
    super::turso_ast_rules::check_rule_statement(&statement)?;
    validate_view_expansion(&statement)?;
    let snapshot = current_catalog_snapshot();
    let mut relations = Vec::new();
    let (observed, parameter_count) = observe_rule_reads(&statement)?;
    for (name, mut columns) in observed {
        let live = native_query_contract::rule_contract::find_relation(&snapshot, &name)
            .ok_or_else(|| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::Engine,
                    format!("rule input observed unaudited relation '{name}'"),
                )
            })?;
        // Rule-side eligibility on top of the structural pin: best-effort
        // and transient relations are refused even if ever admitted.
        native_query_contract::rule_contract::check_rule_eligibility(live)?;
        let population_only = columns.len() == 1 && columns.contains("");
        columns.remove("");
        relations.push(PinnedRelation {
            identity: live.identity.clone(),
            name,
            semantic_version: live.semantic_version,
            columns,
            population_only,
        });
    }
    // Conservative time disposition: hidden now_ms() is rejected — time
    // arrives explicitly via ?N with a declared now_ms parameter source
    // (argument | input_row | now_ms), never as an implicit source. Slots
    // stay token-derived (placeholder_slots), never regex.
    if sql_contract::statement_uses_now_ms(profile, &statement)? {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "rule inputs reject hidden now_ms(): bind time explicitly with ?N and declare the now_ms parameter source",
        ));
    }
    // A rule authorises a write at commit; a viewer-relative input would
    // make its verdict depend on who happened to evaluate it.
    if sql_contract::statement_uses_current_principal(profile, &statement)? {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "rule inputs reject current_principal(): a rule's inputs must not depend on who evaluates it",
        ));
    }
    // Authoritative slots cross-checked against the prepared statement's own
    // parameter count: both derive 1..=N, so any divergence fails closed.
    let parameter_slots = sql_contract::placeholder_slots(profile, &statement)?;
    if parameter_count != parameter_slots.len() {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::Engine,
            "rule input placeholder slots disagree with the prepared parameter count",
        ));
    }
    Ok(RuleInputReadset {
        relations,
        parameter_slots,
        uses_now_ms: false,
    })
}

/// Live catalog as pure data for the shared rule/saved-SQL compatibility
/// policy. Built from the actual catalog constants on every call — there is
/// no public API accepting a caller-supplied catalog; pure-checker tests use
/// synthetic snapshots directly.
pub(crate) fn current_catalog_snapshot() -> native_query_contract::rule_contract::CatalogSnapshot {
    use native_query_contract::rule_contract::{CatalogSnapshot, RelationSnapshot};
    let profile = sql_contract::QuerySqlProfile::SqliteLocal.contract();
    CatalogSnapshot {
        revision: sql_contract::LOGICAL_CATALOG_REVISION,
        profile_id: profile.id.to_owned(),
        profile_revision: profile.revision,
        relations: sql_contract::LOGICAL_RELATIONS
            .iter()
            .map(|relation| RelationSnapshot {
                identity: relation.identity.to_owned(),
                name: relation.name.to_owned(),
                semantic_version: relation.semantic_version,
                columns: relation.columns.iter().map(|c| c.to_string()).collect(),
                completeness: relation.completeness.to_owned(),
                profiles: relation.profiles.iter().map(|p| p.to_string()).collect(),
            })
            .collect(),
    }
}

/// Compatibility entry point for the authorization spike's independent
/// backend validator. Backend preparation remains authoritative there.
#[cfg(test)]
pub(super) fn validate_input(sql: &str) -> Result<()> {
    sql_contract::classify_single_read_statement(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    Ok(())
}

pub(crate) fn json_cell(row: &SqliteRow, index: usize) -> Result<Value> {
    let raw = row.try_get_raw(index)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let value = match raw.type_info().name().to_uppercase().as_str() {
        "INTEGER" => Value::Number(row.try_get::<i64, _>(index)?.into()),
        "REAL" => Number::from_f64(row.try_get::<f64, _>(index)?)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        "BLOB" => {
            use base64::Engine as _;
            let bytes: Vec<u8> = row.try_get(index)?;
            let encoded_len = bytes.len().saturating_add(2) / 3 * 4 + 2;
            if encoded_len > MAX_CELL_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
                ));
            }
            Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        _ => {
            let text: String = row.try_get(index)?;
            if text.len() > MAX_CELL_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
                ));
            }
            Value::String(text)
        }
    };
    if serde_json::to_vec(&value)?.len() > MAX_CELL_ENCODED_BYTES {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
        ));
    }
    Ok(value)
}

async fn populate_messages_awaiting_reply(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<()> {
    let started = Instant::now();
    let ensure_budget = || {
        if started.elapsed() >= QUERY_DEADLINE {
            Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "messages_awaiting_reply exceeded the query execution deadline",
            ))
        } else {
            Ok(())
        }
    };
    sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut **transaction)
        .await?;
    // Caller-relative audience resolution is deliberately exact. Missing or
    // ambiguous account/person/principal bindings produce the same
    // content-free failure and never leak which part was unavailable. An
    // empty relation would falsely claim that a current member was resolved.
    let identities = sqlx::query(
        "SELECT account.record_id, native_principal.identifier
           FROM main.bindings account
           JOIN main.records person ON person.id=account.record_id
           JOIN main.bindings native_principal
             ON native_principal.record_id=account.record_id
            AND native_principal.system='native-principal'
            AND native_principal.is_canonical=1
          WHERE account.system='account' AND account.identifier=?
            AND account.is_canonical=1 AND person.deleted_at IS NULL
            AND person.type='Entity' AND person.kind='person'
          ORDER BY account.record_id,native_principal.identifier LIMIT 2",
    )
    .bind(principal.credential())
    .fetch_all(&mut **transaction)
    .await?;
    ensure_budget()?;
    if identities.len() != 1 {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::Engine,
            "current member unavailable",
        ));
    }
    let native_principal: String = identities[0].try_get("identifier")?;

    let mut candidates = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT message.id
           FROM main.records message
           JOIN temp._query_sql_visible_ids visible ON visible.id=message.id
           JOIN main.facet_values expectation
             ON expectation.record_id=message.id
            AND expectation.key='expectation' AND expectation.value='reply'
           JOIN main.message_audiences audience
             ON audience.message_id=message.id
            AND audience.source='addressed_to' AND audience.principal_id=?
          WHERE message.type='Message' AND message.deleted_at IS NULL
          ORDER BY message.id LIMIT ?",
    )
    .bind(native_principal)
    .bind(MAX_AWAITING_REPLY_CANDIDATES + 1)
    .fetch_all(&mut **transaction)
    .await?;
    ensure_budget()?;
    if candidates.len() > MAX_AWAITING_REPLY_CANDIDATES as usize {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!(
                "messages_awaiting_reply exceeds the {MAX_AWAITING_REPLY_CANDIDATES}-candidate evaluation limit"
            ),
        ));
    }

    for message_id in candidates.drain(..) {
        ensure_budget()?;
        let derivation =
            crate::message_expectation::derive_message_expectation_state_for_viewer_in(
                transaction,
                &message_id,
                principal.credential(),
            )
            .await?;
        ensure_budget()?;
        if derivation.expectation.as_deref() == Some("reply")
            && derivation.state == crate::message_expectation::MessageExpectationState::Open
        {
            sqlx::query(
                "INSERT INTO temp._query_sql_messages_awaiting_reply(message_id) VALUES (?)",
            )
            .bind(message_id)
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

/// Author-facing timeout diagnostic. SQLite reports the progress-handler
/// interrupt as its own terse text ("interrupted"), which names neither the
/// governed deadline nor the usual author-side cause, so replace it here.
/// Internal table names stay out: only the caller-relative relations authors
/// already write against (`records`, `links`) are named.
fn governed_sql_timeout() -> crate::error::Error {
    sql_contract::categorized_error(
        QuerySqlErrorCategory::Timeout,
        sql_contract::deadline_hint(),
    )
}

pub(crate) fn map_stream_error(error: sqlx::Error) -> crate::error::Error {
    if error
        .to_string()
        .to_ascii_lowercase()
        .contains("interrupted")
    {
        governed_sql_timeout()
    } else {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    }
}

/// Bound one validated statement for execution. Ordinary statements run under
/// an outer cap that preserves every caller predicate/aggregate while bounding
/// row work. `EXPLAIN QUERY PLAN` returns the plan rather than record data and
/// cannot be a subquery operand, so it runs as classified; the streaming loop
/// still enforces the row/column/cell/result limits and the progress-handler
/// deadline. The classifier normalizes the only admitted `EXPLAIN` form to
/// this exact prefix over an already-admissible statement.
/// E2 ad-hoc default ORDER BY: when the top-level statement carries LIMIT
/// with no ORDER BY, splice `ORDER BY 1, .., n` (labels from a
/// prepare-without-execution, which also expands `SELECT *`) and report the
/// assumption for disclosure. Stored governed SQL never reaches this helper
/// (the save gate and the `LegacySavedSql` entries do not call it); nested
/// unordered LIMITs keep their refusal in `validate()`, which callers run on
/// the rewritten text.
pub(crate) fn apply_ad_hoc_default_order(
    statement: &str,
    allowance: sql_contract::FunctionAllowance,
) -> Result<(String, Option<sql_contract::AssumedOrder>)> {
    apply_ad_hoc_default_order_with(statement, |statement| match allowance {
        sql_contract::FunctionAllowance::SqliteAdHoc => validated_output_columns_ad_hoc(statement),
        _ => validated_output_columns(statement),
    })
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn apply_kernel_v2_default_order(
    statement: &str,
) -> Result<(String, Option<sql_contract::AssumedOrder>)> {
    apply_ad_hoc_default_order_with(statement, validated_kernel_v2_output_columns)
}

fn apply_ad_hoc_default_order_with(
    statement: &str,
    describe: impl FnOnce(&str) -> Result<Vec<String>>,
) -> Result<(String, Option<sql_contract::AssumedOrder>)> {
    if !super::turso_ast_rules::top_level_unordered_limit(statement) {
        return Ok((statement.to_owned(), None));
    }
    // Label discovery is describe-only, but a failed describe (unknown
    // column, denied relation, duplicate labels) must not invent a new
    // error: fall through so the original validator below surfaces the
    // categorised error exactly as before the default.
    let described = describe(statement);
    let labels = match described {
        Ok(labels) => labels,
        Err(_) => return Ok((statement.to_owned(), None)),
    };
    match sql_contract::apply_default_order(
        sql_contract::QuerySqlProfile::SqliteLocal,
        statement,
        &labels,
    ) {
        Some((rewritten, assumed)) => Ok((rewritten, Some(assumed))),
        None => Ok((statement.to_owned(), None)),
    }
}

/// Name ordering repairs only after the complete repaired SQL validates.
/// Request parameter checks remain at the execution boundaries below.
/// This is diagnostic text: nested row membership is never changed implicitly.
pub(crate) fn default_order_repair(sql: &str) -> Option<String> {
    default_order_repair_with(sql, validated_output_columns, validate)
}

fn default_order_repair_with(
    sql: &str,
    describe: impl Fn(&str) -> Result<Vec<String>>,
    validate_repaired: impl Fn(&str) -> Result<()>,
) -> Option<String> {
    let levels = super::turso_ast_rules::unordered_limit_levels(sql)?;
    if levels.is_empty() {
        return None;
    }
    // Preserve E2's established wording for the top-level-only case.
    if levels.len() == 1 && levels[0].location == "top level" {
        let labels = describe(sql).ok()?;
        let (rewritten, assumed) = sql_contract::apply_default_order(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
            &labels,
        )?;
        validate_repaired(&rewritten).ok()?;
        return Some(format!(
            "the ad-hoc default would order by ({}): add {}",
            assumed.columns.join(", "),
            assumed.order_by
        ));
    }
    let mut rewritten = sql.to_owned();
    let mut fixes = Vec::new();
    let mut edits: Vec<(std::ops::Range<usize>, isize)> = Vec::new();
    // Inner ranges precede their parents in this loop. Reapply the shared E2
    // splice to each updated range so overlapping SELECTs retain child fixes.
    for level in levels.iter().rev() {
        let labels = match level.column_count {
            Some(count) => vec![String::new(); count],
            None => describe(level.describe_sql.as_deref()?).ok()?,
        };
        let growth: isize = edits
            .iter()
            .filter(|(range, _)| range.start >= level.range.start && range.end <= level.range.end)
            .map(|(_, growth)| growth)
            .sum();
        let end = level.range.end.checked_add_signed(growth)?;
        let (fixed, assumed) = sql_contract::apply_default_order(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &rewritten[level.range.start..end],
            &labels,
        )?;
        edits.push((
            level.range.clone(),
            fixed.len() as isize - (end - level.range.start) as isize,
        ));
        rewritten.replace_range(level.range.start..end, &fixed);
        fixes.push(format!("in {}: add {}", level.location, assumed.order_by));
    }
    validate_repaired(&rewritten).ok()?;
    fixes.reverse();
    Some(format!(
        "ordering repair (all output columns in projection order): {}",
        fixes.join("; ")
    ))
}

fn with_nested_order_repair(
    sql: &str,
    error: crate::Error,
    allowance: sql_contract::FunctionAllowance,
) -> crate::Error {
    if error.to_string().contains("LIMIT without ORDER BY") {
        let repair = match allowance {
            sql_contract::FunctionAllowance::SqliteAdHoc => {
                default_order_repair_with(sql, validated_output_columns_ad_hoc, validate_ad_hoc)
            }
            _ => default_order_repair(sql),
        };
        if let Some(repair) = repair {
            return crate::Error::Engine(format!("{error}; {repair}"));
        }
    }
    error
}

pub(crate) fn cap_statement(statement: &str, row_limit: i64) -> String {
    if statement.starts_with("EXPLAIN QUERY PLAN ") {
        statement.to_owned()
    } else {
        format!("SELECT * FROM ({statement}) LIMIT {}", row_limit + 1)
    }
}

/// Run one caller-filtered query. The caller is transport-authenticated and is
/// never derived from tool arguments. The owned path acquires from the
/// dedicated governed-SQL pool, never the write pool, so governed reads —
/// which hold their connection through per-row JSON encoding — cannot starve
/// ordinary writers. Every explicit outcome rolls back; drop does the same
/// for cancellation/unwind, and pool release clears the TEMP state plus
/// progress callback before any later borrower can use it.
/// Ad-hoc `query_sql` entry: the server default ORDER BY is enabled, so an
/// unordered top-level LIMIT executes disclosed instead of refusing. All
/// other callers use the entries below with the default disabled.
pub(crate) async fn query_sql_request_owned(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    query_sql_request_owned_with_vm_work(db, principal, request, None, true).await
}

/// The ad-hoc `query_sql` MCP tool's entry (Native 702de73): identical to
/// [`query_sql_request_owned`] except that online sqlite-local execution
/// runs under [`sql_contract::FunctionAllowance::SqliteAdHoc`]. Member
/// copies keep the portable set on this entry as well. Library, test and
/// internal callers of `query_sql_request_owned` stay portable.
pub(crate) async fn query_sql_request_ad_hoc(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    query_sql_request_owned_observed(
        db,
        principal,
        request,
        None,
        None,
        true,
        sql_contract::FunctionAllowance::SqliteAdHoc,
    )
    .await
}

/// Same governed execution and result as `query_sql_request_owned`, with an
/// internal-only, coarse SQLite VM progress-callback counter. No count is
/// included in `SqlResult` or exposed to the tool caller.
pub(crate) async fn query_sql_request_owned_with_vm_work(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    vm_callbacks: Option<Arc<AtomicU64>>,
    apply_default_order: bool,
) -> Result<SqlResult> {
    query_sql_request_owned_observed(
        db,
        principal,
        request,
        vm_callbacks,
        None,
        apply_default_order,
        sql_contract::FunctionAllowance::Portable,
    )
    .await
}

/// Trusted server-side replay for tests. Production replay now flows through
/// the caller-transaction observed core; the supplied clock replaces only
/// the hidden `now_ms()` bind and is never a tool argument.
#[cfg(test)]
pub(crate) async fn query_sql_request_owned_replay(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    now_ms_override: i64,
) -> Result<SqlResult> {
    query_sql_request_owned_observed(
        db,
        principal,
        request,
        None,
        Some(now_ms_override),
        false,
        sql_contract::FunctionAllowance::Portable,
    )
    .await
}

/// Member-slice execution (contract c323277 rev 8 §2.3 `query_sql`).
/// Rows at parity for served relations; compiled catalog views identical;
/// envelope `as_of_seq` is 0 here and omitted by the member scrub.
/// Slice presence (`main.records`) replaces the policy/Unit fold; excluded
/// tables are never opened (denied above). No read_log/activity/history IO.
#[allow(clippy::too_many_arguments)]
async fn query_sql_member_slice(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    statement: String,
    relation_dependencies: std::collections::BTreeSet<String>,
    vm_callbacks: Option<Arc<AtomicU64>>,
    now_ms_override: Option<i64>,
    assumed_order: Option<sql_contract::AssumedOrder>,
    time_dependent: bool,
    now_ms_uses: usize,
    principal_uses: usize,
) -> Result<SqlResult> {
    let _ = now_ms_uses;
    let pool = db.governed_pool().clone();
    let mut connection = pool.acquire().await?;
    if let Err(error) = install_temp_contract(&mut connection).await {
        connection.close_on_drop();
        return Err(error.into());
    }
    // Member profile drops the physical currency columns (`is_current`,
    // `successor_count`), so the shared view would fail with `no such
    // column`. Replace it with the slice-derived form: visible incoming
    // `supersedes` count (deleted sources never ship) and the tri-state
    // currency (1 iff zero, else NULL, per `ddl.rs` E3 M1). Hidden successors
    // are never counted — the R1 carve-out shared with `get_record`'s
    // `superseded_by`, never a hidden identity, content or count.
    for member_statement in [MEMBER_RECORDS_VIEW_DDL, MEMBER_FACET_VALUES_VIEW_DDL] {
        if let Err(error) = sqlx::query(member_statement)
            .execute(&mut *connection)
            .await
        {
            connection.close_on_drop();
            return Err(error.into());
        }
    }
    for clear in [
        "DELETE FROM temp._query_sql_principal",
        "DELETE FROM temp._query_sql_visible_ids",
        "DELETE FROM temp._query_sql_facet_keys",
        "DELETE FROM temp._query_sql_messages_awaiting_reply",
        "DELETE FROM temp._query_sql_activity_members",
        "DELETE FROM temp._query_sql_claim_candidates",
        "DELETE FROM temp._query_sql_claim_releases",
        "DELETE FROM temp._query_sql_disclosable_actors",
        "DELETE FROM temp._query_sql_activity_observations",
        "DELETE FROM temp._query_sql_activity_capture",
    ] {
        if let Err(error) = sqlx::query(clear).execute(&mut *connection).await {
            connection.close_on_drop();
            return Err(error.into());
        }
    }
    let mut transaction = connection.begin().await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at) VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO temp._query_sql_visible_ids(id) SELECT id FROM main.records",
    )
    .execute(&mut *transaction)
    .await?;
    let facet_deadline = relation_dependencies
        .contains("facet_keys")
        .then(|| Instant::now() + QUERY_DEADLINE);
    if let Some(deadline) = facet_deadline {
        if let Err(error) = populate_facet_keys(&mut transaction, deadline).await {
            drop(transaction);
            connection.close_on_drop();
            return Err(error);
        }
    }
    let now_ms_ms: Option<i64> = time_dependent
        .then(|| now_ms_override.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()));
    // Bounded member statement execution inline (same grammar/bounds/value
    // model as online, over the slice; `as_of_seq` is 0, omitted by scrub).
    // Inline because `transaction` borrows `connection`: moving both into a
    // helper trips E0505, while inline rollback ends the borrow as online.
    use futures::TryStreamExt as _;
    let vm_work_active = vm_callbacks
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));
    let previous_value_limit = {
        let mut handle = transaction.lock_handle().await?;
        let previous = unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                MAX_SQLITE_VALUE_BYTES,
            )
        };
        let mut query_started = None;
        let vm_callbacks = vm_callbacks.clone();
        let vm_work_active = vm_work_active.clone();
        handle.set_progress_handler(PROGRESS_OPS, move || {
            if facet_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return false;
            }
            if let (Some(callbacks), Some(active)) = (&vm_callbacks, &vm_work_active) {
                if active.load(Ordering::Acquire) {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                }
            }
            query_started.get_or_insert_with(Instant::now).elapsed() < QUERY_DEADLINE
        });
        previous
    };
    let capped = cap_statement(&statement, MAX_ROWS);
    let mut effective_parameters = request.parameters.clone();
    if let Some(now_ms) = now_ms_ms {
        effective_parameters.push(sql_contract::QuerySqlParameter::Integer {
            value: Some(now_ms.to_string()),
        });
    }
    push_current_principal_bind(&mut effective_parameters, principal_uses, &principal);
    sql_contract::check_positional_arguments(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        effective_parameters.len(),
    )?;
    let query_result: Result<(Vec<String>, Vec<Value>, bool)> = async {
        check_facet_deadline(facet_deadline)?;
        let query = bind_parameters(sqlx::query(&capped), &effective_parameters)?;
        let _phase = QueryVmWorkPhase::start(vm_work_active.clone());
        let mut stream = query.fetch(&mut *transaction);
        let mut columns = Vec::new();
        let mut output = Vec::new();
        let mut encoded_bytes = 2_usize;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(map_stream_error)? {
            if output.len() as i64 == MAX_ROWS {
                truncated = true;
                break;
            }
            if columns.is_empty() {
                if row.columns().len() > MAX_COLUMNS {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!("result exceeds the {MAX_COLUMNS}-column limit"),
                    ));
                }
                columns = row.columns().iter().map(|c| c.name().to_string()).collect();
                let mut unique = std::collections::HashSet::new();
                if let Some(dup) = columns.iter().find(|c| !unique.insert(c.as_str())) {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::DuplicateColumns,
                        format!("duplicate output column label '{dup}'"),
                    ));
                }
                encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&columns)?.len());
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().to_string(), json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes
                .saturating_add(serde_json::to_vec(&value)?.len())
                .saturating_add(1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("encoded result exceeds the {MAX_RESULT_ENCODED_BYTES}-byte limit"),
                ));
            }
            output.push(value);
        }
        Ok((columns, output, truncated))
    }
    .await;
    let query_result = query_result.and_then(|rows| {
        check_facet_deadline(facet_deadline)?;
        Ok(rows)
    });
    let query_result = annotate_sqlite_toobig_error(
        &mut transaction,
        &relation_dependencies,
        &request.sql,
        query_result,
    )
    .await;
    let query_failed = query_result.is_err();
    let rollback_result = transaction.rollback().await;
    let deadline_result = async {
        let mut handle = connection.lock_handle().await?;
        handle.remove_progress_handler();
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
        Result::<()>::Ok(())
    }
    .await;
    if query_failed || rollback_result.is_err() || deadline_result.is_err() {
        connection.close_on_drop();
    }
    let (columns, rows, truncated) = query_result?;
    rollback_result?;
    deadline_result?;
    Ok(SqlResult {
        columns,
        row_count: rows.len(),
        rows,
        truncated,
        truncation_hint: sql_contract::truncation_hint_for(truncated),
        as_of_seq: 0,
        now_ms_ms,
        time_dependent,
        assumed_order,
    })
}

/// This relation is advertised as hosted-writer-only. The v1 and copy paths
/// may keep an empty validator shape, but never serve it as an empty answer.
fn refuse_named_view_details(dependencies: &BTreeSet<String>) -> Result<()> {
    if dependencies.contains("catalog_view_definitions") {
        return Err(crate::Error::engine("view_profile_unsupported: catalog_view_definitions requires standalone hosted writer reads"));
    }
    Ok(())
}

async fn query_sql_request_owned_observed(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    vm_callbacks: Option<Arc<AtomicU64>>,
    now_ms_override: Option<i64>,
    apply_default_order: bool,
    allowance: sql_contract::FunctionAllowance,
) -> Result<SqlResult> {
    use sql_contract::FunctionAllowance;
    sql_contract::require_available(sql_contract::QuerySqlProfile::SqliteLocal)?;
    request.validate()?;
    let member_mode = db.open_mode() == crate::db::DatabaseOpenMode::MemberReadOnly;
    // Native 702de73: the ad-hoc dialect is online-only. A member copy's
    // preflight, `schema_config` gate and slice execution all run on the
    // portable set, so member ad-hoc SQL stays portable.
    let allowance = match allowance {
        FunctionAllowance::SqliteAdHoc if member_mode => FunctionAllowance::Portable,
        other => other,
    };
    let ad_hoc = allowance == FunctionAllowance::SqliteAdHoc;
    let statement = if ad_hoc {
        sql_contract::classify_sqlite_ad_hoc_statement(&request.sql)?
    } else {
        sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &request.sql,
        )?
    };
    // E2 ad-hoc default ORDER BY: enabled only when the caller passes
    // `apply_default_order` (the ad-hoc `query_sql` entry does; every other
    // caller leaves it off). Splice before validation so `validate()` below
    // runs once, on the final portable text; nested unordered LIMITs keep
    // their refusal there.
    let (statement, assumed_order) = if apply_default_order {
        apply_ad_hoc_default_order(&statement, allowance)?
    } else {
        (statement, None)
    };
    // Member copy (c323277 rev 8 §2.3 `query_sql`): prepare-time typed denial
    // before anything else that can refuse — including `validate()` below,
    // whose column-less gate errors (rather than observes) on some forbidden
    // reads such as `messages_awaiting_reply`. The probe runs on the spliced
    // portable text with observation only and no validation gates, so shapes
    // stay exactly as the existing two-phase validator accepts them; online
    // behavior is unchanged because this branch only runs on member copies.
    // Never fabricates empty TEMP relations.
    if member_mode {
        if let Some(denied) = member_denied_requirement(&statement)? {
            refuse_named_view_details(&BTreeSet::from([denied.clone()]))?;
            return Err(crate::error::Error::unavailable_offline(
                "query_sql",
                denied,
            ));
        }
    }
    let validation = if ad_hoc {
        validate_ad_hoc(&statement)
    } else {
        validate(&statement)
    };
    if let Err(error) = validation {
        // Validation uses an empty schema. Probe through the ordinary bounded
        // executor so online policy and member slice visibility stay identical.
        if let Some(key) = sqlite_records_facet_key_for_refusal(&statement, &error) {
            let probe = QuerySqlRequest {
                sql: "SELECT key FROM facet_values WHERE key = ?1 ORDER BY key LIMIT 1".into(),
                parameters: vec![sql_contract::QuerySqlParameter::Text {
                    value: Some(key.clone()),
                }],
            };
            if Box::pin(query_sql_request_owned_observed(
                db,
                principal,
                probe,
                None,
                None,
                false,
                FunctionAllowance::Portable,
            ))
            .await
            .is_ok_and(|result| result.row_count > 0)
            {
                return Err(crate::Error::Engine(format!(
                    "{error} {}",
                    sql_contract::records_facet_column_hint(&statement, &error.to_string(), &key)
                )));
            }
        }
        return Err(if apply_default_order {
            with_nested_order_repair(&request.sql, error, allowance)
        } else {
            error
        });
    }
    // I1 review: `?2` with one parameter must fail, not bind a silent
    // NULL. The `?N` set has to be exactly `1..=parameters.len()`.
    sql_contract::check_positional_arguments(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        request.parameters.len(),
    )?;
    // E1 M3: bound `?N` regexp patterns meet the same subset and cap as
    // literals (stored definitions predate the registry and may bind
    // anything, so the saved path through here is covered as well).
    sql_contract::validate_regexp_bound_patterns(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &request.parameters,
    )?;
    // Native 702de73: the ad-hoc dialect's clock refusal also covers text
    // bound as `now` / `localtime` / `utc` into a date/time function.
    if ad_hoc {
        sql_contract::validate_ad_hoc_clock_bound_args(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &statement,
            &request.parameters,
        )?;
    }
    // Native e25665c: bound `?N` label arguments meet the integer contract
    // (a `Text`-typed bound value is rejected with the type repair instead
    // of forking per engine at runtime).
    sql_contract::validate_utc_date_label_bound_args(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &request.parameters,
    )?;
    // E1 M3: every `now_ms()` becomes one hidden positional
    // (`?{parameters.len() + 1}`) bound below to the single
    // statement-fixed value. The exact-set check above already refused any
    // caller use of that index, so the hidden value is unspoofable; every
    // use in one statement shares it, so all uses agree.
    let hidden_index = request.parameters.len() + 1;
    let (statement, now_ms_uses) = sql_contract::rewrite_now_ms_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &format!("?{hidden_index}"),
    )?;
    let time_dependent = now_ms_uses > 0;
    // `current_principal()` takes the next hidden slot after the clock.
    let principal_index = hidden_index + usize::from(time_dependent);
    let (statement, principal_uses) = sql_contract::rewrite_current_principal_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &format!("?{principal_index}"),
    )?;
    // Relation dependencies resolve on the portable text: the
    // `utc_date_label` lowering below introduces `strftime`, which the
    // portable classifier refuses by design. The lowering embeds only the
    // caller's own argument, so it adds no relation.
    let relation_dependencies = if ad_hoc {
        validated_relation_dependencies_ad_hoc(&statement)?
    } else {
        validated_relation_dependencies(&statement)?
    };
    refuse_named_view_details(&relation_dependencies)?;
    // Native e25665c: lower `utc_date_label(ms)` to the SQLite `strftime`
    // expression after validation (the validator saw the portable name via
    // the stub above). The lowering introduces no placeholder, so the
    // exact-set check still holds; no engine clock is exposed.
    let (statement, _) = sql_contract::rewrite_utc_date_label_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        sql_contract::UtcDateLabelEngine::Sqlite,
    )?;

    // `catalog_operations` resolves only with the executor's trusted
    // snapshot (attached on the ad-hoc online dispatch). The member probe
    // above already denied member copies with their own typed refusal, so
    // this gate keeps its member-first order: it runs only for online
    // executions.
    let catalog_operations_snapshot =
        resolve_catalog_operations_snapshot(&relation_dependencies, &principal)?;
    // Member slice execution (denial already returned above): never opens
    // excluded policy/history/Unit tables. Forbidden statements never reach
    // here.
    if member_mode {
        return query_sql_member_slice(
            db,
            principal,
            request,
            statement,
            relation_dependencies,
            vm_callbacks,
            now_ms_override,
            assumed_order,
            time_dependent,
            now_ms_uses,
            principal_uses,
        )
        .await;
    }

    let needs_reactions = relation_dependencies.contains("message_reactions");
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let needs_lifecycle = relation_dependencies.contains("record_lifecycle_interpretations");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let needs_claims = relation_dependencies.contains("agent_activity_claims");
    // `actors` additionally resolves each disclosed actor's visible person.
    let needs_actor_persons = relation_dependencies.contains("actors");
    let needs_disclosure = relation_dependencies.contains("content_events") || needs_actor_persons;
    let pool = db.governed_pool().clone();
    let mut connection = pool.acquire().await?;
    if let Err(error) = install_temp_contract(&mut connection).await {
        connection.close_on_drop();
        return Err(error.into());
    }
    // This clear is deliberately outside the transaction: rolling it back
    // would restore a stale principal. Uncertain physical state is discarded.
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_facet_keys; DELETE FROM temp._query_sql_lifecycle_interpretations")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_activity_members")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_claim_releases")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_disclosable_actors")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_visible_ids")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_reaction_winners")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    let mut transaction = connection.begin().await?;
    guard_run_intents_source(&mut transaction, &request.sql).await?;
    // Hosted roster installation touches only TEMP state. Fix the main
    // snapshot before sampling the inference clock so a concurrent commit can
    // never enter rows after their observation time. When the SQL mentions
    // `run_intents` the guard's catalog read above has already started it,
    // and this read keeps every other statement on the same footing.
    let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
        .fetch_optional(&mut *transaction)
        .await?;
    // Freshness stamp (E1 M1 slice A): the workspace content sequence observed
    // inside this same read transaction, so the returned rows and the stamp
    // share one snapshot. This is the unfiltered workspace head, not the
    // caller-visible maximum: hidden writes still advance it.
    let as_of_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
            .fetch_one(&mut *transaction)
            .await?;
    // E1 M3: statement-fixed clock, captured once per statement beside the
    // freshness stamp. `None` when the statement uses no `now_ms()`; every
    // use in one statement shares this value via the hidden bind below.
    let now_ms_ms: Option<i64> = time_dependent
        .then(|| now_ms_override.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()));
    if activity_dependent {
        populate_activity_members(&mut transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
         VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .execute(&mut *transaction)
    .await?;
    // Slice 1 (task 77bd40a): stage the visible set once per read,
    // unconditionally. A dependency gate cannot be exact here: SQLite
    // reports column-less aggregates such as `count(*)` with no database
    // name, so observation silently misses them and a gated-out statement
    // would read an empty table as an empty workspace. One staged
    // evaluation per read is the slice's stated cost; cache hits make
    // repeats cheap.
    #[cfg(test)]
    let stage_cpu_before = slice1_phase_cpu_before();
    populate_visible_ids_owned(&db, &mut transaction, &principal).await?;
    #[cfg(test)]
    slice1_phase_cpu_after(stage_cpu_before, Slice1Phase::Stage);
    let facet_deadline = relation_dependencies
        .contains("facet_keys")
        .then(|| Instant::now() + QUERY_DEADLINE);
    if let Some(deadline) = facet_deadline {
        if let Err(error) = populate_facet_keys(&mut transaction, deadline).await {
            drop(transaction);
            connection.close_on_drop();
            return Err(error);
        }
    }
    if needs_lifecycle {
        if let Err(error) = populate_lifecycle_interpretations(&mut transaction).await {
            drop(transaction);
            connection.close_on_drop();
            return Err(error);
        }
    }
    if let Some(snapshot) = catalog_operations_snapshot.as_ref() {
        if let Err(error) = populate_catalog_operations(&mut transaction, snapshot).await {
            drop(transaction);
            connection.close_on_drop();
            return Err(error);
        }
    }
    if activity_dependent {
        prepare_activity_observations(&mut transaction).await?;
    }
    if needs_claims {
        prepare_claim_candidates(&mut transaction).await?;
    }
    if needs_disclosure {
        prepare_disclosable_actors(&mut transaction, needs_actor_persons).await?;
    }
    let vm_work_active = vm_callbacks
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));
    let previous_value_limit = {
        let mut handle = transaction.lock_handle().await?;
        // SAFETY: `lock_handle` gives exclusive access to this connection's
        // live sqlite3 handle for the duration of the call.
        let previous = unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                MAX_SQLITE_VALUE_BYTES,
            )
        };
        // Start the wall-clock budget when SQLite first executes caller VM
        // work, not when this async task registers the callback. Under process
        // load the task can be descheduled between registration and fetch;
        // charging that queue/scheduler delay made bounded queries fail with
        // SQLITE_INTERRUPT despite doing no work during the elapsed time.
        let mut query_started = None;
        #[cfg(test)]
        let reaction_clock = needs_reactions
            .then(|| REACTION_TEST_CLOCK.try_with(Arc::clone).ok())
            .flatten();
        let vm_callbacks = vm_callbacks.clone();
        let vm_work_active = vm_work_active.clone();
        handle.set_progress_handler(PROGRESS_OPS, move || {
            if facet_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return false;
            }
            if let (Some(callbacks), Some(active)) = (&vm_callbacks, &vm_work_active) {
                if active.load(Ordering::Acquire) {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                }
            }
            #[cfg(test)]
            if let Some(clock) = &reaction_clock {
                return reaction_test_budget_alive(clock, &mut query_started);
            }
            query_started.get_or_insert_with(Instant::now).elapsed() < QUERY_DEADLINE
        });
        previous
    };

    // The outer cap preserves every caller predicate/aggregate while bounding
    // row work. Rows are streamed and encoded under independent cell/result
    // byte ceilings; the progress handler independently bounds VM work.
    let capped = cap_statement(&statement, MAX_ROWS);
    let mut limit_breached = false;
    #[cfg(test)]
    let caller_cpu_before = slice1_phase_cpu_before();
    let query_result: Result<(Vec<String>, Vec<Value>, bool)> = async {
        check_facet_deadline(facet_deadline)?;
        if needs_reactions {
            let _vm_work_phase = QueryVmWorkPhase::start(vm_work_active.clone());
            populate_reaction_winners(&mut transaction).await?;
        }
        if needs_awaiting_reply {
            populate_messages_awaiting_reply(&mut transaction, &principal).await?;
        }
        // E1 M3: caller parameters plus the hidden statement-fixed clock.
        // The defensive exact-set check fails closed if the rewrite above
        // ever disagrees with the bind list.
        let mut effective_parameters = request.parameters.clone();
        if let Some(now_ms) = now_ms_ms {
            effective_parameters.push(sql_contract::QuerySqlParameter::Integer {
                value: Some(now_ms.to_string()),
            });
        }
        push_current_principal_bind(&mut effective_parameters, principal_uses, &principal);
        sql_contract::check_positional_arguments(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &statement,
            effective_parameters.len(),
        )?;
        let query = bind_parameters(sqlx::query(&capped), &effective_parameters)?;
        let _vm_work_phase = QueryVmWorkPhase::start(vm_work_active.clone());
        let mut stream = query.fetch(&mut *transaction);
        let mut columns = Vec::new();
        let mut output = Vec::new();
        let mut encoded_bytes = 2_usize; // JSON array brackets.
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(map_stream_error)? {
            if output.len() as i64 == MAX_ROWS {
                truncated = true;
                break;
            }
            if columns.is_empty() {
                if row.columns().len() > MAX_COLUMNS {
                    limit_breached = true;
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!("result exceeds the {MAX_COLUMNS}-column limit"),
                    ));
                }
                columns = row
                    .columns()
                    .iter()
                    .map(|column| column.name().to_string())
                    .collect();
                let mut unique = std::collections::HashSet::new();
                if let Some(duplicate) = columns
                    .iter()
                    .find(|column| !unique.insert(column.as_str()))
                {
                    limit_breached = true;
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::DuplicateColumns,
                        format!("duplicate output column label '{duplicate}'"),
                    ));
                }
                encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&columns)?.len());
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().to_string(), json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes
                .saturating_add(serde_json::to_vec(&value)?.len())
                .saturating_add(1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                limit_breached = true;
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("encoded result exceeds the {MAX_RESULT_ENCODED_BYTES}-byte limit"),
                ));
            }
            output.push(value);
        }
        Ok((columns, output, truncated))
    }
    .await;
    #[cfg(test)]
    slice1_phase_cpu_after(caller_cpu_before, Slice1Phase::Caller);

    let query_result = query_result.and_then(|rows| {
        check_facet_deadline(facet_deadline)?;
        Ok(rows)
    });
    let query_result = annotate_sqlite_toobig_error(
        &mut transaction,
        &relation_dependencies,
        &request.sql,
        query_result,
    )
    .await;

    let query_failed = query_result.is_err();
    let rollback_result = transaction.rollback().await;
    let deadline_result = async {
        let mut handle = connection.lock_handle().await?;
        handle.remove_progress_handler();
        // SAFETY: as above; restore the exact per-connection limit observed
        // before caller SQL ran. Pool release has an independent backstop for
        // cancellation/unwind before this point.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
        Result::<()>::Ok(())
    }
    .await;
    if query_failed || limit_breached || rollback_result.is_err() || deadline_result.is_err() {
        connection.close_on_drop();
    }
    let (columns, rows, truncated) = query_result?;
    rollback_result?;
    deadline_result?;
    let row_count = rows.len();
    Ok(SqlResult {
        columns,
        rows,
        row_count,
        truncated,
        truncation_hint: sql_contract::truncation_hint_for(truncated),
        as_of_seq,
        now_ms_ms,
        time_dependent,
        assumed_order,
    })
}

/// Snapshot-preserving form for artifact input resolution. The caller owns the
/// surrounding read transaction and must roll it back; this function installs
/// only connection-local TEMP views/principal state and restores VM limits and
/// the progress handler before returning.
#[cfg(test)]
pub(crate) async fn query_sql_request_in(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    query_sql_request_in_with_row_limit(
        transaction,
        principal,
        request,
        MAX_ROWS,
        sql_contract::FunctionAllowance::Portable,
    )
    .await
    .map(|(result, _)| result)
}

/// Internal saved-query execution retains one extra row so the governed
/// envelope can validate the identity/order boundary before truncating it.
/// Stored definitions run under the legacy saved-SQL function allowance
/// (Native e25665c): the only caller executing stored governed SQL.
pub(crate) async fn query_sql_request_in_for_saved(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit(
        transaction,
        principal,
        request,
        MAX_ROWS + 1,
        sql_contract::FunctionAllowance::LegacySavedSql,
    )
    .await
}

/// Bounded governed read inside the caller's transaction. The probe row
/// beyond `row_limit` is how a preparer proves a complete result instead
/// of digesting a truncation (`cap_statement` requests `row_limit + 1`
/// and reports `truncated`).
pub(crate) async fn query_sql_request_in_with_row_limit(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
    allowance: sql_contract::FunctionAllowance,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit_observed(
        transaction,
        principal,
        request,
        row_limit,
        allowance,
        None,
        None,
        // The server default ORDER BY is ad-hoc-`query_sql`-only; every
        // caller of this shared entry (sql_write previews, alpha needs,
        // stored execution, tests) runs with it off.
        false,
    )
    .await
}

/// Server-only observed form of the caller-transaction executor. `replay_clock`
/// replaces only the statement-fixed `now_ms()` bind when the statement
/// genuinely uses it; clock-free statements ignore it. `vm_callbacks` records
/// caller-authored VM work plus reaction-dependent bounded freshness and
/// reaction staging via the progress handler's active phase. Other preparation,
/// metadata, diagnostic probes and cleanup stay uncounted. No
/// caller-supplied clock or public MCP option flows here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn query_sql_request_in_with_row_limit_observed(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
    allowance: sql_contract::FunctionAllowance,
    replay_clock: Option<i64>,
    vm_callbacks: Option<Arc<AtomicU64>>,
    apply_default_order: bool,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit_scoped(
        transaction,
        principal,
        request,
        row_limit,
        allowance,
        replay_clock,
        vm_callbacks,
        apply_default_order,
        &[],
        ContractMode::PerCall,
    )
    .await
}

/// App-only entry after declaration admission and dependency verification.
/// Narrow owner records inside the viewer fence before caller SQL executes.
/// Body chunks join that same narrowed set. Other scoped relations must be refused by admission until their semantics exist.
pub(crate) async fn query_app_sql_request_in_with_row_limit(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
    scopes: &[crate::mcp::tools::alpha_tabs::ReadScope],
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit_scoped(
        transaction,
        principal,
        request,
        row_limit,
        sql_contract::FunctionAllowance::Portable,
        None,
        None,
        false,
        scopes,
        ContractMode::PerCall,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn query_sql_request_in_with_row_limit_scoped(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
    allowance: sql_contract::FunctionAllowance,
    replay_clock: Option<i64>,
    vm_callbacks: Option<Arc<AtomicU64>>,
    apply_default_order: bool,
    record_scopes: &[crate::mcp::tools::alpha_tabs::ReadScope],
    contract: ContractMode<'_>,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    use sql_contract::FunctionAllowance;
    sql_contract::require_available(sql_contract::QuerySqlProfile::SqliteLocal)?;
    request.validate()?;
    let statement = match allowance {
        FunctionAllowance::Portable => sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &request.sql,
        )?,
        FunctionAllowance::LegacySavedSql => sql_contract::classify_stored_saved_sql(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &request.sql,
        )?,
        FunctionAllowance::SqliteAdHoc => {
            sql_contract::classify_sqlite_ad_hoc_statement(&request.sql)?
        }
    };
    // E2 ad-hoc default ORDER BY: enabled only when the caller passes
    // `apply_default_order`. Never keyed on the allowance: `sql_write`
    // selection previews, alpha-tab needs and stored execution all run
    // through this entry with the default off, so a mutation's target set
    // is always stated by the author. Splice before validation so the
    // allowance validators below run once, on the final text.
    let (statement, assumed_order) = if apply_default_order {
        apply_ad_hoc_default_order(&statement, allowance)?
    } else {
        (statement, None)
    };
    let validation = match allowance {
        FunctionAllowance::Portable => validate(&statement),
        FunctionAllowance::LegacySavedSql => validate_legacy_saved_sql(&statement),
        FunctionAllowance::SqliteAdHoc => validate_ad_hoc(&statement).and_then(|()| {
            sql_contract::validate_ad_hoc_clock_bound_args(
                sql_contract::QuerySqlProfile::SqliteLocal,
                &statement,
                &request.parameters,
            )
            .map_err(crate::Error::from)
        }),
    };
    if let Err(error) = validation {
        if let Some(key) = sqlite_records_facet_key_for_refusal(&statement, &error) {
            let probe = QuerySqlRequest {
                sql: "SELECT key FROM facet_values WHERE key = ?1 ORDER BY key LIMIT 1".into(),
                parameters: vec![sql_contract::QuerySqlParameter::Text {
                    value: Some(key.clone()),
                }],
            };
            if Box::pin(query_sql_request_in_with_row_limit_scoped(
                transaction,
                principal,
                probe,
                1,
                FunctionAllowance::Portable,
                None,
                None,
                false,
                record_scopes,
                contract,
            ))
            .await
            .is_ok_and(|(result, _)| result.row_count > 0)
            {
                return Err(crate::Error::Engine(format!(
                    "{error} {}",
                    sql_contract::records_facet_column_hint(&statement, &error.to_string(), &key)
                )));
            }
        }
        return Err(if apply_default_order {
            with_nested_order_repair(&request.sql, error, allowance)
        } else {
            error
        });
    }
    // I1 review: `?2` with one parameter must fail, not bind a silent
    // NULL. The `?N` set has to be exactly `1..=parameters.len()`.
    sql_contract::check_positional_arguments(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        request.parameters.len(),
    )?;
    // E1 M3: bound `?N` regexp patterns meet the same subset and cap as
    // literals (stored definitions predate the registry and may bind
    // anything, so the saved path through here is covered as well).
    sql_contract::validate_regexp_bound_patterns(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &request.parameters,
    )?;
    // Native e25665c: bound `?N` label arguments meet the integer contract
    // (see the ad-hoc path above; stored definitions predate the registry
    // and may bind anything, so the saved path is covered as well).
    sql_contract::validate_utc_date_label_bound_args(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &request.parameters,
    )?;
    // E1 M3: every `now_ms()` becomes one hidden positional
    // (`?{parameters.len() + 1}`), shared by every use in the statement.
    // The exact-set check above already refused any caller use of that
    // index, so the hidden value is unspoofable. Stored definitions keep
    // their text: the wrapped saved query carries `now_ms()` through the
    // legacy allowance and is rewritten here, per statement, like ad-hoc.
    let hidden_index = request.parameters.len() + 1;
    let (statement, now_ms_uses) = sql_contract::rewrite_now_ms_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &format!("?{hidden_index}"),
    )?;
    let time_dependent = now_ms_uses > 0;
    // `current_principal()` takes the next hidden slot after the clock.
    let principal_index = hidden_index + usize::from(time_dependent);
    let (statement, principal_uses) = sql_contract::rewrite_current_principal_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        &format!("?{principal_index}"),
    )?;
    // Dependencies resolve on the portable text (see the ad-hoc path):
    // the lowering below introduces `strftime`, which the portable
    // classifier refuses by design. Stored definitions keep their text
    // through the legacy allowance either way.
    let relation_dependencies = match allowance {
        FunctionAllowance::Portable => validated_relation_dependencies(&statement)?,
        FunctionAllowance::LegacySavedSql => {
            validated_relation_dependencies_legacy_saved_sql(&statement)?
        }
        FunctionAllowance::SqliteAdHoc => validated_relation_dependencies_ad_hoc(&statement)?,
    };
    refuse_named_view_details(&relation_dependencies)?;
    // Saved SQL, alpha-tab needs and every other in-transaction execution
    // carry no serving snapshot, so a real reference refuses here instead
    // of reading an empty table. The ad-hoc owned path above populates;
    // this shared path only ever resolves `None` today.
    let catalog_operations_snapshot =
        resolve_catalog_operations_snapshot(&relation_dependencies, &principal)?;
    // Native e25665c: lower `utc_date_label(ms)` to the SQLite `strftime`
    // expression after the dependency resolution above.
    let (statement, _) = sql_contract::rewrite_utc_date_label_calls(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        sql_contract::UtcDateLabelEngine::Sqlite,
    )?;

    let needs_reactions = relation_dependencies.contains("message_reactions");
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let needs_lifecycle = relation_dependencies.contains("record_lifecycle_interpretations");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let needs_claims = relation_dependencies.contains("agent_activity_claims");
    // `actors` additionally resolves each disclosed actor's visible person.
    let needs_actor_persons = relation_dependencies.contains("actors");
    let needs_disclosure = relation_dependencies.contains("content_events") || needs_actor_persons;
    let presence_only =
        relation_dependencies.len() == 1 && relation_dependencies.contains("agent_activity");
    match contract {
        ContractMode::PerCall => install_temp_contract(transaction).await?,
        // Installed once for the session. Its per-execution state is
        // cleared here in full, so nothing an earlier execution staged
        // (principal, visible ids, activity or claim rows) reaches this one.
        ContractMode::Session(_) => {
            sqlx::query(SESSION_EXECUTION_RESET)
                .persistent(false)
                .execute(&mut **transaction)
                .await?;
        }
    }
    sqlx::query("DELETE FROM temp._query_sql_reaction_winners")
        .execute(&mut **transaction)
        .await?;
    guard_run_intents_source(transaction, &request.sql).await?;
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_facet_keys; DELETE FROM temp._query_sql_lifecycle_interpretations")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_activity_members")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_claim_releases")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_disclosable_actors")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_visible_ids")
        .execute(&mut **transaction)
        .await?;
    // SQLite transactions are deferred: establish the main-database snapshot
    // before sampling the wall clock used for both row inference and receipt
    // metadata. Otherwise a concurrent commit could enter the result after the
    // sampled observation time.
    let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
        .fetch_optional(&mut **transaction)
        .await?;
    // Freshness stamp (E1 M1 slice A): same-snapshot workspace head as the
    // owned path above. Unfiltered on purpose; hidden writes advance it.
    let envelope_sql = if needs_reactions {
        REACTION_BORROWED_ENVELOPE_SQL
    } else {
        "SELECT COALESCE(MAX(seq), 0) FROM main.content_events"
    };
    let as_of_seq: i64 = sqlx::query_scalar(envelope_sql)
        .fetch_one(&mut **transaction)
        .await?;
    // E1 M3: statement-fixed clock, captured once per statement beside the
    // freshness stamp. Stored definitions share this path with ad-hoc.
    // Server replay overrides only this bind when `now_ms()` is used.
    let now_ms_ms: Option<i64> = time_dependent
        .then(|| replay_clock.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()));
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if activity_dependent {
        populate_activity_members(transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
         VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(&observed_at)
    .execute(&mut **transaction)
    .await?;
    // Slice 1 (task 77bd40a): always staged here, same unconditional
    // rule as the owned path (dependency observation misses `count(*)`
    // shapes). This path has no `Db` handle for the shared cache, so the
    // set is evaluated live in the caller's own transaction — same
    // snapshot, same principal row — and the unconditional
    // `visible_content_event_seq` probe below then reads the staged table
    // through `temp.content_events`, exactly one walk either way.
    match contract {
        ContractMode::PerCall => populate_visible_ids_live(transaction).await?,
        // A session carries its database, so the set comes through the
        // shared per-database cache under its exact principal and fence
        // key, sampled in this transaction's snapshot, as the owned
        // `query_sql` path stages it.
        ContractMode::Session(db) => {
            populate_visible_ids_owned(db, transaction, &principal).await?
        }
    }
    if !record_scopes.is_empty() {
        // Scope entries are a union. No kind means every kind (including
        // NULL) of that exact type. This only removes viewer-visible IDs;
        // it cannot grant visibility or depend on caller WHERE predicates.
        let scopes: Vec<Value> = record_scopes
            .iter()
            .map(|scope| match &scope.kind {
                Some(kind) => serde_json::json!({"type": scope.type_name, "kind": kind}),
                None => serde_json::json!({"type": scope.type_name}),
            })
            .collect();
        sqlx::query(
            "DELETE FROM temp._query_sql_visible_ids AS visible
             WHERE NOT EXISTS (
               SELECT 1 FROM main.records AS record, json_each(?) AS scope
               WHERE record.id = visible.id
                 AND record.type COLLATE BINARY = json_extract(scope.value, '$.type')
                 AND (json_type(scope.value, '$.kind') IS NULL
                      OR record.kind COLLATE BINARY = json_extract(scope.value, '$.kind'))
             )",
        )
        .bind(serde_json::to_string(&scopes)?)
        .execute(&mut **transaction)
        .await?;
    }
    let facet_deadline = relation_dependencies
        .contains("facet_keys")
        .then(|| Instant::now() + QUERY_DEADLINE);
    if let Some(deadline) = facet_deadline {
        if let Err(error) = populate_facet_keys(transaction, deadline).await {
            if let ContractMode::PerCall = contract {
                cleanup_query_sql_temp_contract(transaction).await?;
            }
            return Err(error);
        }
    }
    if needs_lifecycle {
        if let Err(error) = populate_lifecycle_interpretations(transaction).await {
            if let ContractMode::PerCall = contract {
                cleanup_query_sql_temp_contract(transaction).await?;
            }
            return Err(error);
        }
    }
    if let Some(snapshot) = catalog_operations_snapshot.as_ref() {
        if let Err(error) = populate_catalog_operations(transaction, snapshot).await {
            if let ContractMode::PerCall = contract {
                cleanup_query_sql_temp_contract(transaction).await?;
            }
            return Err(error);
        }
    }
    let (transient_available, transient_watermark) = if activity_dependent {
        prepare_activity_observations(transaction).await?
    } else {
        (true, None)
    };
    if needs_claims {
        prepare_claim_candidates(transaction).await?;
    }
    if needs_disclosure {
        prepare_disclosable_actors(transaction, needs_actor_persons).await?;
    }
    let visible_content_event_seq: Option<i64> = if needs_reactions {
        // Resolve only inside the existing deadline scope below. Other
        // observations retain their existing head query and semantics.
        None
    } else {
        Some(
            sqlx::query_scalar("SELECT coalesce(max(local_seq),0) FROM temp.content_events")
                .fetch_one(&mut **transaction)
                .await?,
        )
    };
    let (activity_content_event_seq, control_event_seq): (i64, i64) = if activity_dependent {
        sqlx::query_as(
            "SELECT coalesce((SELECT max(event.seq)
                                FROM main.content_events event
                                JOIN main.agent_runs run ON run.run_key=event.run_key
                                LEFT JOIN main.content_event_claim_meta AS claim_meta
                                  ON claim_meta.event_seq = event.seq
                               WHERE event.actor=run.account_id
                                 AND NOT (event.type='record.updated'
                                          AND (COALESCE(claim_meta.has_claimed_by, 1) = 1
                                               OR COALESCE(claim_meta.has_claimed_run, 1) = 1))
                                 AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                                               WHERE member.account_id=run.account_id)
                                      OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                                          AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
                                 AND (run.ended_at IS NULL
                                  OR julianday(event.created_at)<=julianday(run.ended_at))),0),
                coalesce((SELECT max(max(start_event_seq,coalesce(close_event_seq,start_event_seq)))
                            FROM main.agent_runs run
                           WHERE EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                                           WHERE member.account_id=run.account_id)
                              OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                                  AND run.account_id=(SELECT account_id FROM temp._query_sql_principal))),0)",
        )
        .fetch_one(&mut **transaction)
        .await?
    } else {
        (0, 0)
    };
    let content_event_seq = if presence_only {
        Some(activity_content_event_seq)
    } else if activity_dependent {
        visible_content_event_seq.map(|head| head.max(activity_content_event_seq))
    } else {
        visible_content_event_seq
    };
    let authorization_boundary = if presence_only {
        // Presence authorization is independent of record policy state. Hash
        // exactly the request-local roster installed for this query.
        let admitted_accounts: Vec<(String, String)> = sqlx::query_as(
            "SELECT account_id,member_ref FROM temp._query_sql_activity_members ORDER BY account_id",
        )
        .fetch_all(&mut **transaction)
        .await?;
        let source = serde_json::to_vec(&(
            principal.credential(),
            principal.trusted_local_bypass(),
            principal.activity_read(),
            admitted_accounts,
        ))?;
        format!(
            "native.authorization-snapshot.v1.{:x}",
            Sha256::digest(source)
        )
    } else if needs_reactions {
        // Filled only after bounded admission inside the deadline scope.
        String::new()
    } else {
        // Hash the effective caller-visible authorization set rather than the
        // database-global policy epoch. Hidden, unrelated policy mutations
        // cannot perturb this token, while every hide/unhide changes it.
        let mut digest = Sha256::new();
        let prefix = serde_json::to_vec(&(
            principal.credential(),
            principal.trusted_local_bypass(),
            relation_dependencies.iter().cloned().collect::<Vec<_>>(),
        ))?;
        digest.update((prefix.len() as u64).to_be_bytes());
        digest.update(prefix);
        let mut visible = sqlx::query("SELECT id FROM temp._query_sql_visible_ids ORDER BY id")
            .fetch(&mut **transaction);
        while let Some(row) = visible.try_next().await? {
            let id: String = row.try_get(0)?;
            digest.update((id.len() as u64).to_be_bytes());
            digest.update(id.as_bytes());
        }
        format!("native.authorization-snapshot.v1.{:x}", digest.finalize())
    };
    let mut observation = GovernedSqlObservation {
        observed_at,
        content_event_seq,
        lifecycle_event_seq: activity_dependent.then_some(control_event_seq),
        authorization_boundary,
        transient_watermark,
        transient_available,
    };
    let vm_work_active = vm_callbacks
        .as_ref()
        .map(|_| Arc::new(AtomicBool::new(false)));
    // A single absolute deadline covers head seeks, staging and output.
    // Explicit checks between small seeks complement the VM callback: each
    // indexed LIMIT 1 can perform fewer than PROGRESS_OPS instructions.
    let reaction_started = needs_reactions.then(Instant::now);
    let reaction_deadline = reaction_started.map(ReactionDeadline::new);
    let previous_value_limit = {
        let mut handle = transaction.lock_handle().await?;
        // SAFETY: lock_handle gives exclusive access to this sqlite handle.
        let previous = unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                MAX_SQLITE_VALUE_BYTES,
            )
        };
        let mut query_started = None;
        let handler_reaction_deadline = reaction_deadline.clone();
        let vm_callbacks = vm_callbacks.clone();
        let vm_work_active = vm_work_active.clone();
        handle.set_progress_handler(PROGRESS_OPS, move || {
            if facet_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return false;
            }
            if let (Some(callbacks), Some(active)) = (&vm_callbacks, &vm_work_active) {
                if active.load(Ordering::Acquire) {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                }
            }
            if let Some(deadline) = &handler_reaction_deadline {
                !deadline.expired()
            } else {
                query_started.get_or_insert_with(Instant::now).elapsed() < QUERY_DEADLINE
            }
        });
        previous
    };
    let capped = cap_statement(&statement, row_limit);
    let query_result: Result<(Vec<String>, Vec<Value>, bool)> = async {
        check_facet_deadline(facet_deadline)?;
        if needs_reactions {
            let _vm_work_phase = QueryVmWorkPhase::start(vm_work_active.clone());
            let visible_head = bounded_reaction_visible_head(
                transaction,
                reaction_deadline.as_ref().expect("reaction deadline"),
            )
            .await?;
            observation.content_event_seq = Some(if activity_dependent {
                visible_head.max(activity_content_event_seq)
            } else {
                visible_head
            });
            observation.authorization_boundary = reaction_visible_authorization_boundary(
                transaction,
                &principal,
                &relation_dependencies,
                reaction_deadline.as_ref().expect("reaction deadline"),
            )
            .await?;
            populate_reaction_winners(transaction).await?;
        }
        if needs_awaiting_reply {
            populate_messages_awaiting_reply(transaction, &principal).await?;
        }
        if let Some(deadline) = &reaction_deadline {
            ensure_reaction_deadline(deadline)?;
        }
        // E1 M3: caller parameters plus the hidden statement-fixed clock,
        // with the same defensive exact-set check as the owned path.
        let mut effective_parameters = request.parameters.clone();
        if let Some(now_ms) = now_ms_ms {
            effective_parameters.push(sql_contract::QuerySqlParameter::Integer {
                value: Some(now_ms.to_string()),
            });
        }
        push_current_principal_bind(&mut effective_parameters, principal_uses, &principal);
        sql_contract::check_positional_arguments(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &statement,
            effective_parameters.len(),
        )?;
        let query = bind_parameters(sqlx::query(&capped), &effective_parameters)?;
        let _vm_work_phase = QueryVmWorkPhase::start(vm_work_active.clone());
        let mut stream = query.fetch(&mut **transaction);
        let mut columns = Vec::new();
        let mut output = Vec::new();
        let mut encoded_bytes = 2_usize;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(map_stream_error)? {
            if let Some(deadline) = &reaction_deadline {
                ensure_reaction_deadline(deadline)?;
            }
            if output.len() as i64 == row_limit {
                truncated = true;
                break;
            }
            if columns.is_empty() {
                if row.columns().len() > MAX_COLUMNS {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!("result exceeds the {MAX_COLUMNS}-column limit"),
                    ));
                }
                columns = row
                    .columns()
                    .iter()
                    .map(|column| column.name().to_string())
                    .collect();
                let mut unique = std::collections::HashSet::new();
                if let Some(duplicate) = columns
                    .iter()
                    .find(|column| !unique.insert(column.as_str()))
                {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::DuplicateColumns,
                        format!("duplicate output column label '{duplicate}'"),
                    ));
                }
                encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&columns)?.len());
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().to_string(), json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes
                .saturating_add(serde_json::to_vec(&value)?.len())
                .saturating_add(1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("encoded result exceeds the {MAX_RESULT_ENCODED_BYTES}-byte limit"),
                ));
            }
            output.push(value);
        }
        if let Some(deadline) = &reaction_deadline {
            ensure_reaction_deadline(deadline)?;
        }
        Ok((columns, output, truncated))
    }
    .await;
    // Probe while the progress handler is still installed so the 500ms
    // stored-value scan cannot run unbounded. diagnose() replaces the
    // handler with the probe budget; cleanup below removes it.
    let query_result = query_result.and_then(|rows| {
        check_facet_deadline(facet_deadline)?;
        Ok(rows)
    });
    let query_result = annotate_sqlite_toobig_error(
        transaction,
        &relation_dependencies,
        &request.sql,
        query_result,
    )
    .await;
    {
        let mut handle = transaction.lock_handle().await?;
        handle.remove_progress_handler();
        // SAFETY: same exclusive handle; restore the exact previous limit.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
    }
    // The TEMP catalog is connection-scoped and shadows physical table names.
    // Artifact resolution continues in this same transaction to hydrate the
    // selected record IDs, so remove the governed projection before invoking
    // ordinary domain reads. The already-materialized result remains valid.
    let cleanup_result = match contract {
        ContractMode::PerCall => cleanup_query_sql_temp_contract(transaction).await,
        // The session drops the contract once, in `finish`.
        ContractMode::Session(_) => Ok(()),
    };
    let (columns, rows, truncated) = query_result?;
    cleanup_result?;
    Ok((
        SqlResult {
            row_count: rows.len(),
            columns,
            rows,
            truncated,
            truncation_hint: sql_contract::truncation_hint_for(truncated),
            as_of_seq,
            now_ms_ms,
            time_dependent,
            assumed_order,
        },
        observation,
    ))
}

struct OversizedStoredValue {
    relation: &'static str,
    column: &'static str,
    id: String,
    bytes: i32,
}

struct ProbeReport {
    offenders: Vec<OversizedStoredValue>,
    incomplete: Option<&'static str>,
}

struct TooBigBlobTarget {
    relation: &'static str,
    physical_table: &'static str,
    columns: &'static [&'static str],
    visible_rowids_sql: &'static str,
}

/// Physical TEXT/BLOB columns that can exceed SQLITE_LIMIT_LENGTH. Candidate
/// ids are taken from the staged `_query_sql_visible_ids` (or the same join the
/// logical view uses) so the probe cannot name a row the caller cannot see.
/// `facet_values.value` is the stored TEXT column; the generated virtual
/// `value_num` is never opened.
const TOOBIG_BLOB_TARGETS: &[TooBigBlobTarget] = &[
    TooBigBlobTarget {
        relation: "records",
        physical_table: "records",
        columns: &["body", "name", "summary"],
        visible_rowids_sql: "SELECT visible.id, physical.rowid
             FROM temp._query_sql_visible_ids AS visible
             JOIN main.records AS physical ON physical.id = visible.id
             ORDER BY visible.id",
    },
    TooBigBlobTarget {
        relation: "facet_values",
        physical_table: "facet_values",
        columns: &["value"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.facet_values AS physical
             JOIN temp._query_sql_visible_ids AS visible
               ON visible.id = physical.record_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "facet_observations",
        physical_table: "facet_observations",
        columns: &["value"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.facet_observations AS physical
             JOIN temp._query_sql_visible_ids AS visible
               ON visible.id = physical.record_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "schema_config",
        physical_table: "schema_config",
        columns: &["data"],
        visible_rowids_sql: "SELECT config.id, config.rowid
             FROM main.schema_config AS config
            WHERE config.applies_to_collection_id IS NULL
               OR EXISTS (
                    SELECT 1 FROM temp._query_sql_visible_ids AS visible
                     WHERE visible.id = config.applies_to_collection_id
                  )
            ORDER BY config.id",
    },
    TooBigBlobTarget {
        relation: "links",
        physical_table: "links",
        columns: &["note"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.links AS physical
             JOIN temp._query_sql_visible_ids AS source_visible
               ON source_visible.id = physical.source_id
             JOIN temp._query_sql_visible_ids AS target_visible
               ON target_visible.id = physical.target_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "blobs",
        physical_table: "blobs",
        columns: &["bytes"],
        // Inline, non-null bytes only: `size_bytes` describes the external
        // object when storage_tier='external' and bytes IS NULL, so it cannot
        // raise SQLITE_TOOBIG. Length comes from sqlite3_blob_bytes, not the
        // size_bytes column, which is not required to match even for inline.
        visible_rowids_sql: "SELECT blob.id, blob.rowid
             FROM main.blobs AS blob
            WHERE blob.bytes IS NOT NULL
              AND blob.storage_tier = 'inline'
              AND EXISTS (
                    SELECT 1
                      FROM main.records AS attachment
                      JOIN temp._query_sql_visible_ids AS attachment_visible
                        ON attachment_visible.id = attachment.id
                      JOIN main.facet_values AS blob_ref
                        ON blob_ref.record_id = attachment.id
                       AND blob_ref.key = 'blob_ref'
                       AND blob_ref.value = blob.id
                      JOIN main.links AS bearer
                        ON bearer.source_id = attachment.id
                       AND bearer.relationship = 'part_of'
                      JOIN temp._query_sql_visible_ids AS bearer_visible
                        ON bearer_visible.id = bearer.target_id
                     WHERE attachment.type = 'Document'
                       AND attachment.kind = 'attachment'
                  )
            ORDER BY blob.id",
    },
];

fn sqlite_error_is_toobig(error: &crate::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("string or blob too big")
}

fn sqlite_toobig_engine_detail(error: &crate::Error) -> String {
    let rendered = error.to_string();
    rendered
        .strip_prefix("query_sql [syntax_or_type]: ")
        .unwrap_or(&rendered)
        .to_string()
}

fn projected_column_names(sql: &str) -> std::collections::HashSet<String> {
    validated_output_columns(sql)
        .map(|columns| {
            columns
                .into_iter()
                .map(|column| column.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

async fn annotate_sqlite_toobig_error(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    relation_dependencies: &std::collections::BTreeSet<String>,
    sql: &str,
    query_result: Result<(Vec<String>, Vec<Value>, bool)>,
) -> Result<(Vec<String>, Vec<Value>, bool)> {
    match query_result {
        Err(error) if sqlite_error_is_toobig(&error) => Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::SyntaxOrType,
            format_sqlite_toobig_detail(
                &sqlite_toobig_engine_detail(&error),
                &projected_column_names(sql),
                diagnose_oversized_visible_values(transaction, relation_dependencies).await,
                relation_dependencies,
            ),
        )),
        other => other,
    }
}

async fn diagnose_oversized_visible_values(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    relation_dependencies: &std::collections::BTreeSet<String>,
) -> ProbeReport {
    let started = Instant::now();
    let mut handle = match transaction.lock_handle().await {
        Ok(handle) => handle,
        Err(_) => {
            return ProbeReport {
                offenders: Vec::new(),
                incomplete: Some("the stored-value probe could not lock the connection"),
            };
        }
    };
    handle.set_progress_handler(PROGRESS_OPS, move || {
        started.elapsed() < TOOBIG_PROBE_BUDGET
    });
    let db = handle.as_raw_handle().as_ptr();
    let mut report = ProbeReport {
        offenders: Vec::new(),
        incomplete: None,
    };
    for target in TOOBIG_BLOB_TARGETS {
        if report.offenders.len() >= MAX_TOOBIG_NAMED {
            break;
        }
        if !relation_dependencies.contains(target.relation) {
            continue;
        }
        if started.elapsed() >= TOOBIG_PROBE_BUDGET {
            report.incomplete = Some("the stored-value probe reached its 500ms budget");
            break;
        }
        if let Err(reason) = probe_one_target(db, target, started, &mut report.offenders) {
            report.incomplete = Some(reason);
            break;
        }
    }
    if report.incomplete.is_none() && report.offenders.len() >= MAX_TOOBIG_NAMED {
        report.incomplete =
            Some("the stored-value probe named 12 values and stopped; more may exist");
    }
    report
}

fn probe_one_target(
    db: *mut libsqlite3_sys::sqlite3,
    target: &TooBigBlobTarget,
    started: Instant,
    named: &mut Vec<OversizedStoredValue>,
) -> std::result::Result<(), &'static str> {
    let sql = format!(
        "{} LIMIT {}",
        target.visible_rowids_sql, MAX_TOOBIG_PROBE_ROWS
    );
    let sql = std::ffi::CString::new(sql).map_err(|_| "a stored-value probe query was invalid")?;
    let mut stmt = std::ptr::null_mut();
    // SAFETY: `db` is the exclusive live handle from `lock_handle`. The SQL is
    // engine-authored and NUL-terminated. Finalize via PreparedStmt on every path.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut())
    };
    if rc != libsqlite3_sys::SQLITE_OK {
        if !stmt.is_null() {
            unsafe {
                libsqlite3_sys::sqlite3_finalize(stmt);
            }
        }
        return Err("a stored-value probe query failed to prepare");
    }
    let _guard = PreparedStmt(stmt);
    loop {
        if named.len() >= MAX_TOOBIG_NAMED {
            return Ok(());
        }
        if started.elapsed() >= TOOBIG_PROBE_BUDGET {
            return Err("the stored-value probe reached its 500ms budget");
        }
        // SAFETY: `stmt` is a live prepared statement on `db`.
        let step = unsafe { libsqlite3_sys::sqlite3_step(stmt) };
        match step {
            libsqlite3_sys::SQLITE_DONE => return Ok(()),
            libsqlite3_sys::SQLITE_INTERRUPT => {
                return Err("the stored-value probe reached its 500ms budget");
            }
            libsqlite3_sys::SQLITE_ROW => {
                let id = unsafe { sqlite_column_text(stmt, 0) }
                    .ok_or("a stored-value probe row was missing its id")?;
                let rowid = unsafe { libsqlite3_sys::sqlite3_column_int64(stmt, 1) };
                for column in target.columns {
                    if named.len() >= MAX_TOOBIG_NAMED {
                        return Ok(());
                    }
                    if started.elapsed() >= TOOBIG_PROBE_BUDGET {
                        return Err("the stored-value probe reached its 500ms budget");
                    }
                    let Some(bytes) = stored_value_bytes(db, target.physical_table, column, rowid)
                    else {
                        continue;
                    };
                    if bytes > MAX_SQLITE_VALUE_BYTES {
                        named.push(OversizedStoredValue {
                            relation: target.relation,
                            column,
                            id: id.clone(),
                            bytes,
                        });
                    }
                }
            }
            _ => return Err("a stored-value probe query failed"),
        }
    }
}

struct PreparedStmt(*mut libsqlite3_sys::sqlite3_stmt);

impl Drop for PreparedStmt {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: prepared in probe_one_target and not yet finalized.
            unsafe {
                libsqlite3_sys::sqlite3_finalize(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Copy a TEXT column before the next `step` or `blob_open` invalidates it.
unsafe fn sqlite_column_text(
    stmt: *mut libsqlite3_sys::sqlite3_stmt,
    index: i32,
) -> Option<String> {
    let ptr = unsafe { libsqlite3_sys::sqlite3_column_text(stmt, index) };
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr.cast()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Byte length of one stored TEXT/BLOB cell, from the record header only.
fn stored_value_bytes(
    handle: *mut libsqlite3_sys::sqlite3,
    table: &str,
    column: &str,
    rowid: i64,
) -> Option<i32> {
    let db = std::ffi::CString::new("main").ok()?;
    let table = std::ffi::CString::new(table).ok()?;
    let column = std::ffi::CString::new(column).ok()?;
    let mut blob = std::ptr::null_mut();
    // SAFETY: `handle` is the exclusive live connection from `lock_handle`.
    // sqlite3_blob_open reads the record header without copying the payload.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_blob_open(
            handle,
            db.as_ptr(),
            table.as_ptr(),
            column.as_ptr(),
            rowid,
            0,
            &mut blob,
        )
    };
    if rc != libsqlite3_sys::SQLITE_OK {
        if !blob.is_null() {
            // SAFETY: SQLite documented that a non-NULL *ppBlob on error is live.
            unsafe {
                let _ = libsqlite3_sys::sqlite3_blob_close(blob);
            }
        }
        return None;
    }
    // SAFETY: open succeeded; close before returning so the handle cannot leak.
    let bytes = unsafe { libsqlite3_sys::sqlite3_blob_bytes(blob) };
    unsafe {
        let _ = libsqlite3_sys::sqlite3_blob_close(blob);
    }
    Some(bytes)
}

fn format_offender_list(offenders: &[OversizedStoredValue]) -> String {
    let mut message = String::new();
    let mut index = 0;
    let mut first_group = true;
    while index < offenders.len() {
        let relation = offenders[index].relation;
        let column = offenders[index].column;
        if !first_group {
            message.push_str("; ");
        }
        first_group = false;
        message.push_str(&format!("{relation}.{column} for "));
        let mut first_row = true;
        while index < offenders.len()
            && offenders[index].relation == relation
            && offenders[index].column == column
        {
            if !first_row {
                message.push_str(", ");
            }
            first_row = false;
            message.push_str(&format!(
                "id {} ({} bytes)",
                offenders[index].id, offenders[index].bytes
            ));
            index += 1;
        }
    }
    message
}

/// Stable catalog key per logical relation for TOOBIG keyset repair.
/// Current stored-value probe targets expose `id`; other logical scopes use their own keys.
fn toobig_stable_key(relation: &str) -> &'static str {
    match relation {
        "agent_activity" => "activity_id",
        "agent_activity_claims" => "claim_id",
        "messages_awaiting_reply" => "message_id",
        "message_reactions" => "reaction_id",
        _ => "id",
    }
}

fn format_sqlite_toobig_detail(
    original: &str,
    projected: &std::collections::HashSet<String>,
    report: ProbeReport,
    relations: &std::collections::BTreeSet<String>,
) -> String {
    let ceiling = MAX_SQLITE_VALUE_BYTES;
    let mut message = format!(
        "the statement exceeded the {ceiling}-byte SQLite value ceiling. Original error: {original}."
    );
    // Projected-column match is label-only and therefore advisory: output
    // names are matched against physical column names with no relation
    // qualification. An unaliased stored column usually under-blames, which
    // is safe. An alias can over-blame — `WITH RECURSIVE d(body) AS (…)
    // SELECT body FROM d WHERE (SELECT count(id) FROM records) >= 0` yields
    // label `body` and promotes an unrelated oversized `records.body` to
    // Offending. The original engine detail is still present either way.
    // Collect (relation, id) pairs before the partition below consumes the
    // report. Ids are per relation, so the exclusion hint groups them by
    // relation instead of mixing id domains into one unqualified predicate.
    // Owned ids: the partition moves `report.offenders` while the hint
    // borrows these pairs.
    let offender_pairs: Vec<(&str, String)> = report
        .offenders
        .iter()
        .map(|offender| (offender.relation, offender.id.clone()))
        .collect();
    let offender_refs: Vec<(&str, &str)> = offender_pairs
        .iter()
        .map(|(relation, id)| (*relation, id.as_str()))
        .collect();
    let (projected_offenders, incidental): (Vec<_>, Vec<_>) = report
        .offenders
        .into_iter()
        .partition(|offender| projected.contains(&offender.column.to_ascii_lowercase()));
    if projected_offenders.is_empty() && incidental.is_empty() {
        let mut probed: Vec<&str> = TOOBIG_BLOB_TARGETS
            .iter()
            .map(|target| target.relation)
            .filter(|relation| relations.contains(*relation))
            .collect();
        probed.sort_unstable();
        probed.dedup();
        let mut unprobed: Vec<&String> = relations
            .iter()
            .filter(|relation| {
                !TOOBIG_BLOB_TARGETS
                    .iter()
                    .any(|target| target.relation == relation.as_str())
            })
            .collect();
        unprobed.sort_unstable();
        if probed.is_empty() && unprobed.is_empty() {
            message.push_str(
                " No oversized stored value was found in a probed scope; the cause may be a computed intermediate. Repair (keyset): narrow by selecting the relation's stable key only (records: id; agent_activity: activity_id; agent_activity_claims: claim_id; messages_awaiting_reply: message_id) with ORDER BY <key> LIMIT 1000, then WHERE <key> > ?1 to isolate the row.",
            );
        } else {
            if probed.is_empty() {
                message.push_str(" No probed scope contained an oversized stored value.");
            } else {
                message.push_str(&format!(
                    " No oversized stored value was found in probed scopes [{}].",
                    probed.join(", ")
                ));
            }
            if !unprobed.is_empty() {
                let scopes: Vec<&str> = unprobed.iter().map(|scope| scope.as_str()).collect();
                message.push_str(&format!(
                    " Scopes [{}] are not covered by the stored-value probe (e.g. agent_activity text, computed intermediates); an oversize there would abort the same way.",
                    scopes.join(", ")
                ));
                let per_scope: Vec<String> = unprobed
                    .iter()
                    .map(|scope| {
                        let key = toobig_stable_key(scope.as_str());
                        format!("{scope} with ORDER BY {key} LIMIT 1000, then WHERE {key} > ?1")
                    })
                    .collect();
                message.push_str(&format!(
                    " Repair (keyset): narrow {} selecting the stable key only to isolate the row.",
                    per_scope.join("; ")
                ));
            } else {
                message.push_str(
                    " Repair (keyset): narrow by selecting the relation's stable key only with ORDER BY <key> LIMIT 1000, then WHERE <key> > ?1 to isolate the row.",
                );
            }
        }
    } else {
        if !projected_offenders.is_empty() {
            message.push_str(" Offending: ");
            message.push_str(&format_offender_list(&projected_offenders));
            message.push('.');
        }
        if !incidental.is_empty() {
            message.push_str(" The statement also reads these oversized values: ");
            message.push_str(&format_offender_list(&incidental));
            message.push('.');
        }
        message.push_str(
            " These values cannot be read, truncated or matched by any query; select other columns or exclude these records.",
        );
        if let Some(hint) = sql_contract::oversized_exclusion_hint(&offender_refs) {
            message.push(' ');
            message.push_str(&hint);
        }
        let mut offender_relations: Vec<&str> = projected_offenders
            .iter()
            .chain(incidental.iter())
            .map(|offender| offender.relation)
            .collect();
        offender_relations.sort_unstable();
        offender_relations.dedup();
        let per_relation: Vec<String> = offender_relations
            .iter()
            .map(|relation| {
                let key = toobig_stable_key(relation);
                format!("{relation} with ORDER BY {key} LIMIT 1000 / WHERE {key} > ?1")
            })
            .collect();
        message.push_str(&format!(
            " Repair: select only the stable key and safe columns and page {}. For content search prefer full-text search over body LIKE.",
            per_relation.join("; ")
        ));
    }
    if let Some(reason) = report.incomplete {
        message.push(' ');
        message.push_str(reason);
        message.push('.');
    }
    message
}

pub(crate) fn bind_parameters<'q>(
    mut query: Query<'q, Sqlite, SqliteArguments<'q>>,
    parameters: &[QuerySqlParameter],
) -> Result<Query<'q, Sqlite, SqliteArguments<'q>>> {
    for parameter in parameters {
        query = match parameter {
            QuerySqlParameter::Boolean { value } => query.bind(*value),
            QuerySqlParameter::Integer { value } => query.bind(
                value
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()
                    .map_err(|_| {
                        sql_contract::categorized_error(
                            QuerySqlErrorCategory::InvalidArguments,
                            "integer parameter must be a signed 64-bit decimal string",
                        )
                    })?,
            ),
            QuerySqlParameter::Real { value } => query.bind(*value),
            QuerySqlParameter::Text { value } => query.bind(value.clone()),
            QuerySqlParameter::Bytes { value } => {
                use base64::Engine as _;
                query.bind(
                    value
                        .as_deref()
                        .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
                        .transpose()
                        .map_err(|_| {
                            sql_contract::categorized_error(
                                QuerySqlErrorCategory::InvalidArguments,
                                "bytes parameter must be canonical base64",
                            )
                        })?,
                )
            }
            QuerySqlParameter::Json { value } => query.bind(value.clone()),
            QuerySqlParameter::Timestamp { value } => query.bind(value.clone()),
        };
    }
    Ok(query)
}

/// Resolve the `catalog_operations` serving snapshot for a statement that
/// really references the relation. Dependencies come from prepare-time
/// authorizer observation, so same-named CTE aliases, comments and string
/// literals never resolve here. `Some` carries the executor's trusted
/// snapshot for population; `None` (no reference) skips it. A real
/// reference without a snapshot refuses instead of serving an empty table:
/// only the ad-hoc online executor dispatch attaches one, so member/offline,
/// saved SQL, alpha-tab and direct API executions all land here.
fn resolve_catalog_operations_snapshot(
    relation_dependencies: &std::collections::BTreeSet<String>,
    principal: &QueryPrincipal,
) -> Result<Option<super::principal::CatalogOperationsSnapshot>> {
    if !relation_dependencies.contains("catalog_operations") {
        return Ok(None);
    }
    match principal.catalog_operations() {
        Some(snapshot) => Ok(Some(snapshot.clone())),
        None => Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnauthorizedRelation,
            "query_sql relation 'catalog_operations' needs this server's serving executor catalogue, which this entry point does not carry: it resolves only in online executor ad-hoc query_sql (serving standby included - use describe_operation for contracts elsewhere; member/offline copies, saved SQL and alpha-tab executions refuse it)",
        )),
    }
}

/// Stage one execution's serving catalogue rows. Clears first so a pooled
/// connection can never retain a prior request's rows; a second execution
/// with another snapshot (or none, which refuses above) starts empty. One
/// `json_each` statement keeps staging near free however many operations
/// the serving catalogue holds.
async fn populate_catalog_operations(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    snapshot: &super::principal::CatalogOperationsSnapshot,
) -> Result<()> {
    sqlx::query("DELETE FROM temp.catalog_operations")
        .execute(&mut **transaction)
        .await?;
    if snapshot.is_empty() {
        return Ok(());
    }
    let payload = serde_json::to_string(snapshot.as_slice())?;
    sqlx::query(
        "INSERT INTO temp.catalog_operations(executor, operation, surface, access, plan_required, direct_execution_enabled, contract_version, contract_digest, source_tool, selector_field, selector_value, advertised_directly)
         SELECT value ->> 'executor', value ->> 'operation', value ->> 'surface', value ->> 'access',
                json_extract(value, '$.plan_required'), json_extract(value, '$.direct_execution_enabled'),
                value ->> 'contract_version', value ->> 'contract_digest', value ->> 'source_tool',
                value ->> 'selector_field', value ->> 'selector_value',
                json_extract(value, '$.advertised_directly')
         FROM json_each(?)",
    )
    .bind(payload)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Backwards-compatible owned entrypoint retained for internal callers.
pub(crate) async fn query_sql_owned(
    db: Db,
    principal: QueryPrincipal,
    sql: String,
) -> Result<SqlResult> {
    query_sql_request_owned(
        db,
        principal,
        QuerySqlRequest {
            sql,
            parameters: Vec::new(),
        },
    )
    .await
}

/// Library-facing borrowed form. Tool dispatch uses the owned counterpart so
/// its boxed handler future remains `Send + 'static`. Accepts anything that
/// converts into a [`QueryPrincipal`] — in particular `&mcp::Caller`.
pub async fn query_sql(
    db: &Db,
    principal: impl Into<QueryPrincipal>,
    sql: &str,
) -> Result<SqlResult> {
    query_sql_owned(db.clone(), principal.into(), sql.to_string()).await
}

#[cfg(test)]
pub(crate) async fn principal_context_is_empty(db: &Db) -> Result<bool> {
    let mut connection = db.governed_pool().acquire().await?;
    let contract = temp_contract();
    for temp_statement in contract.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(temp_statement)
            .execute(&mut *connection)
            .await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM temp._query_sql_principal")
        .fetch_one(&mut *connection)
        .await?;
    Ok(count == 0)
}

#[cfg(test)]
mod frozen_schema_cache_tests {
    use super::*;

    #[test]
    fn unordered_limit_repair_caps_skip_describing_and_validating() {
        let mut sql = format!(
            "SELECT {} LIMIT 5",
            vec!["(SELECT 1 LIMIT 1)"; 3400].join(",")
        );
        sql.extend(std::iter::repeat_n(
            ' ',
            sql_contract::MAX_SQL_BYTES - sql.len(),
        ));
        assert_eq!(sql.len(), sql_contract::MAX_SQL_BYTES);
        assert!(default_order_repair_with(
            &sql,
            |_| panic!("must not describe"),
            |_| { panic!("must not validate") }
        )
        .is_none());
        let sql = format!("SELECT {}", vec!["(SELECT 1 LIMIT 1)"; 33].join(","));
        assert!(default_order_repair(&sql).is_none());
        // Deep WITH trees must hit a cap without describing or validating.
        for depth in [40, 600] {
            let sql = format!(
                "{}SELECT 1{}",
                "WITH c AS (".repeat(depth),
                ") SELECT 1 LIMIT 1".repeat(depth)
            );
            assert!(default_order_repair_with(
                &sql,
                |_| panic!("must not describe"),
                |_| panic!("must not validate")
            )
            .is_none());
        }
    }

    #[test]
    fn unordered_limit_repair_preserves_top_level_wording_past_range_cap() {
        let values = vec!["coalesce('', '')"; 300].join(", ");
        let sql = format!("SELECT id FROM records WHERE id IN ({values}) LIMIT 5");
        validate(&format!(
            "SELECT id FROM records WHERE id IN ({values}) ORDER BY 1 LIMIT 5"
        ))
        .unwrap();
        assert_eq!(
            default_order_repair(&sql).as_deref(),
            Some("the ad-hoc default would order by (id): add ORDER BY 1")
        );
    }

    #[test]
    fn unordered_limit_repair_preserves_top_level_wording_for_unchecked_join_on() {
        let sql = "SELECT r.id FROM records r JOIN links l ON l.id = (SELECT id FROM links LIMIT 1) LIMIT 5";
        assert_eq!(
            default_order_repair(sql).as_deref(),
            Some("the ad-hoc default would order by (id): add ORDER BY 1")
        );
        validate("SELECT r.id FROM records r JOIN links l ON l.id = (SELECT id FROM links LIMIT 1) ORDER BY 1 LIMIT 5").unwrap();
    }

    /// Statements the shipping validator admits. `EXPLAIN QUERY PLAN` is
    /// admitted by the classifier (it plans without running), so it belongs
    /// here alongside the reads.
    const ADMITTED: [&str; 10] = [
        "SELECT id FROM records",
        "SELECT ID FROM RECORDS",
        "SELECT count(*) FROM records",
        "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
        "WITH visible AS (SELECT id FROM records) SELECT count(*) FROM visible",
        "EXPLAIN QUERY PLAN SELECT id FROM records",
        "SELECT id FROM vocabularies",
        "SELECT id FROM schema_config",
        "SELECT message_id FROM messages_awaiting_reply",
        "SELECT activity_id FROM agent_activity",
    ];

    /// Statements the shipping validator rejects: raw-qualified routes,
    /// TEMP/system probes, spoofed CTEs, unsafe functions, writes, duplicate
    /// labels, non-`?N` placeholders (I1), and syntax errors.
    const REJECTED: [&str; 17] = [
        "SELECT * FROM main.records",
        "SELECT raw.* FROM main.links AS raw",
        "WITH stolen AS (SELECT * FROM main.records) SELECT * FROM stolen",
        "SELECT * FROM temp._query_sql_principal",
        "SELECT * FROM sqlite_master",
        "WITH records AS (SELECT * FROM main.records) SELECT * FROM records",
        "SELECT * FROM pragma_table_info('records')",
        "SELECT * FROM records_fts_data",
        "SELECT randomblob(1000000000)",
        "SELECT load_extension('anything')",
        "SELECT json_group_array(body) FROM records",
        "DELETE FROM records",
        "SELECT id AS dup, name AS dup FROM records",
        "SELECT FROM WHERE",
        "SELECT id FROM records WHERE id = $1",
        "SELECT id FROM records WHERE id = ?",
        "SELECT id FROM records WHERE id = :name",
    ];

    fn rendered(result: Result<()>) -> String {
        result
            .map(|_| "ok".to_owned())
            .unwrap_or_else(|error| error.to_string())
    }

    /// Pre-change behavior: a throwaway connection per leg, batch text
    /// assembled inline. The oracle for "rejected before ⇒ rejected now,
    /// with the same message".
    fn fresh_validate(sql: &str) -> Result<()> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            prepare_under_authorizer(conn, statement, authorize_strict)
        })
    }

    fn fresh_view_expansion(statement: &str) -> Result<()> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        let ddl: String = DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect();
        conn.execute_batch(&ddl)
            .and_then(|_| conn.execute_batch(&temp_contract()))
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        prepare_under_authorizer(&conn, statement, authorize_view_expansion)
    }

    fn fresh_strict<T>(
        statement: &str,
        operation: impl FnOnce(&rusqlite::Connection, &str) -> Result<T>,
    ) -> Result<T> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        conn.execute_batch(STRICT_LOGICAL_SCHEMA)
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        operation(&conn, statement)
    }

    fn fresh_dependencies(sql: &str) -> Result<std::collections::BTreeSet<String>> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            let dependencies = std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeSet::<String>::new(),
            ));
            let observed = dependencies.clone();
            conn.authorizer(Some(move |context: AuthContext<'_>| {
                if let AuthAction::Read { table_name, .. } = context.action {
                    if context.database_name == Some("temp")
                        && sql_contract::is_logical_relation(table_name)
                    {
                        observed
                            .lock()
                            .expect("dependency lock")
                            .insert(table_name.to_owned());
                    }
                }
                authorize_strict(context)
            }));
            let prepared = conn.prepare(statement);
            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            let prepared = prepared.map_err(|error| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::SyntaxOrType,
                    error.to_string(),
                )
            })?;
            if !prepared.readonly() {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "read-only statement writes",
                ));
            }
            drop(prepared);
            Ok(std::sync::Arc::try_unwrap(dependencies)
                .expect("validator releases dependency observer")
                .into_inner()
                .expect("dependency lock"))
        })
    }

    fn fresh_columns(sql: &str) -> Result<Vec<String>> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            conn.authorizer(Some(authorize_strict));
            let prepared = conn.prepare(statement);
            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            let prepared = prepared.map_err(|error| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::SyntaxOrType,
                    error.to_string(),
                )
            })?;
            Ok(prepared
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect())
        })
    }

    #[test]
    fn cached_batch_text_matches_old_style_assembly() {
        let ddl: String = DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect();
        assert_eq!(frozen_ddl_batch(), ddl.as_str());
        assert_eq!(frozen_temp_contract_batch(), temp_contract().as_str());
    }

    #[test]
    fn cached_validation_matches_fresh_connections_exactly() {
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            assert_eq!(
                rendered(validate(sql)),
                rendered(fresh_validate(sql)),
                "{sql}"
            );
        }
    }

    #[test]
    fn blocked_probes_name_the_catalog_fix() {
        let probe = rendered(validate("SELECT * FROM sqlite_master"));
        assert!(probe.contains("catalog introspection"), "{probe}");
        assert!(probe.contains("FROM catalog_columns"), "{probe}");
        let pragma = rendered(validate("SELECT * FROM pragma_table_info('records')"));
        assert!(pragma.contains("catalog introspection"), "{pragma}");
        let mapped = rendered(validate("SELECT * FROM relationships"));
        assert!(mapped.contains("effective_relationships"), "{mapped}");
        let unmapped = rendered(validate("SELECT * FROM member_contexts"));
        assert!(
            unmapped.contains("Queryable relations on sqlite-local:"),
            "{unmapped}"
        );
        // Function denies belong to the allowlist repair, not this one.
        let func = rendered(validate("SELECT GROUP_CONCAT(name) FROM records"));
        assert!(func.contains("GROUP_CONCAT"), "{func}");
        assert!(!func.contains("catalog introspection"), "{func}");
        assert!(!func.contains("Queryable relations on"), "{func}");
        // Raw-qualified and spoofed routes keep their engine detail alone.
        let raw = rendered(validate("SELECT * FROM main.records"));
        assert!(!raw.contains("not a queryable"), "{raw}");
    }

    #[test]
    fn strict_catalog_tables_match_generated_views() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(STRICT_LOGICAL_SCHEMA).unwrap();
        let columns_of = |conn: &rusqlite::Connection, table: &str| {
            conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<String>, _>>()
                .unwrap()
        };
        let strict_relations = columns_of(&conn, "catalog_relations");
        let strict_columns = columns_of(&conn, "catalog_columns");
        // A view cannot shadow the strict table of the same name, so drop
        // the tables before installing the generated views.
        conn.execute_batch("DROP TABLE catalog_relations; DROP TABLE catalog_columns;")
            .unwrap();
        for statement in sql_contract::catalog_view_statements(true, false) {
            conn.execute_batch(&statement).unwrap();
        }
        assert_eq!(columns_of(&conn, "catalog_relations"), strict_relations);
        assert_eq!(columns_of(&conn, "catalog_columns"), strict_columns);
        for (table, strict) in [
            ("catalog_relations", strict_relations),
            ("catalog_columns", strict_columns),
        ] {
            assert_eq!(
                strict,
                sql_contract::LOGICAL_RELATIONS
                    .iter()
                    .find(|r| r.name == table)
                    .unwrap()
                    .columns
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "{table}"
            );
        }
    }

    #[test]
    fn cached_dependencies_and_columns_match_fresh_connections() {
        for sql in ADMITTED {
            let cached = validated_relation_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            let fresh = fresh_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "dependencies {sql}");
            let cached = validated_output_columns(sql).map_err(|error| error.to_string());
            let fresh = fresh_columns(sql).map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "columns {sql}");
        }
        for sql in REJECTED {
            let cached = validated_relation_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            let fresh = fresh_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "rejected dependencies {sql}");
        }
    }

    #[test]
    fn positional_placeholders_pass_and_others_name_the_repair() {
        // I1 (E1 M2): `?N` is the only admitted spelling. A `$1`/`:x` inside
        // a string literal is data and stays admitted.
        validate("SELECT id FROM records WHERE id = ?1").unwrap();
        validate("SELECT id FROM records WHERE name = '$1'").unwrap();
        let bare = validate("SELECT id FROM records WHERE id = ?").unwrap_err();
        assert!(
            bare.to_string()
                .contains("Postgres `?`/`?|`/`?&` operators"),
            "missing jsonb note: {bare}"
        );
        for sql in [
            "SELECT id FROM records WHERE id = $1",
            "SELECT id FROM records WHERE id = ?0",
            "SELECT id FROM records WHERE id = :name",
            "SELECT id FROM records WHERE id = @name",
            "SELECT id FROM records WHERE id = $name",
        ] {
            let error = validate(sql).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("use positional `?N` placeholders"),
                "{sql}: missing repair: {error}"
            );
        }
    }

    #[test]
    fn determinism_rules_reject_and_admit() {
        // I3 (AST design): LIMIT needs ORDER BY and bare GROUP BY columns
        // fail; NULLS ordering and division are native here, never rejected.
        for sql in [
            "SELECT id FROM records ORDER BY id LIMIT 5",
            "SELECT kind, count(*) FROM records GROUP BY kind",
            "SELECT id FROM records ORDER BY id",
            "SELECT 1 / 0 FROM records",
            "SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM records GROUP BY week ORDER BY week",
            "SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM records GROUP BY 1 ORDER BY 1",
            "SELECT kind, count(*) AS n FROM records GROUP BY kind HAVING n > 0",
            // Correlated unqualified outer refs (SQLite admits; strict
            // prepare below proves it end to end).
            "SELECT (SELECT count(*) + kind FROM facet_values) FROM records GROUP BY kind",
            "SELECT kind, count(*) FROM records GROUP BY kind HAVING count(*) > (SELECT count(*) + kind FROM facet_values)",
            // Qualification spelling never decides grouping.
            "SELECT records.kind, count(*) FROM records GROUP BY kind",
            "SELECT kind, count(*) FROM records GROUP BY records.kind",
            "SELECT r.kind, count(*) FROM records r GROUP BY kind",
            // ORDER BY under grouping: keys, aggregates, aliases, ordinals.
            "SELECT kind, count(*) FROM records GROUP BY kind ORDER BY kind",
            "SELECT kind, count(*) AS n FROM records GROUP BY kind ORDER BY n DESC",
            // Qualified outer group key admits.
            "SELECT kind, (SELECT count(*) + t.kind FROM facet_values) FROM records t GROUP BY kind",
        ] {
            validate(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for (sql, repair) in [
            (
                "SELECT id FROM records LIMIT 5",
                "add ORDER BY over a unique key",
            ),
            (
                "SELECT kind, count(*) FROM records GROUP BY type",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Genuinely bare inner column (not an outer group key).
            (
                "SELECT (SELECT count(*) + other FROM facet_values) FROM records GROUP BY kind",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // ORDER BY on a non-grouped column (SQLite admits; Postgres
            // raises) fails with the same repair.
            (
                "SELECT kind, count(*) FROM records GROUP BY kind ORDER BY created_at_ms",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Self-join: the other alias's column is not grouped.
            (
                "SELECT b.kind, count(*) FROM records a JOIN records b ON a.id = b.id GROUP BY a.kind",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Shadowed inner reference (SQLite binds innermost): qualify
            // the outer table or group it.
            (
                "SELECT (SELECT count(*) + kind FROM records) FROM records GROUP BY kind",
                "may resolve to the subquery's own FROM",
            ),
            // Qualified outer non-key: the repair points at the enclosing query.
            (
                "SELECT kind, (SELECT count(*) + t.name FROM facet_values) FROM records t GROUP BY kind",
                "belongs to an enclosing query that groups by other columns",
            ),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
    }

    #[test]
    fn widened_functions_validate_and_dropped_ones_name_the_repair() {
        // I2: preparing proves SQLite itself executes the widened set.
        validate("SELECT lower('AbC'), upper('AbC') FROM records").unwrap();
        validate("SELECT trim(' x '), replace('aab', 'a', 'c') FROM records").unwrap();
        // I2 review: the two-argument `trim(x, chars)` matches Postgres
        // `btrim(x, chars)` exactly, so it validates on every engine.
        validate("SELECT trim('xxhelloxx', 'x') FROM records").unwrap();
        validate("SELECT substr('hello', 2, 3) FROM records").unwrap();
        validate("SELECT coalesce(NULL, 'z'), nullif('a', 'a') FROM records").unwrap();
        validate("SELECT abs(-3), length('hey'), round(1.5) FROM records").unwrap();
        validate("SELECT avg(id), count(*), sum(id), min(id), max(id) FROM records").unwrap();
        validate("SELECT rank() OVER (ORDER BY id) FROM records").unwrap();
        validate("SELECT CASE WHEN id = 1 THEN 'one' ELSE 'other' END FROM records").unwrap();
        validate("SELECT CAST(id AS TEXT) FROM records").unwrap();
        // LIKE (either spelling) still validates.
        validate("SELECT id FROM records WHERE name LIKE 'conf:%'").unwrap();
        validate("SELECT id FROM records WHERE lower(name) LIKE 'conf:%'").unwrap();
        for (sql, repair) in [
            (
                "SELECT instr(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
            ("SELECT glob('*', name) FROM records", "use LIKE"),
            (
                "SELECT date(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT json_type(body) FROM records",
                "facet_values, facet_observations",
            ),
            ("SELECT typeof(name) FROM records", "catalog column types"),
            // Richard 25 Sep: I2 dropped functions stay rejected ad-hoc even
            // though already-stored governed SQL keeps the legacy allowance.
            (
                "SELECT strftime('%w', 'now') FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT julianday('now') FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            ("SELECT total(id) FROM records", "use sum"),
            ("SELECT floor(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT char_length(name) FROM records", "use length"),
            ("SELECT greatest(a, b) FROM records", "CASE"),
            ("SELECT max(a, b) FROM records", "CASE"),
            ("SELECT min(a, b) FROM records", "CASE"),
            ("SELECT max(a, b, c) FROM records", "CASE"),
            ("SELECT min(a, b, c) FROM records", "CASE"),
            (
                "SELECT id, max(length(name), 5) AS m FROM records WHERE id = ?1",
                "CASE",
            ),
            (
                "SELECT round(avg(id), 2) FROM records",
                "catalog numeric type",
            ),
            // I2 review: quoting the name bypasses nothing — the shared
            // classifier runs the same dropped-name and arity checks on
            // `"name"(`, `` `name` `` and `[name](` calls.
            (
                "SELECT \"round\"(1.5, 2) FROM records",
                "catalog numeric type",
            ),
            (
                "SELECT \"instr\"(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
    }

    #[test]
    fn governed_validation_builds_schemas_at_most_once() {
        // Mirror a governed call's validation footprint: validate() plus the
        // dependency pass, over admitted and rejected statements alike. The
        // build counts are thread-local like the caches, so this asserts the
        // current thread reuses its validators — other threads warming up
        // their own cannot move these counts.
        fn builds() -> (usize, usize) {
            (
                FROZEN_VALIDATOR_BUILDS.with(|builds| builds.get()),
                STRICT_VALIDATOR_BUILDS.with(|builds| builds.get()),
            )
        }
        let footprint = |sql: &str| {
            let _ = validate(sql);
            let _ = validated_relation_dependencies(sql);
            let _ = validated_output_columns(sql);
        };
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            footprint(sql);
        }
        let warm = builds();
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            footprint(sql);
        }
        assert_eq!(builds(), warm, "validators rebuilt after warm-up");
    }
}

#[cfg(test)]
mod rule_input_extraction_tests {
    use super::*;

    #[test]
    fn extractor_refuses_current_principal() {
        let error = extract_rule_input_dependencies(
            "SELECT id FROM records WHERE id = current_principal()",
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("rule inputs reject current_principal()"),
            "{error}"
        );
    }

    #[test]
    fn extractor_pins_columns_params_and_population() {
        let readset = extract_rule_input_dependencies("SELECT id, name FROM records WHERE id = ?1")
            .expect("admitted");
        assert_eq!(readset.relations.len(), 1);
        let relation = &readset.relations[0];
        assert_eq!(relation.name, "records");
        assert_eq!(relation.identity, "native.query-sql.records");
        assert_eq!(
            relation.semantic_version,
            sql_contract::LOGICAL_RELATION_VERSION
        );
        assert!(!relation.population_only);
        assert!(relation.columns.contains("id"));
        assert!(relation.columns.contains("name"));
        assert_eq!(readset.parameter_slots, vec![1]);
        assert!(!readset.uses_now_ms);
    }

    #[test]
    fn extractor_supports_count_population_but_rejects_hidden_now_ms() {
        let readset =
            extract_rule_input_dependencies("SELECT count(*) FROM records").expect("admitted");
        assert_eq!(readset.relations.len(), 1);
        assert!(readset.relations[0].population_only);
        assert!(readset.relations[0].columns.is_empty());
        // Hidden now_ms() is rejected: time arrives via ?N with a declared
        // now_ms parameter source, never as an implicit source.
        assert!(extract_rule_input_dependencies(
            "SELECT id FROM records WHERE updated_at_ms >= now_ms() - ?1",
        )
        .is_err());
    }

    #[test]
    fn extractor_keeps_existing_deterministic_gates() {
        // Anything validate() rejects stays rejected: LIMIT without ORDER BY
        // and bare GROUP BY columns fail the shared deterministic gate.
        for sql in [
            "SELECT id FROM records LIMIT 1",
            "SELECT kind, name FROM records GROUP BY kind",
        ] {
            assert!(validate(sql).is_err(), "{sql}");
            assert!(extract_rule_input_dependencies(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn extractor_rejects_hidden_and_nondeterministic_reads() {
        for sql in [
            "SELECT * FROM records",
            "SELECT e.id FROM content_events e JOIN records r USING (id)",
            "SELECT e.id FROM content_events e NATURAL JOIN records r",
            "WITH records AS (SELECT 1) SELECT id FROM records",
            "SELECT activity_id FROM agent_activity",
            "SELECT message_id FROM messages_awaiting_reply",
            "SELECT id FROM records WHERE id = ?1 OR id = ?3",
        ] {
            assert!(extract_rule_input_dependencies(sql).is_err(), "{sql}");
        }
    }

    #[test]
    fn current_snapshot_matches_live_catalog_constants() {
        let snapshot = current_catalog_snapshot();
        assert_eq!(snapshot.revision, sql_contract::LOGICAL_CATALOG_REVISION);
        assert_eq!(snapshot.profile_id, "sqlite-local");
        assert_eq!(
            snapshot.relations.len(),
            sql_contract::LOGICAL_RELATIONS.len()
        );
    }

    #[test]
    fn extractor_captures_bundled_population_reads() {
        // Bundled-SQLite authorizer regressions: constant projections and
        // degenerate joins still report the tables they scan.
        let one = extract_rule_input_dependencies("SELECT 1 FROM records").expect("admitted");
        assert_eq!(one.relations.len(), 1);
        assert!(one.relations[0].population_only);
        let both =
            extract_rule_input_dependencies("SELECT 1 FROM records, links").expect("admitted");
        assert_eq!(both.relations.len(), 2);
        assert!(both.relations.iter().all(|r| r.population_only));
        let exists = extract_rule_input_dependencies(
            "SELECT 1 FROM records WHERE EXISTS (SELECT 1 FROM links)",
        )
        .expect("admitted");
        assert_eq!(exists.relations.len(), 2);
        // Degenerate ON (no records column referenced): records stays a
        // population dependency, content_events pins its column.
        let degenerate = extract_rule_input_dependencies(
            "SELECT e.id FROM content_events e JOIN records r ON e.id = ?1",
        )
        .expect("admitted");
        let events = degenerate
            .relations
            .iter()
            .find(|r| r.name == "content_events")
            .expect("events");
        assert!(events.columns.contains("id"));
        let records = degenerate
            .relations
            .iter()
            .find(|r| r.name == "records")
            .expect("records");
        assert!(records.population_only);
    }

    #[test]
    fn extractor_rejects_quoted_logical_cte_shadows() {
        for sql in [
            "WITH \"records\" AS (SELECT 1) SELECT 1",
            "WITH `records` AS (SELECT 1) SELECT 1",
            "WITH [records] AS (SELECT 1) SELECT 1",
        ] {
            assert!(extract_rule_input_dependencies(sql).is_err(), "{sql}");
        }
    }
}

#[cfg(test)]
mod app_dependency_validation_tests {
    use super::*;
    use crate::mcp::tools::alpha_tabs::{analyze_flat_select_reads, ReadsDeclaration};

    fn checked(sql: &str) -> ReadsDeclaration {
        let reads = analyze_flat_select_reads(sql).expect(sql);
        validate_app_sql_dependencies(sql, &reads).expect(sql);
        reads
    }

    #[test]
    fn app_dependencies_cover_every_catalog_column_and_population() {
        for relation in sql_contract::LOGICAL_RELATIONS {
            for column in relation.columns {
                let sql = format!("SELECT \"{column}\" FROM \"{}\"", relation.name);
                let mut reads = checked(&sql);
                reads.grants[0].columns.clear();
                assert!(
                    validate_app_sql_dependencies(&sql, &reads).is_err(),
                    "{sql}"
                );
            }
            checked(&format!("SELECT * FROM \"{}\"", relation.name));
            checked(&format!("SELECT 1 FROM \"{}\"", relation.name));
            checked(&format!("SELECT count(*) FROM \"{}\"", relation.name));
        }
    }

    #[test]
    fn app_dependencies_cover_join_filter_order_and_expression_reads() {
        for sql in [
            "SELECT a.id, b.source_id FROM records a JOIN links b ON a.id = b.source_id WHERE b.relationship = ?1 ORDER BY a.name",
            "SELECT a.id FROM records a LEFT JOIN links b ON a.id = b.source_id LEFT JOIN facet_values c ON c.record_id = b.target_id WHERE c.key = 'status'",
            "SELECT 1 FROM records a JOIN links b ON 1 = 1",
            "SELECT count(*) FROM records a JOIN records b ON a.home_id = b.id",
            "SELECT a.name AS first, b.name AS second FROM records a JOIN records b ON a.id = b.home_id",
            "SELECT count(*) FILTER (WHERE lifecycle = 'open') FROM records",
            "SELECT CASE WHEN name LIKE '%x%' THEN upper(summary) ELSE substr(body, 1, 8) END AS label FROM records WHERE id IN ('a','b') ORDER BY updated_at_ms",
            "SELECT id FROM records WHERE updated_at_ms < now_ms() AND regexp('a', name)",
            "SELECT id FROM records ORDER BY name LIMIT ?1 OFFSET ?2",
            "SELECT r.id FROM records r JOIN links l ON r.id = l.source_id WHERE l.target_id = r.home_id",
            "SELECT kind, count(*) FROM records GROUP BY kind HAVING count(*) FILTER (WHERE lifecycle = 'open') > 0 ORDER BY kind",
            "SELECT r.type, count(*) FROM records r JOIN links l ON r.id = l.source_id GROUP BY r.type HAVING count(*) FILTER (WHERE l.note IS NOT NULL) > 0",
        ] {
            checked(sql);
        }
    }

    #[test]
    fn app_dependencies_refuse_analyzer_underreporting_and_clear_authorizer() {
        for sql in [
            "SELECT id FROM records WHERE body LIKE '%private%'",
            "SELECT count(*) FROM links",
            "SELECT 1 FROM records a JOIN links b ON 1 = 1",
            "SELECT marker FROM body_task_items",
            "SELECT count(*) FROM records GROUP BY kind HAVING count(*) FILTER (WHERE lifecycle = 'open') > 0",
            "SELECT 1 FROM body_task_items",
            "SELECT count(*) FROM body_task_items",
            "SELECT status FROM record_lifecycle_interpretations",
            "SELECT 1 FROM record_lifecycle_interpretations",
            "SELECT count(*) FROM record_lifecycle_interpretations",
        ] {
            let reads = checked(sql);
            // A dropped relation must refuse even a population-only read.
            let mut missing = reads.clone();
            missing.grants.clear();
            let error = validate_app_sql_dependencies(sql, &missing).unwrap_err();
            assert!(error.to_string().contains("app_sql [dependency_mismatch]"));
            assert!(!error.to_string().contains(sql));
            // Drop all columns to reproduce an analyzer omission. Population
            // reads legitimately have no columns and are covered above.
            if reads.grants.iter().any(|grant| !grant.columns.is_empty()) {
                let mut missing = reads.clone();
                for grant in &mut missing.grants {
                    grant.columns.clear();
                }
                assert!(validate_app_sql_dependencies(sql, &missing).is_err());
            }
            validate_app_sql_dependencies(sql, &reads).expect("reused validator resets gate");
            validated_output_columns("SELECT name FROM records").expect("direct SQL unaffected");
        }
    }
}

#[cfg(test)]
mod logical_catalog_contract_tests {
    use super::*;

    fn columns(connection: &rusqlite::Connection, relation: &str) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("PRAGMA temp.table_info('{relation}')"))
            .unwrap();
        statement
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<std::result::Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn logical_catalog_metadata_matches_both_sqlite_schemas_exactly() {
        let expanded = rusqlite::Connection::open_in_memory().unwrap();
        let ddl = DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect::<String>();
        expanded.execute_batch(&ddl).unwrap();
        expanded.execute_batch(&temp_contract()).unwrap();

        let strict = rusqlite::Connection::open_in_memory().unwrap();
        strict.execute_batch(STRICT_LOGICAL_SCHEMA).unwrap();

        for relation in sql_contract::LOGICAL_RELATIONS {
            let expected = relation
                .columns
                .iter()
                .map(|column| (*column).to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                columns(&expanded, relation.name),
                expected,
                "expanded {}",
                relation.name
            );
            assert_eq!(
                columns(&strict, relation.name),
                expected,
                "strict {}",
                relation.name
            );
        }
    }

    /// Every `(type, name)` the contract creates, read from its text.
    fn temp_contract_objects() -> std::collections::BTreeSet<(String, String)> {
        let contract = temp_contract();
        let mut objects = std::collections::BTreeSet::new();
        for (at, _) in contract.match_indices("CREATE TEMP ") {
            let rest = &contract[at + "CREATE TEMP ".len()..];
            let (kind, rest) = if let Some(rest) = rest.strip_prefix("TABLE ") {
                ("table", rest)
            } else if let Some(rest) = rest.strip_prefix("VIEW ") {
                ("view", rest)
            } else {
                continue;
            };
            let rest = rest.trim_start();
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let rest = rest.strip_prefix("temp.").unwrap_or(rest);
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            objects.insert((kind.to_string(), name));
        }
        objects
    }

    /// The one-script install runs every statement: each object the contract
    /// text creates is present afterwards, and cleanup removes them all.
    #[tokio::test]
    async fn install_creates_every_contract_object_and_cleanup_drops_them() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = db.governed_pool().begin().await.unwrap();
        install_temp_contract(&mut tx).await.unwrap();
        let created: std::collections::BTreeSet<(String, String)> = sqlx::query_as(
            "SELECT type, name FROM sqlite_temp_master WHERE type IN ('table', 'view')",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap()
        .into_iter()
        .collect();
        let expected = temp_contract_objects();
        assert!(expected.len() > 40, "{expected:?}");
        assert_eq!(created, expected);
        cleanup_query_sql_temp_contract(&mut tx).await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_temp_master")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert!(left.is_empty(), "{left:?}");
        tx.rollback().await.unwrap();
        db.close().await;
    }

    /// The release hook's object list (its sentinel and its drops) is
    /// exactly the contract's views followed by its tables.
    #[test]
    fn release_hook_object_list_matches_the_contract() {
        use crate::db::{QUERY_SQL_TEMP_CONTRACT_OBJECTS, QUERY_SQL_TEMP_VIEW_COUNT};
        let names = |kind: &str| -> std::collections::BTreeSet<String> {
            temp_contract_objects()
                .into_iter()
                .filter(|(object_kind, _)| object_kind == kind)
                .map(|(_, name)| name)
                .collect()
        };
        let listed = |slice: &[&str]| -> std::collections::BTreeSet<String> {
            slice.iter().map(|name| name.to_string()).collect()
        };
        let (views, tables) = QUERY_SQL_TEMP_CONTRACT_OBJECTS.split_at(QUERY_SQL_TEMP_VIEW_COUNT);
        assert_eq!(listed(views), names("view"));
        assert_eq!(listed(tables), names("table"));
        assert_eq!(
            listed(QUERY_SQL_TEMP_CONTRACT_OBJECTS).len(),
            QUERY_SQL_TEMP_CONTRACT_OBJECTS.len(),
            "duplicate entries"
        );
    }

    #[test]
    fn temp_contract_comments_survive_naive_semicolon_splitting() {
        // The full contract installs as one script, which SQLite parses
        // comment-aware. The subset installer (`install_visible_records_in`)
        // and some test helpers still run `temp_contract().split(';')`,
        // which is not comment-aware. Any semicolon that is not
        // the last non-whitespace character of its comment line leaves a
        // following fragment starting with bare prose, which fails every
        // query_sql call with a syntax error. A trailing semicolon is
        // harmless: the next fragment still opens with a comment or a
        // statement.
        for line in temp_contract().lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("--") {
                assert!(
                    trimmed
                        .split(';')
                        .skip(1)
                        .all(|after| after.trim().is_empty()),
                    "semicolon not at end of contract comment line: {line}"
                );
            }
        }
    }

    #[test]
    fn additive_relation_keeps_the_saved_query_breaking_epoch() {
        assert_eq!(sql_contract::LOGICAL_CATALOG_REVISION, 4);
        let relation = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "messages_awaiting_reply")
            .expect("additive Messages relation is registered");
        assert_eq!(relation.semantic_version, 1);
        assert_eq!(relation.profiles, ["sqlite-local"]);
        assert!(relation.caller_relative);
        assert_eq!(relation.columns, ["message_id"]);
        let activity = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "agent_activity")
            .expect("agent activity relation is registered");
        assert_eq!(activity.semantic_version, 3);
        let actors = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "actors")
            .expect("additive actors relation is registered");
        assert_eq!(actors.semantic_version, 1);
    }
}

#[cfg(test)]
mod catalog_operations_tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::query::principal::{CatalogOperationRow, CatalogOperationsSnapshot};

    fn fixture_snapshot() -> CatalogOperationsSnapshot {
        std::sync::Arc::new(vec![
            CatalogOperationRow {
                executor: "b_read".to_string(),
                operation: "get".to_string(),
                surface: "ordinary".to_string(),
                access: "read".to_string(),
                plan_required: false,
                direct_execution_enabled: true,
                contract_version: "native.operation-contract.v1".to_string(),
                contract_digest: "d1".to_string(),
                source_tool: "get_record".to_string(),
                selector_field: None,
                selector_value: None,
                advertised_directly: true,
            },
            CatalogOperationRow {
                executor: "a_write".to_string(),
                operation: "put".to_string(),
                surface: "ordinary".to_string(),
                access: "mutation".to_string(),
                plan_required: true,
                direct_execution_enabled: false,
                contract_version: "native.operation-contract.v1".to_string(),
                contract_digest: "d2".to_string(),
                source_tool: "save_record".to_string(),
                selector_field: Some("kind".to_string()),
                selector_value: Some("task".to_string()),
                advertised_directly: false,
            },
        ])
    }

    fn principal_with_snapshot() -> QueryPrincipal {
        QueryPrincipal::authenticated("alice", true)
            .with_catalog_operations_snapshot(fixture_snapshot())
    }

    const COLUMNS: [&str; 11] = [
        "executor",
        "operation",
        "surface",
        "access",
        "plan_required",
        "direct_execution_enabled",
        "contract_version",
        "contract_digest",
        "source_tool",
        "selector_field",
        "selector_value",
    ];

    #[tokio::test]
    async fn serves_snapshot_rows_sorted_with_scalar_projection() {
        let db = crate::create_database(":memory:").await.unwrap();
        let result = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT executor, operation, surface, access, plan_required, direct_execution_enabled, contract_version, contract_digest, source_tool, selector_field, selector_value FROM catalog_operations ORDER BY executor, operation",
        )
        .await
        .unwrap();
        assert_eq!(result.columns, COLUMNS);
        assert_eq!(
            result.rows,
            vec![
                json!({"executor": "a_write", "operation": "put", "surface": "ordinary", "access": "mutation", "plan_required": 1, "direct_execution_enabled": 0, "contract_version": "native.operation-contract.v1", "contract_digest": "d2", "source_tool": "save_record", "selector_field": "kind", "selector_value": "task"}),
                json!({"executor": "b_read", "operation": "get", "surface": "ordinary", "access": "read", "plan_required": 0, "direct_execution_enabled": 1, "contract_version": "native.operation-contract.v1", "contract_digest": "d1", "source_tool": "get_record", "selector_field": Value::Null, "selector_value": Value::Null}),
            ]
        );
        assert!(!result.truncated);
        db.close().await;
    }

    /// The lean surface marks call_executor-only operations; the column is
    /// an INTEGER 0/1 like the other catalogue booleans.
    #[tokio::test]
    async fn projects_advertised_directly_as_an_integer_marker() {
        let db = crate::create_database(":memory:").await.unwrap();
        let result = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT executor, operation, advertised_directly FROM catalog_operations ORDER BY executor, operation",
        )
        .await
        .unwrap();
        assert_eq!(
            result.rows,
            vec![
                json!({"executor": "a_write", "operation": "put", "advertised_directly": 0}),
                json!({"executor": "b_read", "operation": "get", "advertised_directly": 1}),
            ]
        );
        let hidden = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT executor, operation FROM catalog_operations WHERE advertised_directly = 0 ORDER BY executor, operation",
        )
        .await
        .unwrap();
        assert_eq!(
            hidden.rows,
            vec![json!({"executor": "a_write", "operation": "put"})]
        );
        db.close().await;
    }

    #[tokio::test]
    async fn refuses_without_snapshot_but_ignores_aliases_and_literals() {
        let db = crate::create_database(":memory:").await.unwrap();
        let bare = QueryPrincipal::authenticated("alice", true);
        let error = query_sql(&db, bare.clone(), "SELECT executor FROM catalog_operations")
            .await
            .expect_err("no snapshot must refuse, not serve empty rows");
        let message = error.to_string();
        assert!(message.contains("catalog_operations"), "{message}");
        assert!(message.contains("ad-hoc"), "{message}");
        // A same-named CTE is not a relation read: no refusal.
        let aliased = query_sql(
            &db,
            bare.clone(),
            "WITH catalog_operations(executor) AS (SELECT 'x' AS executor) SELECT executor FROM catalog_operations",
        )
        .await
        .unwrap();
        assert_eq!(aliased.rows, vec![json!({"executor": "x"})]);
        // A string literal naming it is not a read either.
        let literal = query_sql(&db, bare, "SELECT 'catalog_operations' AS name")
            .await
            .unwrap();
        assert_eq!(literal.rows, vec![json!({"name": "catalog_operations"})]);
        db.close().await;
    }

    #[tokio::test]
    async fn isolates_contexts_and_retains_nothing_readable() {
        let db = crate::create_database(":memory:").await.unwrap();
        let first = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT executor FROM catalog_operations ORDER BY executor",
        )
        .await
        .unwrap();
        assert_eq!(
            first.rows,
            vec![
                json!({"executor": "a_write"}),
                json!({"executor": "b_read"})
            ]
        );
        // A second context replaces the first entirely on the same handle.
        let other = std::sync::Arc::new(vec![fixture_snapshot()[0].clone()]);
        let second = query_sql(
            &db,
            QueryPrincipal::authenticated("alice", true).with_catalog_operations_snapshot(other),
            "SELECT executor FROM catalog_operations ORDER BY executor",
        )
        .await
        .unwrap();
        assert_eq!(second.rows, vec![json!({"executor": "b_read"})]);
        // Without a snapshot the pooled connection's leftovers stay
        // unreadable: refusal, never prior rows and never empty success.
        let refused = query_sql(
            &db,
            QueryPrincipal::authenticated("alice", true),
            "SELECT executor FROM catalog_operations",
        )
        .await
        .expect_err("stale rows must not leak across requests");
        assert!(refused.to_string().contains("catalog_operations"));
        db.close().await;
    }

    #[tokio::test]
    async fn aggregates_over_named_columns_work_but_column_less_refuses() {
        // The snapshot stages in a table (like the lifecycle staging
        // tables), so a column-less `count(*)` reports no database to the
        // validator authorizer and meets the staged-table refusal — while a
        // named-column aggregate observes, populates and serves. Verified
        // against SQLite authorizer callbacks: column-less reads carry no
        // database name, named reads carry `temp`.
        let db = crate::create_database(":memory:").await.unwrap();
        let named = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT count(executor) AS n FROM catalog_operations",
        )
        .await
        .unwrap();
        assert_eq!(named.rows, vec![json!({"n": 2})]);
        let refused = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT count(*) AS n FROM catalog_operations",
        )
        .await
        .expect_err("column-less aggregates refuse over staged tables");
        assert!(
            refused.to_string().contains("unauthorized_relation"),
            "{refused}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn columns_match_the_declared_contract() {
        let db = crate::create_database(":memory:").await.unwrap();
        let listed = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT column_name FROM catalog_columns WHERE relation_name = 'catalog_operations' ORDER BY column_position",
        )
        .await
        .unwrap();
        let names: Vec<String> = listed
            .rows
            .iter()
            .map(|row| row["column_name"].as_str().unwrap().to_string())
            .collect();
        // The declared relation appends the lean direct-advertisement marker
        // after the original columns, so their positions are unchanged.
        assert_eq!(
            names,
            [COLUMNS.as_slice(), &["advertised_directly"]].concat()
        );
        let relation = query_sql(
            &db,
            principal_with_snapshot(),
            "SELECT identity, caller_relative, completeness, profiles FROM catalog_relations WHERE relation_name = 'catalog_operations'",
        )
        .await
        .unwrap();
        assert_eq!(relation.rows.len(), 1);
        assert_eq!(
            relation.rows[0]["identity"],
            json!("native.query-sql.catalog-operations")
        );
        assert_eq!(relation.rows[0]["profiles"], json!("sqlite-local"));
        db.close().await;
    }

    #[tokio::test]
    async fn member_probe_denies_real_reads_only() {
        let denied = member_denied_requirement("SELECT executor FROM catalog_operations")
            .unwrap()
            .expect("member copies refuse the serving relation");
        assert_eq!(denied, "catalog_operations");
        assert!(member_denied_requirement(
            "WITH catalog_operations(executor) AS (SELECT 'x' AS executor) SELECT executor FROM catalog_operations"
        )
        .unwrap()
        .is_none());
    }
}

#[cfg(test)]
mod production_acl_tests {
    use std::time::Duration;

    use futures::{stream, FutureExt, StreamExt};
    use serde_json::json;

    use super::*;
    use crate::authorization::{
        effective_capability, replace_explicit_policy, AllowEntry, Capability, Principal,
        MAX_DERIVED_BEARER_DEPTH,
    };
    use crate::events::{FacetSetPayload, LinkAddedPayload};
    use crate::store::{
        add_link, append, create_record, delete_record, set_facet, update_record, AppendSpec,
    };

    #[tokio::test]
    async fn lifecycle_relation_matches_get_record_for_two_schema_viewers() {
        let db = crate::create_database(":memory:").await.unwrap();
        let bearer = "9e795c01-0000-4000-8000-000000000001";
        let task = "9e795c01-0000-4000-8000-000000000002";
        create_record(
            &db,
            json!({
                "id": bearer, "type": "Collection", "kind": "folder", "name": "private bearer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": task, "type": "WorkItem", "kind": "task", "name": "shared task",
                "home_id": bearer, "lifecycle": "open"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:lifecycle-bearer",
            bearer,
            vec![AllowEntry::account("acct:owner", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:lifecycle-task",
            task,
            vec![
                AllowEntry::account("acct:owner", Capability::View),
                AllowEntry::account("acct:viewer", Capability::View),
            ],
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO schema_config(id,layer,name,data,applies_to_collection_id,created_at)
             VALUES('test:lifecycle-hidden','user','hidden',?,?,'2026-09-30T00:00:00.000Z')",
        )
        .bind(
            json!({"shapes":{"WorkItem:task":{"facets":{"lifecycle":{
                "axis":{"key":"hidden_axis","label":"Hidden"},
                "vocab_ref":"nonexistent-vocab"
            }}}}})
            .to_string(),
        )
        .bind(bearer)
        .execute(db.write_pool())
        .await
        .unwrap();

        for (account, expected_status) in
            [("acct:viewer", "governed"), ("acct:owner", "unclassified")]
        {
            let auth = Principal::bound(account, true);
            let record = crate::query::read::get_record_with_lens_as(
                &crate::query::lens::ReadLens::live(&db),
                task,
                crate::query::read::EnrichOptions::default(),
                auth,
            )
            .await
            .unwrap()
            .expect("task visible to both callers");
            let expected = serde_json::to_value(record.record.lifecycle_interpretation).unwrap();
            assert_eq!(expected["status"], expected_status);
            let caller = QueryPrincipal::authenticated(account, true);
            let bearer_rows = query_sql(
                &db,
                caller.clone(),
                &format!("SELECT id FROM records WHERE id='{bearer}'"),
            )
            .await
            .unwrap();
            assert_eq!(bearer_rows.rows.len(), usize::from(account == "acct:owner"));
            let schema_rows = query_sql(
                &db,
                caller.clone(),
                "SELECT id FROM schema_config WHERE id='test:lifecycle-hidden'",
            )
            .await
            .unwrap();
            assert_eq!(schema_rows.rows.len(), usize::from(account == "acct:owner"));
            let sql = format!(
                "SELECT record_id,status,raw,axis_key,axis_label,vocabulary_id,vocabulary_name,value_id,canonical,terminality,reason FROM record_lifecycle_interpretations WHERE record_id='{task}'"
            );
            let result = query_sql(&db, caller.clone(), &sql).await.unwrap();
            assert_eq!(result.rows.len(), 1);
            let row = &result.rows[0];
            assert_eq!(row["record_id"], task);
            assert_eq!(row["status"], expected["status"]);
            let expected_raw = if expected_status == "governed" {
                &expected["value"]["raw"]
            } else {
                &expected["raw"]
            };
            assert_eq!(&row["raw"], expected_raw);
            if expected_status == "governed" {
                assert_eq!(row["axis_key"], expected["axis"]["key"]);
                assert_eq!(row["axis_label"], expected["axis"]["label"]);
                assert_eq!(row["vocabulary_id"], expected["vocabulary"]["id"]);
                assert_eq!(row["vocabulary_name"], expected["vocabulary"]["name"]);
                assert_eq!(row["value_id"], expected["value"]["id"]);
                assert_eq!(row["canonical"], expected["value"]["canonical"]);
                assert_eq!(row["terminality"], expected["terminality"]);
                assert!(row["reason"].is_null());
            } else {
                assert_eq!(row["reason"], expected["reason"]);
                for field in [
                    "axis_key",
                    "axis_label",
                    "vocabulary_id",
                    "vocabulary_name",
                    "value_id",
                    "canonical",
                    "terminality",
                ] {
                    assert!(
                        row[field].is_null(),
                        "{field} must be absent for unclassified"
                    );
                }
            }
            let mut tx = db.write_pool().begin().await.unwrap();
            let in_transaction = query_sql_request_in(
                &mut tx,
                caller.clone(),
                QuerySqlRequest {
                    sql: sql.clone(),
                    parameters: Vec::new(),
                },
            )
            .await
            .unwrap();
            assert_eq!(in_transaction.rows, result.rows);
            let temp_left: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='record_lifecycle_interpretations'",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(
                temp_left, 0,
                "successful lifecycle read must remove TEMP state"
            );
            tx.rollback().await.unwrap();
            let count = query_sql(
                &db,
                caller.clone(),
                &format!("SELECT count(*) AS n FROM record_lifecycle_interpretations WHERE record_id='{task}'"),
            )
            .await
            .unwrap();
            assert_eq!(count.rows[0]["n"], 1);
            let raw = query_sql(
                &db,
                caller,
                &format!("SELECT lifecycle FROM records WHERE id='{task}'"),
            )
            .await
            .unwrap();
            assert_eq!(raw.rows[0]["lifecycle"], "open");
        }
        let viewer = QueryPrincipal::authenticated("acct:viewer", true);
        let hidden = query_sql(
            &db,
            viewer,
            &format!(
                "SELECT record_id FROM record_lifecycle_interpretations WHERE record_id='{bearer}'"
            ),
        )
        .await
        .unwrap();
        assert!(hidden.rows.is_empty());
    }

    #[tokio::test]
    async fn lifecycle_relation_refuses_oversized_visible_snapshot_without_shadowing_caller_tx() {
        let db = crate::create_database(":memory:").await.unwrap();
        let root = crate::schema::ROOT_RECORD_ID;
        // One statement plants policy-anchored records without a 20k-event
        // write loop. All IDs are live and visible to a member through ROOT.
        sqlx::query(
            "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)),
                  numbers(n) AS (
                    SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d
                    FROM digits a,digits b,digits c,digits d,digits e
                  )
             INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id)
             SELECT printf('9e795c03-0000-4000-8000-%012d',n),
                    'Document','note','bulk',?1,?1
             FROM numbers WHERE n <= 20000",
        )
        .bind(root)
        .execute(db.write_pool())
        .await
        .unwrap();
        let caller = QueryPrincipal::authenticated("acct:owner", true);
        let visible = query_sql(
            &db,
            caller.clone(),
            "SELECT count(*) AS n FROM records WHERE id LIKE '9e795c03-%'",
        )
        .await
        .unwrap();
        assert_eq!(visible.rows[0]["n"], MAX_LIFECYCLE_VISIBLE_RECORDS + 1);
        assert_eq!(
            query_sql(&db, caller.clone(), "SELECT 1 AS ok")
                .await
                .unwrap()
                .rows[0]["ok"],
            1
        );
        let dependent = "SELECT count(*) AS n FROM record_lifecycle_interpretations";
        let error = query_sql(&db, caller.clone(), dependent).await.unwrap_err();
        assert!(error.to_string().contains("result_too_large"), "{error}");
        assert!(error.to_string().contains("20000"), "{error}");

        let mut tx = db.write_pool().begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            caller.clone(),
            QuerySqlRequest {
                sql: dependent.into(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("result_too_large"), "{error}");
        let leaked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='record_lifecycle_interpretations'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(leaked, 0, "early refusal must remove every TEMP object");
        let after = query_sql_request_in(
            &mut tx,
            caller,
            QuerySqlRequest {
                sql: "SELECT 1 AS ok".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(after.rows[0]["ok"], 1);
        tx.rollback().await.unwrap();
    }

    // Pinned fixture record ids. Three properties of the old slugs were
    // load-bearing and are preserved deliberately:
    //
    //   * `LIKE 'artifact-%'` selected exactly the artifact fixtures, so those
    //     ids now share `ARTIFACT_ID_PREFIX` and nothing else does.
    //   * `LIKE '%-private'` selected exactly Alice's and Bea's private notes,
    //     so those two ids now share `PRIVATE_ID_SUFFIX` and nothing else does.
    //   * Several assertions read rows back `ORDER BY id` (and blob filenames
    //     `ORDER BY 1`, which are `{id}.txt`). The numbering below keeps every
    //     one of those orders: alice/bea before common, hidden before kindless,
    //     attachment-alice before attachment-common.
    const ARTIFACT_ID_PREFIX: &str = "9e795a47-";
    const PRIVATE_ID_SUFFIX: &str = "0b1a7e";
    const ALICE_PRIVATE_ID: &str = "9e795000-0000-4000-8000-0000010b1a7e";
    const BEA_PRIVATE_ID: &str = "9e795000-0000-4000-8000-0000020b1a7e";
    const COMMON_ID: &str = "9e795000-0000-4000-8000-000003000000";
    const TOMBSTONE_ID: &str = "9e795000-0000-4000-8000-000004000000";
    const KINDLESS_BEARER_ALICE_ID: &str = "9e795000-0000-4000-8000-000005000000";
    const ATTACHMENT_ALICE_ID: &str = "9e795000-0000-4000-8000-000006000000";
    const ATTACHMENT_COMMON_ID: &str = "9e795000-0000-4000-8000-000007000000";
    const ARTIFACT_HIDDEN_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000001";
    const ARTIFACT_KINDLESS_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000002";
    const ARTIFACT_VISIBLE_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000003";
    const ARTIFACT_BEARERLESS_ID: &str = "9e795a47-0000-4000-8000-000000000004";
    const ARTIFACT_MULTIPLE_ID: &str = "9e795a47-0000-4000-8000-000000000005";
    const ARTIFACT_CYCLE_A_ID: &str = "9e795a47-0000-4000-8000-000000000006";
    const ARTIFACT_CYCLE_B_ID: &str = "9e795a47-0000-4000-8000-000000000007";
    const ARTIFACT_TOMBSTONED_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000008";
    const DEPTH_TERMINAL_ID: &str = "9e795000-0000-4000-8000-000008000000";
    const LOCAL_MALFORMED_ID: &str = "9e795000-0000-4000-8000-00000a000000";
    const LOCAL_TOMBSTONE_ID: &str = "9e795000-0000-4000-8000-00000b000000";
    const LOCAL_MALFORMED_ANCHOR_ID: &str = "9e795000-0000-4000-8000-00000c000000";
    const OVERSIZE_CELL_ID: &str = "9e795000-0000-4000-8000-00000d000000";
    const REPEATED_BYTES_ID: &str = "9e795000-0000-4000-8000-00000e000000";
    const TOOBIG_ALICE_ID: &str = "9e795000-0000-4000-8000-00000f000000";
    const TOOBIG_BEA_ID: &str = "9e795000-0000-4000-8000-000010000000";
    const TOOBIG_ALICE_BYTES: usize = 264_975;
    const TOOBIG_BEA_BYTES: usize = 479_257;
    const TOOBIG_ALICE_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000011000000";
    const TOOBIG_BEA_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000012000000";
    const TOOBIG_EXTERNAL_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000013000000";
    const TOOBIG_EXTERNAL_BLOB_ID: &str = "9e795000-0000-4000-8000-000014000000";
    const COMPUTED_TOOBIG_SQL: &str = "WITH RECURSIVE d(s) AS (
         SELECT 'x' UNION ALL SELECT s||s FROM d WHERE length(s) < 1000000
       ) SELECT s FROM d";

    async fn protected_fixture() -> (Db, QueryPrincipal, QueryPrincipal) {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, name, body) in [
            (ALICE_PRIVATE_ID, "Alice private", "sharedterm alice-only"),
            (BEA_PRIVATE_ID, "Bea private", "sharedterm bea-only"),
            (COMMON_ID, "Common", "sharedterm common"),
            (TOMBSTONE_ID, "Tombstone", "sharedterm removed"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                    "body": body,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": KINDLESS_BEARER_ALICE_ID,
                "type": "Document",
                "kind": "note",
                "name": "Kindless bearer Alice",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "UPDATE records SET kind = NULL WHERE id = '{KINDLESS_BEARER_ALICE_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            BEA_PRIVATE_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            TOMBSTONE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            KINDLESS_BEARER_ALICE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        for (record_id, account, email) in [
            (ALICE_PRIVATE_ID, "alice", "alice@example.test"),
            (BEA_PRIVATE_ID, "bea", "bea@example.test"),
        ] {
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1), (?, 'email', ?, 1)",
            )
            .bind(record_id)
            .bind(account)
            .bind(record_id)
            .bind(email)
            .execute(db.write_pool())
            .await
            .unwrap();
            set_facet(
                &db,
                record_id,
                FacetSetPayload {
                    key: "secret".into(),
                    value: Some(format!("{account}-facet")),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("alice-common".into()),
                source_id: ALICE_PRIVATE_ID.into(),
                target_id: COMMON_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("common-bea".into()),
                source_id: COMMON_ID.into(),
                target_id: BEA_PRIVATE_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        for (attachment_id, bearer_id, grants) in [
            (ATTACHMENT_ALICE_ID, ALICE_PRIVATE_ID, vec!["alice"]),
            (ATTACHMENT_COMMON_ID, COMMON_ID, vec!["alice", "bea"]),
        ] {
            create_record(
                &db,
                json!({
                    "id": attachment_id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("{attachment_id}.txt"),
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                attachment_id,
                grants
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
            let blob = crate::blob::insert_blob(
                &db,
                attachment_id.as_bytes(),
                Some("text/plain"),
                Some(&format!("{attachment_id}.txt")),
            )
            .await
            .unwrap();
            set_facet(
                &db,
                attachment_id,
                FacetSetPayload {
                    key: "blob_ref".into(),
                    value: Some(blob.id),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(format!("bearer-{attachment_id}")),
                    source_id: attachment_id.into(),
                    target_id: bearer_id.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }

        for (id, record_type, kind, grants) in [
            (
                ARTIFACT_HIDDEN_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (
                ARTIFACT_VISIBLE_BEARER_ID,
                "Document",
                "attachment",
                vec!["alice"],
            ),
            (
                ARTIFACT_BEARERLESS_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (ARTIFACT_MULTIPLE_ID, "Annotation", "citation", vec!["bea"]),
            (ARTIFACT_CYCLE_A_ID, "Annotation", "citation", vec!["bea"]),
            (ARTIFACT_CYCLE_B_ID, "Annotation", "citation", vec!["bea"]),
            (
                ARTIFACT_TOMBSTONED_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (
                ARTIFACT_KINDLESS_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": record_type,
                    "kind": kind,
                    "name": id,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                grants
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
        }
        for (id, source, target) in [
            (
                "part-artifact-hidden",
                ARTIFACT_HIDDEN_BEARER_ID,
                ALICE_PRIVATE_ID,
            ),
            (
                "part-artifact-visible",
                ARTIFACT_VISIBLE_BEARER_ID,
                BEA_PRIVATE_ID,
            ),
            ("part-artifact-multiple-a", ARTIFACT_MULTIPLE_ID, COMMON_ID),
            (
                "part-artifact-multiple-b",
                ARTIFACT_MULTIPLE_ID,
                BEA_PRIVATE_ID,
            ),
            (
                "part-artifact-cycle-a",
                ARTIFACT_CYCLE_A_ID,
                ARTIFACT_CYCLE_B_ID,
            ),
            (
                "part-artifact-cycle-b",
                ARTIFACT_CYCLE_B_ID,
                ARTIFACT_CYCLE_A_ID,
            ),
            (
                "part-artifact-tombstone",
                ARTIFACT_TOMBSTONED_BEARER_ID,
                TOMBSTONE_ID,
            ),
            (
                "part-artifact-kindless",
                ARTIFACT_KINDLESS_BEARER_ID,
                KINDLESS_BEARER_ALICE_ID,
            ),
        ] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.into()),
                    source_id: source.into(),
                    target_id: target.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        set_facet(
            &db,
            TOMBSTONE_ID,
            FacetSetPayload {
                key: "secret".into(),
                value: Some("removed".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        delete_record(&db, TOMBSTONE_ID).await.unwrap();
        (
            db,
            QueryPrincipal::authenticated("alice", true),
            QueryPrincipal::authenticated("bea", true),
        )
    }

    async fn governed_query(
        db: &Db,
        principal: QueryPrincipal,
        sql: &str,
    ) -> (SqlResult, GovernedSqlObservation) {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        let result = query_sql_request_in_for_saved(
            &mut transaction,
            principal,
            QuerySqlRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap();
        transaction.rollback().await.unwrap();
        result
    }

    /// Hold every governed-pool slot but one so the queries below must reuse a
    /// single physical connection. This is the Tier 1.2 form of the old
    /// hold-four-of-five write-pool pinning: governed TEMP state now lives on
    /// the governed pool, so pinning write slots would no longer force any
    /// governed reuse. Sized from the configured pool size so the pinning
    /// stays exact under `NATIVE_CE_GOVERNED_SQL_POOL_SIZE` overrides.
    fn session_request(sql: &str) -> QuerySqlRequest {
        QuerySqlRequest {
            sql: sql.to_string(),
            parameters: Vec::new(),
        }
    }

    async fn per_call_execution(db: &Db, principal: &QueryPrincipal, sql: &str) -> SqlResult {
        let mut tx = db.governed_pool().begin().await.unwrap();
        let (result, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            principal.clone(),
            session_request(sql),
            MAX_ROWS,
            sql_contract::FunctionAllowance::Portable,
            None,
            None,
            false,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        result
    }

    async fn run_in_session(
        session: &mut GovernedSqlSession<'_, '_>,
        principal: QueryPrincipal,
        sql: &str,
    ) -> SqlResult {
        session
            .execute(
                principal,
                session_request(sql),
                MAX_ROWS,
                sql_contract::FunctionAllowance::Portable,
                None,
                None,
                false,
            )
            .await
            .unwrap()
            .0
    }

    /// Executions sharing one session, for two viewers in turn, answer
    /// exactly as per-call executions do: each starts from cleared contract
    /// state, so no principal, visible set or helper rows carry over.
    #[tokio::test]
    async fn session_executions_match_per_call_executions() {
        let (db, alice, bea) = protected_fixture().await;
        // Activity and claims rows for an activity reader, so the activity,
        // claims and disclosure tables are populated by some executions and
        // must be empty again for the next.
        for (account, person) in [("alice", ALICE_PRIVATE_ID), ("bea", BEA_PRIVATE_ID)] {
            sqlx::query(
                "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
                 VALUES(?,?,?,'2026-08-31T00:00:00.000Z')",
            )
            .bind(account)
            .bind(person)
            .bind(person)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let run = "scout-chair-c748b2";
        crate::control::ensure_agent_run(
            &db,
            run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:session-claim",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({"record_id": ALICE_PRIVATE_ID, "action": "claim", "run_key": run}),
            )
            .await
            .unwrap();
        // SAFETY: models the hosted ingress after it admitted this member
        // context; no SQL argument controls it.
        let activity_reader = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "alice",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        let activity_sql = "SELECT activity_id, run_key FROM agent_activity ORDER BY activity_id";
        let claims_sql = "SELECT claim_id, record_id FROM agent_activity_claims ORDER BY claim_id";
        let statements = [
            format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}' ORDER BY id"),
            "SELECT count(*) AS n FROM records".to_string(),
            "SELECT id, name FROM records ORDER BY id LIMIT 10".to_string(),
            "SELECT count(*) AS n FROM content_events".to_string(),
            activity_sql.to_string(),
            claims_sql.to_string(),
            "SELECT record_id, status FROM record_lifecycle_interpretations ORDER BY record_id, axis_key"
                .to_string(),
        ];
        let tx = db.governed_pool().begin().await.unwrap();
        let mut session = GovernedSqlSession::begin(&db, tx).await.unwrap();
        for principal in [&alice, &activity_reader, &alice, &bea, &activity_reader] {
            for sql in &statements {
                let in_session = run_in_session(&mut session, principal.clone(), sql).await;
                let alone = per_call_execution(&db, principal, sql).await;
                assert_eq!(in_session.columns, alone.columns, "{sql}");
                assert_eq!(in_session.rows, alone.rows, "{sql}");
            }
        }
        // Straight after the activity reader's rows, plain Alice sees none.
        for sql in [activity_sql, claims_sql] {
            let reader = run_in_session(&mut session, activity_reader.clone(), sql).await;
            assert!(reader.row_count > 0, "{sql}");
            let plain = run_in_session(&mut session, alice.clone(), sql).await;
            assert_eq!(plain.row_count, 0, "{sql}");
        }
        let alice_private = run_in_session(&mut session, alice.clone(), &statements[0]).await;
        assert_eq!(first_strings(&alice_private), [ALICE_PRIVATE_ID]);
        session.finish().await.unwrap().rollback().await.unwrap();
        db.close().await;
    }

    /// While the contract is installed, an unqualified `records` read sees
    /// the viewer-filtered contract view, not the table. That is the hazard
    /// a session keeps domain reads away from by owning the transaction;
    /// `finish` must hand it back with every name resolving to `main` again.
    #[tokio::test]
    async fn session_shadows_domain_names_until_finish() {
        let (db, alice, _) = protected_fixture().await;
        let tx = db.governed_pool().begin().await.unwrap();
        let mut session = GovernedSqlSession::begin(&db, tx).await.unwrap();
        session
            .execute(
                alice,
                session_request("SELECT count(*) AS n FROM records"),
                MAX_ROWS,
                sql_contract::FunctionAllowance::Portable,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        let main_count: i64 = sqlx::query_scalar("SELECT count(*) FROM main.records")
            .fetch_one(&mut **session.transaction_for_test())
            .await
            .unwrap();
        let shadowed: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
            .fetch_one(&mut **session.transaction_for_test())
            .await
            .unwrap();
        assert!(shadowed < main_count, "{shadowed} of {main_count}");
        let mut tx = session.finish().await.unwrap();
        let unqualified: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(unqualified, main_count);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(left, 0);
        tx.rollback().await.unwrap();
        db.close().await;
    }

    /// A session that ends without `finish` (abandoned after a failed
    /// execution, or dropped by an error or a cancelled future) returns its
    /// pooled connection with no contract left on it.
    #[tokio::test]
    async fn abandoned_session_leaves_the_pooled_connection_clean() {
        let (db, alice, _) = protected_fixture().await;
        let held = hold_all_but_one_governed_slot(&db).await;
        for abandon in [true, false] {
            let tx = db.governed_pool().begin().await.unwrap();
            let mut session = GovernedSqlSession::begin(&db, tx).await.unwrap();
            session
                .execute(
                    alice.clone(),
                    session_request("SELECT count(*) AS n FROM records"),
                    MAX_ROWS,
                    sql_contract::FunctionAllowance::Portable,
                    None,
                    None,
                    false,
                )
                .await
                .unwrap();
            if abandon {
                session.abandon().await;
            } else {
                drop(session);
            }
            // The one free slot is the connection the session used.
            let mut connection = db.governed_pool().acquire().await.unwrap();
            let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            assert_eq!(left, 0, "abandon: {abandon}");
            let unqualified: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            let main_count: i64 = sqlx::query_scalar("SELECT count(*) FROM main.records")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            assert_eq!(unqualified, main_count, "abandon: {abandon}");
        }
        drop(held);
        db.close().await;
    }

    async fn hold_all_but_one_governed_slot(
        db: &Db,
    ) -> Vec<sqlx::pool::PoolConnection<sqlx::Sqlite>> {
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size().max(1) - 1 {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        held
    }

    fn first_strings(result: &SqlResult) -> Vec<String> {
        result
            .rows
            .iter()
            .map(|row| {
                row.as_object()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .into()
            })
            .collect()
    }

    #[tokio::test]
    async fn legacy_saved_sql_skips_new_determinism_rejections() {
        // New-SQL-only I3 rejections: stored definitions execute under
        // LegacySavedSql, so LIMIT without ORDER BY and bare GROUP BY
        // columns still run here while ad-hoc and new saves refuse them.
        let (db, alice, _) = protected_fixture().await;
        let (limited, _) =
            governed_query(&db, alice.clone(), "SELECT id FROM records LIMIT 1").await;
        assert_eq!(limited.row_count, 1);
        let (grouped, _) = governed_query(
            &db,
            alice,
            "SELECT kind, count(*) AS n FROM records GROUP BY type",
        )
        .await;
        assert!(!grouped.rows.is_empty());
    }

    /// App-route execution through the admission seam: same caller-owned
    /// transaction discipline as `governed_query`, but the declaration gate
    /// runs before the executor. Rolls back like every other governed read.
    async fn app_query(
        db: &Db,
        declared: &crate::mcp::tools::alpha_tabs::ReadsDeclaration,
        principal: QueryPrincipal,
        sql: &str,
    ) -> Result<SqlResult> {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        let result = crate::mcp::tools::alpha_tabs::execute_app_sql_in(
            &mut transaction,
            declared,
            principal,
            QuerySqlRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            },
        )
        .await;
        transaction.rollback().await.unwrap();
        result
    }

    fn app_declared_records() -> crate::mcp::tools::alpha_tabs::ReadsDeclaration {
        use crate::mcp::tools::alpha_tabs::{ReadGrant, ReadsDeclaration};
        ReadsDeclaration {
            grants: vec![ReadGrant {
                relation: "records".to_string(),
                columns: vec!["body".to_string(), "id".to_string(), "name".to_string()],
            }],
            scopes: vec![],
        }
    }

    #[tokio::test]
    async fn app_sql_two_viewers_see_only_permitted_rows() {
        let (db, alice, bea) = protected_fixture().await;
        let declared = app_declared_records();
        let sql = "SELECT id, name FROM records WHERE body LIKE '%sharedterm%' ORDER BY id";
        let names = |result: SqlResult| {
            let mut names: Vec<String> = result
                .rows
                .iter()
                .map(|row| row["name"].as_str().unwrap().to_string())
                .collect();
            names.sort();
            names
        };
        // Caller authority still filters accepted SQL: each viewer sees the
        // common row plus only their own private row.
        let alice_names = names(app_query(&db, &declared, alice, sql).await.unwrap());
        assert_eq!(alice_names, vec!["Alice private", "Common"]);
        let bea_names = names(app_query(&db, &declared, bea, sql).await.unwrap());
        assert_eq!(bea_names, vec!["Bea private", "Common"]);
    }

    #[tokio::test]
    async fn app_sql_empty_result_preserves_verified_columns() {
        let (db, alice, _) = protected_fixture().await;
        let declared = app_declared_records();
        let result = app_query(
            &db,
            &declared,
            alice,
            "SELECT id AS record_id, name FROM records WHERE 0 ORDER BY id",
        )
        .await
        .unwrap();
        assert!(result.rows.is_empty());
        assert_eq!(result.columns, vec!["record_id", "name"]);
        let response = crate::mcp::tools::alpha_tabs::AppSqlResponse::project(&result);
        assert_eq!(response.columns, result.columns);
        assert!(response.row_count_complete);
        assert!(!serde_json::to_value(response)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("as_of_seq"));
    }

    #[tokio::test]
    async fn app_sql_record_scopes_filter_before_counts_and_joins() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        let db = crate::create_database(":memory:").await.unwrap();
        // Include NULL kinds and kind case variants. Scope matching is exact,
        // not a heuristic based on SQL predicates or type-name normalization.
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id)
             VALUES ('scope-task-a','WorkItem','task','a',?1,?1),
                    ('scope-task-b','WorkItem','task','b',?1,?1),
                    ('scope-bug','WorkItem','bug','c',?1,?1),
                    ('scope-kindless','WorkItem',NULL,'d',?1,?1),
                    ('scope-kind-case','WorkItem','Task','e',?1,?1),
                    ('scope-message','Message','note','g',?1,?1)",
        )
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        let viewer = QueryPrincipal::authenticated("alice", true);
        let declared = |scopes: Value| {
            parse_reads_declaration(&json!({
                "relations": {"records": ["id", "kind", "name", "type"]},
                "scope": scopes,
            }))
            .unwrap()
        };
        for (scopes, expected) in [
            (json!([{"type": "WorkItem", "kind": "task"}]), 2),
            (json!([{"type": "WorkItem", "kind": "Task"}]), 1),
            (json!([{"type": "workitem"}]), 0),
            (json!([{"type": "WorkItem"}]), 5),
            (json!([{"type": "Absent"}]), 0),
            (
                json!([{"type": "WorkItem", "kind": "task"}, {"type": "WorkItem", "kind": "bug"}]),
                3,
            ),
            (json!([{"type": "WorkItem"}, {"type": "Message"}]), 6),
        ] {
            let declaration = declared(scopes);
            let result = app_query(
                &db,
                &declaration,
                viewer.clone(),
                "SELECT count(*) AS n FROM records WHERE type = 'Message' OR 1 = 1",
            )
            .await
            .unwrap();
            assert_eq!(result.rows[0]["n"], expected);
            let grouped = app_query(
                &db,
                &declaration,
                viewer.clone(),
                "SELECT kind, count(*) AS n FROM records GROUP BY kind HAVING count(*) > 0 ORDER BY kind",
            )
            .await
            .unwrap();
            let total: i64 = grouped
                .rows
                .iter()
                .map(|row| row["n"].as_i64().unwrap())
                .sum();
            assert_eq!(total, expected, "grouping sees only scoped records");
        }
        let tasks = declared(json!([{"type": "WorkItem", "kind": "task"}]));
        let joined = app_query(
            &db,
            &tasks,
            viewer.clone(),
            "SELECT a.id AS first_id, b.id AS second_id FROM records a LEFT JOIN records b ON a.type = b.type ORDER BY a.id, b.id",
        )
        .await
        .unwrap();
        assert_eq!(joined.row_count, 4, "both join sides are narrowed");
        for row in joined.rows {
            for column in ["first_id", "second_id"] {
                assert!(matches!(
                    row[column].as_str().unwrap(),
                    "scope-task-a" | "scope-task-b"
                ));
            }
        }
        let messages = app_query(
            &db,
            &tasks,
            viewer,
            "SELECT id FROM records WHERE type = 'Message' ORDER BY id",
        )
        .await
        .unwrap();
        assert!(messages.rows.is_empty());
        assert_eq!(messages.columns, vec!["id"]);
    }

    #[tokio::test]
    async fn app_sql_task_marker_scopes_follow_current_owner_and_viewer() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        let (db, alice, bea) = protected_fixture().await;
        for id in [ALICE_PRIVATE_ID, BEA_PRIVATE_ID, COMMON_ID] {
            crate::store::update_record(
                &db,
                id,
                serde_json::json!({"body": "- [ ] pending\n- [x] completed"}),
            )
            .await
            .unwrap();
        }
        let declared = parse_reads_declaration(&serde_json::json!({
            "relations": {"body_task_items": ["record_id", "checked", "marker"]},
            "scope": [{"type": "Document", "kind": "note"}],
        }))
        .unwrap();
        let sql = "SELECT record_id, count(*) AS n, sum(checked) AS completed FROM body_task_items GROUP BY record_id ORDER BY record_id";
        for (viewer, private) in [(alice.clone(), ALICE_PRIVATE_ID), (bea, BEA_PRIVATE_ID)] {
            let result = app_query(&db, &declared, viewer.clone(), sql)
                .await
                .unwrap();
            assert_eq!(result.rows.len(), 2);
            assert_eq!(result.rows[0]["record_id"], private);
            assert_eq!(result.rows[1]["record_id"], COMMON_ID);
            for row in result.rows {
                assert_eq!(row["n"], 2);
                assert_eq!(row["completed"], 1);
            }
            let count = app_query(
                &db,
                &declared,
                viewer,
                "SELECT count(*) AS n FROM body_task_items WHERE marker = '-' OR 1 = 1",
            )
            .await
            .unwrap();
            assert_eq!(count.rows[0]["n"], 4);
        }
        sqlx::query("UPDATE records SET kind = 'other' WHERE id = ?")
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = app_query(&db, &declared, alice.clone(), sql).await.unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["record_id"], ALICE_PRIVATE_ID);
        let absent = parse_reads_declaration(&serde_json::json!({
            "relations": {"body_task_items": ["checked"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        let result = app_query(
            &db,
            &absent,
            alice.clone(),
            "SELECT checked FROM body_task_items",
        )
        .await
        .unwrap();
        assert!(result.rows.is_empty());
        assert_eq!(result.columns, vec!["checked"]);
        let direct = query_sql(&db, alice, "SELECT count(*) AS n FROM body_task_items")
            .await
            .unwrap();
        assert_eq!(direct.rows[0]["n"], 4);
    }

    #[tokio::test]
    async fn app_sql_time_facet_scopes_follow_current_owner_and_viewer() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        use crate::mcp::{Caller, ToolRegistry};
        let (db, alice, bea) = protected_fixture().await;
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_schema_config",
                serde_json::json!({
                    "action": "write", "data": {"shapes": {"Document:note": {"facets": {
                        "due": {"type": "date"},
                    }}}},
                }),
            )
            .await
            .unwrap();
        for id in [ALICE_PRIVATE_ID, BEA_PRIVATE_ID, COMMON_ID] {
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "update_record",
                    serde_json::json!({
                        "id": id, "facets": {"due": "2026-10-05"},
                        "reason": "Scoped typed-time fixture value.",
                    }),
                )
                .await
                .unwrap();
        }
        let declared = parse_reads_declaration(&serde_json::json!({
            "relations": {"facet_times": ["record_id", "start_date"]},
            "scope": [{"type": "Document", "kind": "note"}],
        }))
        .unwrap();
        let sql = "SELECT record_id, start_date FROM facet_times WHERE start_date = '2026-10-05' OR 1 = 1 ORDER BY record_id";
        for (viewer, private) in [(alice.clone(), ALICE_PRIVATE_ID), (bea, BEA_PRIVATE_ID)] {
            let result = app_query(&db, &declared, viewer.clone(), sql)
                .await
                .unwrap();
            assert_eq!(result.rows.len(), 2);
            assert_eq!(result.rows[0]["record_id"], private);
            assert_eq!(result.rows[1]["record_id"], COMMON_ID);
            assert!(result
                .rows
                .iter()
                .all(|row| row["start_date"] == "2026-10-05"));
            let count = app_query(
                &db,
                &declared,
                viewer,
                "SELECT count(*) AS n FROM facet_times",
            )
            .await
            .unwrap();
            assert_eq!(count.rows[0]["n"], 2);
        }
        sqlx::query("UPDATE records SET kind = 'other' WHERE id = ?")
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = app_query(&db, &declared, alice.clone(), sql).await.unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["record_id"], ALICE_PRIVATE_ID);
        let absent = parse_reads_declaration(&serde_json::json!({
            "relations": {"facet_times": ["start_date"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        let result = app_query(
            &db,
            &absent,
            alice.clone(),
            "SELECT start_date FROM facet_times",
        )
        .await
        .unwrap();
        assert!(result.rows.is_empty());
        assert_eq!(result.columns, vec!["start_date"]);
        let direct = query_sql(&db, alice, "SELECT count(*) AS n FROM facet_times")
            .await
            .unwrap();
        assert_eq!(direct.rows[0]["n"], 2);
    }

    #[tokio::test]
    async fn app_sql_body_block_scopes_follow_owner_and_viewer_for_counts_and_joins() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        let (db, alice, bea) = protected_fixture().await;
        let declaration = |relations: Value, scopes: Value| {
            parse_reads_declaration(&serde_json::json!({
                "relations": relations, "scope": scopes,
            }))
            .unwrap()
        };
        let chunks = declaration(
            serde_json::json!({"body_blocks": ["record_id", "text", "block_index", "chunk_index"]}),
            serde_json::json!([{"type": "Document", "kind": "note"}]),
        );
        let sql = "SELECT record_id, text FROM body_blocks WHERE text LIKE '%sharedterm%' OR 1 = 1 ORDER BY record_id, block_index, chunk_index";
        for (viewer, private) in [(alice.clone(), ALICE_PRIVATE_ID), (bea, BEA_PRIVATE_ID)] {
            let result = app_query(&db, &chunks, viewer.clone(), sql).await.unwrap();
            assert_eq!(result.rows.len(), 2);
            assert_eq!(result.rows[0]["record_id"], private);
            assert_eq!(result.rows[1]["record_id"], COMMON_ID);
            let count = app_query(
                &db,
                &chunks,
                viewer,
                "SELECT count(*) AS n FROM body_blocks",
            )
            .await
            .unwrap();
            assert_eq!(count.rows[0]["n"], 2);
        }
        let joined = declaration(
            serde_json::json!({"records": ["id", "name"], "body_blocks": ["record_id", "text", "block_index", "chunk_index"]}),
            serde_json::json!([{"type": "Document", "kind": "note"}]),
        );
        let result = app_query(
            &db, &joined, alice.clone(),
            "SELECT r.id, b.text FROM records r JOIN body_blocks b ON r.id = b.record_id ORDER BY r.id, b.block_index, b.chunk_index",
        ).await.unwrap();
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0]["id"], ALICE_PRIVATE_ID);
        assert_eq!(result.rows[1]["id"], COMMON_ID);
        // A viewer-visible body outside the requested owner kind cannot
        // travel through the chunk relation, even without records granted.
        sqlx::query("UPDATE records SET kind = 'other' WHERE id = ?")
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = app_query(&db, &chunks, alice.clone(), sql).await.unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["record_id"], ALICE_PRIVATE_ID);
        for scopes in [
            serde_json::json!([{"type": "WorkItem"}]),
            serde_json::json!([{"type": "document"}]),
        ] {
            let absent = declaration(serde_json::json!({"body_blocks": ["text"]}), scopes);
            let result = app_query(&db, &absent, alice.clone(), "SELECT text FROM body_blocks")
                .await
                .unwrap();
            assert!(result.rows.is_empty());
            assert_eq!(result.columns, vec!["text"]);
        }
        let direct = query_sql(
            &db,
            alice,
            "SELECT record_id FROM body_blocks WHERE text LIKE '%sharedterm%' ORDER BY record_id",
        )
        .await
        .unwrap();
        assert_eq!(
            direct.rows.len(),
            2,
            "direct reads keep viewer authority after scopes"
        );
    }

    #[tokio::test]
    async fn app_sql_record_scopes_intersect_viewer_and_mask_parent() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        let (db, alice, bea) = protected_fixture().await;
        let declared = parse_reads_declaration(&json!({
            "relations": {"records": ["body", "home_id", "id", "name"]},
            "scope": [{"type": "Document", "kind": "note"}],
        }))
        .unwrap();
        let sql =
            "SELECT id, name, home_id FROM records WHERE body LIKE '%sharedterm%' ORDER BY id";
        for (viewer, private) in [(alice.clone(), ALICE_PRIVATE_ID), (bea, BEA_PRIVATE_ID)] {
            let result = app_query(&db, &declared, viewer, sql).await.unwrap();
            let ids: Vec<_> = result
                .rows
                .iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect();
            assert_eq!(ids, vec![private, COMMON_ID]);
            assert!(
                result.rows.iter().all(|row| row["home_id"].is_null()),
                "a visible parent outside scope is still masked"
            );
        }
        // A parent inside the scope can travel; narrowing its kind masks it
        // even though Alice still has viewer authority over that parent.
        sqlx::query("UPDATE records SET home_id = ?1 WHERE id = ?2")
            .bind(COMMON_ID)
            .bind(ALICE_PRIVATE_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = app_query(&db, &declared, alice.clone(), sql).await.unwrap();
        assert_eq!(result.rows[0]["home_id"], COMMON_ID);
        sqlx::query("UPDATE records SET kind = 'other' WHERE id = ?")
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let result = app_query(&db, &declared, alice, sql).await.unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["id"], ALICE_PRIVATE_ID);
        assert!(result.rows[0]["home_id"].is_null());
    }

    #[tokio::test]
    async fn app_sql_record_scopes_do_not_persist_in_caller_transaction() {
        use crate::mcp::tools::alpha_tabs::{execute_app_sql_in, parse_reads_declaration};
        let (db, alice, _) = protected_fixture().await;
        let scoped = parse_reads_declaration(&json!({
            "relations": {"records": ["id", "body"]},
            "scope": [{"type": "Absent"}],
        }))
        .unwrap();
        let broad = app_declared_records();
        let mut tx = db.write_pool().begin().await.unwrap();
        let request = || QuerySqlRequest {
            sql: "SELECT count(*) AS n FROM records WHERE body LIKE '%sharedterm%'".into(),
            parameters: vec![],
        };
        for (declaration, expected) in [(&scoped, 0), (&broad, 2), (&scoped, 0)] {
            let result = execute_app_sql_in(&mut tx, declaration, alice.clone(), request())
                .await
                .unwrap();
            assert_eq!(result.rows[0]["n"], expected);
            let remaining: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name = 'records'",
            ).fetch_one(&mut *tx).await.unwrap();
            assert_eq!(remaining, 0, "each read removes the scoped TEMP projection");
        }
        let direct = query_sql_request_in(&mut tx, alice, request())
            .await
            .unwrap();
        assert_eq!(
            direct.rows[0]["n"], 2,
            "direct SQL retains viewer authority"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn app_sql_rejects_undeclared_reads_before_execution() {
        let (db, alice, _) = protected_fixture().await;
        let declared = app_declared_records();
        for (sql, code) in [
            ("SELECT id FROM messages", "unsupported_sql"),
            ("SELECT source_id FROM links", "undeclared_relation"),
            ("SELECT count(*) FROM links", "undeclared_relation"),
            ("SELECT id, lifecycle FROM records", "undeclared_column"),
            (
                "WITH v AS (SELECT id FROM records) SELECT id FROM v",
                "unsupported_sql",
            ),
        ] {
            let error = app_query(&db, &declared, alice.clone(), sql)
                .await
                .expect_err("refused");
            let rendered = error.to_string();
            assert!(
                rendered.contains(&format!("app_sql [{code}]")),
                "{rendered}"
            );
            assert!(!rendered.contains(sql), "no SQL text leaks: {rendered}");
        }
    }

    #[tokio::test]
    async fn app_sql_refusals_do_not_change_direct_query_sql() {
        let (db, alice, _) = protected_fixture().await;
        // The ad-hoc entry keeps its own contract: CTEs run here while the
        // app seam refuses them, and unordered LIMIT still executes disclosed.
        let cte = query_sql(
            &db,
            alice.clone(),
            "WITH v AS (SELECT id FROM records) SELECT id FROM v LIMIT 1",
        )
        .await
        .unwrap();
        assert_eq!(cte.row_count, 1);
        let limited = query_sql(&db, alice, "SELECT id FROM records LIMIT 1")
            .await
            .unwrap();
        assert_eq!(limited.row_count, 1);
    }

    #[tokio::test]
    async fn app_sql_applies_explicit_row_cap_and_portable_rules() {
        let db = crate::create_database(":memory:").await.unwrap();
        let root = crate::schema::ROOT_RECORD_ID;
        // 250 member-visible rows: past the 200-row app cap, no explicit
        // policy needed (visible through ROOT like the lifecycle bulk rows).
        sqlx::query(
            "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)),
                  numbers(n) AS (
                    SELECT a.d + 10*b.d + 100*c.d FROM digits a, digits b, digits c
                    WHERE c.d < 3
                  )
             INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id)
             SELECT printf('appcap-%03d',n), 'Document', 'note', printf('bulk %03d',n), ?1, ?1
             FROM numbers WHERE n < 250",
        )
        .bind(root)
        .execute(db.write_pool())
        .await
        .unwrap();
        let declared = app_declared_records();
        let viewer = QueryPrincipal::authenticated("alice", true);
        let capped = app_query(
            &db,
            &declared,
            viewer.clone(),
            "SELECT id FROM records ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(capped.rows.len(), 200);
        assert_eq!(capped.row_count, 200);
        assert!(capped.truncated);
        // WHERE/binds flow through the portable executor unchanged.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        let bound = crate::mcp::tools::alpha_tabs::execute_app_sql_in(
            &mut transaction,
            &declared,
            viewer.clone(),
            QuerySqlRequest {
                sql: "SELECT id, name FROM records WHERE name = ?1 ORDER BY id".to_string(),
                parameters: vec![crate::query::sql_contract::QuerySqlParameter::Text {
                    value: Some("bulk 007".to_string()),
                }],
            },
        )
        .await
        .unwrap();
        transaction.rollback().await.unwrap();
        assert_eq!(bound.rows.len(), 1);
        assert_eq!(bound.rows[0]["name"], "bulk 007");
        // Portable rules still apply past admission: unordered LIMIT refuses.
        let error = app_query(&db, &declared, viewer, "SELECT id FROM records LIMIT 5")
            .await
            .expect_err("portable LIMIT rule");
        assert_eq!(
            error.to_string(),
            "app_sql [unsafe_statement]: app read violates portable SQL rules"
        );
    }

    #[tokio::test]
    async fn workspace_filter_matches_governed_relations_and_exclusions() {
        let (db, alice, bea) = protected_fixture().await;
        let attribution = "9e795000-0000-4000-8000-000015000000";
        let unit = "9e795000-0000-4000-8000-000016000000";
        let unit_child = "9e795000-0000-4000-8000-000017000000";
        for (id, record_type, kind) in [
            (attribution, "Annotation", "attribution"),
            (unit, "Entity", "semantic-unit"),
            (unit_child, "Document", "attachment"),
        ] {
            // These are projection fixtures. The public record writer
            // correctly reserves attribution and semantic-unit creation for
            // their atomic aggregate APIs.
            sqlx::query(
                "INSERT INTO records(id, type, kind, name, home_id, policy_anchor_id) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(record_type)
            .bind(kind)
            .bind(kind)
            .bind(crate::schema::ROOT_RECORD_ID)
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        for (id, source, target) in [
            ("attribution-bearer", attribution, COMMON_ID),
            ("unit-child", unit_child, unit),
        ] {
            sqlx::query(
                "INSERT INTO links(id, source_id, target_id, relationship) \
                 VALUES (?, ?, ?, 'part_of')",
            )
            .bind(id)
            .bind(source)
            .bind(target)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, \
             causal_envelope_version, causal_status) \
             VALUES ('9e795000-0000-4000-8000-000019000000', ?, \
             'record.created', '{}', 'test:projection', 1, 'complete')",
        )
        .bind(unit)
        .execute(db.write_pool())
        .await
        .unwrap();
        let receipt_event_id = "9e795000-0000-4000-8000-000019000001";
        sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, \
             causal_envelope_version, causal_status) \
             VALUES (?, ?, 'receipt.committed.v1', '{}', 'test:projection', 1, 'complete')",
        )
        .bind(receipt_event_id)
        .bind(COMMON_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        let (creation_event_id, creation_seq): (String, i64) = sqlx::query_as(
            "SELECT id, seq FROM content_events WHERE record_id = ? ORDER BY seq LIMIT 1",
        )
        .bind(unit)
        .fetch_one(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semantic_units(unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at) \
             VALUES (?, ?, ?, ?, '2026-09-23T00:00:00.000Z')"
        ).bind(unit).bind(COMMON_ID).bind(creation_event_id).bind(creation_seq)
            .execute(db.write_pool()).await.unwrap();

        // SAFETY: this test models the hosted ingress setting activity_read
        // for an authenticated member. Record visibility must remain governed
        // by the same view regardless of that capability.
        let alice_activity =
            unsafe { QueryPrincipal::activity_reader_unchecked("alice", Vec::new(), true) };
        for principal in [alice, bea, alice_activity] {
            let filtered = db
                .filtered_workspace_index(principal.clone())
                .await
                .unwrap()
                .unwrap();
            let governed = |sql: &'static str, principal: QueryPrincipal| async {
                let result = query_sql(&db, principal, sql).await.unwrap();
                first_strings(&result).into_iter().collect::<HashSet<_>>()
            };
            let expected_records = governed("SELECT id FROM records", principal.clone()).await;
            let expected_facets = governed("SELECT id FROM facet_values", principal.clone()).await;
            let expected_links = governed("SELECT id FROM links", principal.clone()).await;
            let expected_events = query_sql(
                &db,
                principal.clone(),
                "SELECT id, type FROM content_events",
            )
            .await
            .unwrap()
            .rows
            .into_iter()
            .map(|row| {
                let row = row.as_object().unwrap();
                (
                    row["id"].as_str().unwrap().to_string(),
                    row["type"].as_str().unwrap().to_string(),
                )
            })
            .collect::<HashSet<_>>();
            assert_eq!(
                filtered.records.keys().cloned().collect::<HashSet<_>>(),
                expected_records
            );
            assert_eq!(
                filtered.facets.keys().cloned().collect::<HashSet<_>>(),
                expected_facets
            );
            assert_eq!(
                filtered.links.keys().cloned().collect::<HashSet<_>>(),
                expected_links
            );
            assert_eq!(
                filtered
                    .content_events
                    .iter()
                    .map(|e| (e.id.clone(), e.event_type.clone()))
                    .collect::<HashSet<_>>(),
                expected_events
            );
            assert!(expected_events
                .contains(&(receipt_event_id.to_string(), "record.updated".to_string())));
            assert!(!filtered.records.contains_key(attribution));
            assert!(!filtered.records.contains_key(unit));
            assert!(!filtered.records.contains_key(unit_child));
            assert!(!filtered.links.contains_key("attribution-bearer"));
            assert!(!filtered.links.contains_key("unit-child"));
            let epoch: i64 =
                sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(filtered.authorization_epoch, epoch);
            let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(filtered.content_seq, seq);
        }
    }

    /// Tier 1.4: the (epoch, unit fence) key. A derived artifact attached to
    /// an un-unitized `Entity`/`semantic-unit` envelope is visible; the later
    /// unit.created projection flips it hidden with the authorization epoch
    /// unmoved — the stale risk a pure-epoch key would serve. Every
    /// transition below runs through supported write seams (each `append` is
    /// one write transaction), so the interleaving is reachable, not
    /// constructed. The oracle is governed `query_sql` itself, compared per
    /// principal at every phase, plus a narrowing epoch bump and the
    /// activity-reader shape.
    ///
    /// Seam distinction this relies on: the MCP-facing `create_record`
    /// writer reserves kind `semantic-unit`, but the public lower-level
    /// event seam (`store::append`) admits both the envelope record.created
    /// and unit.created.v1 — only attribution, claims, receipts, and
    /// type-corrections are rejected there (`reject_public_runtime_event`,
    /// `reject_public_governed_attribution_in`).
    #[tokio::test]
    async fn visible_set_cache_invalidates_on_unit_fence_without_epoch_move() {
        let (db, alice, bea) = protected_fixture().await;
        let envelope = "9e796100-0000-4000-8000-000001000000";
        let derived = "9e796100-0000-4000-8000-000002000000";
        // SAFETY: this test models the hosted ingress setting activity_read
        // for an authenticated member. Record visibility must remain governed
        // by the same view regardless of that capability.
        let alice_activity =
            unsafe { QueryPrincipal::activity_reader_unchecked("alice", Vec::new(), true) };
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Entity",
                    "kind": "semantic-unit",
                    "name": "tier14-envelope",
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": derived,
                "type": "Document",
                "kind": "attachment",
                "name": "tier14-derived",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        // Anchor the derived where both principals may see it, whatever the
        // creation planner assigned.
        let derived_anchor: String =
            sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id = ?")
                .bind(derived)
                .fetch_one(db.pool())
                .await
                .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &derived_anchor,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("tier14-child".to_string()),
                source_id: derived.to_string(),
                target_id: envelope.to_string(),
                relationship: "part_of".to_string(),
                note: None,
            },
        )
        .await
        .unwrap();
        let governed = |principal: QueryPrincipal| async {
            first_strings(
                &query_sql(&db, principal, "SELECT id FROM records")
                    .await
                    .unwrap(),
            )
            .into_iter()
            .collect::<HashSet<_>>()
        };
        let epoch_of = || async {
            sqlx::query_scalar::<_, i64>("SELECT epoch FROM authorization_revision WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .unwrap()
        };
        // Phase 1: envelope un-unitized, derived visible to both principals.
        let epoch_before = epoch_of().await;
        let first_timing = crate::mcp::request_timing::RequestTiming::new();
        first_timing.enable_visible_set_lookups();
        let first = first_timing
            .scope(workspace_visible_set(&db, alice.clone()))
            .await
            .unwrap();
        assert_eq!(
            first_timing.visible_set_lookups(),
            Some(crate::mcp::request_timing::VisibleSetLookups { hits: 0, misses: 1 })
        );
        assert!(first.ids.contains(derived));
        assert!(!first.ids.contains(envelope));
        assert_eq!(*first.ids, governed(alice.clone()).await);
        // Slice 1 (task 77bd40a): governed `query_sql` stages `records`
        // through `workspace_visible_set`, so each governed call below
        // records a hit against the entry the direct call just cached.
        assert_eq!(db.visible_set_cache_stats(), (1, 1));
        let second_timing = crate::mcp::request_timing::RequestTiming::new();
        second_timing.enable_visible_set_lookups();
        let second = second_timing
            .scope(workspace_visible_set(&db, alice.clone()))
            .await
            .unwrap();
        assert_eq!(
            second_timing.visible_set_lookups(),
            Some(crate::mcp::request_timing::VisibleSetLookups { hits: 1, misses: 0 })
        );
        assert_eq!(second.ids, first.ids);
        assert_eq!(db.visible_set_cache_stats(), (2, 1));
        // Second principal and activity reader hold their own entries; the
        // reader's set equals the member's (activity_read gates only the
        // activity views, never the visible set).
        let bea_first = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(bea_first.ids.contains(derived));
        assert_eq!(*bea_first.ids, governed(bea.clone()).await);
        let activity_first = workspace_visible_set(&db, alice_activity.clone())
            .await
            .unwrap();
        assert_eq!(activity_first.ids, first.ids);
        assert_eq!(db.visible_set_cache_stats(), (3, 3));
        // Phase 2: unitize the envelope through the same public seam — its
        // own write transaction, after the link committed. The live set
        // changes; the epoch must not.
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version": "native.freshness-kernel.v1",
                    "authority_bearer_record_id": COMMON_ID,
                    "label": "tier14-unit",
                }),
                actor: Some("test:unit".to_string()),
            },
        )
        .await
        .unwrap();
        assert_eq!(epoch_of().await, epoch_before);
        let unit_max: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(creation_event_seq), 0) FROM semantic_units")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(unit_max > 0);
        // The moved fence is a miss, and the fresh answer hides the derived.
        let third = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert!(!third.ids.contains(derived));
        assert_eq!(*third.ids, governed(alice.clone()).await);
        assert_eq!(db.visible_set_cache_stats(), (4, 4));
        let fourth = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert_eq!(fourth.ids, third.ids);
        assert_eq!(db.visible_set_cache_stats(), (5, 4));
        let bea_second = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(!bea_second.ids.contains(derived));
        assert_eq!(*bea_second.ids, governed(bea.clone()).await);
        // Phase 3: narrowing epoch bump revokes bea without leaking.
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let narrowed_bea = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(!narrowed_bea.ids.contains(COMMON_ID));
        assert!(!narrowed_bea.ids.contains(derived));
        assert_eq!(*narrowed_bea.ids, governed(bea.clone()).await);
        let narrowed_alice = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert!(narrowed_alice.ids.contains(COMMON_ID));
        assert_eq!(*narrowed_alice.ids, governed(alice.clone()).await);
        db.close().await;
    }

    /// Tier 1.4 fixture-C measurement and agreement proof. Opens a caller
    /// supplied COPY (never the source) via `GSQL_TIER14_COPY`; returns
    /// immediately when unset so CI without the fixture stays green. Asserts
    /// the cached set equals governed `query_sql` on live-shaped data and
    /// prints miss/hit timings plus the cached byte size (`--nocapture`).
    /// Timings are reported, never asserted — the host is shared and noisy.
    #[tokio::test]
    async fn visible_set_cache_fixture_c_agreement_and_timing() {
        let copy = match std::env::var("GSQL_TIER14_COPY") {
            Ok(path) => path,
            Err(_) => {
                eprintln!("skipping fixture-C measurement: GSQL_TIER14_COPY unset");
                return;
            }
        };
        // Non-migrating open: the export predates the current engine schema
        // and the lens needs only long-stable projection tables. The copy is
        // expendable; the source must never be opened in place.
        let db = crate::open_database_at(std::path::Path::new(&copy))
            .await
            .unwrap();
        let principal =
            QueryPrincipal::authenticated("acct_404434c8f87443c88b162247bb53bbc8", true);
        let timed = |label: &str, millis: f64| {
            eprintln!("tier14 fixture-C {label}: {millis:.2}ms");
        };
        let start = std::time::Instant::now();
        let miss = workspace_visible_set(&db, principal.clone()).await.unwrap();
        timed(
            "miss (full evaluation)",
            start.elapsed().as_secs_f64() * 1000.0,
        );
        // Paged oracle: one governed statement serves at most MAX_ROWS
        // (1,000) rows while fixture C holds ~4.6k visible records. Keyset
        // pagination (`WHERE id > last`) terminates on the empty page, so a
        // short page — whatever caps it — can never end the walk early.
        // Page shape, not semantics.
        let mut governed = HashSet::new();
        let mut last = String::new();
        loop {
            let page = first_strings(
                &query_sql(
                    &db,
                    principal.clone(),
                    &format!(
                        "SELECT id FROM records WHERE id > '{last}' \
                         ORDER BY id LIMIT {}",
                        sql_contract::MAX_ROWS,
                    ),
                )
                .await
                .unwrap(),
            );
            if page.is_empty() {
                break;
            }
            last = page.iter().max().unwrap().clone();
            governed.extend(page);
        }
        // Bounded diff reporter: fixture-C sets are thousands of ids, so a
        // bare assert_eq would dump megabytes. Report counts plus samples.
        fn assert_same_set(context: &str, left: &HashSet<String>, right: &HashSet<String>) {
            if left != right {
                let mut only_left: Vec<&str> = left.difference(right).map(String::as_str).collect();
                let mut only_right: Vec<&str> =
                    right.difference(left).map(String::as_str).collect();
                only_left.sort_unstable();
                only_right.sort_unstable();
                panic!(
                    "{context}: left={} right={} only_left={:?} only_right={:?}",
                    left.len(),
                    right.len(),
                    &only_left[..only_left.len().min(10)],
                    &only_right[..only_right.len().min(10)],
                );
            }
        }
        assert_same_set("fixture-C miss vs governed", &miss.ids, &governed);
        eprintln!(
            "tier14 fixture-C cached ids: {} bytes over {} records",
            miss.ids.iter().map(|id| id.len()).sum::<usize>(),
            miss.ids.len()
        );
        let mut hits = Vec::new();
        for _ in 0..5 {
            let start = std::time::Instant::now();
            let hit = workspace_visible_set(&db, principal.clone()).await.unwrap();
            hits.push(start.elapsed().as_secs_f64() * 1000.0);
            assert_same_set("fixture-C hit vs governed", &hit.ids, &governed);
        }
        hits.sort_by(|a, b| a.partial_cmp(b).unwrap());
        timed("hit min", hits[0]);
        timed("hit median", hits[hits.len() / 2]);
        assert_eq!(db.visible_set_cache_stats(), (5, 1));
        db.close().await;
    }

    #[tokio::test]
    async fn workspace_filter_rebuilds_after_epoch_narrows_visibility() {
        let (db, alice, _) = protected_fixture().await;
        let before = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(before.records.contains_key(COMMON_ID));
        let old_epoch = before.authorization_epoch;
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let after = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(after.authorization_epoch > old_epoch);
        assert!(!after.records.contains_key(COMMON_ID));
        assert!(!after.links.contains_key("alice-common"));
        let governed = query_sql(&db, alice, "SELECT id FROM records")
            .await
            .unwrap();
        assert_eq!(
            after.records.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed).into_iter().collect::<HashSet<_>>()
        );
    }

    #[tokio::test]
    async fn workspace_filter_repairs_subtree_anchor_and_relationship_only_changes() {
        let (db, alice, _) = protected_fixture().await;
        let child = "9e795000-0000-4000-8000-000020000000";
        let grandchild = "9e795000-0000-4000-8000-000021000000";
        create_record(
            &db,
            json!({
                "id": child, "type": "Collection", "kind": "folder", "name": "branch",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": grandchild, "type": "Document", "kind": "note", "name": "descendant",
                "home_id": child
            }),
        )
        .await
        .unwrap();
        let before = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(before.records.contains_key(grandchild));

        // The policy replacement changes a subtree of projected anchors, but
        // its content event names only the child, leaving the held grandchild
        // stale until a full rebuild.
        replace_explicit_policy(
            &db,
            "test:policy",
            child,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let narrowed = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(narrowed.authorization_epoch > before.authorization_epoch);
        assert!(!narrowed.records.contains_key(child));
        assert!(!narrowed.records.contains_key(grandchild));
        let relationship_before: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM relationship_events")
                .fetch_one(db.pool())
                .await
                .unwrap();

        // The index is now settled at the new policy epoch. The next write
        // changes only the relationship stream; no policy or record write
        // follows before the second snapshot.
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let asserted = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "manage_relationships",
                json!({
                    "action":"assert", "relationship_type":"relates_to",
                    "endpoints":[
                        {"role":"participant", "record_id":ALICE_PRIVATE_ID},
                        {"role":"participant", "record_id":COMMON_ID}
                    ],
                    "idempotency_key":"workspace-index-fence"
                }),
            )
            .await
            .unwrap();
        let link_id = format!(
            "rel:{}:{}",
            asserted["relationship_origin_db_id"].as_str().unwrap(),
            asserted["relationship_id"].as_str().unwrap()
        );

        let after = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.authorization_epoch, narrowed.authorization_epoch);
        assert_eq!(after.content_seq, narrowed.content_seq);
        assert!(!after.records.contains_key(child));
        assert!(!after.records.contains_key(grandchild));
        assert!(after.links.contains_key(&link_id));
        let relationship_after: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM relationship_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(relationship_after > relationship_before);
        let governed_records = query_sql(&db, alice.clone(), "SELECT id FROM records")
            .await
            .unwrap();
        let governed_links = query_sql(&db, alice, "SELECT id FROM links").await.unwrap();
        assert_eq!(
            after.records.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed_records)
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert_eq!(
            after.links.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed_links)
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[tokio::test]
    async fn workspace_filter_signals_governed_fallback_above_cap() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "9e795000-0000-4000-8000-000018000000";
        create_record(
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": "large",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let large_summary = "x".repeat(25 * 1024 * 1024);
        sqlx::query("UPDATE records SET summary = ? WHERE id = ?")
            .bind(large_summary)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        let built = crate::workspace_index::build_on(db.pool()).await.unwrap();
        assert!(!built.within_cap(crate::workspace_index::MAX_INDEX_BYTES));
        let alice = QueryPrincipal::authenticated("alice", true);
        assert!(db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .is_none());
        assert!(!db.workspace_index_built_for_tests().await);
        let governed = query_sql(
            &db,
            alice,
            &format!("SELECT id FROM records WHERE id = '{id}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&governed), [id]);
    }

    #[tokio::test]
    async fn bearer_depth_boundary_agrees_across_rust_fts_and_restricted_sql() {
        let db = crate::create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": DEPTH_TERMINAL_ID,
                "type": "WorkItem",
                "kind": "task",
                "name": "Depth terminal"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            DEPTH_TERMINAL_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();

        let mut bearer = DEPTH_TERMINAL_ID.to_string();
        let mut boundary = String::new();
        let mut over_limit = String::new();
        for depth in 1..=MAX_DERIVED_BEARER_DEPTH + 1 {
            let id = format!("9e795000-0000-4000-8000-0000090{depth:05}");
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("Depth artifact {depth}"),
                    "body": "depthlimitterm"
                }),
            )
            .await
            .unwrap();
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(format!("depth-part-{depth:03}")),
                    source_id: id.clone(),
                    target_id: bearer,
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
            bearer = id.clone();
            if depth == MAX_DERIVED_BEARER_DEPTH {
                boundary = id;
            } else if depth == MAX_DERIVED_BEARER_DEPTH + 1 {
                over_limit = id;
            }
        }

        let principal = Principal::bound("alice", true);
        assert_eq!(
            effective_capability(&db, principal, &boundary)
                .await
                .unwrap(),
            Capability::View
        );
        assert!(effective_capability(&db, principal, &over_limit)
            .await
            .is_err());

        let hits = crate::query::fts::search(
            &db,
            "alice",
            true,
            "depthlimitterm",
            &crate::query::fts::FtsOptions {
                limit: Some(200),
                ..crate::query::fts::FtsOptions::default()
            },
        )
        .await
        .unwrap();
        let hit_ids: std::collections::HashSet<&str> =
            hits.iter().map(|hit| hit.id.as_str()).collect();
        assert!(hit_ids.contains(boundary.as_str()));
        assert!(!hit_ids.contains(over_limit.as_str()));

        let caller = QueryPrincipal::authenticated("alice", true);
        let sql = format!(
            "SELECT id FROM records WHERE id IN ('{boundary}', '{over_limit}') ORDER BY id"
        );
        let rows = query_sql(&db, &caller, &sql).await.unwrap();
        assert_eq!(first_strings(&rows), [boundary]);

        // Complexity guard. This fixture is the shape that used to sit on the
        // QUERY_DEADLINE_MS edge: a MAX_DERIVED_BEARER_DEPTH-long derived
        // chain, projected through `records`, which formerly referenced the
        // visibility relation twice (the row and the home_id parent probe).
        // The bearer-first walk makes that cost proportional to the live
        // record count instead of to chain depth.
        //
        // Deliberately NOT a wall-clock threshold. `query_sql` already
        // enforces QUERY_DEADLINE internally, so a return to depth-quadratic
        // cost fails this call on its own; a second, tighter time bound would
        // only fire for regressions the deadline already catches, while adding
        // exactly the host-speed-decides-the-outcome flake this task exists to
        // remove. If this projection starts failing, the walk's complexity
        // changed — it is not "the usual timeout".
        let projected = query_sql(&db, &caller, "SELECT id, home_id FROM records ORDER BY id")
            .await
            .unwrap();
        assert!(!projected.rows.is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_local_bypasses_grants_but_not_live_shape_or_explicit_anchor_checks() {
        let (db, _alice, _bea) = protected_fixture().await;
        sqlx::query(&format!(
            "UPDATE records SET name = 'localbypassterm valid' WHERE id = '{ATTACHMENT_ALICE_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();

        for id in [LOCAL_MALFORMED_ID, LOCAL_TOMBSTONE_ID] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("localbypassterm {id}")
                }),
            )
            .await
            .unwrap();
        }
        for (id, source, target) in [
            ("local-malformed-a", LOCAL_MALFORMED_ID, ALICE_PRIVATE_ID),
            ("local-malformed-b", LOCAL_MALFORMED_ID, BEA_PRIVATE_ID),
            ("local-tombstone-part", LOCAL_TOMBSTONE_ID, BEA_PRIVATE_ID),
        ] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.into()),
                    source_id: source.into(),
                    target_id: target.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        delete_record(&db, LOCAL_TOMBSTONE_ID).await.unwrap();

        create_record(
            &db,
            json!({
                "id": LOCAL_MALFORMED_ANCHOR_ID,
                "type": "Document",
                "kind": "note",
                "name": "localbypassterm malformed anchor",
                "owner_id": ALICE_PRIVATE_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            LOCAL_MALFORMED_ANCHOR_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "DELETE FROM record_policies WHERE record_id = '{LOCAL_MALFORMED_ANCHOR_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();

        // Pin governed work to one available slot so restricted SQL must reuse
        // the same physical connection; the following ordinary FTS query runs
        // on the write pool, which never sees governed TEMP state at all.
        // This guards against leaked TEMP views shadowing main relations.
        let held_connections = hold_all_but_one_governed_slot(&db).await;
        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let authenticated = QueryPrincipal::authenticated("local", true);
        let statement = &format!(
            "SELECT id FROM records WHERE id IN (
                '{ATTACHMENT_ALICE_ID}', '{LOCAL_MALFORMED_ID}',
                '{LOCAL_TOMBSTONE_ID}', '{LOCAL_MALFORMED_ANCHOR_ID}'
            ) ORDER BY id"
        );
        assert_eq!(
            first_strings(&query_sql(&db, &trusted, statement).await.unwrap()),
            [ATTACHMENT_ALICE_ID]
        );
        assert!(query_sql(&db, &authenticated, statement)
            .await
            .unwrap()
            .rows
            .is_empty());

        let opts = crate::query::fts::FtsOptions {
            limit: Some(20),
            ..crate::query::fts::FtsOptions::default()
        };
        let trusted_hits = crate::query::fts::search_with_policy_bypass(
            &db,
            trusted.credential(),
            true,
            true,
            "localbypassterm",
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(
            trusted_hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            [ATTACHMENT_ALICE_ID]
        );
        assert!(
            crate::query::fts::search(&db, "local", true, "localbypassterm", &opts)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(effective_capability(
            &db,
            Principal::bound("alice", true),
            LOCAL_MALFORMED_ANCHOR_ID
        )
        .await
        .is_err());
        drop(held_connections);
        db.close().await;
    }

    /// Frozen pre-per-anchor fold, renamed so it can sit beside the shipping
    /// TEMP contract in one snapshot. This text is the oracle for the Tier 1.5
    /// fold change: it is the exact `_query_sql_visible_records` view logic
    /// the per-anchor rewrite replaces, with only the temp object names
    /// changed (`_query_sql_visible_records` -> `_qs_legacy_visible_records`,
    /// `records`/`links` -> `_qs_legacy_records`/`_qs_legacy_links`). Any
    /// change that alters membership fails the comparison below. Do not update
    /// this text when the shipping view changes; that disagreement is the
    /// signal.
    const LEGACY_FOLD_CONTRACT: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_visible_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._query_sql_authorization_subjects AS resolved
  ON resolved.record_id = r.id
JOIN main.records AS authorization_subject
  ON authorization_subject.id = resolved.subject_id
CROSS JOIN temp._query_sql_principal AS principal
WHERE r.deleted_at IS NULL
  AND NOT (r.type = 'Annotation' AND r.kind IN ('attribution','acknowledgement'))
  AND NOT (r.type = 'Entity' AND r.kind IS 'semantic-unit')
  AND NOT EXISTS (
        SELECT 1 FROM main.semantic_units AS semantic_subject
        WHERE semantic_subject.unit_id = authorization_subject.id
      )
  AND EXISTS (
       SELECT 1 FROM main.record_policies AS explicit_policy
       WHERE explicit_policy.record_id = authorization_subject.policy_anchor_id
     )
  AND (principal.trusted_local_bypass = 1 OR (EXISTS (
        SELECT 1 FROM main.bindings AS owner_account
        WHERE owner_account.record_id = authorization_subject.owner_id
          AND owner_account.system = 'account'
          AND owner_account.identifier = principal.account_id
          AND owner_account.is_canonical = 1
      )
   OR EXISTS (
        SELECT 1 FROM main.policy_entries AS entry
        WHERE entry.policy_anchor_id = authorization_subject.policy_anchor_id
          AND entry.effect = 'allow'
          AND entry.capability IN ('view', 'edit', 'manage')
          AND (
            (entry.subject_kind = 'members'
             AND entry.subject_id = 'native:members'
             AND principal.is_member = 1)
            OR
            (entry.subject_kind = 'account'
             AND entry.subject_id = principal.account_id)
          )
      )));

CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._qs_legacy_visible_records AS visible ON visible.id = r.id
LEFT JOIN temp._qs_legacy_visible_records AS parent_visible
       ON parent_visible.id = r.home_id;

CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_links AS
SELECT l.id
FROM main.links AS l
JOIN temp._qs_legacy_visible_records AS source_visible
  ON source_visible.id = l.source_id
JOIN temp._qs_legacy_visible_records AS target_visible
  ON target_visible.id = l.target_id;
"#;

    /// The visibility fold does not change with the per-anchor rewrite. For
    /// every caller shape — per-account, trusted-local bypass, and a stranger
    /// with no grants — the shipping view must hold exactly the row set the
    /// frozen fold computes, and the governed `records`/`links` projections
    /// must agree end to end. The added anchors cover the shapes the shared
    /// fixture lacks: members grants, edit/manage capabilities, an empty
    /// explicit policy, and an inherited (non-explicit) anchor.
    #[tokio::test]
    async fn per_anchor_fold_matches_the_legacy_fold_model() {
        const MEMBERS_ID: &str = "9e796000-0000-4000-8000-000001000000";
        const EDIT_ID: &str = "9e796000-0000-4000-8000-000002000000";
        const MANAGE_ID: &str = "9e796000-0000-4000-8000-000003000000";
        const EMPTY_ID: &str = "9e796000-0000-4000-8000-000004000000";
        const PARENT_ID: &str = "9e796000-0000-4000-8000-000005000000";
        const CHILD_ID: &str = "9e796000-0000-4000-8000-000006000000";

        let (db, alice, bea) = protected_fixture().await;
        for (id, record_type, kind, name) in [
            (MEMBERS_ID, "Document", "note", "Oracle members"),
            (EDIT_ID, "Document", "note", "Oracle edit"),
            (MANAGE_ID, "Document", "note", "Oracle manage"),
            (EMPTY_ID, "Document", "note", "Oracle empty"),
            (PARENT_ID, "Collection", "folder", "Oracle parent"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": record_type,
                    "kind": kind,
                    "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": CHILD_ID,
                "type": "Document",
                "kind": "note",
                "name": "Oracle child",
                "home_id": PARENT_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            MEMBERS_ID,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            EDIT_ID,
            vec![AllowEntry::account("bea", Capability::Edit)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            MANAGE_ID,
            vec![AllowEntry::account("alice", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:policy", EMPTY_ID, Vec::new())
            .await
            .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            PARENT_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();

        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        // A guest footing: the members arm is dead for this caller, so the
        // members-grant anchor below must stay invisible to it under both
        // formulations.
        let stranger = QueryPrincipal::authenticated("nobody", false);
        for (label, principal) in [
            ("alice", alice.clone()),
            ("bea", bea.clone()),
            ("trusted", trusted.clone()),
            ("stranger", stranger.clone()),
        ] {
            let mut connection = db.write_pool().acquire().await.unwrap();
            for statement in temp_contract()
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            for statement in LEGACY_FOLD_CONTRACT
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            let mut transaction = connection.begin().await.unwrap();
            let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
                .fetch_optional(&mut *transaction)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
                 VALUES (1, ?, ?, ?, ?, '2026-09-17T00:00:00.000Z')",
            )
            .bind(principal.credential().to_string())
            .bind(principal.trusted_local_bypass())
            .bind(principal.activity_read())
            .bind(principal.is_member())
            .execute(&mut *transaction)
            .await
            .unwrap();
            // Slice 1 (task 77bd40a): shipping `records` joins the staged
            // visible-id table, so stage it exactly as production does
            // before comparing projections. Membership logic itself is
            // still guarded by the live-view comparison below.
            sqlx::query(
                "INSERT OR IGNORE INTO temp._query_sql_visible_ids(id) \
                 SELECT id FROM temp._query_sql_visible_records",
            )
            .execute(&mut *transaction)
            .await
            .unwrap();
            async fn visible_sorted(
                transaction: &mut sqlx::Transaction<'_, Sqlite>,
                relation: &str,
            ) -> Vec<String> {
                sqlx::query_scalar(&format!("SELECT id FROM temp.{relation} ORDER BY id"))
                    .fetch_all(&mut **transaction)
                    .await
                    .unwrap()
            }
            let shipping: Vec<String> =
                visible_sorted(&mut transaction, "_query_sql_visible_records").await;
            let legacy: Vec<String> =
                visible_sorted(&mut transaction, "_qs_legacy_visible_records").await;
            assert_eq!(
                shipping,
                legacy,
                "visible set differs for {label}: shipping {} rows, legacy {} rows",
                shipping.len(),
                legacy.len()
            );
            assert_eq!(
                visible_sorted(&mut transaction, "records").await,
                visible_sorted(&mut transaction, "_qs_legacy_records").await,
                "records projection differs for {label}"
            );
            assert_eq!(
                visible_sorted(&mut transaction, "links").await,
                visible_sorted(&mut transaction, "_qs_legacy_links").await,
                "links projection differs for {label}"
            );
            // Spot-check the added shapes on the shipping view, so a future
            // fixture change that silently drops them fails loudly.
            let has = |id: &str| shipping.iter().any(|seen| seen == id);
            match label {
                "alice" => {
                    assert!(has(MEMBERS_ID) && has(MANAGE_ID));
                    assert!(has(PARENT_ID) && has(CHILD_ID));
                    assert!(!has(EDIT_ID) && !has(EMPTY_ID));
                }
                "bea" => {
                    assert!(has(MEMBERS_ID) && has(EDIT_ID));
                    assert!(!has(MANAGE_ID) && !has(EMPTY_ID));
                    assert!(!has(CHILD_ID));
                }
                "stranger" => {
                    // Guest footing: no account grants, no owner bindings,
                    // and the members arm requires is_member = 1. Empty under
                    // both formulations.
                    assert!(
                        shipping.is_empty(),
                        "guest stranger sees {} rows: {shipping:?}",
                        shipping.len()
                    );
                }
                "trusted" => {
                    for id in [MEMBERS_ID, EDIT_ID, MANAGE_ID, PARENT_ID, CHILD_ID] {
                        assert!(has(id), "trusted misses {id}");
                    }
                }
                _ => unreachable!(),
            }
            transaction.rollback().await.unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn production_relations_filter_rows_counts_and_tombstoned_bearers() {
        let (db, alice, bea) = protected_fixture().await;
        let alice_rows = query_sql(
            &db,
            &alice,
            "SELECT id FROM records WHERE kind = 'note' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&alice_rows), [ALICE_PRIVATE_ID, COMMON_ID]);
        let bea_rows = query_sql(
            &db,
            &bea,
            "SELECT id FROM records WHERE kind = 'note' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_rows), [BEA_PRIVATE_ID, COMMON_ID]);
        let kindless_document = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id = '{KINDLESS_BEARER_ALICE_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&kindless_document),
            [KINDLESS_BEARER_ALICE_ID]
        );
        let alice_artifacts = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id LIKE '{ARTIFACT_ID_PREFIX}%' ORDER BY id"),
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_artifacts),
            [ARTIFACT_HIDDEN_BEARER_ID, ARTIFACT_KINDLESS_BEARER_ID]
        );
        let bea_artifacts = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '{ARTIFACT_ID_PREFIX}%' ORDER BY id"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_artifacts), [ARTIFACT_VISIBLE_BEARER_ID]);
        let count = query_sql(
            &db,
            &bea,
            "SELECT CAST(count(*) AS TEXT) AS n FROM records WHERE kind = 'note'",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&count), ["2"]);
        let alice_links = query_sql(
            &db,
            &alice,
            "SELECT id FROM links WHERE relationship = 'mentions' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&alice_links), ["alice-common"]);
        let bea_links = query_sql(
            &db,
            &bea,
            "SELECT id FROM links WHERE relationship = 'mentions' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_links), ["common-bea"]);
        let alice_bindings = query_sql(
            &db,
            &alice,
            "SELECT system || ':' || identifier AS binding FROM bindings ORDER BY binding",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_bindings),
            ["account:alice", "email:alice@example.test"]
        );
        let bea_bindings = query_sql(
            &db,
            &bea,
            "SELECT system || ':' || identifier AS binding FROM bindings ORDER BY binding",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&bea_bindings),
            ["account:bea", "email:bea@example.test"]
        );
        let alice_blobs = query_sql(
            &db,
            &alice,
            "SELECT original_filename FROM blobs ORDER BY 1",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_blobs),
            [
                format!("{ATTACHMENT_ALICE_ID}.txt"),
                format!("{ATTACHMENT_COMMON_ID}.txt")
            ]
        );
        let bea_blobs = query_sql(&db, &bea, "SELECT original_filename FROM blobs ORDER BY 1")
            .await
            .unwrap();
        assert_eq!(
            first_strings(&bea_blobs),
            [format!("{ATTACHMENT_COMMON_ID}.txt")]
        );
        for relation in ["content_events", "facet_values", "facet_observations"] {
            let statement =
                format!("SELECT record_id FROM {relation} WHERE record_id = '{TOMBSTONE_ID}'");
            assert!(query_sql(&db, &alice, &statement)
                .await
                .unwrap()
                .rows
                .is_empty());
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn content_events_discloses_attribution_by_history_rule() {
        let db = crate::create_database(":memory:").await.unwrap();
        for (person, account, viewers) in [
            (
                "9e796000-0000-4000-8000-000001000000",
                "alice",
                vec!["alice", "bea"],
            ),
            ("9e796000-0000-4000-8000-000002000000", "bea", vec!["bea"]),
        ] {
            create_record(
                &db,
                json!({
                    "id": person,
                    "type": "Document",
                    "kind": "note",
                    "name": person,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                person,
                viewers
                    .into_iter()
                    .map(|viewer| AllowEntry::account(viewer, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1)",
            )
            .bind(person)
            .bind(account)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": "9e796000-0000-4000-8000-000003000000",
                "type": "Document",
                "kind": "note",
                "name": "common",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            "9e796000-0000-4000-8000-000003000000",
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        for (id, payload, actor, run_key, parent_key) in [
            (
                "evt-disclosed",
                "{}",
                Some("alice"),
                Some("scout-chair-a748b2"),
                Some("heron-river-b748b2"),
            ),
            (
                "evt-hidden",
                "{}",
                Some("bea"),
                Some("scout-chair-b748b2"),
                None,
            ),
            (
                "evt-actorless",
                "{}",
                None,
                Some("otter-field-c748b2"),
                None,
            ),
            (
                "evt-claim",
                r#"{"claimed_by_account":"alice","claimed_run_key":"scout-chair-a749b2"}"#,
                Some("alice"),
                Some("scout-chair-a749b2"),
                Some("heron-river-c748b2"),
            ),
            (
                "evt-claim-hidden",
                r#"{"claimed_by_account":"bea","claimed_run_key":"otter-field-d748b2"}"#,
                Some("bea"),
                Some("otter-field-d748b2"),
                None,
            ),
            // An explicit-JSON-null claim key is still claim-shaped: the
            // history rule tests key presence (`.get(..).is_some()`), and
            // `json_type` reports the JSON null as the text 'null'.
            (
                "evt-claim-null",
                r#"{"claimed_by_account":null}"#,
                Some("alice"),
                Some("scout-chair-a750b2"),
                Some("heron-river-d748b2"),
            ),
            (
                "evt-unbound",
                "{}",
                Some("carol"),
                Some("run-unbound"),
                None,
            ),
        ] {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key,
                                            created_at, causal_envelope_version, causal_status)
                 VALUES (?, '9e796000-0000-4000-8000-000003000000', 'record.updated', ?, ?, ?, ?, '2026-01-01T00:00:00.000Z', 1, 'complete')",
            )
            .bind(id)
            .bind(payload)
            .bind(actor)
            .bind(run_key)
            .bind(parent_key)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        async fn attributed_rows(
            db: &Db,
            principal: QueryPrincipal,
        ) -> std::collections::HashMap<String, (Option<String>, Option<String>, Option<String>)>
        {
            let result = query_sql(
                db,
                principal,
                "SELECT id, actor, run_key, parent_key FROM content_events ORDER BY id",
            )
            .await
            .unwrap();
            result
                .rows
                .iter()
                .map(|row| {
                    let row = row.as_object().unwrap();
                    let cell = |column: &str| row[column].as_str().map(str::to_string);
                    (
                        row["id"].as_str().unwrap().to_string(),
                        (cell("actor"), cell("run_key"), cell("parent_key")),
                    )
                })
                .collect()
        }
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let as_alice = attributed_rows(&db, alice.clone()).await;
        assert_eq!(
            as_alice["evt-disclosed"],
            (
                Some("alice".into()),
                Some("scout-chair-a748b2".into()),
                Some("heron-river-b748b2".into())
            )
        );
        assert_eq!(as_alice["evt-hidden"], (None, None, None));
        assert_eq!(as_alice["evt-actorless"], (None, None, None));
        assert_eq!(
            as_alice["evt-claim"],
            (
                Some("alice".into()),
                Some("scout-chair-a749b2".into()),
                Some("heron-river-c748b2".into())
            )
        );
        assert_eq!(as_alice["evt-claim-hidden"], (None, None, None));
        assert_eq!(
            as_alice["evt-claim-null"],
            (
                Some("alice".into()),
                Some("scout-chair-a750b2".into()),
                Some("heron-river-d748b2".into())
            )
        );
        assert_eq!(as_alice["evt-unbound"], (None, None, None));
        let as_bea = attributed_rows(&db, bea.clone()).await;
        assert_eq!(
            as_bea["evt-disclosed"],
            (
                Some("alice".into()),
                Some("scout-chair-a748b2".into()),
                Some("heron-river-b748b2".into())
            )
        );
        assert_eq!(
            as_bea["evt-hidden"],
            (Some("bea".into()), Some("scout-chair-b748b2".into()), None)
        );
        assert_eq!(as_bea["evt-actorless"], (None, None, None));
        assert_eq!(as_bea["evt-claim"], (Some("alice".into()), None, None));
        assert_eq!(as_bea["evt-claim-null"], (Some("alice".into()), None, None));
        assert_eq!(
            as_bea["evt-claim-hidden"],
            (Some("bea".into()), Some("otter-field-d748b2".into()), None)
        );
        assert_eq!(as_bea["evt-unbound"], (None, None, None));
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let as_local = attributed_rows(&db, trusted).await;
        for (id, run_key, parent_key) in [
            (
                "evt-disclosed",
                "scout-chair-a748b2",
                Some("heron-river-b748b2"),
            ),
            ("evt-hidden", "scout-chair-b748b2", None),
            ("evt-actorless", "otter-field-c748b2", None),
            (
                "evt-claim",
                "scout-chair-a749b2",
                Some("heron-river-c748b2"),
            ),
            ("evt-claim-hidden", "otter-field-d748b2", None),
            (
                "evt-claim-null",
                "scout-chair-a750b2",
                Some("heron-river-d748b2"),
            ),
            ("evt-unbound", "run-unbound", None),
        ] {
            assert_eq!(
                as_local[id].1,
                Some(run_key.to_string()),
                "trusted-local keeps run_key on {id}"
            );
            assert_eq!(
                as_local[id].2,
                parent_key.map(str::to_string),
                "trusted-local keeps parent_key on {id}"
            );
        }
        // Visible-set membership agrees with the capability fold the view
        // encodes: bea's disclosure of alice follows View on person-alice,
        // alice's non-disclosure of bea follows its absence.
        for (viewer, person, expected) in [
            ("alice", "9e796000-0000-4000-8000-000001000000", true),
            ("bea", "9e796000-0000-4000-8000-000001000000", true),
            ("alice", "9e796000-0000-4000-8000-000002000000", false),
            ("bea", "9e796000-0000-4000-8000-000002000000", true),
        ] {
            let capability =
                effective_capability(&db, Principal::bound(viewer, true), person).await;
            assert_eq!(
                capability.is_ok_and(|actual| actual.allows(Capability::View)),
                expected,
                "{viewer} View on {person}"
            );
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn content_events_channel_kind_is_viewer_visible_only() {
        // Richard ruling: transport travels exactly when the actor gate
        // discloses the actor, and is NULL otherwise — never the built-in
        // unknown-fallback on hidden rows. Same person/record disclosure
        // shape as content_events_discloses_attribution_by_history_rule,
        // plus one alice-only record for the record-invisible direction.
        let db = crate::create_database(":memory:").await.unwrap();
        for (person, account, viewers) in [
            (
                "9e796000-0000-4000-8000-000001000000",
                "alice",
                vec!["alice", "bea"],
            ),
            ("9e796000-0000-4000-8000-000002000000", "bea", vec!["bea"]),
            (
                "9e796000-0000-4000-8000-000004000000",
                "alice",
                vec!["alice"],
            ),
        ] {
            create_record(
                &db,
                json!({
                    "id": person,
                    "type": "Document",
                    "kind": "note",
                    "name": person,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                person,
                viewers
                    .into_iter()
                    .map(|viewer| AllowEntry::account(viewer, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
            // One canonical account binding per actor: the alice-only
            // record reuses alice's existing binding (UNIQUE system,
            // identifier), and disclosure follows record visibility.
            if person != "9e796000-0000-4000-8000-000004000000" {
                sqlx::query(
                    "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                     VALUES (?, 'account', ?, 1)",
                )
                .bind(person)
                .bind(account)
                .execute(db.write_pool())
                .await
                .unwrap();
            }
        }
        for (id, actor) in [
            ("evt-ch-web", Some("alice")),
            ("evt-ch-mcp", Some("bea")),
            ("evt-ch-none", Some("alice")),
            ("evt-ch-inv", Some("alice")),
        ] {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key,
                                            created_at, causal_envelope_version, causal_status)
                 VALUES (?, '9e796000-0000-4000-8000-000001000000', 'record.updated', '{}', ?, NULL, NULL, '2026-01-01T00:00:00.000Z', 1, 'complete')",
            )
            .bind(id)
            .bind(actor)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        async fn attest(db: &Db, attestation: &str, channel: &str, event: &str) {
            sqlx::query(
                "INSERT INTO provenance_action_attestations(id, schema_version, principal, executor_kind, channel,
                    operation, action_commitment, action_digest, output_event_set_digest, issuer,
                    issuer_origin_database_id, issued_at)
                 VALUES (?, 1, 'test', 'agent', ?, 'test.op',
                    '\"00000000000000000000000000000000000000000000000000000000000000\"',
                    '\"11111111111111111111111111111111111111111111111111111111111111\"',
                    '\"22222222222222222222222222222222222222222222222222222222222222\"',
                    'test', 'ndb_19e713014089aad42fc47d5a5740a094', '2026-01-01T00:00:00.000Z')",
            )
            .bind(attestation)
            .bind(channel)
            .execute(db.write_pool())
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO provenance_action_outputs(action_attestation_id, ordinal, output_domain, output_event_id)
                 VALUES (?, 0, 'content', ?)",
            )
            .bind(attestation)
            .bind(event)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        attest(&db, "att-ch-web", "web", "evt-ch-web").await;
        attest(&db, "att-ch-mcp", "mcp", "evt-ch-mcp").await;
        attest(&db, "att-ch-inv", "web", "evt-ch-inv").await;
        sqlx::query(
            "INSERT INTO provenance_attestation_validity_events(id, attestation_id, ordinal, status, reason, issuer, issued_at)
             VALUES ('att-ch-inv-v0', 'att-ch-inv', 0, 'invalidated', 'test', 'test', '2026-01-02T00:00:00.000Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        async fn channel_rows(
            db: &Db,
            principal: QueryPrincipal,
        ) -> std::collections::HashMap<String, (Option<String>, Option<String>)> {
            let result = query_sql(
                db,
                principal,
                "SELECT id, actor, channel_kind FROM content_events ORDER BY id",
            )
            .await
            .unwrap();
            result
                .rows
                .iter()
                .map(|row| {
                    let row = row.as_object().unwrap();
                    let cell = |column: &str| row[column].as_str().map(str::to_string);
                    (
                        row["id"].as_str().unwrap().to_string(),
                        (cell("actor"), cell("channel_kind")),
                    )
                })
                .collect()
        }
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        // Attested transport travels exactly where the actor is disclosed;
        // hidden rows carry NULL, never the built-in unknown-fallback.
        let as_alice = channel_rows(&db, alice.clone()).await;
        assert_eq!(
            as_alice["evt-ch-web"],
            (Some("alice".into()), Some("web".into()))
        );
        assert_eq!(as_alice["evt-ch-mcp"], (None, None));
        assert_eq!(
            as_alice["evt-ch-none"],
            (Some("alice".into()), Some("unknown".into()))
        );
        assert_eq!(
            as_alice["evt-ch-inv"],
            (Some("alice".into()), Some("unknown".into()))
        );
        let as_bea = channel_rows(&db, bea.clone()).await;
        assert_eq!(
            as_bea["evt-ch-web"],
            (Some("alice".into()), Some("web".into()))
        );
        assert_eq!(
            as_bea["evt-ch-mcp"],
            (Some("bea".into()), Some("mcp".into()))
        );
        assert_eq!(
            as_bea["evt-ch-none"],
            (Some("alice".into()), Some("unknown".into()))
        );
        // Record-invisible writes move neither viewer's rows: the view
        // joins visible records, so the snapshot digest, count and hint
        // derived from these rows cannot move either.
        async fn full_rows(db: &Db, principal: QueryPrincipal) -> Vec<String> {
            let result = query_sql(
                db,
                principal,
                "SELECT ce.local_seq, ce.record_id, ce.type, ce.actor, ce.run_key, ce.parent_key, \
                        ce.channel_kind, ce.created_at_ms, r.name \
                 FROM content_events ce JOIN records r ON r.id = ce.record_id \
                 ORDER BY ce.local_seq DESC LIMIT 100",
            )
            .await
            .unwrap();
            result
                .rows
                .iter()
                .map(|row| serde_json::to_string(row).unwrap())
                .collect()
        }
        async fn insert_noise(db: &Db, id: &str, record: &str, actor: &str) {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key,
                                            created_at, causal_envelope_version, causal_status)
                 VALUES (?, ?, 'record.updated', '{}', ?, NULL, NULL, '2026-01-03T00:00:00.000Z', 1, 'complete')",
            )
            .bind(id)
            .bind(record)
            .bind(actor)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        // Each direction snapshots the declared latest-100 statement,
        // writes only where that viewer cannot see, then requires
        // byte-identical rows. This proves row-window stability; host
        // digest and revision delivery are separate integration concerns.
        let alice_before = full_rows(&db, alice.clone()).await;
        insert_noise(
            &db,
            "evt-noise-bea-only",
            "9e796000-0000-4000-8000-000002000000",
            "alice",
        )
        .await;
        assert_eq!(
            full_rows(&db, alice.clone()).await,
            alice_before,
            "a bea-only record write moves none of alice's rows"
        );
        let bea_before = full_rows(&db, bea.clone()).await;
        insert_noise(
            &db,
            "evt-noise-alice-only",
            "9e796000-0000-4000-8000-000004000000",
            "bea",
        )
        .await;
        assert_eq!(
            full_rows(&db, bea.clone()).await,
            bea_before,
            "an alice-only record write moves none of bea's rows"
        );
        // A visible write must move the same window in both directions.
        let alice_window_before_visible = full_rows(&db, alice.clone()).await;
        let bea_window_before_visible = full_rows(&db, bea.clone()).await;
        insert_noise(
            &db,
            "evt-visible-both",
            "9e796000-0000-4000-8000-000001000000",
            "alice",
        )
        .await;
        for (principal, before) in [
            (alice, alice_window_before_visible),
            (bea, bea_window_before_visible),
        ] {
            let after = full_rows(&db, principal).await;
            assert_eq!(after.len(), before.len() + 1);
            assert!(before.iter().all(|row| after.contains(row)));
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn activity_changes_window_statement_is_install_admissible() {
        // The exact `activity.changes` snapshot statement the Activity
        // package declares (fixtures/activity-sql.mjs): every clause has a
        // slice-1 precedent (JOIN, ORDER BY DESC, LIMIT), and `channel_kind`
        // is a contract column, so install validation must accept it.
        let sql = "SELECT ce.local_seq, ce.record_id, ce.type, ce.actor, ce.run_key, ce.parent_key, ce.channel_kind, ce.created_at_ms, r.name FROM content_events ce JOIN records r ON r.id = ce.record_id ORDER BY ce.local_seq DESC LIMIT 100";
        validate(sql).unwrap();
        let columns = validated_output_columns(sql).unwrap();
        assert!(columns.contains(&"channel_kind".to_string()));
        let db = crate::create_database(":memory:").await.unwrap();
        let alice = QueryPrincipal::authenticated("alice", true);
        let result = query_sql(&db, &alice, sql).await.unwrap();
        assert!(result.rows.len() <= 100);
        assert!(result
            .rows
            .iter()
            .all(|row| row.get("channel_kind").is_some()));
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[test]
    fn dual_prepare_rejects_every_raw_qualified_and_spoofed_route() {
        let raw = [
            "records",
            "content_events",
            "policy_events",
            "control_events",
            "links",
            "facet_values",
            "facet_observations",
            "bindings",
            "blobs",
            "record_policies",
            "policy_entries",
            "member_contexts",
            "instruction_bindings",
            "onboarding_programmes",
            "onboarding_programme_sources",
            "member_obligations",
            "member_obligation_progress",
            "seeded_instruction_sources",
            "control_event_applications",
            "records_fts",
            "records_name_idx",
            "embeddings",
            "meta_events",
            "jobs",
            "annotation_targets",
            "read_log_calls",
            "read_log_touches",
            "read_log_record_ids",
        ];
        for relation in raw {
            for statement in [
                format!("SELECT * FROM main.{relation}"),
                format!("SELECT raw.* FROM main.{relation} AS raw"),
                format!("WITH stolen AS (SELECT * FROM main.{relation}) SELECT * FROM stolen"),
            ] {
                assert!(
                    validate(&statement).is_err(),
                    "unexpectedly admitted {statement}"
                );
            }
        }
        for statement in [
            "SELECT * FROM temp._query_sql_principal",
            "SELECT * FROM sqlite_master",
            "WITH records AS (SELECT * FROM main.records) SELECT * FROM records",
            "SELECT * FROM pragma_table_info('records')",
            "SELECT * FROM records_fts_data",
        ] {
            assert!(
                validate(statement).is_err(),
                "unexpectedly admitted {statement}"
            );
        }
        for statement in [
            "SELECT randomblob(1000000000)",
            "SELECT zeroblob(1000000000)",
            "SELECT printf('%1000000000s', 'x')",
            "SELECT json_group_array(body) FROM records",
            "SELECT load_extension('anything')",
        ] {
            assert!(
                validate(statement).is_err(),
                "unexpectedly admitted unsafe function in {statement}"
            );
        }
        for statement in [
            "SELECT id FROM records",
            "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
            "WITH visible AS (SELECT id FROM records) SELECT count(*) FROM visible",
            "SELECT id FROM vocabularies",
            "SELECT id FROM schema_config",
            "SELECT substr(name, 1, 5) AS preview FROM records",
            "SELECT substr(body, 1, 10) AS preview FROM records",
        ] {
            validate(statement).unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
    }

    #[tokio::test]
    async fn substr_truncates_text_in_sql() {
        let (db, alice, _bea) = protected_fixture().await;
        // "Common" / "sharedterm common" are the COMMON_ID fixture values.
        let preview = query_sql(
            &db,
            &alice,
            &format!("SELECT substr(name, 1, 5) AS preview FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&preview), ["Commo"]);
        let tail = query_sql(
            &db,
            &alice,
            &format!("SELECT substr(name, 4) AS tail FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&tail), ["mon"]);
        // I2: `substring` is dropped everywhere (Turso never had it);
        // the repair names `substr`.
        let dropped = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT substring(body, 1, 10) AS preview FROM records WHERE id = '{COMMON_ID}'"
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            dropped.contains("function 'substring' is unavailable — use substr"),
            "missing repair: {dropped}"
        );
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn ad_hoc_unordered_top_level_limit_executes_with_disclosed_default() {
        // E2 default ORDER BY: a top-level LIMIT with no ORDER BY executes
        // ordered by every output column, and says so in `assumed_order`.
        let (db, alice, _bea) = protected_fixture().await;
        let defaulted = query_sql(&db, &alice, "SELECT id, name FROM records LIMIT 2")
            .await
            .unwrap();
        let assumed = defaulted.assumed_order.clone().expect("default disclosed");
        assert_eq!(assumed.columns, vec!["id".to_owned(), "name".to_owned()]);
        assert_eq!(assumed.order_by, "ORDER BY 1, 2");
        assert_eq!(assumed.reason, sql_contract::ASSUMED_ORDER_REASON);
        assert_eq!(defaulted.row_count, 2);
        // Membership and order match the explicit ordering exactly.
        let explicit = query_sql(
            &db,
            &alice,
            "SELECT id, name FROM records ORDER BY id, name LIMIT 2",
        )
        .await
        .unwrap();
        assert!(explicit.assumed_order.is_none());
        assert_eq!(defaulted.rows, explicit.rows);
    }

    #[tokio::test]
    async fn ad_hoc_unordered_limit_with_other_defects_keeps_validator_error() {
        // E2 describe-failure fallback: label discovery fails on these, so
        // the original validator's categorised refusal surfaces exactly as
        // before the default (the LIMIT rule runs before scope/prepare).
        let (db, alice, _bea) = protected_fixture().await;
        for sql in [
            "SELECT nosuchcol FROM records LIMIT 2",
            "SELECT id AS dup, name AS dup FROM records LIMIT 2",
        ] {
            let error = query_sql(&db, &alice, sql).await.unwrap_err().to_string();
            assert!(error.contains("LIMIT without ORDER BY"), "{sql}: {error}");
        }
    }

    #[tokio::test]
    async fn ad_hoc_nested_unordered_limit_still_refuses() {
        let (db, alice, _bea) = protected_fixture().await;
        for (sql, repaired, expected) in [
            (
                "SELECT * FROM (SELECT id, name FROM records LIMIT 1) s LIMIT 2",
                "SELECT * FROM (SELECT id, name FROM records ORDER BY 1, 2 LIMIT 1) s ORDER BY 1, 2 LIMIT 2",
                vec!["in top level: add ORDER BY 1, 2", "in subquery s: add ORDER BY 1, 2"],
            ),
            (
                "WITH c AS (SELECT id, name FROM records LIMIT 1) SELECT id FROM c LIMIT 2",
                "WITH c AS (SELECT id, name FROM records ORDER BY 1, 2 LIMIT 1) SELECT id FROM c ORDER BY 1 LIMIT 2",
                vec!["in top level: add ORDER BY 1", "in CTE c: add ORDER BY 1, 2"],
            ),
            (
                "SELECT * FROM (SELECT id FROM records LIMIT 1) s ORDER BY id",
                "SELECT * FROM (SELECT id FROM records ORDER BY 1 LIMIT 1) s ORDER BY id",
                vec!["in subquery s: add ORDER BY 1"],
            ),
            (
                "SELECT id FROM records UNION ALL SELECT id FROM (SELECT id FROM records LIMIT 1) s ORDER BY 1",
                "SELECT id FROM records UNION ALL SELECT id FROM (SELECT id FROM records ORDER BY 1 LIMIT 1) s ORDER BY 1",
                vec!["in compound arm subquery s: add ORDER BY 1"],
            ),
            (
                "SELECT id FROM records UNION SELECT id FROM records ORDER BY 1 LIMIT (SELECT 1 LIMIT 1)",
                "SELECT id FROM records UNION SELECT id FROM records ORDER BY 1 LIMIT (SELECT 1 ORDER BY 1 LIMIT 1)",
                vec!["in subquery: add ORDER BY 1"],
            ),
            (
                "WITH c AS (SELECT id, name FROM records) SELECT * FROM (SELECT * FROM c LIMIT 1) s",
                "WITH c AS (SELECT id, name FROM records) SELECT * FROM (SELECT * FROM c ORDER BY 1, 2 LIMIT 1) s",
                vec!["in subquery s: add ORDER BY 1, 2"],
            ),
            (
                "SELECT * FROM (SELECT id FROM records                                        LIMIT 1) s LIMIT 2",
                "SELECT * FROM (SELECT id FROM records ORDER BY 1 LIMIT 1) s ORDER BY 1 LIMIT 2",
                vec!["in top level: add ORDER BY 1", "in subquery s: add ORDER BY 1"],
            ),
            (
                "WITH a AS (SELECT id FROM records LIMIT 1), b AS (SELECT id FROM records LIMIT 1) SELECT a.id FROM a JOIN b ON a.id=b.id",
                "WITH a AS (SELECT id FROM records ORDER BY 1 LIMIT 1), b AS (SELECT id FROM records ORDER BY 1 LIMIT 1) SELECT a.id FROM a JOIN b ON a.id=b.id",
                vec!["in CTE a: add ORDER BY 1", "in CTE b: add ORDER BY 1"],
            ),
            (
                "SELECT 'LIMIT (SELECT id FROM records LIMIT 1)' AS note, id FROM (SELECT id FROM records /* LIMIT */ LIMIT 1) s",
                "SELECT 'LIMIT (SELECT id FROM records LIMIT 1)' AS note, id FROM (SELECT id FROM records /* LIMIT */ ORDER BY 1 LIMIT 1) s",
                vec!["in subquery s: add ORDER BY 1"],
            ),
            (
                "SELECT a.id FROM (SELECT id FROM records LIMIT 1) a JOIN (SELECT id, name FROM records LIMIT 1) b ON a.id=b.id",
                "SELECT a.id FROM (SELECT id FROM records ORDER BY 1 LIMIT 1) a JOIN (SELECT id, name FROM records ORDER BY 1, 2 LIMIT 1) b ON a.id=b.id",
                vec!["in subquery a: add ORDER BY 1", "in subquery b: add ORDER BY 1, 2"],
            ),
            (
                "SELECT * FROM (SELECT * FROM (SELECT id, name FROM records LIMIT 1) a LIMIT 2) b",
                "SELECT * FROM (SELECT * FROM (SELECT id, name FROM records ORDER BY 1, 2 LIMIT 1) a ORDER BY 1, 2 LIMIT 2) b",
                vec!["in subquery b: add ORDER BY 1, 2", "in subquery a: add ORDER BY 1, 2"],
            ),
        ] {
            let error = query_sql(&db, &alice, sql).await.unwrap_err().to_string();
            assert!(error.contains("LIMIT without ORDER BY"), "{sql}: {error}");
            for fix in expected {
                assert!(error.contains(fix), "{sql}: missing {fix}: {error}");
            }
            validate(repaired).unwrap_or_else(|error| panic!("{repaired}: {error}"));
            query_sql(&db, &alice, repaired).await.unwrap();
            let repair = default_order_repair_with(sql, validated_output_columns, |candidate| {
                assert_eq!(candidate, repaired, "{sql}: repair must change only the named ordering");
                validate(candidate)
            });
            assert!(repair.is_some(), "{sql}");
        }
        for sql in [
            "SELECT * FROM (SELECT nosuchcol FROM records LIMIT 1) s",
            "SELECT * FROM (SELECT id FROM records LIMIT 1) s JOIN forbidden f ON 1=1",
            "SELECT * FROM (SELECT name, count(*) AS n FROM records LIMIT 1) s",
            "SELECT s.id AS dup, s.name AS dup FROM (SELECT id, name FROM records LIMIT 1) s",
        ] {
            assert!(default_order_repair(sql).is_none(), "{sql}");
        }
    }

    #[tokio::test]
    async fn ad_hoc_default_discloses_on_zero_row_and_star_results() {
        // Labels come from prepare-without-execution, so `SELECT *` and
        // empty results still disclose the assumed order.
        let (db, alice, _bea) = protected_fixture().await;
        let empty = query_sql(
            &db,
            &alice,
            "SELECT * FROM records WHERE id = '00000000-0000-4000-8000-000000000000' LIMIT 5",
        )
        .await
        .unwrap();
        assert!(empty.rows.is_empty());
        assert!(empty.columns.is_empty());
        let assumed = empty.assumed_order.clone().expect("default disclosed");
        assert!(assumed.columns.contains(&"id".to_owned()));
        assert!(
            assumed.order_by.starts_with("ORDER BY 1"),
            "{}",
            assumed.order_by
        );
    }

    #[test]
    fn governed_sql_timeout_names_the_deadline_and_the_usual_cause() {
        let rendered = governed_sql_timeout().to_string();
        assert_eq!(
            rendered,
            format!("query_sql [timeout]: {}", sql_contract::deadline_hint())
        );
        assert!(rendered.contains(&format!("{}ms", sql_contract::QUERY_DEADLINE_MS)));
        assert!(rendered.contains("LIMIT with ORDER BY"));
    }

    #[tokio::test]
    async fn runaway_query_surfaces_the_governed_sql_timeout() {
        let (db, alice, _bea) = protected_fixture().await;
        let error = query_sql_owned(
            db.clone(),
            alice,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".into(),
        )
        .await
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("[timeout]"), "{rendered}");
        assert!(rendered.contains("governed SQL deadline"), "{rendered}");
        assert!(!rendered.contains("interrupted"), "{rendered}");
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn explain_query_plan_reports_plans_without_widening_the_surface() {
        let (db, alice, _bea) = protected_fixture().await;
        validate(&format!(
            "EXPLAIN QUERY PLAN SELECT id FROM records WHERE id = '{COMMON_ID}'"
        ))
        .unwrap();
        let plan = query_sql(
            &db,
            &alice,
            &format!("EXPLAIN QUERY PLAN SELECT id FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        // The plan column labels are SQLite-version cosmetics (older
        // selectid/order/from, newer id/parent/notused); pin the stable
        // shape instead: four columns ending in the human-readable detail.
        assert_eq!(plan.columns.len(), 4);
        assert_eq!(plan.columns[3], "detail");
        assert!(!plan.rows.is_empty());
        for row in &plan.rows {
            let object = row.as_object().unwrap();
            assert_eq!(object.len(), 4);
            assert!(object["detail"].as_str().is_some());
        }
        // Bare EXPLAIN and any explained statement that is not itself
        // admissible stay rejected, through validation and through execution.
        for statement in [
            "EXPLAIN SELECT id FROM records".to_string(),
            "EXPLAIN QUERY PLAN DELETE FROM records".to_string(),
            "EXPLAIN QUERY PLAN SELECT randomblob(1)".to_string(),
            "EXPLAIN QUERY PLAN SELECT * FROM main.records".to_string(),
        ] {
            assert!(
                validate(&statement).is_err(),
                "unexpectedly admitted {statement}"
            );
            assert!(
                query_sql(&db, &alice, &statement).await.is_err(),
                "unexpectedly executed {statement}"
            );
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn sql_input_cells_and_cumulative_results_are_bounded_and_discard_cleanly() {
        let (db, alice, bea) = protected_fixture().await;
        for (id, body) in [
            (OVERSIZE_CELL_ID, "x".repeat(MAX_CELL_ENCODED_BYTES + 1)),
            (REPEATED_BYTES_ID, "y".repeat(32 * 1024)),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": id,
                    "body": body,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                vec![AllowEntry::account("alice", Capability::View)],
            )
            .await
            .unwrap();
        }

        let too_long = format!("SELECT id FROM records --{}", "x".repeat(MAX_SQL_BYTES));
        assert!(query_sql(&db, &alice, &too_long).await.is_err());
        for statement in [
            "SELECT randomblob(1000000000)",
            "SELECT zeroblob(1000000000)",
        ] {
            assert!(query_sql(&db, &alice, statement).await.is_err());
        }

        // Pin all governed work to one available slot. Both breaches must
        // discard the physical connection and leave its replacement clean
        // for Bea.
        let held = hold_all_but_one_governed_slot(&db).await;
        assert!(query_sql(
            &db,
            &alice,
            &format!("SELECT body FROM records WHERE id = '{OVERSIZE_CELL_ID}'"),
        )
        .await
        .is_err());
        let after_cell = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_cell), [BEA_PRIVATE_ID]);

        assert!(query_sql(
            &db,
            &alice,
            &format!("SELECT min(body) FROM records WHERE id = '{OVERSIZE_CELL_ID}'"),
        )
        .await
        .is_err());
        let after_function = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_function), [BEA_PRIVATE_ID]);

        assert!(query_sql(
            &db,
            &alice,
            &format!(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 200)
                 SELECT body FROM records, n WHERE id = '{REPEATED_BYTES_ID}'"
            ),
        )
        .await
        .is_err());
        let after_total = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_total), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_thousand_interleaved_and_forced_single_connection_reuse_isolate_callers() {
        let (db, alice, bea) = protected_fixture().await;
        let observations = stream::iter(0..1_000usize)
            .map(|index| {
                let db = db.clone();
                let caller = if index % 2 == 0 {
                    alice.clone()
                } else {
                    bea.clone()
                };
                async move {
                    let expected = if index % 2 == 0 {
                        ALICE_PRIVATE_ID
                    } else {
                        BEA_PRIVATE_ID
                    };
                    let result = query_sql_owned(
                        db,
                        caller,
                        format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
                    )
                    .await
                    .unwrap();
                    (expected.to_string(), first_strings(&result))
                }
            })
            // Stay above the governed pool size so requests must queue and
            // reuse physical connections, while leaving the full parallel
            // suite's scheduler load out of the governed acquire timeout.
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for (expected, actual) in observations {
            assert_eq!(actual, [expected]);
        }

        // Hold every governed-pool slot but one: every alternation below must
        // reuse the one remaining physical connection.
        let held = hold_all_but_one_governed_slot(&db).await;
        for index in 0..100 {
            let (caller, expected) = if index % 2 == 0 {
                (&alice, ALICE_PRIVATE_ID)
            } else {
                (&bea, BEA_PRIVATE_ID)
            };
            let result = query_sql(
                &db,
                caller,
                &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
            )
            .await
            .unwrap();
            assert_eq!(first_strings(&result), [expected]);
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    /// Tier 1.2: governed reads must not occupy write-pool connections. Hold
    /// every write slot, then require a governed query to succeed — before
    /// this rung it would have waited on a writer's slot.
    #[tokio::test]
    async fn governed_reads_do_not_occupy_write_pool_connections() {
        let (db, alice, _) = protected_fixture().await;
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(db.write_pool().acquire().await.unwrap());
        }
        let rows = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&rows), [ALICE_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
        db.close().await;
    }

    #[tokio::test]
    async fn vm_work_counter_measures_caller_sql_without_changing_result_or_pool_reuse() {
        let (db, alice, _) = protected_fixture().await;
        let sql = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000) SELECT sum(x) AS n FROM n";
        let request = QuerySqlRequest {
            sql: sql.to_string(),
            parameters: Vec::new(),
        };
        let callbacks = Arc::new(AtomicU64::new(0));
        let measured = query_sql_request_owned_with_vm_work(
            db.clone(),
            alice.clone(),
            request.clone(),
            Some(Arc::clone(&callbacks)),
            false,
        )
        .await
        .unwrap();
        assert!(callbacks.load(Ordering::Relaxed) > 0);
        let ordinary = query_sql_request_owned(db.clone(), alice.clone(), request)
            .await
            .unwrap();
        assert_eq!(measured.columns, ordinary.columns);
        assert_eq!(measured.rows, ordinary.rows);
        assert_eq!(measured.row_count, ordinary.row_count);
        assert_eq!(measured.truncated, ordinary.truncated);
        assert_eq!(measured.truncation_hint, ordinary.truncation_hint);
        let after = query_sql(&db, alice, "SELECT count(*) AS n FROM records")
            .await
            .unwrap();
        assert_eq!(after.row_count, 1);
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_replay_uses_exact_hidden_now_ms_bind_without_changing_public_query() {
        let (db, alice, _) = protected_fixture().await;
        let request = QuerySqlRequest {
            sql: "SELECT now_ms() AS clock_value".to_string(),
            parameters: Vec::new(),
        };
        let replay =
            query_sql_request_owned_replay(db.clone(), alice.clone(), request.clone(), 1_234_567)
                .await
                .unwrap();
        assert_eq!(replay.now_ms_ms, Some(1_234_567));
        assert_eq!(replay.rows[0]["clock_value"], serde_json::json!(1_234_567));
        let ordinary = query_sql_request_owned(db.clone(), alice.clone(), request)
            .await
            .unwrap();
        assert!(ordinary.now_ms_ms.unwrap() > 1_234_567);
        // A fresh clock can legitimately change a time predicate before
        // the subscription's next due tick. Replaying the old bind keeps
        // that distinction out of missed-content measurements.
        let cutoff = chrono::Utc::now().timestamp_millis() - 1_000;
        let predicate = QuerySqlRequest {
            sql: format!("SELECT 1 AS eligible WHERE now_ms() >= {cutoff}"),
            parameters: Vec::new(),
        };
        let held = query_sql_request_owned_replay(
            db.clone(),
            alice.clone(),
            predicate.clone(),
            cutoff - 1,
        )
        .await
        .unwrap();
        assert!(held.rows.is_empty());
        let fresh = query_sql_request_owned(db.clone(), alice, predicate)
            .await
            .unwrap();
        assert_eq!(fresh.row_count, 1);
        db.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_measured_sql_cleans_handler_before_governed_pool_reuse() {
        let (db, alice, bea) = protected_fixture().await;
        let held = hold_all_but_one_governed_slot(&db).await;
        let callbacks = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&callbacks);
        let worker = tokio::spawn(query_sql_request_owned_with_vm_work(
            db.clone(),
            alice,
            QuerySqlRequest {
                sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".to_string(),
                parameters: Vec::new(),
            },
            Some(callbacks),
            false,
        ));
        // Wait for actual caller VM work before cancellation. Pool/setup
        // scheduling is outside this proof and can exceed one second in a
        // parallel debug suite; the production VM deadline is unchanged.
        // Keep a bounded failure ceiling without busy-spinning against the
        // worker whose progress we need to observe.
        tokio::time::timeout(Duration::from_secs(30), async {
            while observed.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("measured caller SQL never reached the progress callback");
        worker.abort();
        let _ = worker.await;
        let after = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
        db.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_tx_governed_warm_reuse_and_cancel_sanitizes() {
        use sql_contract::FunctionAllowance;
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let (db, alice, bea) = protected_fixture().await;
        // Warm the governed pool through the ordinary owned path first.
        let warm = query_sql(&db, alice.clone(), "SELECT count(*) AS n FROM records")
            .await
            .unwrap();
        assert_eq!(warm.row_count, 1);
        // Same-pool caller-transaction core: authored VM counts, a server
        // replay clock binds only genuine now_ms uses (this statement has
        // none, so the override is ignored), TEMP is cleaned in-tx.
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let callbacks = Arc::new(AtomicU64::new(0));
        let (result, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000) SELECT sum(x) AS n FROM n".to_string(),
                parameters: Vec::new(),
            },
            MAX_ROWS,
            FunctionAllowance::Portable,
            Some(7_777),
            Some(Arc::clone(&callbacks)),
            false,
        )
        .await
        .unwrap();
        assert!(callbacks.load(Ordering::Relaxed) > 0);
        assert_eq!(result.now_ms_ms, None);
        assert!(!result.time_dependent);
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
        // Warm reuse of the SAME connection after prior SQL: a fresh gate
        // and data read on a new transaction must see no TEMP shadows.
        let mut tx = connection.begin().await.unwrap();
        let (second, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id LIMIT 1".to_string(),
                parameters: Vec::new(),
            },
            MAX_ROWS,
            FunctionAllowance::Portable,
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(second.rows.len(), 1);
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
        drop(connection);
        // Cancellation mid-flight returns the governed connection clean.
        let held = hold_all_but_one_governed_slot(&db).await;
        let observed = Arc::new(AtomicU64::new(0));
        let worker_callbacks = Arc::clone(&observed);
        let worker_db = db.clone();
        let worker = tokio::spawn(async move {
            let mut connection = worker_db.governed_pool().acquire().await.unwrap();
            let mut tx = connection.begin().await.unwrap();
            query_sql_request_in_with_row_limit_observed(
                &mut tx,
                alice,
                QuerySqlRequest {
                    sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".to_string(),
                    parameters: Vec::new(),
                },
                MAX_ROWS,
                FunctionAllowance::Portable,
                None,
                Some(worker_callbacks),
                false,
            )
            .await
        });
        // This waits for the cancellation phase, not for a product latency
        // bound. The preceding principal/visibility setup can queue behind
        // parallel tests on the shared host; keep the callback assertion.
        tokio::time::timeout(Duration::from_secs(10), async {
            while observed.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("caller-tx SQL never reached the progress callback");
        worker.abort();
        let _ = worker.await;
        let after = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
        db.close().await;
    }

    #[tokio::test]
    async fn governed_same_connection_gate_after_sql_sees_no_temp_shadows() {
        use sql_contract::FunctionAllowance;
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let (db, alice, _) = protected_fixture().await;
        // Baseline from the write pool: the unqualified gate-style read
        // below must see main-table truth, never a TEMP shadow.
        let main_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM main.records")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        // Hold-all-but-one sized from the ACTUAL pool config (not the env):
        // the remaining slot is the only connection this test can borrow.
        let max = db.governed_pool().options().get_max_connections().max(1);
        let mut held = Vec::new();
        for _ in 0..max - 1 {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let identity = {
            let mut handle = connection.lock_handle().await.unwrap();
            handle.as_raw_handle().as_ptr() as usize
        };
        // Prior SQL: installs the TEMP contract, drops it before returning.
        let mut tx = connection.begin().await.unwrap();
        let (result, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id LIMIT 3".to_string(),
                parameters: Vec::new(),
            },
            MAX_ROWS,
            FunctionAllowance::Portable,
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(result.rows.len(), 3);
        tx.rollback().await.unwrap();
        // Return the connection so the real release hook runs, then
        // reacquire the pinned slot: the other holds leave exactly one
        // connection borrowable, so reuse must be the SAME physical
        // connection. A cleanup failure that replaced it is rejected here
        // instead of masquerading as warm proof on a cold connection.
        drop(connection);
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let reuse = {
            let mut handle = connection.lock_handle().await.unwrap();
            handle.as_raw_handle().as_ptr() as usize
        };
        assert_eq!(identity, reuse);
        // Gate-after-SQL on the warmed connection: unqualified domain reads
        // must resolve to main, and the TEMP catalog must be empty.
        let mut tx = connection.begin().await.unwrap();
        let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(seen, main_count);
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
        drop(connection);
        drop(held);
        db.close().await;
    }

    /// Tier 1.2, other direction: saturating the governed pool must leave
    /// ordinary writes unaffected — the availability win this rung exists for.
    #[tokio::test]
    async fn writes_proceed_while_the_governed_pool_is_saturated() {
        let (db, alice, _) = protected_fixture().await;
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        create_record(
            &db,
            json!({
                "id": "9e795000-0000-4000-8000-00000f000000",
                "type": "Document",
                "kind": "note",
                "name": "Written while governed is saturated",
            }),
        )
        .await
        .unwrap();
        drop(held);
        let rows = query_sql(
            &db,
            &alice,
            "SELECT id FROM records WHERE id = '9e795000-0000-4000-8000-00000f000000'",
        )
        .await
        .unwrap();
        assert_eq!(rows.row_count, 1);
        db.close().await;
    }

    /// Tier 1.2: the governed pool is the concurrency limit. A burst several
    /// times the pool size must queue and complete — every caller isolated —
    /// rather than exhausting writer connections or cross-contaminating TEMP
    /// principal state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn governed_burst_beyond_pool_size_queues_and_completes() {
        let (db, alice, bea) = protected_fixture().await;
        let burst = 4 * crate::db::governed_sql_pool_size() as usize;
        let outcomes = stream::iter(0..burst)
            .map(|index| {
                let db = db.clone();
                let caller = if index % 2 == 0 {
                    alice.clone()
                } else {
                    bea.clone()
                };
                let expected = if index % 2 == 0 {
                    ALICE_PRIVATE_ID
                } else {
                    BEA_PRIVATE_ID
                };
                async move {
                    let result = query_sql(
                        &db,
                        &caller,
                        &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
                    )
                    .await
                    .unwrap();
                    (expected, first_strings(&result))
                }
            })
            .buffer_unordered(burst)
            .collect::<Vec<_>>()
            .await;
        for (expected, actual) in outcomes {
            assert_eq!(actual, [expected]);
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
        db.close().await;
    }

    /// Tier 1.2: the pool bound is visible at checkout. With every slot
    /// checked out, a further `try_acquire` fails immediately rather than
    /// minting contention the engine cannot see. (A plain `acquire` still
    /// queues, bounded by the pool's acquire timeout — the limit is the pool
    /// size, not a refusal to wait.)
    #[tokio::test]
    async fn governed_pool_full_pool_refuses_checkout() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        assert!(
            db.governed_pool().try_acquire().is_none(),
            "governed pool admitted a checkout beyond its configured size"
        );
        drop(held);
        db.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_and_deadline_cannot_poison_or_indefinitely_delay_reuse() {
        let (db, alice, bea) = protected_fixture().await;
        let held = hold_all_but_one_governed_slot(&db).await;

        // Force an unwind after principal installation and progress-handler
        // registration on the sole available governed-pool connection.
        // Transaction drop queues rollback; pool release must remove every
        // connection-local remnant before Bea can borrow it.
        let panic_result = std::panic::AssertUnwindSafe(async {
            let mut connection = db.governed_pool().acquire().await.unwrap();
            let contract = temp_contract();
            for statement in contract.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            sqlx::query("DELETE FROM temp._query_sql_principal")
                .execute(&mut *connection)
                .await
                .unwrap();
            let mut transaction = connection.begin().await.unwrap();
            sqlx::query(
                "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
                 VALUES (1, 'alice', 0, 0, 1, '2026-08-31T00:00:00.000Z')",
            )
            .execute(&mut *transaction)
            .await
            .unwrap();
            {
                let mut handle = transaction.lock_handle().await.unwrap();
                handle.set_progress_handler(PROGRESS_OPS, || true);
            }
            panic!("synthetic query handler unwind");
        })
        .catch_unwind()
        .await;
        assert!(panic_result.is_err());
        let after_unwind = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_unwind), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());

        let runaway = query_sql_owned(
            db.clone(),
            alice,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".into(),
        );
        assert!(tokio::time::timeout(Duration::from_millis(5), runaway)
            .await
            .is_err());
        let started = Instant::now();
        let result = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&result), [BEA_PRIVATE_ID]);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    #[tokio::test]
    async fn agent_activity_and_claims_enforce_authority_lifecycle_and_visibility() {
        let (db, alice, bea) = protected_fixture().await;
        for (account, person, root) in [
            ("alice", ALICE_PRIVATE_ID, ALICE_PRIVATE_ID),
            ("bea", BEA_PRIVATE_ID, BEA_PRIVATE_ID),
        ] {
            sqlx::query(
                "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
                 VALUES(?,?,?,'2026-08-31T00:00:00.000Z')",
            )
            .bind(account)
            .bind(person)
            .bind(root)
            .execute(db.write_pool())
            .await
            .unwrap();
        }

        let current_run = "scout-chair-a748b2";
        let stale_run = "scout-chair-b748b2";
        let current = crate::control::ensure_agent_run(
            &db,
            current_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let stale = crate::control::ensure_agent_run(
            &db,
            stale_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        assert_ne!(current.activity_id, stale.activity_id);

        // A credential supplied to the public query API cannot self-assert
        // activity.read. The transport-established member authority is a
        // separate, unsafe construction seam.
        let unauthorized = query_sql(&db, &alice, "SELECT run_key FROM agent_activity")
            .await
            .unwrap();
        assert_eq!(unauthorized.row_count, 0);
        // SAFETY: exercising the transport-only bit without a live membership
        // demonstrates that database admission remains independently required.
        let departed =
            unsafe { QueryPrincipal::activity_reader_unchecked("departed", Vec::new(), true) };
        assert_eq!(
            query_sql(&db, &departed, "SELECT run_key FROM agent_activity")
                .await
                .unwrap()
                .row_count,
            0
        );
        // SAFETY: this test models the authenticated hosted ingress after it
        // has admitted Bea's live member context; no SQL argument controls it.
        let bea_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        let two_runs = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,run_key,principal_ref,principal_display_name FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap()
        ;
        assert_eq!(two_runs.row_count, 2);
        let mut visible_run_keys = two_runs
            .rows
            .iter()
            .map(|row| row["run_key"].as_str().unwrap())
            .collect::<Vec<_>>();
        visible_run_keys.sort_unstable();
        assert_eq!(visible_run_keys, [current_run, stale_run]);
        assert!(two_runs
            .rows
            .iter()
            .all(|row| row["principal_ref"] == "native:workspace-member:alice"));
        assert!(two_runs
            .rows
            .iter()
            .all(|row| row["principal_display_name"].is_null()));

        // A guest on the same roster keeps attribution presence but sees no
        // agent activity: the admission consults membership, not just roster.
        let guest_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                false,
            )
        };
        let no_runs = query_sql(
            &db,
            &guest_activity,
            "SELECT activity_id FROM agent_activity",
        )
        .await
        .unwrap();
        assert_eq!(no_runs.row_count, 0);

        // Portable member_contexts survive hosted offboarding. A current
        // roster that omits Alice must therefore suppress her lifecycle even
        // while that stale projection remains in the workspace file.
        let bea_after_alice_departed = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        assert_eq!(
            query_sql(
                &db,
                &bea_after_alice_departed,
                "SELECT run_key FROM agent_activity",
            )
            .await
            .unwrap()
            .row_count,
            0
        );

        // The inference clock is execution-owned: advancing only observed_at
        // flips appears_active while every factual timestamp stays byte-stable.
        let started = chrono::DateTime::parse_from_rfc3339(&current.started_at).unwrap();
        let within = (started + chrono::Duration::minutes(4))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let expired = (started + chrono::Duration::minutes(6))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut clock_connection = db.governed_pool().acquire().await.unwrap();
        for statement in temp_contract()
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            sqlx::query(statement)
                .execute(&mut *clock_connection)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT OR REPLACE INTO temp._query_sql_principal
             (singleton,account_id,trusted_local_bypass,activity_read,is_member,observed_at)
             VALUES (1,'bea',0,1,1,?)",
        )
        .bind(&within)
        .execute(&mut *clock_connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR REPLACE INTO temp._query_sql_activity_members(account_id,member_ref)
             VALUES ('alice','native:workspace-member:alice'),
                    ('bea','native:workspace-member:bea')",
        )
        .execute(&mut *clock_connection)
        .await
        .unwrap();
        // This second predicate stands in for a held `now_ms()` bind: it
        // stays identical while the activity view's observed_at advances.
        // A live clock probe must therefore exclude this relation.
        let held_clock = started.timestamp_millis();
        let fresh: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT started_at,last_observed_activity_at,ended_at,appears_active
               FROM temp.agent_activity WHERE activity_id=? AND ? > 0",
        )
        .bind(&current.activity_id)
        .bind(held_clock)
        .fetch_one(&mut *clock_connection)
        .await
        .unwrap();
        sqlx::query("UPDATE temp._query_sql_principal SET observed_at=? WHERE singleton=1")
            .bind(&expired)
            .execute(&mut *clock_connection)
            .await
            .unwrap();
        let expired_row: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT started_at,last_observed_activity_at,ended_at,appears_active
               FROM temp.agent_activity WHERE activity_id=? AND ? > 0",
        )
        .bind(&current.activity_id)
        .bind(held_clock)
        .fetch_one(&mut *clock_connection)
        .await
        .unwrap();
        assert_eq!(
            (&fresh.0, &fresh.1, &fresh.2),
            (&expired_row.0, &expired_row.1, &expired_row.2)
        );
        assert_eq!((fresh.3, expired_row.3), (1, 0));
        drop(clock_connection);

        // An inactive run older than the fixed observation window disappears;
        // explicit closure remains visible but can never appear active.
        sqlx::query(
            "UPDATE agent_runs SET started_at='2020-01-01T00:00:00.000Z' WHERE activity_id=?",
        )
        .bind(&stale.activity_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE agent_runs
                SET started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-10 minutes')
              WHERE activity_id=?",
        )
        .bind(&current.activity_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls
             (id,tool,run_key,actor,outcome,started_at,ended_at)
             VALUES ('cross-account-spoof','get_dashboard',?,'bea','ok',
                     strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 minute'),
                     strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 minute'))",
        )
        .bind(current_run)
        .execute(db.write_pool())
        .await
        .unwrap();
        let lifecycle = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(lifecycle.row_count, 1);
        assert_eq!(lifecycle.rows[0]["activity_id"], current.activity_id);
        assert!(lifecycle.rows[0]["ended_at"].is_null());
        assert_eq!(
            lifecycle.rows[0]["appears_active"], 0,
            "a different account cannot refresh an admitted run by reusing its key"
        );

        let presence_sql =
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id";
        let (before_claims, before_claim_receipt) =
            governed_query(&db, bea_activity.clone(), presence_sql).await;
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let claim = |record_id: &str, action: &str| {
            json!({
                "record_id": record_id,
                "action": action,
                "run_key": current_run,
            })
        };
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(ALICE_PRIVATE_ID, "claim"),
            )
            .await
            .unwrap();
        let (after_hidden_claim, after_hidden_claim_receipt) =
            governed_query(&db, bea_activity.clone(), presence_sql).await;
        assert_eq!(after_hidden_claim.rows, before_claims.rows);
        assert_eq!(after_hidden_claim.row_count, before_claims.row_count);
        assert_eq!(
            after_hidden_claim.rows[0]["activity_id"],
            current.activity_id
        );
        assert_eq!(
            (
                after_hidden_claim_receipt.content_event_seq,
                after_hidden_claim_receipt.lifecycle_event_seq,
                &after_hidden_claim_receipt.authorization_boundary,
                after_hidden_claim_receipt.transient_watermark,
                after_hidden_claim_receipt.transient_available,
            ),
            (
                before_claim_receipt.content_event_seq,
                before_claim_receipt.lifecycle_event_seq,
                &before_claim_receipt.authorization_boundary,
                before_claim_receipt.transient_watermark,
                before_claim_receipt.transient_available,
            ),
            "a hidden claim must not perturb the presence receipt; observed_at is execution-owned"
        );

        // Changing only record visibility changes the claims join, never the
        // already-admitted presence bytes.
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let after_unhide = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_unhide.rows, after_hidden_claim.rows);
        assert_eq!(
            query_sql(
                &db,
                &bea_activity,
                "SELECT claim_id FROM agent_activity_claims ORDER BY claim_id",
            )
            .await
            .unwrap()
            .row_count,
            1
        );
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        let after_rehide = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_rehide.rows, after_hidden_claim.rows);

        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "claim"),
            )
            .await
            .unwrap();
        let visible_claim: String = sqlx::query_scalar(
            "SELECT event.id FROM content_events event
               JOIN content_event_claim_meta claim_meta ON claim_meta.event_seq = event.seq
              WHERE event.record_id=? AND event.type='record.updated'
                AND claim_meta.claim_class = 'claim' ORDER BY event.seq DESC LIMIT 1",
        )
        .bind(COMMON_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "release"),
            )
            .await
            .unwrap();

        let claims = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,activity_id,record_id,claimed_at,released_at,is_current FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(claims.row_count, 1, "Alice's private claim must be absent");
        assert_eq!(claims.rows[0]["claim_id"], visible_claim);
        assert_eq!(claims.rows[0]["activity_id"], current.activity_id);
        assert_eq!(claims.rows[0]["record_id"], COMMON_ID);
        assert!(claims.rows[0]["released_at"].is_string());
        assert_eq!(claims.rows[0]["is_current"], 0);

        // Claim/release are admitted activity, but cannot perturb presence
        // membership or ordering.
        let after_claims = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_claims.row_count, before_claims.row_count);
        assert_eq!(after_claims.rows[0]["activity_id"], current.activity_id);

        crate::control::close_agent_run(&db, current_run, "alice")
            .await
            .unwrap();
        let closed = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert!(closed.rows[0]["ended_at"].is_string());
        assert_eq!(closed.rows[0]["appears_active"], 0);
        let post_close_claim = registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "claim"),
            )
            .await
            .unwrap_err();
        assert!(post_close_claim.to_string().contains("run is closed"));

        sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
            .execute(db.write_pool())
            .await
            .unwrap();
        let durable_only = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(durable_only.rows, closed.rows);

        // Preserve the fixture's ordinary caller-relative assertions elsewhere.
        assert_eq!(bea.credential(), "bea");
    }

    type ActorRow = (Option<String>, Option<String>, Option<String>);

    /// A record named `name`, viewable by exactly `viewers`, optionally bound
    /// to `account` as its person.
    async fn actors_person(db: &Db, id: &str, name: &str, viewers: &[&str], account: Option<&str>) {
        create_record(
            db,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": name,
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:actors",
            id,
            viewers
                .iter()
                .map(|viewer| AllowEntry::account(*viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
        if let Some(account) = account {
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1)",
            )
            .bind(id)
            .bind(account)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
    }

    /// One history event on `record_id` attributed to `actor`, so the actor
    /// has acted wherever that record is visible.
    async fn actors_event(db: &Db, record_id: &str, actor: &str) {
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
             VALUES ('actors-acted-' || (SELECT COUNT(*) FROM content_events), ?, 'record.updated', '{}', ?,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 'legacy_unknown')",
        )
        .bind(record_id)
        .bind(actor)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn actor_directory(db: &Db, principal: &QueryPrincipal) -> Vec<ActorRow> {
        query_sql(
            db,
            principal,
            "SELECT actor, person_id, display_name FROM actors ORDER BY actor",
        )
        .await
        .unwrap()
        .rows
        .iter()
        .map(|row| {
            (
                row["actor"].as_str().map(str::to_owned),
                row["person_id"].as_str().map(str::to_owned),
                row["display_name"].as_str().map(str::to_owned),
            )
        })
        .collect()
    }

    fn named(actor: &str, person: &str, name: &str) -> ActorRow {
        (
            Some(actor.to_owned()),
            Some(person.to_owned()),
            Some(name.to_owned()),
        )
    }

    fn unnamed(actor: &str) -> ActorRow {
        (Some(actor.to_owned()), None, None)
    }

    /// `actors` re-derives from current state on every execution: archive
    /// keeps a person visible, deletion and binding removal withdraw the
    /// name, and a transferred binding follows the new person's visibility.
    /// A viewer whose own person is invisible to them keeps their own row
    /// with a NULL identity.
    #[tokio::test]
    async fn actors_follow_lifecycle_and_binding_changes() {
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000011";
        const P_BEA: &str = "9e795ac7-0000-4000-8000-000000000012";
        const P_CAL: &str = "9e795ac7-0000-4000-8000-000000000013";
        const P_VERA: &str = "9e795ac7-0000-4000-8000-000000000014";
        const P_SPARE: &str = "9e795ac7-0000-4000-8000-000000000015";
        const P_SECRET: &str = "9e795ac7-0000-4000-8000-000000000016";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(
            &db,
            P_ALICE,
            "Alice Person",
            &["alice", "bea"],
            Some("alice"),
        )
        .await;
        actors_person(&db, P_BEA, "Bea Person", &["alice", "bea"], Some("bea")).await;
        actors_person(&db, P_CAL, "Cal Person", &["alice", "cal"], Some("cal")).await;
        actors_person(&db, P_VERA, "Vera Person", &["alice"], Some("vera")).await;
        actors_person(&db, P_SPARE, "Spare Person", &["alice", "bea"], None).await;
        actors_person(&db, P_SECRET, "Secret Person", &["alice"], None).await;
        // Everyone acts on one record they can all see.
        const SHARED: &str = "9e795ac7-0000-4000-8000-000000000017";
        actors_person(
            &db,
            SHARED,
            "Shared",
            &["alice", "bea", "cal", "vera"],
            None,
        )
        .await;
        for actor in ["alice", "bea", "cal", "vera"] {
            actors_event(&db, SHARED, actor).await;
        }
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let cal = QueryPrincipal::authenticated("cal", true);
        let vera = QueryPrincipal::authenticated("vera", true);

        // Vera's own person is visible to Alice but not to Vera herself: her
        // own row stays, with no identity, and Bea never learns of her.
        assert_eq!(actor_directory(&db, &vera).await, [unnamed("vera")]);
        assert_eq!(
            actor_directory(&db, &alice).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("bea", P_BEA, "Bea Person"),
                named("cal", P_CAL, "Cal Person"),
                named("vera", P_VERA, "Vera Person"),
            ]
        );

        // Archive is lifecycle, not access: the person stays visible and named.
        crate::store::archive_record(&db, P_BEA).await.unwrap();
        assert!(actor_directory(&db, &alice)
            .await
            .contains(&named("bea", P_BEA, "Bea Person")));
        assert_eq!(
            actor_directory(&db, &bea).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("bea", P_BEA, "Bea Person"),
            ]
        );

        // Deletion withdraws the person: Cal disappears for Alice, and Cal
        // keeps only his own unnamed row.
        assert_eq!(
            actor_directory(&db, &cal).await,
            [named("cal", P_CAL, "Cal Person")]
        );
        delete_record(&db, P_CAL).await.unwrap();
        assert!(!actor_directory(&db, &alice)
            .await
            .iter()
            .any(|row| row.0.as_deref() == Some("cal")));
        assert_eq!(actor_directory(&db, &cal).await, [unnamed("cal")]);

        // Removing Bea's binding withdraws her from others and her own name.
        sqlx::query("DELETE FROM bindings WHERE system = 'account' AND identifier = 'bea'")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(!actor_directory(&db, &alice)
            .await
            .iter()
            .any(|row| row.0.as_deref() == Some("bea")));
        assert_eq!(
            actor_directory(&db, &bea).await,
            [named("alice", P_ALICE, "Alice Person"), unnamed("bea")]
        );

        // Transferring Alice's binding moves her name with it, under the new
        // person's visibility: to a person Bea can see, then to one she cannot.
        for (person, bea_sees) in [(P_SPARE, true), (P_SECRET, false)] {
            sqlx::query(
                "UPDATE bindings SET record_id = ? WHERE system = 'account' AND identifier = 'alice'",
            )
            .bind(person)
            .execute(db.write_pool())
            .await
            .unwrap();
            let name = if bea_sees {
                "Spare Person"
            } else {
                "Secret Person"
            };
            assert!(actor_directory(&db, &alice)
                .await
                .contains(&named("alice", person, name)));
            let for_bea = actor_directory(&db, &bea).await;
            if bea_sees {
                assert_eq!(
                    for_bea,
                    [named("alice", P_SPARE, "Spare Person"), unnamed("bea")]
                );
            } else {
                assert_eq!(for_bea, [unnamed("bea")]);
            }
        }
    }

    /// Every statement shape over `actors` is authorized (`count(*)`,
    /// self-joins, CTE cross joins, joins to history), which the view's
    /// load-bearing WHERE term secures. Shapes that read an `actors` column
    /// see the caller's rows. Shapes that read none are pinned as they
    /// behave today, empty, pending task d8d7e9b.
    #[tokio::test]
    async fn actors_statement_shapes_resolve_and_column_less_reads_see_no_rows() {
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000031";
        const P_BEA: &str = "9e795ac7-0000-4000-8000-000000000032";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(
            &db,
            P_ALICE,
            "Alice Person",
            &["alice", "bea"],
            Some("alice"),
        )
        .await;
        actors_person(&db, P_BEA, "Bea Person", &["alice", "bea"], Some("bea")).await;
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
             VALUES ('actors-shape-event', ?, 'record.updated', '{}', 'bea',
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1, 'legacy_unknown')",
        )
        .bind(P_ALICE)
        .execute(db.write_pool())
        .await
        .unwrap();
        actors_event(&db, P_ALICE, "alice").await;
        let alice = QueryPrincipal::authenticated("alice", true);
        for (sql, column, expected) in [
            // Reading any `actors` column makes it a dependency: correct rows.
            ("SELECT count(actor) AS v FROM actors", "v", json!(2)),
            (
                "SELECT count(*) AS v FROM actors WHERE actor IS NOT NULL",
                "v",
                json!(2),
            ),
            (
                "SELECT count(*) AS v FROM actors a1, actors a2 WHERE a1.actor IS NOT NULL AND a2.actor IS NOT NULL",
                "v",
                json!(4),
            ),
            (
                "SELECT count(*) AS v FROM actors a1 JOIN actors a2 ON a1.actor = a2.actor",
                "v",
                json!(2),
            ),
            (
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 3) \
                 SELECT sum(x) AS v FROM n CROSS JOIN actors WHERE actors.actor IS NOT NULL",
                "v",
                json!(12),
            ),
            // A USING join to history reads no `actors` column of its own,
            // but history fills the actor set, so it still counts correctly.
            (
                "SELECT count(e.id) AS v FROM content_events e JOIN actors a USING (actor) \
                 WHERE e.id = 'actors-shape-event'",
                "v",
                json!(1),
            ),
            // Known limitation, shared with every on-demand relation (task
            // d8d7e9b): a statement that reads no `actors` column is admitted
            // but sees the relation empty, never another caller's rows.
            ("SELECT count(*) AS v FROM actors", "v", json!(0)),
            (
                "WITH wanted(actor) AS (VALUES('bea')) \
                 SELECT count(*) AS v FROM wanted JOIN actors USING (actor)",
                "v",
                json!(0),
            ),
            (
                "SELECT count(*) AS v FROM actors a1, actors a2",
                "v",
                json!(0),
            ),
            (
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 3) \
                 SELECT sum(x) AS v FROM n CROSS JOIN actors",
                "v",
                json!(null),
            ),
            (
                "SELECT a.display_name AS v FROM content_events e JOIN actors a USING (actor) \
                 WHERE e.id = 'actors-shape-event'",
                "v",
                json!("Bea Person"),
            ),
        ] {
            let result = query_sql(&db, &alice, sql)
                .await
                .unwrap_or_else(|error| panic!("{sql}: {error}"));
            assert_eq!(result.rows[0][column], expected, "{sql}");
        }
    }

    /// The reviewer's statement: a CTE named `messages_awaiting_reply` read
    /// without a column. Main runs it without preparing the expectation
    /// evaluator, which needs a bound member and fails for a local caller.
    const MESSAGES_CTE_SQL: &str = "SELECT id FROM records WHERE EXISTS (\
        WITH messages_awaiting_reply(x) AS (VALUES(1)), \
             records AS (SELECT count(*) AS n FROM messages_awaiting_reply) \
        SELECT n FROM records)";

    /// Statements whose CTEs borrow on-demand relation names run, ad hoc and
    /// on the saved path, for callers with no account, person or principal
    /// bindings, and return exactly what the plain read returns. Neither
    /// shape prepares anything for the borrowed name, as on main.
    #[tokio::test]
    async fn phantom_cte_statements_run_for_callers_without_bindings() {
        const VISIBLE: &str = "9e795ac7-0000-4000-8000-000000000051";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(&db, VISIBLE, "Unbound note", &["nobody"], None).await;
        let actors_cte = "SELECT id FROM records WHERE EXISTS (\
            WITH actors(x) AS (VALUES(1)), \
                 records AS (SELECT count(*) AS n FROM actors) \
            SELECT n FROM records)";
        // A CTE named `actors` is not the relation: nothing prepares the
        // actor table for it.
        assert!(!validated_relation_dependencies(actors_cte)
            .unwrap()
            .contains("actors"));
        // SAFETY: the trusted-local boundary is the ordinary local caller.
        let local = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let nobody = QueryPrincipal::authenticated("nobody", false);
        let ids = |result: &SqlResult| {
            let mut ids = result
                .rows
                .iter()
                .map(|row| row["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            ids.sort();
            ids
        };
        for principal in [local, nobody.clone()] {
            let plain = ids(&query_sql(&db, &principal, "SELECT id FROM records")
                .await
                .unwrap());
            assert!(!plain.is_empty());
            for sql in [actors_cte, MESSAGES_CTE_SQL] {
                let ad_hoc = query_sql(&db, &principal, sql)
                    .await
                    .unwrap_or_else(|error| panic!("{sql}: {error}"));
                assert_eq!(ids(&ad_hoc), plain, "{sql}");
                let (saved, _) = governed_query(&db, principal.clone(), sql).await;
                assert_eq!(ids(&saved), plain, "{sql}");
            }
        }
        assert_eq!(
            ids(&query_sql(&db, &nobody, "SELECT id FROM records")
                .await
                .unwrap()),
            [VISIBLE]
        );
    }

    /// The dependency set decides every on-demand preparation, `actors`
    /// included, and is exactly main's rule. Each expectation is written out,
    /// not derived from the scanner under test: a relation read without any
    /// column is normally not a dependency, and neither is a same-named CTE.
    /// Task items are the deliberate exception because Turso loads them only
    /// when this dependency is present.
    #[test]
    fn dependency_set_matches_main_for_column_less_and_cte_reads() {
        let set = |names: &[&str]| {
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<std::collections::BTreeSet<_>>()
        };
        for (sql, dependencies) in [
            (
                "SELECT count(*) AS c FROM body_task_items",
                set(&["body_task_items"]),
            ),
            ("SELECT 1 FROM body_task_items", set(&["body_task_items"])),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM links)",
                set(&["records"]),
            ),
            ("SELECT actor FROM actors", set(&["actors"])),
            ("SELECT count(actor) AS c FROM actors", set(&["actors"])),
            // SQLite credits a USING column to the left operand, so a join
            // that reads no other `actors` column depends on history alone.
            // History fills the actor set, so the join still filters right.
            (
                "SELECT e.id FROM content_events e JOIN actors a USING (actor)",
                set(&["content_events"]),
            ),
            (
                "SELECT e.id, a.display_name FROM content_events e JOIN actors a USING (actor)",
                set(&["actors", "content_events"]),
            ),
            ("SELECT count(*) AS c FROM actors", set(&[])),
            ("SELECT count(*) AS c FROM actors a1, actors a2", set(&[])),
            (
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 3) \
                 SELECT sum(x) AS v FROM n CROSS JOIN actors",
                set(&[]),
            ),
            ("SELECT count(*) AS c FROM agent_activity", set(&[])),
            ("SELECT count(*) AS c FROM content_events", set(&[])),
            (
                "SELECT id FROM records WHERE EXISTS (WITH actors(x) AS (VALUES(1)), records AS (SELECT count(*) AS n FROM actors) SELECT n FROM records)",
                set(&["records"]),
            ),
            (MESSAGES_CTE_SQL, set(&["records"])),
            (
                "SELECT id FROM records WHERE EXISTS (WITH agent_activity(x) AS (VALUES(1)), records AS (SELECT count(*) AS n FROM agent_activity) SELECT n FROM records)",
                set(&["records"]),
            ),
            (
                "WITH actors AS (SELECT id FROM records) SELECT id FROM actors",
                set(&["records"]),
            ),
            (
                "WITH agent_activity AS (SELECT id FROM records) SELECT id FROM agent_activity",
                set(&["records"]),
            ),
        ] {
            assert_eq!(
                validated_relation_dependencies(sql).unwrap_or_else(|error| panic!("{sql}: {error}")),
                dependencies,
                "{sql}"
            );
        }
    }

    /// Member preflight (c323277 rev 8 §2.3 `query_sql`): forbidden relations
    /// deny with the relation name even for column-less `COUNT(*)`/`EXISTS`,
    /// `WHERE 0` and `LIMIT 0`; served relations, same-named CTEs, comments
    /// and literals never deny. Only shapes the existing two-phase validator
    /// already accepts appear here — rejected shapes stay rejected upstream
    /// and are not asserted as positives.
    #[test]
    fn heading_dependencies_distinguish_population_reads_from_cte_shadows() {
        let expected = BTreeSet::from(["body_block_headings".to_owned()]);
        for sql in [
            "SELECT title FROM body_block_headings",
            "SELECT count(*) AS n FROM body_block_headings",
            "SELECT count(*) AS n FROM body_block_headings WHERE 0",
            "SELECT * FROM body_block_headings LIMIT 0",
            "SELECT EXISTS(SELECT 1 FROM body_block_headings) AS n",
        ] {
            assert_eq!(
                validated_relation_dependencies(sql).unwrap(),
                expected,
                "{sql}"
            );
            assert_eq!(
                validated_relation_dependencies_legacy_saved_sql(sql).unwrap(),
                expected,
                "{sql}"
            );
        }
        for sql in [
            "WITH body_block_headings AS (SELECT 1 AS x) SELECT x FROM body_block_headings",
            "SELECT 'body_block_headings' AS x",
            "SELECT 1 AS x -- body_block_headings",
        ] {
            assert!(
                validated_relation_dependencies(sql).unwrap().is_empty(),
                "{sql}"
            );
            assert!(
                validated_relation_dependencies_legacy_saved_sql(sql)
                    .unwrap()
                    .is_empty(),
                "{sql}"
            );
        }
    }

    #[tokio::test]
    async fn facet_keys_population_and_statement_share_deadline() {
        let db = crate::create_database(":memory:").await.unwrap();
        let principal = QueryPrincipal::authenticated("alice", true);
        let request = || QuerySqlRequest {
            sql: "SELECT count(*) AS n FROM facet_keys".into(),
            parameters: vec![],
        };
        let error = FACET_TEST_EXHAUST_AFTER_POPULATION
            .scope(
                true,
                query_sql_request_owned(db.clone(), principal.clone(), request()),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("query_sql [timeout]"), "{error}");
        let mut tx = db.write_pool().begin().await.unwrap();
        let error = FACET_TEST_EXHAUST_AFTER_POPULATION
            .scope(true, query_sql_request_in(&mut tx, principal, request()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("query_sql [timeout]"), "{error}");
        let n: i64 = sqlx::query_scalar("SELECT 42")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(n, 42);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn facet_keys_schema_loader_interrupt_is_timeout() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        tx.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, || false);
        let error = crate::query::cascade::schema_config_rows_in(&mut tx)
            .await
            .unwrap_err();
        tx.lock_handle().await.unwrap().remove_progress_handler();
        assert!(error.to_string().contains("query_sql [timeout]"), "{error}");
        tx.rollback().await.unwrap();
    }

    #[test]
    fn facet_keys_grouping_collapses_unanchored_homes_and_excludes_reserved_keys() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TEMP TABLE records(id TEXT,type TEXT,kind TEXT,home_id TEXT);
            CREATE TEMP TABLE facet_values(record_id TEXT,key TEXT);
            CREATE TEMP TABLE schema_config(applies_to_collection_id TEXT);
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<8000)
            INSERT INTO records SELECT 'r'||i,'WorkItem','task','home'||i FROM n;
            INSERT INTO facet_values SELECT id,key FROM records CROSS JOIN
              (SELECT 'area' AS key UNION ALL SELECT 'priority' UNION ALL SELECT 'lifecycle' UNION ALL SELECT 'archived');").unwrap();
        let read = || {
            conn.prepare(facet_key_groups_sql())
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let groups = read();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|(home, key, n)| home.is_none()
            && matches!(key.as_str(), "area" | "priority")
            && *n == 8000));
        conn.execute("INSERT INTO schema_config VALUES ('home1')", [])
            .unwrap();
        let groups = read();
        assert_eq!(groups.len(), 4);
        assert_eq!(
            groups
                .iter()
                .filter(|(home, _, n)| home.as_deref() == Some("home1") && *n == 1)
                .count(),
            2
        );
    }

    #[test]
    fn facet_keys_dependency_and_member_schema_gate() {
        for sql in [
            "SELECT key FROM facet_keys",
            "SELECT count(*) FROM facet_keys",
            "SELECT 1 FROM facet_keys WHERE 0",
            "SELECT * FROM facet_keys LIMIT 0",
        ] {
            assert!(
                validated_relation_dependencies(sql)
                    .unwrap()
                    .contains("facet_keys"),
                "{sql}"
            );
            assert!(member_denied_requirement(sql).unwrap().is_none(), "{sql}");
            assert!(member_reads_schema_config(sql).unwrap(), "{sql}");
        }
        let shadow = "WITH facet_keys(key) AS (SELECT 'local') SELECT key FROM facet_keys";
        assert!(!validated_relation_dependencies(shadow)
            .unwrap()
            .contains("facet_keys"));
        assert!(!member_reads_schema_config(shadow).unwrap());
    }

    #[test]
    fn member_preflight_denies_forbidden_and_spares_shadows() {
        let denied = |sql: &str| {
            member_denied_requirement(sql).unwrap_or_else(|error| panic!("{sql}: {error}"))
        };
        // Forbidden: column reads, counts, EXISTS, zero-row shapes.
        for (sql, requirement) in [
            (
                "SELECT title FROM body_block_headings",
                "body_block_headings",
            ),
            (
                "SELECT count(*) AS c FROM body_block_headings",
                "body_block_headings",
            ),
            (
                "SELECT count(*) AS c FROM body_block_headings WHERE 0",
                "body_block_headings",
            ),
            (
                "SELECT * FROM body_block_headings LIMIT 0",
                "body_block_headings",
            ),
            (
                "SELECT EXISTS(SELECT 1 FROM body_block_headings) AS n",
                "body_block_headings",
            ),
            (
                "SELECT config_id FROM schema_config_json_nodes",
                "schema_config_json_nodes",
            ),
            (
                "SELECT count(*) AS c FROM schema_config_json_nodes",
                "schema_config_json_nodes",
            ),
            (
                "SELECT count(*) AS c FROM schema_config_json_nodes WHERE 0",
                "schema_config_json_nodes",
            ),
            (
                "SELECT * FROM schema_config_json_nodes WHERE 0 LIMIT 0",
                "schema_config_json_nodes",
            ),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM schema_config_json_nodes)",
                "schema_config_json_nodes",
            ),
            ("SELECT local_seq FROM content_events", "content_events"),
            ("SELECT count(*) AS c FROM content_events", "content_events"),
            (
                "SELECT count(*) AS c FROM content_events WHERE 0",
                "content_events",
            ),
            (
                "SELECT * FROM content_events WHERE 0 LIMIT 0",
                "content_events",
            ),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM content_events)",
                "content_events",
            ),
            (
                "SELECT event_seq FROM facet_observations",
                "facet_observations",
            ),
            (
                "SELECT count(*) AS c FROM facet_observations",
                "facet_observations",
            ),
            ("SELECT actor FROM actors", "actors"),
            ("SELECT count(*) AS c FROM actors", "actors"),
            ("SELECT count(*) AS c FROM agent_activity", "agent_activity"),
            (
                "SELECT count(*) AS c FROM agent_activity_claims",
                "agent_activity_claims",
            ),
            (
                "SELECT message_id FROM messages_awaiting_reply",
                "messages_awaiting_reply",
            ),
            (
                "SELECT count(*) AS c FROM messages_awaiting_reply",
                "messages_awaiting_reply",
            ),
            (
                "SELECT relationship_id FROM effective_relationships",
                "effective_relationships",
            ),
            (
                "SELECT count(*) AS c FROM effective_relationships",
                "effective_relationships",
            ),
            ("SELECT run_key FROM runs", "runs"),
            ("SELECT count(*) AS c FROM runs", "runs"),
            ("SELECT intent FROM run_intents", "run_intents"),
            (
                "SELECT count(*) AS c FROM body_task_items",
                "body_task_items",
            ),
            (
                "SELECT e.id FROM content_events e JOIN actors a USING (actor)",
                "actors",
            ),
        ] {
            assert_eq!(denied(sql).as_deref(), Some(requirement), "{sql}");
        }
        // Served: rows, counts, zero-row shapes, literals and aliases.
        for sql in [
            "WITH body_block_headings AS (SELECT 1 AS x) SELECT count(*) AS c FROM body_block_headings",
            "SELECT 'body_block_headings' AS v",
            "SELECT id FROM records -- body_block_headings",
            "WITH schema_config_json_nodes AS (SELECT 1 AS x) SELECT count(*) AS c FROM schema_config_json_nodes",
            "SELECT 'schema_config_json_nodes' AS v",
            "SELECT id FROM records -- schema_config_json_nodes",

            "SELECT id FROM records",
            "SELECT count(*) AS c FROM records",
            "SELECT * FROM records WHERE 0 LIMIT 0",
            "SELECT id FROM links",
            "SELECT count(*) AS c FROM facet_values",
            "SELECT * FROM facet_times",
            "SELECT relation_name FROM catalog_relations ORDER BY relation_name",
            "SELECT column_name FROM catalog_columns ORDER BY relation_name, column_name",
            "SELECT 1 AS seq",
            "SELECT 'rec:123' AS v",
            "SELECT 'obs:456' AS v",
            "SELECT 'content_events' AS v",
            "SELECT id FROM records -- content_events",
            "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM links)",
            "WITH actors AS (SELECT id FROM records) SELECT id FROM actors",
            "WITH content_events AS (SELECT 1 AS x) SELECT count(*) AS c FROM content_events",
            "WITH content_events AS (SELECT 1 AS x) SELECT * FROM content_events",
            "SELECT id FROM records WHERE EXISTS (WITH actors(x) AS (VALUES(1)), records AS (SELECT count(*) AS n FROM actors) SELECT n FROM records)",
        ] {
            assert_eq!(denied(sql), None, "{sql}");
        }
    }

    /// A CTE named after an on-demand relation is what the statement reads
    /// within its scope, even when the real relation is also prepared.
    #[tokio::test]
    async fn cte_named_after_an_on_demand_relation_reads_the_cte() {
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000041";
        const P_BEA: &str = "9e795ac7-0000-4000-8000-000000000042";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(&db, P_ALICE, "Alice Person", &["alice"], Some("alice")).await;
        actors_person(&db, P_BEA, "Bea Person", &["alice"], Some("bea")).await;
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("actors-cte-link".into()),
                source_id: P_ALICE.into(),
                target_id: P_BEA.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        actors_event(&db, P_ALICE, "alice").await;
        actors_event(&db, P_BEA, "bea").await;
        let alice = QueryPrincipal::authenticated("alice", true);
        for (sql, expected) in [
            (
                format!("SELECT id AS v FROM records WHERE id = '{P_ALICE}' AND EXISTS (SELECT 1 FROM links)"),
                json!(P_ALICE),
            ),
            // The real `actors` holds two rows for Alice. The CTE holds one.
            (
                format!(
                    "SELECT id AS v FROM records WHERE id = '{P_ALICE}' AND EXISTS \
                     (WITH actors(x) AS (VALUES(1)), records AS (SELECT count(*) AS n FROM actors) \
                      SELECT n FROM records WHERE n = 1)"
                ),
                json!(P_ALICE),
            ),
            (
                "WITH actors(x) AS (VALUES(1),(2),(3)) SELECT count(x) AS v FROM actors".to_owned(),
                json!(3),
            ),
            (
                format!("WITH actors AS (SELECT id FROM records WHERE id = '{P_BEA}') SELECT id AS v FROM actors"),
                json!(P_BEA),
            ),
            (
                format!("WITH agent_activity AS (SELECT id FROM records WHERE id = '{P_BEA}') SELECT id AS v FROM agent_activity"),
                json!(P_BEA),
            ),
            // The real relation next to a same-named CTE in another scope.
            (
                "SELECT count(actor) AS v FROM actors WHERE EXISTS \
                 (WITH actors(x) AS (VALUES(1)) SELECT x FROM actors)"
                    .to_owned(),
                json!(2),
            ),
        ] {
            let result = query_sql(&db, &alice, &sql)
                .await
                .unwrap_or_else(|error| panic!("{sql}: {error}"));
            assert_eq!(result.row_count, 1, "{sql}");
            assert_eq!(result.rows[0]["v"], expected, "{sql}");
        }
    }

    /// The per-execution actor table lives on a pooled governed connection.
    /// A failed, timed-out or cancelled execution for Alice must never leave
    /// her directory behind for the next principal on the same connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actors_table_is_not_reused_after_error_or_cancellation() {
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000021";
        const P_BEA: &str = "9e795ac7-0000-4000-8000-000000000022";
        const P_HARRIET: &str = "9e795ac7-0000-4000-8000-000000000023";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(&db, P_ALICE, "Alice Person", &["alice"], Some("alice")).await;
        actors_person(&db, P_BEA, "Bea Person", &["bea"], Some("bea")).await;
        actors_person(
            &db,
            P_HARRIET,
            "Harriet Hidden",
            &["alice"],
            Some("harriet"),
        )
        .await;
        for (record, actor) in [(P_ALICE, "alice"), (P_BEA, "bea"), (P_HARRIET, "harriet")] {
            actors_event(&db, record, actor).await;
        }
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let bea_only = [named("bea", P_BEA, "Bea Person")];
        let held = hold_all_but_one_governed_slot(&db).await;

        // An engine error after the actor table is populated.
        let error = query_sql(
            &db,
            &alice,
            "SELECT actor FROM actors WHERE abs(-9223372036854775808) > 0",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("integer overflow"), "{error}");
        assert_eq!(actor_directory(&db, &bea).await, bea_only);

        // A statement that runs into the query deadline.
        let runaway = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS total FROM n CROSS JOIN actors WHERE actors.actor IS NOT NULL";
        assert!(query_sql(&db, &alice, runaway).await.is_err());
        assert_eq!(actor_directory(&db, &bea).await, bea_only);

        // A caller that abandons the statement mid-flight.
        let abandoned = query_sql_owned(db.clone(), alice.clone(), runaway.into());
        assert!(tokio::time::timeout(Duration::from_millis(200), abandoned)
            .await
            .is_err());
        assert_eq!(actor_directory(&db, &bea).await, bea_only);
        // A column-less read prepares nothing, and sees an empty relation
        // rather than rows a previous caller left on the connection.
        assert_eq!(
            actor_directory(&db, &alice).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("harriet", P_HARRIET, "Harriet Hidden"),
            ]
        );
        assert_eq!(
            query_sql(&db, &bea, "SELECT count(*) AS v FROM actors")
                .await
                .unwrap()
                .rows[0]["v"],
            json!(0)
        );
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    /// Q-b1 (decision 0052432): the directory lists only members who have
    /// acted where the caller can see it. A visible bound person with no
    /// history, history only on records the caller cannot see, and history
    /// whose actor's person is hidden all leave the actor out. An unbound
    /// caller's own visible event lists them with no identity.
    #[tokio::test]
    async fn actors_lists_only_members_with_visible_history() {
        const SHARED: &str = "9e795ac7-0000-4000-8000-000000000061";
        const HIDDEN_DOC: &str = "9e795ac7-0000-4000-8000-000000000062";
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000063";
        const P_NORA: &str = "9e795ac7-0000-4000-8000-000000000064";
        const P_HECTOR: &str = "9e795ac7-0000-4000-8000-000000000065";
        const P_IVY: &str = "9e795ac7-0000-4000-8000-000000000066";
        let db = crate::create_database(":memory:").await.unwrap();
        actors_person(&db, SHARED, "Shared", &["alice", "bea", "uma"], None).await;
        actors_person(&db, HIDDEN_DOC, "Alice only", &["alice"], None).await;
        actors_person(
            &db,
            P_ALICE,
            "Alice Person",
            &["alice", "bea", "uma"],
            Some("alice"),
        )
        .await;
        // Never acts anywhere.
        actors_person(
            &db,
            P_NORA,
            "Nora Never",
            &["alice", "bea", "uma"],
            Some("nora"),
        )
        .await;
        // Acts only on a record Bea and Uma cannot see.
        actors_person(
            &db,
            P_HECTOR,
            "Hector Hidden History",
            &["alice", "bea", "uma"],
            Some("hector"),
        )
        .await;
        // Acts on the shared record, but only Alice can see her person.
        actors_person(&db, P_IVY, "Ivy Invisible", &["alice"], Some("ivy")).await;
        actors_event(&db, SHARED, "alice").await;
        actors_event(&db, HIDDEN_DOC, "hector").await;
        actors_event(&db, SHARED, "ivy").await;
        // Uma has no binding at all.
        actors_event(&db, SHARED, "uma").await;

        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let uma = QueryPrincipal::authenticated("uma", true);
        assert_eq!(
            actor_directory(&db, &alice).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("hector", P_HECTOR, "Hector Hidden History"),
                named("ivy", P_IVY, "Ivy Invisible"),
            ]
        );
        assert_eq!(
            actor_directory(&db, &bea).await,
            [named("alice", P_ALICE, "Alice Person")]
        );
        assert_eq!(
            actor_directory(&db, &uma).await,
            [named("alice", P_ALICE, "Alice Person"), unnamed("uma")]
        );
        // Bea's history on the shared record carries Ivy and Uma unnamed.
        let history = query_sql(
            &db,
            &bea,
            &format!(
                "SELECT actor FROM content_events WHERE record_id = '{SHARED}' AND id LIKE 'actors-acted-%' ORDER BY local_seq"
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            history
                .rows
                .iter()
                .map(|row| row["actor"].clone())
                .collect::<Vec<_>>(),
            [json!("alice"), json!(null), json!(null)]
        );
        // For every caller the directory is a subset of disclosed history.
        for principal in [&alice, &bea, &uma] {
            assert_eq!(
                query_sql(
                    &db,
                    principal,
                    "SELECT actor FROM actors WHERE actor NOT IN \
                     (SELECT actor FROM content_events WHERE actor IS NOT NULL)",
                )
                .await
                .unwrap()
                .row_count,
                0
            );
        }
    }

    /// b1c8a94: `actors` discloses exactly what `get_history` would, per
    /// viewer. The fixture has two
    /// members (Alice, Bea), a guest (Gus), a member whose person is visible
    /// to Alice but hidden from Bea (Harriet), and a member account with no
    /// person binding at all (Orphan).
    #[tokio::test]
    async fn actors_relation_names_only_disclosable_actors_per_viewer() {
        const SHARED: &str = "9e795ac7-0000-4000-8000-000000000001";
        const P_ALICE: &str = "9e795ac7-0000-4000-8000-000000000002";
        const P_BEA: &str = "9e795ac7-0000-4000-8000-000000000003";
        const P_GUS: &str = "9e795ac7-0000-4000-8000-000000000004";
        const P_HARRIET: &str = "9e795ac7-0000-4000-8000-000000000005";
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, name, viewers, account) in [
            (
                SHARED,
                "Shared",
                vec!["alice", "bea", "gus", "orphan"],
                None,
            ),
            (
                P_ALICE,
                "Alice Person",
                vec!["alice", "bea", "gus"],
                Some("alice"),
            ),
            (P_BEA, "Bea Person", vec!["alice", "bea"], Some("bea")),
            (P_GUS, "Gus Guest", vec!["alice", "bea", "gus"], Some("gus")),
            (P_HARRIET, "Harriet Hidden", vec!["alice"], Some("harriet")),
        ] {
            actors_person(&db, id, name, &viewers, account).await;
        }
        for actor in ["alice", "bea", "harriet", "gus", "orphan"] {
            sqlx::query(
                "INSERT INTO content_events
                    (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
                 VALUES (?, ?, 'record.updated', '{}', ?,
                         strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || (SELECT COUNT(*) FROM content_events) || ' seconds'),
                         1, 'legacy_unknown')",
            )
            .bind(format!("actors-event-{actor}"))
            .bind(SHARED)
            .bind(actor)
            .execute(db.write_pool())
            .await
            .unwrap();
        }

        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let gus = QueryPrincipal::authenticated("gus", false);
        let orphan = QueryPrincipal::authenticated("orphan", true);
        assert_eq!(
            actor_directory(&db, &alice).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("bea", P_BEA, "Bea Person"),
                named("gus", P_GUS, "Gus Guest"),
                named("harriet", P_HARRIET, "Harriet Hidden"),
            ]
        );
        // Harriet's person is hidden from Bea, so Bea cannot name her, and
        // cannot even learn that she exists: the row is absent, not blank.
        assert_eq!(
            actor_directory(&db, &bea).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("bea", P_BEA, "Bea Person"),
                named("gus", P_GUS, "Gus Guest"),
            ]
        );
        assert_eq!(
            query_sql(
                &db,
                &bea,
                "SELECT actor FROM actors WHERE actor = 'harriet' OR actor = 'orphan'",
            )
            .await
            .unwrap()
            .row_count,
            0
        );
        // The guest sees exactly the people their own grants make visible.
        assert_eq!(
            actor_directory(&db, &gus).await,
            [
                named("alice", P_ALICE, "Alice Person"),
                named("gus", P_GUS, "Gus Guest"),
            ]
        );
        // An account with no person binding is disclosable to itself, and
        // its name stays NULL: the raw account token is never offered.
        assert_eq!(actor_directory(&db, &orphan).await, [unnamed("orphan")]);

        // Bylines: joining history to actors names disclosed actors and
        // leaves hidden ones NULL in both relations.
        let bylines = format!(
            "SELECT e.actor, a.display_name FROM content_events e \
             LEFT JOIN actors a ON a.actor = e.actor \
             WHERE e.record_id = '{SHARED}' AND e.id LIKE 'actors-event-%' \
             ORDER BY e.local_seq"
        );
        let bylines_for = |principal: QueryPrincipal| {
            let db = db.clone();
            let bylines = bylines.clone();
            async move {
                query_sql(&db, &principal, &bylines)
                    .await
                    .unwrap()
                    .rows
                    .iter()
                    .map(|row| {
                        (
                            row["actor"].as_str().map(str::to_owned),
                            row["display_name"].as_str().map(str::to_owned),
                        )
                    })
                    .collect::<Vec<_>>()
            }
        };
        let some = |value: &str| Some(value.to_owned());
        assert_eq!(
            bylines_for(bea.clone()).await,
            [
                (some("alice"), some("Alice Person")),
                (some("bea"), some("Bea Person")),
                (None, None),
                (some("gus"), some("Gus Guest")),
                (None, None),
            ]
        );
        assert_eq!(
            bylines_for(alice.clone()).await,
            [
                (some("alice"), some("Alice Person")),
                (some("bea"), some("Bea Person")),
                (some("harriet"), some("Harriet Hidden")),
                (some("gus"), some("Gus Guest")),
                (None, None),
            ]
        );
        assert_eq!(
            bylines_for(orphan.clone()).await,
            [
                (None, None),
                (None, None),
                (None, None),
                (None, None),
                (some("orphan"), None),
            ]
        );
    }

    /// Task 6867ce6 fixture: two members (Alice, Bea), a guest (Gus), a
    /// member whose person only Alice can see (Harriet), and a member account
    /// with no person binding (Orphan). Each owns one run. Alice's run started
    /// in January and is closed, so it is far outside any 24-hour window, and
    /// declared twice, with a third declaration on her key spoofed by Bea's
    /// account. Returns the run keys by owner.
    async fn runs_fixture(db: &Db) -> std::collections::BTreeMap<&'static str, &'static str> {
        for (id, name, viewers, account) in [
            (
                RUNS_P_ALICE,
                "Alice Person",
                vec!["alice", "bea", "gus"],
                "alice",
            ),
            (RUNS_P_BEA, "Bea Person", vec!["alice", "bea"], "bea"),
            (RUNS_P_GUS, "Gus Guest", vec!["alice", "bea", "gus"], "gus"),
            (RUNS_P_HARRIET, "Harriet Hidden", vec!["alice"], "harriet"),
        ] {
            actors_person(db, id, name, &viewers, Some(account)).await;
        }
        let runs = std::collections::BTreeMap::from([
            ("alice", "scout-chair-a11ce1"),
            ("bea", "scout-chair-bea001"),
            ("gus", "scout-chair-905001"),
            ("harriet", "scout-chair-4a8810"),
            ("orphan", "scout-chair-0a9ha1"),
        ]);
        for (account, run_key) in &runs {
            let reported = if *account == "alice" {
                crate::control::ReportedRunIdentity {
                    client_name: Some("claude-code".into()),
                    client_version: Some("2.1.0".into()),
                    model: Some("claude-opus-5-5".into()),
                }
            } else {
                crate::control::ReportedRunIdentity::default()
            };
            crate::control::ensure_agent_run(db, run_key, account, reported)
                .await
                .unwrap();
        }
        crate::control::close_agent_run(db, runs["alice"], "alice")
            .await
            .unwrap();
        sqlx::query(
            "UPDATE agent_runs SET started_at='2026-01-05T09:00:00.000Z',
                                   ended_at='2026-01-05T10:00:00.000Z'
              WHERE run_key=?",
        )
        .bind(runs["alice"])
        .execute(db.write_pool())
        .await
        .unwrap();
        for (id, run_key, actor, intent, at) in [
            (
                "ri-alice-1",
                runs["alice"],
                "alice",
                "First framing",
                "2026-01-05T09:00:01.000Z",
            ),
            (
                "ri-alice-spoof",
                runs["alice"],
                "bea",
                "Spoofed aim",
                "2026-01-05T09:10:00.000Z",
            ),
            (
                "ri-alice-2",
                runs["alice"],
                "alice",
                "Reframed aim",
                "2026-01-05T09:20:00.000Z",
            ),
            (
                "ri-harriet",
                runs["harriet"],
                "harriet",
                "Harriet private plan",
                "2026-01-06T09:00:00.000Z",
            ),
            (
                "ri-orphan",
                runs["orphan"],
                "orphan",
                "Orphan plan",
                "2026-01-07T09:00:00.000Z",
            ),
            (
                "ri-gus",
                runs["gus"],
                "gus",
                "Guest plan",
                "2026-01-08T09:00:00.000Z",
            ),
        ] {
            sqlx::query(
                "INSERT INTO read_log_calls (id, tool, run_key, actor, intent, outcome, started_at, ended_at)
                 VALUES (?, 'set_intent', ?, ?, ?, 'ok', ?, ?)",
            )
            .bind(id)
            .bind(run_key)
            .bind(actor)
            .bind(intent)
            .bind(at)
            .bind(at)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        // A failed declaration and a non-declaring call never count.
        for (id, tool, outcome) in [
            ("ri-alice-failed", "set_intent", "error"),
            ("ri-alice-read", "get_record", "ok"),
        ] {
            sqlx::query(
                "INSERT INTO read_log_calls (id, tool, run_key, actor, intent, outcome, started_at, ended_at)
                 VALUES (?, ?, ?, 'alice', 'Not a declaration', ?, '2026-01-05T09:30:00.000Z', '2026-01-05T09:30:00.000Z')",
            )
            .bind(id)
            .bind(tool)
            .bind(runs["alice"])
            .bind(outcome)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        runs
    }

    const RUNS_P_ALICE: &str = "6867ce60-0000-4000-8000-000000000001";
    const RUNS_P_BEA: &str = "6867ce60-0000-4000-8000-000000000002";
    const RUNS_P_GUS: &str = "6867ce60-0000-4000-8000-000000000003";
    const RUNS_P_HARRIET: &str = "6867ce60-0000-4000-8000-000000000004";

    async fn run_owners(db: &Db, principal: &QueryPrincipal) -> Vec<(String, Option<String>)> {
        query_sql(
            db,
            principal,
            "SELECT run_key, principal_person_id FROM runs ORDER BY run_key",
        )
        .await
        .unwrap()
        .rows
        .iter()
        .map(|row| {
            (
                row["run_key"].as_str().unwrap().to_owned(),
                row["principal_person_id"].as_str().map(str::to_owned),
            )
        })
        .collect()
    }

    async fn single_count(db: &Db, principal: &QueryPrincipal, sql: &str) -> i64 {
        query_sql(db, principal, sql)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .rows[0]["n"]
            .as_i64()
            .unwrap()
    }

    /// 6867ce6: for members, `runs` and `run_intents` admit a run exactly
    /// when `get_history` would disclose its owner (decision 0052432,
    /// Q-6867). Guests see only their own runs for now. A hidden run adds no
    /// row and no count, the owner is only ever a visible person id, and
    /// there is no time window.
    #[tokio::test]
    async fn runs_disclose_owners_by_the_history_rule_per_viewer() {
        let db = crate::create_database(":memory:").await.unwrap();
        let runs = runs_fixture(&db).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let gus = QueryPrincipal::authenticated("gus", false);
        let orphan = QueryPrincipal::authenticated("orphan", true);
        let owned = |account: &str, person: Option<&str>| {
            (runs[account].to_owned(), person.map(str::to_owned))
        };
        let mut expected_alice = vec![
            owned("alice", Some(RUNS_P_ALICE)),
            owned("bea", Some(RUNS_P_BEA)),
            owned("gus", Some(RUNS_P_GUS)),
            owned("harriet", Some(RUNS_P_HARRIET)),
        ];
        expected_alice.sort();
        assert_eq!(run_owners(&db, &alice).await, expected_alice);
        let mut expected_bea = vec![
            owned("alice", Some(RUNS_P_ALICE)),
            owned("bea", Some(RUNS_P_BEA)),
            owned("gus", Some(RUNS_P_GUS)),
        ];
        expected_bea.sort();
        assert_eq!(run_owners(&db, &bea).await, expected_bea);
        // Guests see only their own runs for now (orchestrator decision on
        // 6867ce6, pending Richard): Gus can View Alice's person, and still
        // sees none of her runs or intents.
        assert_eq!(
            run_owners(&db, &gus).await,
            [owned("gus", Some(RUNS_P_GUS))]
        );
        let gus_intents = query_sql(&db, &gus, "SELECT run_key, intent FROM run_intents")
            .await
            .unwrap();
        assert_eq!(
            gus_intents.rows,
            [json!({"run_key": runs["gus"], "intent": "Guest plan"})]
        );
        // The narrowing is the run relations' alone: `actors` still names
        // Alice to Gus exactly as on main once she acts where he can see.
        actors_event(&db, RUNS_P_ALICE, "alice").await;
        assert_eq!(
            actor_directory(&db, &gus).await,
            [named("alice", RUNS_P_ALICE, "Alice Person")]
        );
        // No person binding: the account's own runs, with no identity.
        assert_eq!(run_owners(&db, &orphan).await, [owned("orphan", None)]);

        // Hidden runs contribute nothing to any count or probe.
        for (principal, runs_n, intents_n) in
            [(&alice, 4, 4), (&bea, 3, 3), (&gus, 1, 1), (&orphan, 1, 1)]
        {
            assert_eq!(
                single_count(&db, principal, "SELECT count(*) AS n FROM runs").await,
                runs_n
            );
            assert_eq!(
                single_count(&db, principal, "SELECT count(run_key) AS n FROM runs").await,
                runs_n
            );
            assert_eq!(
                single_count(&db, principal, "SELECT count(*) AS n FROM run_intents").await,
                intents_n
            );
            assert_eq!(
                single_count(&db, principal, "SELECT count(intent) AS n FROM run_intents").await,
                intents_n
            );
        }
        let probe = |account: &str| {
            format!(
                "SELECT (SELECT count(*) FROM runs WHERE run_key = '{}') + \
                        (SELECT count(*) FROM run_intents WHERE run_key = '{}') AS n",
                runs[account], runs[account]
            )
        };
        for (principal, hidden) in [
            (&bea, "harriet"),
            (&gus, "harriet"),
            (&gus, "alice"),
            (&gus, "bea"),
        ] {
            assert_eq!(
                single_count(&db, principal, &probe(hidden)).await,
                0,
                "{hidden}"
            );
        }

        // Nothing in any row is a raw account id, a sequence or an activity id.
        let every_row = query_sql(
            &db,
            &alice,
            "SELECT r.*, i.ordinal, i.intent, i.declared_at_ms FROM runs r \
             LEFT JOIN run_intents i USING (run_key) ORDER BY r.run_key, i.ordinal",
        )
        .await
        .unwrap();
        assert_eq!(
            every_row.columns,
            [
                "run_key",
                "principal_person_id",
                "started_at_ms",
                "ended_at_ms",
                "reported_model",
                "reported_client",
                "model_assurance",
                "ordinal",
                "intent",
                "declared_at_ms",
            ]
        );
        let activity_ids: Vec<String> = sqlx::query_scalar("SELECT activity_id FROM agent_runs")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        for row in &every_row.rows {
            for (column, value) in row.as_object().unwrap() {
                assert!(!column.contains("seq"), "{column}");
                if let Some(text) = value.as_str() {
                    for account in ["alice", "bea", "gus", "harriet", "orphan"] {
                        assert_ne!(text, account, "{column} leaks an account id");
                    }
                    assert!(!activity_ids.iter().any(|id| id == text), "{column}");
                }
            }
        }
    }

    /// Query plan of `sql` for one viewer, read on a governed connection with
    /// the real TEMP contract installed (governed SQL itself refuses EXPLAIN).
    async fn governed_plan(db: &Db, account: &str, is_member: bool, sql: &str) -> Vec<String> {
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        for statement in temp_contract()
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query(statement).execute(&mut *tx).await.unwrap();
        }
        sqlx::query("DELETE FROM temp._query_sql_principal")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
             VALUES (1, ?, 0, 0, ?, '2026-09-29T00:00:00.000Z')",
        )
        .bind(account)
        .bind(is_member)
        .execute(&mut *tx)
        .await
        .unwrap();
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}"))
                .fetch_all(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        plan.into_iter().map(|(_, _, _, detail)| detail).collect()
    }

    /// Rows and coarse VM work (one progress callback per `PROGRESS_OPS`
    /// caller VM ops) of one governed execution.
    async fn rows_and_vm_work(db: &Db, principal: &QueryPrincipal, sql: &str) -> (Vec<Value>, u64) {
        let callbacks = Arc::new(AtomicU64::new(0));
        let result = query_sql_request_owned_with_vm_work(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: sql.into(),
                parameters: vec![],
            },
            Some(callbacks.clone()),
            false,
        )
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
        (result.rows, callbacks.load(Ordering::Relaxed))
    }

    /// 6867ce6 review (anchor lesson 6): work over `runs` and `run_intents`
    /// scales only with what the viewer may see. 20k runs and 20k
    /// declarations behind each of two owners neither the guest nor the member
    /// may see (an unbound account, and Harriet, bound to a person only Alice
    /// can see) change neither the rows nor, beyond one progress interval, the VM work,
    /// and the plans visit runs by admitted account and declarations by
    /// admitted run, never by scanning either table.
    #[tokio::test]
    async fn run_relation_work_does_not_grow_with_hidden_volume() {
        let db = crate::create_database(":memory:").await.unwrap();
        runs_fixture(&db).await;
        let gus = QueryPrincipal::authenticated("gus", false);
        let bea = QueryPrincipal::authenticated("bea", true);
        let statements = [
            "SELECT count(*) AS n FROM runs",
            "SELECT count(*) AS n FROM run_intents",
            "SELECT run_key, started_at_ms FROM runs ORDER BY started_at_ms, run_key",
            "SELECT run_key, ordinal, intent FROM run_intents ORDER BY run_key, ordinal",
        ];
        let mut before = Vec::new();
        for principal in [&gus, &bea] {
            for sql in statements {
                before.push(rows_and_vm_work(&db, principal, sql).await);
            }
        }
        // Hidden volume: 20k runs and 20k declarations of an account bound to
        // no person, so no viewer here may attribute it. Inserted directly
        // (the views never read the control events these would reference).
        {
            let mut connection = db.write_pool().acquire().await.unwrap();
            sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO agent_runs (activity_id, run_key, account_id, started_at, start_event_id, start_event_seq)
                 SELECT 'ghost-activity-' || i, 'ghost-run-' || i, 'ghost', '2026-02-01T00:00:00.000Z',
                        'ghost-start-' || i, 900000000 + i
                   FROM n",
            )
            .execute(&mut *connection)
            .await
            .unwrap();
            // The same volume behind Harriet, who is bound to a person record
            // only Alice can see: a hidden owner with a real binding.
            sqlx::query(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO agent_runs (activity_id, run_key, account_id, started_at, start_event_id, start_event_seq)
                 SELECT 'shadow-activity-' || i, 'shadow-run-' || i, 'harriet', '2026-02-01T00:00:00.000Z',
                        'shadow-start-' || i, 950000000 + i
                   FROM n",
            )
            .execute(&mut *connection)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO read_log_calls (id, tool, run_key, actor, intent, outcome, started_at, ended_at)
                 SELECT 'hidden-decl-' || run_key, 'set_intent', run_key, account_id, 'Hidden plan', 'ok',
                        started_at, started_at
                   FROM agent_runs WHERE account_id IN ('ghost', 'harriet')
                    AND run_key LIKE '%-run-%'",
            )
            .execute(&mut *connection)
            .await
            .unwrap();
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        let mut after = Vec::new();
        for principal in [&gus, &bea] {
            for sql in statements {
                after.push(rows_and_vm_work(&db, principal, sql).await);
            }
        }
        let labels = ["guest", "member"]
            .iter()
            .flat_map(|viewer| statements.iter().map(move |sql| format!("{viewer}: {sql}")));
        // Report every measurement and plan before judging any of them.
        let mut failures = Vec::new();
        for ((label, (rows_before, work_before)), (rows_after, work_after)) in
            labels.zip(&before).zip(&after)
        {
            eprintln!("VOLUME {label}: vm callbacks {work_before} -> {work_after}");
            if rows_before != rows_after {
                failures.push(format!("{label}: rows changed with hidden volume"));
            }
            if *work_after > work_before + 1 {
                failures.push(format!(
                    "{label}: hidden volume grew VM work {work_before} -> {work_after}"
                ));
            }
        }
        for (account, is_member) in [("gus", false), ("bea", true)] {
            for sql in statements {
                let plan = governed_plan(&db, account, is_member, sql).await;
                eprintln!("PLAN {account} {sql}");
                for line in &plan {
                    eprintln!("PLAN   {line}");
                }
                if plan.iter().any(|line| {
                    line.starts_with("SCAN run")
                        || line.starts_with("SCAN declaration")
                        || line.starts_with("SCAN declared")
                        || line.contains("AUTOMATIC PARTIAL")
                        || (line.contains("AUTOMATIC") && line.contains("declar"))
                }) {
                    failures.push(format!("{account} {sql}: scans a run source"));
                }
                let mut wanted = vec![(
                    "SEARCH run USING",
                    "INDEX idx_agent_runs_account_started (account_id=?)",
                )];
                if sql.contains("run_intents") {
                    wanted.push((
                        "SEARCH declaration USING",
                        "INDEX idx_read_log_calls_run (run_key=?)",
                    ));
                    wanted.push(("SEARCH declared USING", "rowid=?)"));
                }
                for (step, access) in wanted {
                    if !plan
                        .iter()
                        .any(|line| line.starts_with(step) && line.contains(access))
                    {
                        failures.push(format!("{account} {sql}: no `{step} ... {access}`"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// 6867ce6: a January run is listed with its self-declared model and
    /// client, labelled as such, and its intent history in order. The spoofed,
    /// failed and non-declaring calls on the same key are not declarations.
    #[tokio::test]
    async fn runs_list_old_runs_with_self_declared_identity_and_ordered_intents() {
        let db = crate::create_database(":memory:").await.unwrap();
        let runs = runs_fixture(&db).await;
        let bea = QueryPrincipal::authenticated("bea", true);
        let alice_run = query_sql(
            &db,
            &bea,
            &format!(
                "SELECT started_at_ms, ended_at_ms, reported_model, reported_client, model_assurance \
                 FROM runs WHERE run_key = '{}'",
                runs["alice"]
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            alice_run.rows,
            [json!({
                "started_at_ms": 1_767_603_600_000_i64,
                "ended_at_ms": 1_767_607_200_000_i64,
                "reported_model": "claude-opus-5-5",
                "reported_client": "claude-code/2.1.0",
                "model_assurance": "self_declared",
            })]
        );
        // Every run carries the label, whether or not it reported anything.
        let labels = query_sql(
            &db,
            &bea,
            "SELECT DISTINCT model_assurance AS label, count(*) AS n FROM runs GROUP BY model_assurance",
        )
        .await
        .unwrap();
        assert_eq!(labels.rows, [json!({"label": "self_declared", "n": 3})]);
        let open = query_sql(
            &db,
            &bea,
            &format!(
                "SELECT ended_at_ms, reported_model, reported_client FROM runs WHERE run_key = '{}'",
                runs["bea"]
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            open.rows,
            [json!({"ended_at_ms": null, "reported_model": null, "reported_client": null})]
        );

        let intents = query_sql(
            &db,
            &bea,
            &format!(
                "SELECT ordinal, intent, declared_at_ms FROM run_intents \
                 WHERE run_key = '{}' ORDER BY ordinal",
                runs["alice"]
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            intents.rows,
            [
                json!({"ordinal": 1, "intent": "First framing", "declared_at_ms": 1_767_603_601_000_i64}),
                json!({"ordinal": 2, "intent": "Reframed aim", "declared_at_ms": 1_767_604_800_000_i64}),
            ]
        );
        // Keyset paging on (started_at_ms, run_key) needs no sequence.
        let first_page = query_sql(
            &db,
            &bea,
            "SELECT run_key, started_at_ms FROM runs ORDER BY started_at_ms, run_key LIMIT 1",
        )
        .await
        .unwrap();
        assert_eq!(first_page.rows[0]["run_key"], runs["alice"]);
        let next_page = query_sql_request_owned(
            db.clone(),
            bea.clone(),
            QuerySqlRequest {
                sql: "SELECT run_key FROM runs WHERE started_at_ms > ?1 OR (started_at_ms = ?1 AND run_key > ?2) \
                      ORDER BY started_at_ms, run_key"
                    .into(),
                parameters: vec![
                    QuerySqlParameter::Integer {
                        value: Some(first_page.rows[0]["started_at_ms"].to_string()),
                    },
                    QuerySqlParameter::Text {
                        value: Some(runs["alice"].into()),
                    },
                ],
            },
        )
        .await
        .unwrap();
        assert_eq!(next_page.row_count, 2);
        assert!(next_page
            .rows
            .iter()
            .all(|row| row["run_key"] != runs["alice"]));
    }

    /// 6867ce6: `run_intents` reads the optional read log. Without the table
    /// it is empty rather than failing, in every statement shape and on both
    /// executors, `runs` is unaffected, and the real view returns once the
    /// table does.
    #[tokio::test]
    async fn run_intents_is_empty_when_the_read_log_is_absent() {
        let db = crate::create_database(":memory:").await.unwrap();
        let runs = runs_fixture(&db).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        assert_eq!(
            single_count(&db, &alice, "SELECT count(intent) AS n FROM run_intents").await,
            4
        );
        sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
            .execute(db.write_pool())
            .await
            .unwrap();
        for sql in [
            "SELECT count(intent) AS n FROM run_intents",
            "SELECT count(*) AS n FROM run_intents",
            "SELECT count(i.ordinal) AS n FROM runs r JOIN run_intents i USING (run_key)",
            "WITH x(v) AS (VALUES(0)) SELECT coalesce(sum(v), 0) AS n FROM x CROSS JOIN run_intents",
        ] {
            assert_eq!(single_count(&db, &alice, sql).await, 0, "{sql}");
        }
        assert_eq!(
            single_count(&db, &alice, "SELECT count(run_key) AS n FROM runs").await,
            4
        );
        let listed = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT r.run_key, i.intent FROM runs r LEFT JOIN run_intents i USING (run_key) \
                 WHERE r.run_key = '{}'",
                runs["alice"]
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            listed.rows,
            [json!({"run_key": runs["alice"], "intent": null})]
        );
        // The caller-transaction core on a warm governed connection (the
        // tab snapshot path): the stand-in lives and dies inside the
        // transaction, and no logical view survives its cleanup.
        {
            let mut connection = db.governed_pool().acquire().await.unwrap();
            let mut tx = connection.begin().await.unwrap();
            let result = query_sql_request_in(
                &mut tx,
                alice.clone(),
                QuerySqlRequest {
                    sql: "SELECT count(intent) AS n FROM run_intents".into(),
                    parameters: vec![],
                },
            )
            .await
            .unwrap();
            assert_eq!(result.rows, [json!({"n": 0})]);
            let leftover: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE name IN ('runs','run_intents','_query_sql_disclosable_persons')",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(leftover, 0);
            tx.rollback().await.unwrap();
        }
        sqlx::query("ALTER TABLE read_log_calls_unavailable RENAME TO read_log_calls")
            .execute(db.write_pool())
            .await
            .unwrap();
        // Pooled governed connections keep no empty stand-in.
        for _ in 0..4 {
            assert_eq!(
                single_count(&db, &alice, "SELECT count(intent) AS n FROM run_intents").await,
                4
            );
        }
    }

    /// 6867ce6 review: `run_intents` pins `idx_read_log_calls_run`. A read log
    /// that exists without that index reads as empty, like an absent log,
    /// rather than failing on the missing pinned index, and `runs` is
    /// unaffected.
    #[tokio::test]
    async fn run_intents_is_empty_when_its_run_index_is_missing() {
        let db = crate::create_database(":memory:").await.unwrap();
        runs_fixture(&db).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        sqlx::query("DROP INDEX idx_read_log_calls_run")
            .execute(db.write_pool())
            .await
            .unwrap();
        for sql in [
            "SELECT count(intent) AS n FROM run_intents",
            "SELECT count(*) AS n FROM run_intents",
            "SELECT count(i.ordinal) AS n FROM runs r JOIN run_intents i USING (run_key)",
        ] {
            assert_eq!(single_count(&db, &alice, sql).await, 0, "{sql}");
        }
        assert_eq!(
            single_count(&db, &alice, "SELECT count(run_key) AS n FROM runs").await,
            4
        );
        // Restore it (idempotently: the engine may already have re-created it).
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_read_log_calls_run ON read_log_calls(run_key, seq)",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            single_count(&db, &alice, "SELECT count(intent) AS n FROM run_intents").await,
            4
        );
    }

    /// 6867ce6: an oversized declaration reads as a NULL intent that keeps its
    /// ordinal. Its size is measured without loading it, so it fails neither
    /// the statement at the caller value ceiling nor a cell.
    #[tokio::test]
    async fn oversized_declared_intent_reads_as_null_and_keeps_its_ordinal() {
        let db = crate::create_database(":memory:").await.unwrap();
        let runs = runs_fixture(&db).await;
        let over_cap = "a".repeat(MAX_RUN_INTENT_BYTES + 1);
        let over_ceiling = "b".repeat(MAX_SQLITE_VALUE_BYTES as usize + 1024);
        for (id, intent, at) in [
            (
                "ri-alice-over-cap",
                over_cap.as_str(),
                "2026-01-05T09:40:00.000Z",
            ),
            (
                "ri-alice-over-ceiling",
                over_ceiling.as_str(),
                "2026-01-05T09:50:00.000Z",
            ),
            ("ri-alice-last", "Wrapped up", "2026-01-05T09:55:00.000Z"),
        ] {
            sqlx::query(
                "INSERT INTO read_log_calls (id, tool, run_key, actor, intent, outcome, started_at, ended_at)
                 VALUES (?, 'set_intent', ?, 'alice', ?, 'ok', ?, ?)",
            )
            .bind(id)
            .bind(runs["alice"])
            .bind(intent)
            .bind(at)
            .bind(at)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let at_cap = "c".repeat(MAX_RUN_INTENT_BYTES);
        sqlx::query(
            "INSERT INTO read_log_calls (id, tool, run_key, actor, intent, outcome, started_at, ended_at)
             VALUES ('ri-bea-at-cap', 'set_intent', ?, 'bea', ?, 'ok', '2026-01-09T09:00:00.000Z', '2026-01-09T09:00:00.000Z')",
        )
        .bind(runs["bea"])
        .bind(&at_cap)
        .execute(db.write_pool())
        .await
        .unwrap();
        let bea = QueryPrincipal::authenticated("bea", true);
        let intents = query_sql(
            &db,
            &bea,
            "SELECT run_key, ordinal, intent FROM run_intents ORDER BY run_key, ordinal",
        )
        .await
        .unwrap();
        let alice_rows: Vec<_> = intents
            .rows
            .iter()
            .filter(|row| row["run_key"] == runs["alice"])
            .map(|row| (row["ordinal"].as_i64().unwrap(), row["intent"].clone()))
            .collect();
        assert_eq!(
            alice_rows,
            [
                (1, json!("First framing")),
                (2, json!("Reframed aim")),
                (3, Value::Null),
                (4, Value::Null),
                (5, json!("Wrapped up")),
            ]
        );
        let bea_rows: Vec<_> = intents
            .rows
            .iter()
            .filter(|row| row["run_key"] == runs["bea"])
            .collect();
        assert_eq!(bea_rows.len(), 1);
        assert_eq!(bea_rows[0]["intent"], json!(at_cap));
    }

    /// 6867ce6: the dependency set is exactly main's rule for the two new
    /// relations (a relation is a dependency only when a column of it is
    /// read), and because neither needs preparation every statement shape
    /// over them reads the same rows, column-less ones included.
    #[tokio::test]
    async fn runs_dependencies_follow_main_rule_and_every_shape_reads_the_same_rows() {
        let set = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        for (sql, expected) in [
            ("SELECT run_key FROM runs", set(&["runs"])),
            ("SELECT intent FROM run_intents", set(&["run_intents"])),
            ("SELECT count(*) AS n FROM runs", set(&[])),
            ("SELECT count(*) AS n FROM run_intents", set(&[])),
            (
                "SELECT r.run_key, i.intent FROM runs r JOIN run_intents i USING (run_key)",
                set(&["run_intents", "runs"]),
            ),
            (
                "WITH runs AS (SELECT id FROM records) SELECT id FROM runs",
                set(&["records"]),
            ),
            (
                "WITH run_intents AS (SELECT id FROM records) SELECT id FROM run_intents",
                set(&["records"]),
            ),
        ] {
            assert_eq!(
                validated_relation_dependencies(sql).unwrap(),
                expected,
                "{sql}"
            );
        }

        let db = crate::create_database(":memory:").await.unwrap();
        runs_fixture(&db).await;
        let bea = QueryPrincipal::authenticated("bea", true);
        for (sql, n) in [
            ("SELECT count(*) AS n FROM runs", 3),
            ("SELECT count(*) AS n FROM runs r1, runs r2", 9),
            (
                "SELECT count(*) AS n FROM runs r1 JOIN runs r2 ON r1.run_key = r2.run_key",
                3,
            ),
            (
                "WITH x(v) AS (VALUES(1),(2)) SELECT sum(v) AS n FROM x CROSS JOIN runs",
                9,
            ),
            (
                "WITH x(v) AS (VALUES(1)) SELECT sum(v) AS n FROM x CROSS JOIN run_intents",
                3,
            ),
            (
                "SELECT count(*) AS n FROM run_intents i1, run_intents i2",
                9,
            ),
            (
                "SELECT count(*) AS n FROM runs JOIN run_intents USING (run_key)",
                3,
            ),
        ] {
            assert_eq!(single_count(&db, &bea, sql).await, n, "{sql}");
        }
        // A caller CTE named after either relation is the caller's own table.
        let shadowed = query_sql(
            &db,
            &bea,
            "WITH runs(run_key) AS (VALUES('mine')), run_intents(intent) AS (VALUES('ours')) \
             SELECT run_key, intent FROM runs CROSS JOIN run_intents",
        )
        .await
        .unwrap();
        assert_eq!(
            shadowed.rows,
            [json!({"run_key": "mine", "intent": "ours"})]
        );
    }

    // Design D6 (task b2583dc) fixture ids. Alice's person id has a prefix
    // no other fixture record shares, so a short reference to it resolves
    // uniquely until a visible look-alike is added.
    const D6_P_ALICE: &str = "a11ce000-0000-4000-8000-000000000001";
    const D6_P_BEA: &str = "bea00000-0000-4000-8000-000000000002";
    const D6_P_GUS: &str = "9e500000-0000-4000-8000-000000000003";
    const D6_P_HARRIET: &str = "4a881000-0000-4000-8000-000000000004";
    const D6_M_OPEN: &str = "0e550000-0000-4000-8000-00000000000a";
    const D6_M_TEAM: &str = "0e550000-0000-4000-8000-00000000000b";
    const D6_M_BEA_ONLY: &str = "0e550000-0000-4000-8000-00000000000c";
    const D6_D_REF: &str = "d0c00000-0000-4000-8000-000000000001";
    const D6_D_HIDDEN_REF: &str = "d0c00000-0000-4000-8000-000000000002";
    const D6_ACCOUNTS: [&str; 5] = ["alice", "bea", "gus", "harriet", "orphan"];

    /// A record of `kind` ("person", "message" or "note"), viewable by exactly
    /// `viewers`, optionally owned by a person and bound to an account.
    async fn d6_record(
        db: &Db,
        id: &str,
        kind: &str,
        name: &str,
        viewers: &[&str],
        owner: Option<&str>,
        account: Option<&str>,
    ) {
        create_record(
            db,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": name,
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:d6",
            id,
            viewers
                .iter()
                .map(|viewer| AllowEntry::account(*viewer, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
        let (record_type, record_kind) = match kind {
            "person" => ("Entity", Some("person")),
            "message" => ("Message", None),
            _ => ("Document", Some("note")),
        };
        sqlx::query(
            "UPDATE records SET type = ?, kind = ?, owner_id = COALESCE(?, owner_id) WHERE id = ?",
        )
        .bind(record_type)
        .bind(record_kind)
        .bind(owner)
        .bind(id)
        .execute(db.write_pool())
        .await
        .unwrap();
        if let Some(account) = account {
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1)",
            )
            .bind(id)
            .bind(account)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
    }

    /// An effective principal @-mention of `person` on `message`.
    async fn d6_principal_mention(db: &Db, message: &str, mention_id: &str, person: &str) {
        sqlx::query(
            "INSERT INTO message_mentions
               (message_id, mention_id, target_kind, target_binding, target_record_id,
                span_start, span_end, authored_label, source_event_seq, effective)
             VALUES (?, ?, 'principal', 'native-principal:' || ?, ?, 0, 6, '@someone',
                     (SELECT max(seq) FROM content_events WHERE record_id = ?), 1)",
        )
        .bind(message)
        .bind(mention_id)
        .bind(person)
        .bind(person)
        .bind(message)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    /// One `record_mentions` row: `source` references `lookup_key`.
    async fn d6_reference(db: &Db, source: &str, occurrence: i64, lookup_key: &str) {
        sqlx::query(
            "INSERT INTO record_mentions
               (source_id, occurrence_ix, source_event_seq, span_start, span_end,
                authored_reference, lookup_key, form, parser_version)
             VALUES (?, ?, (SELECT max(seq) FROM content_events WHERE record_id = ?),
                     0, 8, ?, ?, 'bare_hex', 1)",
        )
        .bind(source)
        .bind(occurrence)
        .bind(source)
        .bind(lookup_key)
        .bind(lookup_key)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    /// Advance `account`'s human lane on `message` through the real
    /// awareness writer.
    async fn d6_advance(
        db: &Db,
        account: &str,
        message: &str,
        stage: crate::awareness::HumanStage,
    ) {
        let expected: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT version FROM human_message_awareness
                               WHERE subject_account_id = ? AND message_id = ?), 0)",
        )
        .bind(account)
        .bind(message)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let key = format!("d6-{account}-{message}-{stage:?}");
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::awareness::advance_human(
            &mut tx,
            account,
            message,
            stage,
            expected,
            &key,
            &crate::awareness::VerifiedHumanInteraction {
                nonce: format!("nonce-{key}"),
                executor_ref: "trusted-ui".into(),
            },
            "d6 test",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Apply one preference action for `account` through the real writer.
    async fn d6_prefer(
        db: &Db,
        account: &str,
        message: &str,
        action: crate::awareness::PreferenceAction,
        snoozed_until: Option<&str>,
    ) {
        let expected: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT version FROM message_preferences
                               WHERE subject_account_id = ? AND message_id = ?), 0)",
        )
        .bind(account)
        .bind(message)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let key = format!("d6-pref-{account}-{message}-{expected}");
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::awareness::set_preference(
            &mut tx,
            account,
            message,
            action,
            snoozed_until,
            expected,
            &key,
            "d6 test",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    /// Two members (Alice, Bea), a guest (Gus), a member whose person only
    /// Alice can see (Harriet) and an account with no person (Orphan). Three
    /// Messages: one everyone sees (Alice's), one Alice and Bea see (Bea's,
    /// @-mentioning Alice) and one only Bea sees (Bea's, also @-mentioning
    /// Alice). A note Alice and Bea see references Alice by a short prefix,
    /// and a note only Bea sees references her by full id. Sequences start at
    /// distinctive values so a leak of any of them is recognisable.
    async fn d6_fixture(db: &Db) {
        for (name, start) in [
            ("content_events", 7_700_000_i64),
            ("awareness_events", 7_800_000),
        ] {
            sqlx::query("DELETE FROM sqlite_sequence WHERE name = ?")
                .bind(name)
                .execute(db.write_pool())
                .await
                .unwrap();
            sqlx::query("INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)")
                .bind(name)
                .bind(start)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let everyone = ["alice", "bea", "gus"];
        for (id, name, viewers, account) in [
            (D6_P_ALICE, "Alice Person", &everyone[..], "alice"),
            (D6_P_BEA, "Bea Person", &everyone[..], "bea"),
            (D6_P_GUS, "Gus Guest", &everyone[..], "gus"),
            (D6_P_HARRIET, "Harriet Hidden", &["alice"][..], "harriet"),
        ] {
            d6_record(db, id, "person", name, viewers, None, Some(account)).await;
        }
        d6_record(
            db,
            D6_M_OPEN,
            "message",
            "Hello all",
            &everyone,
            Some(D6_P_ALICE),
            None,
        )
        .await;
        d6_record(
            db,
            D6_M_TEAM,
            "message",
            "Team note",
            &["alice", "bea"],
            Some(D6_P_BEA),
            None,
        )
        .await;
        d6_record(
            db,
            D6_M_BEA_ONLY,
            "message",
            "Bea only",
            &["bea"],
            Some(D6_P_BEA),
            None,
        )
        .await;
        d6_record(
            db,
            D6_D_REF,
            "note",
            "Refers to Alice",
            &["alice", "bea"],
            Some(D6_P_BEA),
            None,
        )
        .await;
        d6_record(
            db,
            D6_D_HIDDEN_REF,
            "note",
            "Hidden reference",
            &["bea"],
            Some(D6_P_BEA),
            None,
        )
        .await;
        d6_principal_mention(db, D6_M_TEAM, "m-team-alice", D6_P_ALICE).await;
        d6_principal_mention(db, D6_M_BEA_ONLY, "m-hidden-alice", D6_P_ALICE).await;
        d6_reference(db, D6_D_REF, 0, "a11ce000").await;
        d6_reference(db, D6_D_REF, 1, "a11ce000-0").await;
        d6_reference(db, D6_D_HIDDEN_REF, 0, D6_P_ALICE).await;
    }

    fn d6_viewers() -> [QueryPrincipal; 5] {
        [
            QueryPrincipal::authenticated("alice", true),
            QueryPrincipal::authenticated("bea", true),
            QueryPrincipal::authenticated("gus", false),
            QueryPrincipal::authenticated("harriet", true),
            QueryPrincipal::authenticated("orphan", true),
        ]
    }

    async fn d6_rows(db: &Db, principal: &QueryPrincipal, sql: &str) -> Vec<Value> {
        query_sql(db, principal, sql)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .rows
    }

    /// D6 3.1: one row per Message the caller can see, carrying only the
    /// caller's own stage, preferences, authorship and mention flag.
    #[tokio::test]
    async fn my_message_state_reports_only_the_callers_own_state() {
        use crate::awareness::{HumanStage, PreferenceAction};
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let [alice, bea, gus, _harriet, orphan] = d6_viewers();
        let sql = "SELECT message_id, stage, unread, is_own, mentioned, flagged, muted, archived, \
                   snoozed_until, snoozed_until_ms, reactable FROM my_message_state ORDER BY message_id";
        let fresh = |id: &str, own: i64, mentioned: i64| {
            json!({
                "message_id": id, "stage": "unsurfaced", "unread": 1 - own, "is_own": own,
                "mentioned": mentioned, "flagged": 0, "muted": 0, "archived": 0,
                "snoozed_until": null, "snoozed_until_ms": null, "reactable": 1
            })
        };
        assert_eq!(
            d6_rows(&db, &alice, sql).await,
            [fresh(D6_M_OPEN, 1, 0), fresh(D6_M_TEAM, 0, 1)]
        );
        assert_eq!(
            d6_rows(&db, &bea, sql).await,
            [
                fresh(D6_M_OPEN, 0, 0),
                fresh(D6_M_TEAM, 1, 0),
                fresh(D6_M_BEA_ONLY, 1, 0)
            ]
        );
        assert_eq!(d6_rows(&db, &gus, sql).await, [fresh(D6_M_OPEN, 0, 0)]);
        assert!(d6_rows(&db, &orphan, sql).await.is_empty());

        // Bea's own writes move only Bea's rows.
        d6_advance(&db, "bea", D6_M_OPEN, HumanStage::Opened).await;
        d6_prefer(&db, "bea", D6_M_TEAM, PreferenceAction::FlagAttention, None).await;
        d6_prefer(&db, "bea", D6_M_TEAM, PreferenceAction::Mute, None).await;
        d6_prefer(
            &db,
            "bea",
            D6_M_TEAM,
            PreferenceAction::Snooze,
            Some("2026-10-01T09:00:00.000Z"),
        )
        .await;
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Presented).await;
        d6_prefer(&db, "gus", D6_M_OPEN, PreferenceAction::Archive, None).await;
        let bea_rows = d6_rows(&db, &bea, sql).await;
        assert_eq!(bea_rows[0]["stage"], "opened");
        assert_eq!(bea_rows[0]["unread"], 0);
        assert_eq!(
            bea_rows[1],
            json!({
                "message_id": D6_M_TEAM, "stage": "unsurfaced", "unread": 0, "is_own": 1,
                "mentioned": 0, "flagged": 1, "muted": 1, "archived": 0,
                "snoozed_until": "2026-10-01T09:00:00.000Z",
                "snoozed_until_ms": 1_790_845_200_000_i64, "reactable": 1
            })
        );
        let alice_rows = d6_rows(&db, &alice, sql).await;
        assert_eq!(alice_rows[0], fresh(D6_M_OPEN, 1, 0));
        assert_eq!(alice_rows[1]["stage"], "presented");
        assert_eq!(alice_rows[1]["unread"], 1);
        let gus_rows = d6_rows(&db, &gus, sql).await;
        assert_eq!(gus_rows[0]["archived"], 1);
        assert_eq!(gus_rows[0]["unread"], 0);

        // A federated Message cannot take reactions.
        {
            let mut connection = db.write_pool().acquire().await.unwrap();
            sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO destination_message_ingest
                   (message_id, source_event_id, relay_state, ingest_state, received_at, sender_state)
                 VALUES (?, 'd6-federated', 'collected', 'applied', '2026-09-30T00:00:00.000Z', 'principal_only')",
            )
            .bind(D6_M_TEAM)
            .execute(&mut *connection)
            .await
            .unwrap();
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        let reactable = d6_rows(
            &db,
            &alice,
            "SELECT message_id, reactable FROM my_message_state ORDER BY message_id",
        )
        .await;
        assert_eq!(
            reactable,
            [
                json!({"message_id": D6_M_OPEN, "reactable": 1}),
                json!({"message_id": D6_M_TEAM, "reactable": 0}),
            ]
        );
    }

    const MESSAGES_PAGE_SQL: &str = r#"WITH w AS (SELECT r.id, r.type, r.home_id, r.created_at_ms, r.name, r.body, (SELECT l.target_id FROM links l WHERE l.source_id = r.id AND l.relationship = 'part_of' ORDER BY l.target_id LIMIT 1) AS bearer_id FROM records r WHERE r.type IN ('Message', 'Annotation') AND r.kind IN ('text', 'comment') AND r.deleted_at IS NULL AND (r.created_at_ms < ?1 OR (r.created_at_ms = ?1 AND r.id < ?2)) ORDER BY r.created_at_ms DESC, r.id DESC LIMIT 200) SELECT s.stage AS private_stage, s.archived AS private_archived, s.unread AS private_unread, s.is_own AS private_own, s.mentioned AS private_mentioned, EXISTS(SELECT 1 FROM my_mentions mm WHERE mm.source_id=w.id) AS private_reference, w.id, origin.id AS origin_id, origin.name AS origin_name, a.person_id AS actor_person_id, a.display_name AS actor_name, CASE w.type WHEN 'Message' THEN 'message' ELSE 'comment' END AS kind, w.created_at_ms, w.name AS title, substr(w.body, 1, 1200) AS body, length(w.body) AS body_len, (SELECT e.actor FROM content_events e WHERE e.record_id = w.id AND e.type = 'record.created' ORDER BY e.local_seq LIMIT 1) AS actor, (SELECT e.run_key FROM content_events e WHERE e.record_id = w.id AND e.type = 'record.created' ORDER BY e.local_seq LIMIT 1) AS run_key, (SELECT l.target_id FROM links l WHERE l.source_id = w.id AND l.relationship = 'addressed_to' ORDER BY l.target_id LIMIT 1) AS to_id, (SELECT p.name FROM links l JOIN records p ON p.id = l.target_id WHERE l.source_id = w.id AND l.relationship = 'addressed_to' ORDER BY l.target_id LIMIT 1) AS to_name, (SELECT l.target_id FROM links l WHERE l.source_id = w.id AND l.relationship = 'reply_to' ORDER BY l.target_id LIMIT 1) AS reply_to, w.bearer_id, (SELECT b.type FROM records b WHERE b.id = w.bearer_id) AS bearer_type, (SELECT b.name FROM records b WHERE b.id = w.bearer_id) AS bearer_name, (SELECT v.value FROM facet_values v WHERE v.record_id = w.id AND v.key = 'expectation') AS expectation, (SELECT sum(CASE e.type WHEN 'message.reaction.added.v1' THEN 1 ELSE -1 END) FROM content_events e WHERE e.record_id = w.id AND e.type IN ('message.reaction.added.v1', 'message.reaction.removed.v1')) AS reactions FROM w LEFT JOIN my_message_state s ON s.message_id=w.id LEFT JOIN records origin ON origin.id = w.home_id LEFT JOIN actors a ON a.actor = (SELECT e.actor FROM content_events e WHERE e.record_id = w.id AND e.type = 'record.created' ORDER BY e.local_seq LIMIT 1) ORDER BY w.created_at_ms DESC, w.id DESC LIMIT 200"#;

    /// The Messages v2 PAGE_SQL bounded consumer, including its nested
    /// content/actor reads and private relation joins (b2583dc).
    #[tokio::test]
    async fn messages_bounded_page_private_read_wake_changes_only_own_rows() {
        use crate::awareness::PreferenceAction;
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        sqlx::query("UPDATE records SET kind='text' WHERE type='Message'")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE records SET type='Annotation',kind='comment' WHERE id=?")
            .bind(D6_D_REF)
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO links(id,source_id,target_id,relationship) VALUES('page-comment-bearer',?,?,'part_of')")
            .bind(D6_D_REF).bind(D6_M_TEAM).execute(db.write_pool()).await.unwrap();
        let [alice, bea, ..] = d6_viewers();
        // Kept literal so SQL admission is tested on the shipped page shape.
        let request = || QuerySqlRequest {
            sql: MESSAGES_PAGE_SQL.into(),
            parameters: vec![
                QuerySqlParameter::Integer {
                    value: Some(i64::MAX.to_string()),
                },
                QuerySqlParameter::Text {
                    value: Some("".into()),
                },
            ],
        };
        let before = query_sql_request_owned(db.clone(), alice.clone(), request())
            .await
            .unwrap();
        let other = query_sql_request_owned(db.clone(), bea.clone(), request())
            .await
            .unwrap();
        assert_eq!(
            before.rows.iter().find(|r| r["id"] == D6_M_TEAM).unwrap()["private_unread"],
            1
        );
        assert!(before.rows.iter().any(|r| r["kind"] == "comment"
            && r["private_unread"].is_null()
            && r["private_reference"] == 1));
        let head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        d6_prefer(&db, "alice", D6_M_TEAM, PreferenceAction::MarkRead, None).await;
        let after = query_sql_request_owned(db.clone(), alice, request())
            .await
            .unwrap();
        assert_ne!(before.rows, after.rows);
        assert_eq!(
            after.rows.iter().find(|r| r["id"] == D6_M_TEAM).unwrap()["private_unread"],
            0
        );
        assert_eq!(
            query_sql_request_owned(db.clone(), bea, request())
                .await
                .unwrap()
                .rows,
            other.rows
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT MAX(seq) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            head
        );
    }

    /// Reuse D6's policy anchors and Message templates at the retained 5,000
    /// Message scale. Execute the exact page under production admission and
    /// byte/deadline budgets, and measure VM work independently of wall time.
    #[tokio::test]
    async fn messages_bounded_page_private_read_at_5000_messages() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        sqlx::query("UPDATE records SET kind='text',created_at='2026-10-01T00:00:00.000Z' WHERE type='Message'")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 4997)
            INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id,created_at)
            SELECT printf('scale-message-%05d',n.i),template.type,template.kind,template.name,template.body,
                   template.home_id,template.owner_id,template.policy_anchor_id,'2026-10-06T00:00:00.000Z'
              FROM n JOIN records template ON template.id=CASE n.i%2 WHEN 0 THEN ? ELSE ? END")
            .bind(D6_M_BEA_ONLY).bind(D6_M_TEAM).execute(db.write_pool()).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE type='Message'")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            5000
        );
        let plan = governed_plan(
            &db,
            "bea",
            true,
            &MESSAGES_PAGE_SQL
                .replace("?1", "9223372036854775807")
                .replace("?2", "''"),
        )
        .await;
        assert!(
            !plan.iter().any(|line| line == "SCAN visible_message"
                || line == "MATERIALIZE _query_sql_mention_visible"),
            "{plan:#?}"
        );
        let [alice, bea, ..] = d6_viewers();
        let execute = |principal: QueryPrincipal| {
            let db = db.clone();
            async move {
                let work = Arc::new(AtomicU64::new(0));
                let result = query_sql_request_owned_with_vm_work(
                    db,
                    principal,
                    QuerySqlRequest {
                        sql: MESSAGES_PAGE_SQL.into(),
                        parameters: vec![
                            QuerySqlParameter::Integer {
                                value: Some(i64::MAX.to_string()),
                            },
                            QuerySqlParameter::Text {
                                value: Some("".into()),
                            },
                        ],
                    },
                    Some(work.clone()),
                    false,
                )
                .await
                .unwrap();
                assert_eq!(result.rows.len(), 200);
                assert!(serde_json::to_vec(&result.rows).unwrap().len() < MAX_RESULT_ENCODED_BYTES);
                let callbacks = work.load(Ordering::Relaxed);
                // Bound the 5,000-Message page at 2.5 million caller VM
                // operations, independently of the production deadline and
                // result caps, which remain enabled. No host-speed assertion.
                assert!(
                    callbacks > 0 && callbacks <= 2_500,
                    "page used {callbacks} progress intervals"
                );
                eprintln!("PAGE_SQL 5000: {callbacks} progress intervals");
                (result.rows, callbacks)
            }
        };
        let (before, work_before) = execute(alice.clone()).await;
        let (other, _) = execute(bea.clone()).await;
        // Alice cannot see Bea-only templates; Bea sees both policy cohorts.
        assert!(before.iter().all(|row| row["id"]
            .as_str()
            .unwrap()
            .strip_prefix("scale-message-")
            .unwrap()
            .parse::<i64>()
            .unwrap()
            % 2
            == 1));
        assert!(other.iter().any(|row| row["id"]
            .as_str()
            .unwrap()
            .strip_prefix("scale-message-")
            .unwrap()
            .parse::<i64>()
            .unwrap()
            % 2
            == 0));
        assert!(before.iter().all(|row| row["private_unread"] == 1));
        assert!(other.iter().all(|row| row["private_unread"] == 0));
        let selected = before[0]["id"].as_str().unwrap();
        let head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        d6_prefer(
            &db,
            "alice",
            selected,
            crate::awareness::PreferenceAction::MarkRead,
            None,
        )
        .await;
        let (after, work_after) = execute(alice).await;
        assert_eq!(after[0]["private_unread"], 0);
        assert_eq!(&after[1..], &before[1..]);
        assert_eq!(execute(bea).await.0, other);
        assert!(
            work_after <= work_before + 2,
            "preference changed page work from {work_before} to {work_after}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT MAX(seq) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            head
        );
    }

    #[tokio::test]
    async fn private_read_preferences_match_tools_and_preserve_human_history() {
        use crate::awareness::{HumanStage, PreferenceAction};
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let [alice, bea, ..] = d6_viewers();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let bea_before = d6_rows(
            &db,
            &bea,
            "SELECT * FROM my_message_state ORDER BY message_id",
        )
        .await;
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Opened).await;
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Acknowledged).await;
        let human_before: (String, i64, i64, String, String) = sqlx::query_as(
            "SELECT stage,version,last_event_seq,opened_at,acknowledged_at FROM human_message_awareness WHERE subject_account_id='alice' AND message_id=?",
        ).bind(D6_M_TEAM).fetch_one(db.pool()).await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::awareness::set_routing(
            &mut tx,
            &crate::awareness::MutationContext {
                subject_account_id: "alice",
                authenticated_actor: "alice",
                executor_kind: "system",
                executor_ref: None,
                delegation_ref: None,
                reason_code: "open obligation fixture",
            },
            D6_M_TEAM,
            "open",
            "agent",
            Some("fixture-policy-v1"),
            0,
            "routing-fixture",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let routing_before:(String,String,i64,i64) = sqlx::query_as("SELECT obligation_state,executor_route,version,last_event_seq FROM message_inbox_routing WHERE subject_account_id='alice' AND message_id=?").bind(D6_M_TEAM).fetch_one(db.pool()).await.unwrap();
        let content_before: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (version, preference, expected) in [
            (0, "mark_unread", true),
            (1, "mark_read", false),
            (2, "mark_unread", true),
        ] {
            let receipt = registry.call(db.clone(), crate::mcp::Caller::authenticated("alice"), "manage_messages", json!({
                "action":"set_preference","message_id":D6_M_TEAM,"preference":preference,
                "expected_version":version,"idempotency_key":format!("read-{version}"),"reason":"explicit read preference",
            })).await.unwrap();
            assert_eq!(receipt["version"], version + 1);
            assert_eq!(receipt["unread_override"], expected);
            let tool = registry
                .call(
                    db.clone(),
                    crate::mcp::Caller::authenticated("alice"),
                    "manage_messages",
                    json!({"action":"list_message_state","message_ids":[D6_M_TEAM]}),
                )
                .await
                .unwrap();
            assert_eq!(tool["messages"][0]["human"]["stage"], "acknowledged");
            assert_eq!(tool["messages"][0]["human"]["version"], human_before.1);
            assert_eq!(tool["messages"][0]["mention"]["principal"], true);
            assert_eq!(tool["messages"][0]["attention"]["unread"], expected);
            assert_eq!(tool["messages"][0]["attention"]["version"], version + 1);
            let rows = d6_rows(&db,&alice,"SELECT unread,stage FROM my_message_state WHERE message_id='0e550000-0000-4000-8000-00000000000b'").await;
            assert_eq!(rows[0]["unread"], i64::from(expected));
            assert_eq!(rows[0]["stage"], "acknowledged");
        }
        // Retrying the original mark-read after mark-unread returns its own
        // receipt before checking the stale CAS, without reverting current state.
        let retry = registry.call(db.clone(), crate::mcp::Caller::authenticated("alice"), "manage_messages", json!({
            "action":"set_preference","message_id":D6_M_TEAM,"preference":"mark_read",
            "expected_version":1,"idempotency_key":"read-1","reason":"explicit read preference",
        })).await.unwrap();
        assert_eq!(retry["version"], 2);
        assert_eq!(retry["unread_override"], false);
        assert_eq!(retry["idempotent"], true);
        d6_prefer(&db, "alice", D6_M_TEAM, PreferenceAction::Mute, None).await;
        assert_eq!(
            d6_rows(
                &db,
                &alice,
                "SELECT unread FROM my_message_state WHERE is_own=0"
            )
            .await[0]["unread"],
            1
        );
        d6_prefer(&db, "alice", D6_M_OPEN, PreferenceAction::MarkUnread, None).await;
        assert_eq!(
            d6_rows(
                &db,
                &alice,
                "SELECT unread FROM my_message_state WHERE is_own=1"
            )
            .await[0]["unread"],
            0
        );
        d6_prefer(&db, "alice", D6_M_TEAM, PreferenceAction::Archive, None).await;
        assert_eq!(
            d6_rows(
                &db,
                &alice,
                "SELECT unread FROM my_message_state WHERE is_own=0"
            )
            .await[0]["unread"],
            0
        );
        d6_prefer(&db, "alice", D6_M_TEAM, PreferenceAction::Restore, None).await;
        assert_eq!(
            d6_rows(
                &db,
                &alice,
                "SELECT unread FROM my_message_state WHERE is_own=0"
            )
            .await[0]["unread"],
            1
        );
        assert_eq!(
            d6_rows(
                &db,
                &bea,
                "SELECT * FROM my_message_state ORDER BY message_id"
            )
            .await,
            bea_before
        );
        let human_after: (String,i64,i64,String,String) = sqlx::query_as("SELECT stage,version,last_event_seq,opened_at,acknowledged_at FROM human_message_awareness WHERE subject_account_id='alice' AND message_id=?").bind(D6_M_TEAM).fetch_one(db.pool()).await.unwrap();
        assert_eq!(human_after, human_before);
        assert_eq!(sqlx::query_as::<_,(String,String,i64,i64)>("SELECT obligation_state,executor_route,version,last_event_seq FROM message_inbox_routing WHERE subject_account_id='alice' AND message_id=?").bind(D6_M_TEAM).fetch_one(db.pool()).await.unwrap(),routing_before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT MAX(seq) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            content_before
        );
        crate::awareness::rebuild_projections(&db).await.unwrap();
        assert_eq!(
            d6_rows(
                &db,
                &alice,
                "SELECT unread,stage FROM my_message_state WHERE is_own=0"
            )
            .await,
            [json!({"unread":1,"stage":"acknowledged"})]
        );
        // A caller may neither mutate nor read a hidden viewer's Message.
        assert!(registry.call(db.clone(),crate::mcp::Caller::authenticated("alice"),"manage_messages",json!({"action":"set_preference","message_id":D6_M_BEA_ONLY,"preference":"mark_read","expected_version":0,"idempotency_key":"hidden","reason":"test"})).await.is_err());
        replace_explicit_policy(
            &db,
            "test:d6",
            D6_M_TEAM,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let revoked = registry.call(db.clone(),crate::mcp::Caller::authenticated("alice"),"manage_messages",json!({"action":"set_preference","message_id":D6_M_TEAM,"preference":"mark_read","expected_version":1,"idempotency_key":"read-1","reason":"explicit read preference"})).await.unwrap_err();
        assert!(revoked.to_string().contains("does not exist"), "{revoked}");
        assert!(registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "manage_messages",
                json!({"action":"list_message_state","message_ids":[D6_M_TEAM]})
            )
            .await
            .is_err());
        assert!(d6_rows(
            &db,
            &alice,
            "SELECT unread FROM my_message_state WHERE is_own=0"
        )
        .await
        .is_empty());
        // The own-human rule resolves the same active person in SQL and tools.
        sqlx::query("UPDATE records SET deleted_at='2026-10-06T00:00:00.000Z' WHERE id=?")
            .bind(D6_P_ALICE)
            .execute(db.write_pool())
            .await
            .unwrap();
        let own_tool = registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "manage_messages",
                json!({"action":"list_message_state","message_ids":[D6_M_OPEN]}),
            )
            .await
            .unwrap();
        let own_sql = d6_rows(&db, &alice, "SELECT unread FROM my_message_state").await;
        assert_eq!(own_tool["messages"][0]["attention"]["unread"], true);
        assert_eq!(own_sql, [json!({"unread":1})]);
    }

    /// D6 5.1 and 5.4: no other viewer's awareness write, in any lane, moves
    /// Alice's serialized result for any statement shape over the two
    /// relations, column-less counts, aggregates, self-joins and CTE cross
    /// joins included, and those shapes read real rows rather than an empty
    /// relation.
    #[tokio::test]
    async fn other_viewers_state_never_reaches_a_viewers_results() {
        use crate::awareness::{HumanStage, PreferenceAction};
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let [alice, bea, gus, ..] = d6_viewers();
        let statements = [
            "SELECT * FROM my_message_state ORDER BY message_id",
            "SELECT count(*) AS n FROM my_message_state",
            "SELECT sum(unread) AS unread, max(stage) AS stage, sum(muted) AS muted FROM my_message_state",
            "SELECT r.home_id, sum(s.unread) AS unread, sum(s.unread * s.mentioned) AS mentions \
             FROM my_message_state s JOIN records r ON r.id = s.message_id WHERE s.muted = 0 GROUP BY r.home_id",
            "SELECT count(*) AS n FROM my_message_state a, my_message_state b",
            "SELECT count(*) AS n FROM my_message_state a JOIN my_message_state b ON a.message_id = b.message_id AND a.stage = b.stage",
            "WITH x(v) AS (VALUES(1),(2)) SELECT sum(v) AS n FROM x CROSS JOIN my_message_state",
            "SELECT * FROM my_mentions ORDER BY source_id, via",
            "SELECT count(*) AS n FROM my_mentions",
            "SELECT sum(seen) AS seen, count(seen) AS tracked FROM my_mentions",
            "WITH x(v) AS (VALUES(1)) SELECT sum(v) AS n FROM x CROSS JOIN my_mentions",
        ];
        let mut before = Vec::new();
        for sql in statements {
            before.push(serde_json::to_string(&d6_rows(&db, &alice, sql).await).unwrap());
        }
        // Column-less shapes read real rows.
        assert_eq!(before[1], r#"[{"n":2}]"#);
        assert_eq!(before[4], r#"[{"n":4}]"#);
        assert_eq!(before[6], r#"[{"n":6}]"#);
        assert_eq!(before[8], r#"[{"n":2}]"#);

        // Every awareness lane Bea and Gus can write, on Messages Alice sees
        // and on one she does not, plus a notification candidate for Bea.
        for message in [D6_M_OPEN, D6_M_TEAM, D6_M_BEA_ONLY] {
            d6_advance(&db, "bea", message, HumanStage::Presented).await;
            d6_advance(&db, "bea", message, HumanStage::Opened).await;
            d6_advance(&db, "bea", message, HumanStage::Acknowledged).await;
            for (action, until) in [
                (PreferenceAction::FlagAttention, None),
                (PreferenceAction::Mute, None),
                (PreferenceAction::Snooze, Some("2026-12-01T00:00:00.000Z")),
                (PreferenceAction::Archive, None),
            ] {
                d6_prefer(&db, "bea", message, action, until).await;
            }
        }
        d6_advance(&db, "gus", D6_M_OPEN, HumanStage::Opened).await;
        d6_prefer(&db, "gus", D6_M_OPEN, PreferenceAction::Mute, None).await;
        {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            crate::awareness::set_routing(
                &mut tx,
                &crate::awareness::MutationContext {
                    subject_account_id: "bea",
                    authenticated_actor: "policy",
                    executor_kind: "system",
                    executor_ref: Some("policy"),
                    delegation_ref: None,
                    reason_code: "d6 routing",
                },
                D6_M_TEAM,
                "open",
                "human",
                Some("policy-v1"),
                0,
                "d6-routing-bea",
                &mut act_alloc,
            )
            .await
            .unwrap();
            crate::awareness::append_notification_candidate_in(
                &mut tx,
                "bea",
                D6_M_TEAM,
                "principal_mention",
                "routine",
                None,
                "metadata_only",
                "portable_default",
                "v1",
                "record.created",
                "d6-candidate-event",
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        for (sql, earlier) in statements.iter().zip(&before) {
            let now = serde_json::to_string(&d6_rows(&db, &alice, sql).await).unwrap();
            assert_eq!(&now, earlier, "{sql} moved with another viewer's state");
        }
        // The writes did land, for their own subjects only.
        let bea_state = d6_rows(
            &db,
            &bea,
            "SELECT count(*) AS n FROM my_message_state WHERE stage = 'acknowledged' AND archived = 1",
        )
        .await;
        assert_eq!(bea_state, [json!({"n": 3})]);
        let gus_state = d6_rows(&db, &gus, "SELECT stage, muted FROM my_message_state").await;
        assert_eq!(gus_state, [json!({"stage": "opened", "muted": 1})]);
    }

    /// D6 3.2: principal @-mentions of the caller on visible Messages, and
    /// `record_mentions` references that resolve to the caller exactly as
    /// `get_record` resolves them. Hidden sources, hidden look-alike ids and
    /// references that name someone else contribute nothing, and a visible
    /// look-alike makes a short reference ambiguous.
    #[tokio::test]
    async fn my_mentions_reuse_record_mentions_and_resolve_as_get_record_does() {
        use crate::awareness::HumanStage;
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let [alice, bea, gus, _harriet, orphan] = d6_viewers();
        let sql = "SELECT source_id, source_kind, via, own_source, seen FROM my_mentions ORDER BY source_id, via";
        let row = |source: &str, kind: &str, via: &str, seen: Value| json!({"source_id": source, "source_kind": kind, "via": via, "own_source": 0, "seen": seen});
        assert_eq!(
            d6_rows(&db, &alice, sql).await,
            [
                row(D6_M_TEAM, "message", "principal", json!(0)),
                row(D6_D_REF, "record", "reference", Value::Null),
            ]
        );
        // Bea can see both notes, but neither references Bea.
        assert!(d6_rows(&db, &bea, sql).await.is_empty());
        assert!(d6_rows(&db, &gus, sql).await.is_empty());
        assert!(d6_rows(&db, &orphan, sql).await.is_empty());

        // `get_record`'s own resolution of the note's references agrees.
        let visible = workspace_visible_set(&db, alice.clone()).await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        let gathered = crate::query::read::gather_mentions(&mut connection, D6_D_REF)
            .await
            .unwrap();
        let resolved =
            crate::query::read::finish_mentions(&mut connection, gathered, &visible.ids, 50, 0)
                .await
                .unwrap();
        drop(connection);
        let out = serde_json::to_value(resolved.out.unwrap()).unwrap();
        assert!(
            out.as_array()
                .unwrap()
                .iter()
                .all(|group| group["resolution"]["id"] == D6_P_ALICE),
            "{out}"
        );

        // Opening the Message marks the principal mention seen.
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Opened).await;
        assert_eq!(
            d6_rows(&db, &alice, sql).await[0],
            row(D6_M_TEAM, "message", "principal", json!(1))
        );
        let when = d6_rows(
            &db,
            &alice,
            "SELECT m.mentioned_at_ms = r.created_at_ms AS same FROM my_mentions m \
             JOIN records r ON r.id = m.source_id WHERE m.via = 'principal'",
        )
        .await;
        assert_eq!(when, [json!({"same": 1})]);

        // A hidden look-alike is never a rival.
        d6_record(
            &db,
            "a11ce000-0000-4000-8000-0000000000ee",
            "note",
            "Hidden twin",
            &["bea"],
            None,
            None,
        )
        .await;
        assert_eq!(d6_rows(&db, &alice, sql).await.len(), 2);
        // A visible look-alike makes both short references ambiguous, so the
        // note no longer mentions Alice. A full-id reference still does.
        d6_record(
            &db,
            "a11ce000-0000-4000-8000-0000000000ff",
            "note",
            "Visible twin",
            &["alice"],
            None,
            None,
        )
        .await;
        assert_eq!(
            d6_rows(&db, &alice, sql).await,
            [row(D6_M_TEAM, "message", "principal", json!(1))]
        );
        d6_reference(&db, D6_D_REF, 2, D6_P_ALICE).await;
        assert_eq!(d6_rows(&db, &alice, sql).await.len(), 2);
        // A reference that resolves to someone else is not Alice's mention.
        d6_reference(&db, D6_D_REF, 3, "bea00000").await;
        assert_eq!(d6_rows(&db, &alice, sql).await.len(), 2);
    }

    /// D6 5.4 and 5.5: no sequence, version, head or account reaches any of
    /// the two relations, and caller SQL cannot read the private tables or
    /// the engine's helpers directly, through a subquery or a CTE.
    #[tokio::test]
    async fn message_state_relations_expose_no_counters_and_admit_no_direct_reads() {
        use crate::awareness::{HumanStage, PreferenceAction};
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Opened).await;
        d6_prefer(
            &db,
            "alice",
            D6_M_OPEN,
            PreferenceAction::FlagAttention,
            None,
        )
        .await;
        let alice = QueryPrincipal::authenticated("alice", true);
        let columns: Vec<String> = d6_rows(
            &db,
            &alice,
            "SELECT column_name FROM catalog_columns \
             WHERE relation_name IN ('my_message_state', 'my_mentions')",
        )
        .await
        .iter()
        .map(|row| row["column_name"].as_str().unwrap().to_owned())
        .collect();
        assert_eq!(columns.len(), 18);
        for column in &columns {
            for forbidden in ["seq", "version", "head", "account", "subject"] {
                assert!(!column.contains(forbidden), "{column}");
            }
        }
        let mut sequences: Vec<i64> = Vec::new();
        for sql in [
            "SELECT seq FROM awareness_events",
            "SELECT seq FROM content_events",
            "SELECT last_event_seq FROM human_message_awareness",
            "SELECT last_event_seq FROM message_preferences",
            "SELECT source_event_seq FROM message_mentions",
            "SELECT source_event_seq FROM record_mentions",
        ] {
            sequences.extend(
                sqlx::query_scalar::<_, i64>(sql)
                    .fetch_all(db.write_pool())
                    .await
                    .unwrap(),
            );
        }
        // Only the distinctive fixture-era values are recognisable.
        sequences.retain(|seq| *seq > 7_000_000);
        assert!(sequences.iter().any(|seq| *seq > 7_800_000));
        for relation in ["my_message_state", "my_mentions"] {
            let rows = d6_rows(&db, &alice, &format!("SELECT * FROM {relation}")).await;
            assert!(!rows.is_empty(), "{relation}");
            for row in &rows {
                for (column, value) in row.as_object().unwrap() {
                    if let Some(number) = value.as_i64() {
                        assert!(
                            column.ends_with("_ms") || !sequences.contains(&number),
                            "{relation}.{column} = {number} is a sequence"
                        );
                        assert!(
                            column.ends_with("_ms") || number < 10,
                            "{relation}.{column}"
                        );
                    }
                    if let Some(text) = value.as_str() {
                        assert!(!D6_ACCOUNTS.contains(&text), "{relation}.{column} = {text}");
                    }
                }
            }
        }
        for sql in [
            "SELECT stage FROM main.human_message_awareness",
            "SELECT stage FROM human_message_awareness",
            "SELECT count(*) AS n FROM awareness_events",
            "SELECT muted FROM message_preferences",
            "SELECT count(*) AS n FROM notification_candidates",
            "SELECT count(*) AS n FROM message_mentions",
            "SELECT count(*) AS n FROM record_mentions",
            "SELECT message_id FROM _query_sql_reaction_rows",
            "SELECT message_id FROM _query_sql_reaction_oversized",
            "SELECT person_id FROM _query_sql_my_person",
            "SELECT id FROM _query_sql_mention_visible",
            "SELECT message_id FROM my_message_state WHERE message_id IN (SELECT message_id FROM human_message_awareness)",
            "WITH peek AS (SELECT subject_account_id FROM main.human_message_awareness) SELECT * FROM peek",
            "WITH _query_sql_mention_visible AS (SELECT message_id AS id FROM main.human_message_awareness) SELECT id FROM _query_sql_mention_visible",
        ] {
            assert!(query_sql(&db, &alice, sql).await.is_err(), "{sql} was admitted");
        }
    }

    /// The dependency set follows main's rule for the two relations, every
    /// statement shape reads real rows (they need no preparation), and a
    /// caller CTE named after either of them is the caller's own table.
    #[tokio::test]
    async fn message_state_dependencies_follow_main_rule_and_ctes_shadow_them() {
        let set = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        for (sql, expected) in [
            (
                "SELECT unread FROM my_message_state",
                set(&["my_message_state"]),
            ),
            ("SELECT via FROM my_mentions", set(&["my_mentions"])),
            ("SELECT count(*) AS n FROM my_message_state", set(&[])),
            (
                "WITH my_message_state AS (SELECT id FROM records) SELECT id FROM my_message_state",
                set(&["records"]),
            ),
            (
                "WITH my_mentions AS (SELECT id FROM records) SELECT id FROM my_mentions",
                set(&["records"]),
            ),
        ] {
            assert_eq!(
                validated_relation_dependencies(sql).unwrap(),
                expected,
                "{sql}"
            );
        }
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let bea = QueryPrincipal::authenticated("bea", true);
        let shadowed = d6_rows(
            &db,
            &bea,
            "WITH my_message_state(a) AS (VALUES('mine')), my_mentions(b) AS (VALUES('ours')) \
             SELECT a, b FROM my_message_state CROSS JOIN my_mentions",
        )
        .await;
        assert_eq!(shadowed, [json!({"a": "mine", "b": "ours"})]);
        for (sql, n) in [
            ("SELECT count(*) AS n FROM my_message_state", 3),
            ("SELECT count(*) AS n FROM my_message_state s, my_message_state t", 9),
            (
                "SELECT count(*) AS n FROM my_message_state s JOIN my_message_state t ON s.message_id = t.message_id",
                3,
            ),
            ("SELECT count(*) AS n FROM my_mentions", 0),
        ] {
            assert_eq!(single_count(&db, &bea, sql).await, n, "{sql}");
        }
    }

    /// D6 (anchor lesson 6): work over the two relations is driven from
    /// what the viewer may see. 20k rows of other viewers' awareness and
    /// preferences, and 20k mentions, references and reaction events on a
    /// Message and a note neither viewer can see, change neither the rows
    /// nor, beyond one progress interval, the VM work of a member or a guest,
    /// plus 20k hidden Messages, and no plan scans a Message, mention,
    /// reaction, awareness or preference source.
    #[tokio::test]
    async fn message_state_work_does_not_grow_with_hidden_volume() {
        use crate::awareness::HumanStage;
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        d6_advance(&db, "alice", D6_M_TEAM, HumanStage::Opened).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        let gus = QueryPrincipal::authenticated("gus", false);
        let statements = [
            "SELECT count(*) AS n FROM my_message_state",
            "SELECT message_id, stage, unread, mentioned, muted FROM my_message_state ORDER BY message_id",
            "SELECT count(*) AS n FROM my_mentions",
            "SELECT source_id, via, seen FROM my_mentions ORDER BY source_id, via",
        ];
        let mut before = Vec::new();
        for principal in [&alice, &gus] {
            for sql in statements {
                before.push(rows_and_vm_work(&db, principal, sql).await);
            }
        }
        {
            let mut connection = db.write_pool().acquire().await.unwrap();
            sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut *connection)
                .await
                .unwrap();
            // Hidden Messages share Bea's private policy anchor. Growing the
            // physical Message set must not grow either caller statement.
            sqlx::query(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO records (id, type, kind, name, home_id, owner_id, policy_anchor_id)
                 SELECT 'hidden-message-' || n.i, template.type, template.kind,
                        template.name, template.home_id, template.owner_id, template.policy_anchor_id
                 FROM records AS template CROSS JOIN n WHERE template.id = ?",
            )
            .bind(D6_M_BEA_ONLY)
            .execute(&mut *connection)
            .await
            .unwrap();
            for sql in [
                // Other viewers' human lane and preferences, on Messages both
                // viewers can see and on ones they cannot.
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO human_message_awareness
                   (subject_account_id, message_id, stage, last_event_seq, version)
                 SELECT 'ghost-' || i,
                        CASE i % 3 WHEN 0 THEN '0e550000-0000-4000-8000-00000000000a'
                                   WHEN 1 THEN '0e550000-0000-4000-8000-00000000000b'
                                   ELSE 'ghost-message-' || i END,
                        'opened', 7900000 + i, 1 FROM n",
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO message_preferences
                   (subject_account_id, message_id, attention_flag, muted, archived, last_event_seq, version)
                 SELECT 'ghost-' || i,
                        CASE i % 2 WHEN 0 THEN '0e550000-0000-4000-8000-00000000000a'
                                   ELSE '0e550000-0000-4000-8000-00000000000b' END,
                        1, 1, 1, 7950000 + i, 1 FROM n",
                // Mentions of Alice and references to her on sources neither
                // viewer can see.
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO message_mentions
                   (message_id, mention_id, target_kind, target_binding, target_record_id,
                    span_start, span_end, authored_label, source_event_seq, effective)
                 SELECT '0e550000-0000-4000-8000-00000000000c', 'ghost-mention-' || i, 'principal',
                        'native-principal:a11ce', 'a11ce000-0000-4000-8000-000000000001',
                        0, 6, '@Alice', 1, 1 FROM n",
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO record_mentions
                   (source_id, occurrence_ix, source_event_seq, span_start, span_end,
                    authored_reference, lookup_key, form, parser_version)
                 SELECT 'd0c00000-0000-4000-8000-000000000002', 100 + i, 1, 0, 8,
                        'a11ce000', 'a11ce000', 'bare_hex', 1 FROM n",
                // Reactions on the Message only Bea sees, a few oversized.
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 20000)
                 INSERT INTO content_events
                   (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
                 SELECT 'ghost-reaction-' || i, '0e550000-0000-4000-8000-00000000000c',
                        CASE i % 2 WHEN 0 THEN 'message.reaction.added.v1' ELSE 'message.reaction.removed.v1' END,
                        json_object('format', 'native.message-reaction.v1', 'emoji', '👍',
                                    'idempotency_key', 'ghost-' || i, 'command', 'add_reaction',
                                    'changed', json('true'), 'actor_account_id', 'ghost-' || (i % 500),
                                    'executor_kind', 'authenticated_principal',
                                    'reason', CASE WHEN i % 1000 = 0 THEN replace(hex(zeroblob(150000)), '0', 'r') ELSE 'x' END),
                        'ghost-' || (i % 500), '2026-02-01T00:00:00.000Z', 1, 'legacy_unknown'
                   FROM n",
            ] {
                sqlx::query(sql).execute(&mut *connection).await.unwrap();
            }
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        let mut after = Vec::new();
        for principal in [&alice, &gus] {
            for sql in statements {
                after.push(rows_and_vm_work(&db, principal, sql).await);
            }
        }
        let labels = ["member", "guest"]
            .iter()
            .flat_map(|viewer| statements.iter().map(move |sql| format!("{viewer}: {sql}")));
        let mut failures = Vec::new();
        for ((label, (rows_before, work_before)), (rows_after, work_after)) in
            labels.zip(&before).zip(&after)
        {
            eprintln!("VOLUME {label}: vm callbacks {work_before} -> {work_after}");
            if rows_before != rows_after {
                failures.push(format!("{label}: rows changed with hidden volume"));
            }
            if *work_after > work_before + 1 {
                failures.push(format!(
                    "{label}: hidden volume grew VM work {work_before} -> {work_after}"
                ));
            }
        }
        for (account, is_member) in [("alice", true), ("gus", false)] {
            for sql in statements {
                let plan = governed_plan(&db, account, is_member, sql).await;
                eprintln!("PLAN {account} {sql}");
                for line in &plan {
                    eprintln!("PLAN   {line}");
                }
                if plan.iter().any(|line| {
                    line.starts_with("SCAN message")
                        || (line.starts_with("SEARCH message") && line.contains("idx_records_kind"))
                }) {
                    failures.push(format!("{account} {sql}: starts from all Messages"));
                }
                for source in [
                    "event",
                    "latest",
                    "reference",
                    "mention",
                    "awareness",
                    "preference",
                    "ingest",
                    "target",
                    "oversized",
                ] {
                    if plan.iter().any(|line| {
                        line == &format!("SCAN {source}")
                            || line.starts_with(&format!("SCAN {source} "))
                            || (line.contains("AUTOMATIC") && line.contains(&format!(" {source} ")))
                    }) {
                        failures.push(format!("{account} {sql}: scans {source}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[tokio::test]
    async fn agent_activity_declared_intent_discloses_same_account_only() {
        let (db, _alice, _bea) = protected_fixture().await;
        for (account, person, root) in [
            ("alice", ALICE_PRIVATE_ID, ALICE_PRIVATE_ID),
            ("bea", BEA_PRIVATE_ID, BEA_PRIVATE_ID),
        ] {
            sqlx::query(
                "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
                 VALUES(?,?,?,'2026-08-31T00:00:00.000Z')",
            )
            .bind(account)
            .bind(person)
            .bind(root)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let alice_run = "scout-chair-a748b2";
        let alice_quiet_run = "scout-chair-a749b2";
        let bea_run = "scout-chair-b748b2";
        crate::control::ensure_agent_run(
            &db,
            alice_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            alice_quiet_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            bea_run,
            "bea",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // The spoof row carries the highest seq on Alice's key, so the
        // latest-declaration lookup must skip it on the actor filter rather
        // than on ordering alone.
        for (id, tool, run_key, actor, intent) in [
            (
                "intent-alice-first",
                "set_intent",
                alice_run,
                "alice",
                Some("First framing"),
            ),
            (
                "intent-alice-latest",
                "set_intent",
                alice_run,
                "alice",
                Some("Reframed aim"),
            ),
            (
                "intent-alice-spoof",
                "set_intent",
                alice_run,
                "bea",
                Some("Spoofed aim"),
            ),
            (
                "intent-bea-only",
                "set_intent",
                bea_run,
                "bea",
                Some("Bea private plan"),
            ),
            (
                "call-alice-quiet",
                "get_record",
                alice_quiet_run,
                "alice",
                None,
            ),
            ("call-bea", "get_record", bea_run, "bea", None),
        ] {
            sqlx::query(
                "INSERT INTO read_log_calls
                 (id,tool,run_key,actor,intent,outcome,started_at,ended_at)
                 VALUES (?,?,?,?,?,'ok',
                         strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                         strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            )
            .bind(id)
            .bind(tool)
            .bind(run_key)
            .bind(actor)
            .bind(intent)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        // SAFETY: these tests model the authenticated hosted ingress after it
        // has admitted the live member roster; no SQL argument controls it.
        let viewer = |credential: &str| unsafe {
            QueryPrincipal::activity_reader_unchecked(
                credential,
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        let intent_sql =
            "SELECT run_key,declared_intent,declared_intent_state FROM agent_activity ORDER BY run_key";
        let as_alice = query_sql(&db, viewer("alice"), intent_sql).await.unwrap();
        assert_eq!(as_alice.row_count, 3);
        assert_eq!(as_alice.rows[0]["run_key"], alice_run);
        assert_eq!(as_alice.rows[0]["declared_intent"], "Reframed aim");
        assert_eq!(as_alice.rows[0]["declared_intent_state"], "disclosed");
        assert_eq!(as_alice.rows[1]["run_key"], alice_quiet_run);
        assert!(as_alice.rows[1]["declared_intent"].is_null());
        assert_eq!(as_alice.rows[1]["declared_intent_state"], "none");
        assert_eq!(as_alice.rows[2]["run_key"], bea_run);
        assert!(as_alice.rows[2]["declared_intent"].is_null());
        assert_eq!(as_alice.rows[2]["declared_intent_state"], "withheld");

        let as_bea = query_sql(&db, viewer("bea"), intent_sql).await.unwrap();
        assert_eq!(as_bea.row_count, 3);
        assert!(as_bea.rows[0]["declared_intent"].is_null());
        assert_eq!(as_bea.rows[0]["declared_intent_state"], "withheld");
        assert!(as_bea.rows[1]["declared_intent"].is_null());
        assert_eq!(as_bea.rows[1]["declared_intent_state"], "withheld");
        assert_eq!(as_bea.rows[2]["declared_intent"], "Bea private plan");
        assert_eq!(as_bea.rows[2]["declared_intent_state"], "disclosed");

        // Without the read-log capture table the column reads unavailable
        // with a reason, never a silent empty. This covers only the absent
        // table shape (RENAME here, DROP TABLE in conformance), not a standby
        // replica whose export strips the rows but keeps the tables, which
        // still reads `none`. That stripped-but-present gap is known and
        // needs a durable capture-removed signal the export writes.
        sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
            .execute(db.write_pool())
            .await
            .unwrap();
        let degraded = query_sql(&db, viewer("alice"), intent_sql).await.unwrap();
        assert_eq!(degraded.row_count, 3);
        assert!(
            degraded
                .rows
                .iter()
                .all(|row| row["declared_intent"].is_null()
                    && row["declared_intent_state"] == "unavailable"),
            "unexpected degraded rows: {:?}",
            degraded.rows
        );
    }

    #[tokio::test]
    async fn same_principal_release_from_another_run_closes_the_claim() {
        let (db, _alice, _bea) = protected_fixture().await;
        let first_run = "scout-chair-a748b2";
        let second_run = "scout-chair-b748b2";
        crate::control::ensure_agent_run(
            &db,
            first_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            second_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        // SAFETY: this test models the authenticated hosted ingress after it
        // has admitted Bea's live member context; no SQL argument controls it.
        let bea_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({ "record_id": COMMON_ID, "run_key": first_run }),
            )
            .await
            .unwrap();
        let open = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,is_current,released_at FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(open.row_count, 1);
        assert_eq!(open.rows[0]["is_current"], 1);
        assert!(open.rows[0]["released_at"].is_null());
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({
                    "record_id": COMMON_ID,
                    "action": "release",
                    "run_key": second_run,
                    "expected_holder_run_key": first_run,
                }),
            )
            .await
            .unwrap();
        let closed = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,is_current,released_at FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(closed.row_count, 1);
        assert_eq!(closed.rows[0]["claim_id"], open.rows[0]["claim_id"]);
        assert!(closed.rows[0]["released_at"].is_string());
        assert_eq!(closed.rows[0]["is_current"], 0);
    }

    // Covers the non-run-scoped shape only: the oversized payload here
    // carries no run_key/actor stamp. A run-stamped over-limit payload can
    // still fail this relation through the joined `agent_activity`
    // relation, which is the separately tracked sibling defect.
    #[tokio::test]
    async fn claims_ignore_oversized_event_payloads_outside_the_activity_window() {
        let (db, _alice, _bea) = protected_fixture().await;
        update_record(
            &db,
            COMMON_ID,
            json!({ "body": "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 1024) }),
        )
        .await
        .unwrap();
        let (oversized_event_id, payload_bytes): (String, i64) = sqlx::query_as(
            "SELECT id,length(CAST(payload AS BLOB))
               FROM content_events
              WHERE record_id=? AND type='record.updated'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(COMMON_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert!(payload_bytes > MAX_SQLITE_VALUE_BYTES as i64);

        update_record(&db, COMMON_ID, json!({ "body": "small current body" }))
            .await
            .unwrap();
        // content_events is append-only by trigger; this test deliberately
        // backdates one event to exercise the bounded activity window. Drop
        // only the update guard and restore its exact sqlite_master SQL on the
        // same connection around that test-only mutation.
        let mut fixture = db.write_pool().acquire().await.unwrap();
        let update_guard: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_events_no_update'",
        )
        .fetch_one(&mut *fixture)
        .await
        .unwrap();
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(&mut *fixture)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE content_events
                SET created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-48 hours')
              WHERE id=?",
        )
        .bind(&oversized_event_id)
        .execute(&mut *fixture)
        .await
        .unwrap();
        sqlx::query(&update_guard)
            .execute(&mut *fixture)
            .await
            .unwrap();
        drop(fixture);

        let run_key = "scout-chair-c748b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({ "record_id": COMMON_ID, "run_key": run_key }),
            )
            .await
            .unwrap();
        let alice_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "alice",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                ],
                true,
            )
        };

        let claims = query_sql(
            &db,
            &alice_activity,
            "SELECT claim_id,record_id,is_current FROM agent_activity_claims",
        )
        .await
        .unwrap();
        assert_eq!(claims.row_count, 1);
        assert_eq!(claims.rows[0]["record_id"], COMMON_ID);
        assert_eq!(claims.rows[0]["is_current"], 1);
    }

    // Task 73e5b92: over-ceiling events written through the governed path —
    // actor plus run/parent stamps, exactly an agent tool dispatch — keep
    // every run-keyed metadata read working. Claim-shaped payloads cannot
    // pass the public append seam (start_work-owned), so the governed
    // oversized rows here are plain; oversized claim-shaped privacy is
    // pinned by raw legacy rows in the visibility-matrix suite below.
    #[tokio::test]
    async fn claim_meta_oversized_governed_run_stamped_updates_stay_queryable() {
        let (db, alice, bea) = protected_fixture().await;
        // Bea must disclose alice as an actor: the fixture keeps alice's
        // person record private, so admit it explicitly here.
        replace_explicit_policy(
            &db,
            "test:claim-meta-person",
            ALICE_PRIVATE_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let run = "scout-chair-e748b2";
        crate::control::ensure_agent_run(
            &db,
            run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let big = "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 4096);
        assert!(big.len() > MAX_SQLITE_VALUE_BYTES as usize);
        // Oversized plain update through the governed choke.
        let claimed_event = crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some(run.into()),
                parent_key: Some(run.into()),
                intent: None,
            },
            crate::store::append(
                &db,
                crate::store::AppendSpec {
                    record_id: COMMON_ID.into(),
                    event_type: "record.updated".into(),
                    payload: json!({ "body": big }),
                    actor: Some("alice".into()),
                },
            ),
        )
        .await
        .unwrap();
        // Oversized non-claim create: a different event type, same stamps.
        let big_created = crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some(run.into()),
                parent_key: Some(run.into()),
                intent: None,
            },
            crate::store::create_record_as(
                &db,
                json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "big-created",
                    "home_id": crate::schema::ROOT_RECORD_ID,
                    "body": big,
                }),
                Some("alice"),
            ),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:claim-meta",
            &big_created,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();

        // Holder-actor: SELECT, FILTER and COUNT by run all succeed past the
        // ceiling, and the stamped lineage is disclosed.
        let as_alice = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT id, run_key, parent_key FROM content_events
                  WHERE run_key = '{run}' ORDER BY local_seq"
            ),
        )
        .await
        .unwrap();
        assert_eq!(as_alice.row_count, 2);
        for row in &as_alice.rows {
            assert_eq!(row["run_key"].as_str().unwrap(), run);
            assert_eq!(row["parent_key"].as_str().unwrap(), run);
        }
        assert!(as_alice
            .rows
            .iter()
            .any(|row| row["id"].as_str().unwrap() == claimed_event.id.as_str()));
        let count = query_sql(
            &db,
            &alice,
            &format!("SELECT COUNT(*) AS n FROM content_events WHERE run_key = '{run}'"),
        )
        .await
        .unwrap();
        assert_eq!(count.rows[0]["n"], 2);
        let by_parent = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM content_events WHERE parent_key = '{run}'"),
        )
        .await
        .unwrap();
        assert_eq!(by_parent.row_count, 2);

        // Disclosable non-holder: the reads succeed and both plain rows
        // disclose their runs past the ceiling.
        let bea_rows = query_sql(
            &db,
            &bea,
            &format!(
                "SELECT id, actor, run_key, parent_key FROM content_events
                  WHERE run_key = '{run}' ORDER BY local_seq"
            ),
        )
        .await
        .unwrap();
        assert_eq!(bea_rows.row_count, 2);
        for row in &bea_rows.rows {
            assert_eq!(row["actor"].as_str(), Some("alice"));
            assert_eq!(row["run_key"].as_str().unwrap(), run);
            assert_eq!(row["parent_key"].as_str().unwrap(), run);
        }

        // Trusted local sees every stamped run past the ceiling.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let as_local = query_sql(
            &db,
            &trusted,
            &format!("SELECT COUNT(*) AS n FROM content_events WHERE run_key = '{run}'"),
        )
        .await
        .unwrap();
        assert_eq!(as_local.rows[0]["n"], 2);

        // Legitimate oversize-result rejection is unchanged: the 300 KB body
        // cell still cannot be read, only its bounded metadata can.
        let body_error = query_sql(
            &db,
            &alice,
            &format!("SELECT body FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(body_error.contains("too big"), "{body_error}");
    }

    // Task 768eb1d: an over-ceiling event stamped with a run and its actor
    // keeps both activity relations queryable. A plain oversized row feeds
    // liveness; the suite below pins the run present and the claims
    // surface intact.
    #[tokio::test]
    async fn claim_meta_oversized_run_stamped_events_keep_activity_and_claims_queryable() {
        let (db, _alice, _) = protected_fixture().await;
        let run = "scout-chair-f748b2";
        crate::control::ensure_agent_run(
            &db,
            run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // SAFETY: this test models the authenticated hosted ingress after it
        // has admitted the live member roster; no SQL argument controls it.
        let bea_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        // start_work needs edit capability on the record.
        replace_explicit_policy(
            &db,
            "test:claim-meta-activity",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let claim = |record_id: &str, action: &str| {
            json!({
                "record_id": record_id,
                "action": action,
                "run_key": run,
            })
        };
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "claim"),
            )
            .await
            .unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "release"),
            )
            .await
            .unwrap();
        let baseline_activity = query_sql(&db, &bea_activity, "SELECT * FROM agent_activity")
            .await
            .unwrap();
        assert!(baseline_activity.row_count >= 1);

        // Oversized plain update through the governed choke, stamped with
        // the run and its actor — the exact shape that used to fail both
        // relations with string-or-blob-too-big.
        let big = "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 4096);
        crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some(run.into()),
                parent_key: Some(run.into()),
                intent: None,
            },
            crate::store::append(
                &db,
                crate::store::AppendSpec {
                    record_id: COMMON_ID.into(),
                    event_type: "record.updated".into(),
                    payload: json!({ "body": big }),
                    actor: Some("alice".into()),
                },
            ),
        )
        .await
        .unwrap();

        let activity = query_sql(&db, &bea_activity, "SELECT * FROM agent_activity")
            .await
            .unwrap();
        assert_eq!(activity.row_count, baseline_activity.row_count);
        assert!(activity
            .rows
            .iter()
            .any(|row| row["run_key"].as_str() == Some(run)));
        let claims = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,record_id,is_current FROM agent_activity_claims",
        )
        .await
        .unwrap();
        assert_eq!(claims.row_count, 1);
        assert_eq!(claims.rows[0]["record_id"], COMMON_ID);
        assert_eq!(claims.rows[0]["is_current"], 0);
    }

    // The two-bit activity exclusion survives the ceiling, and so does
    // claim mining: an over-ceiling release-shaped row is excluded from
    // liveness yet still read by the miner (holder extraction runs
    // pre-limit at full limits). Claim-shaped payloads cannot pass the
    // public append seam (start_work-owned), so the suite pairs a governed
    // small claim with a legacy-shaped oversized release on the same
    // private record: presence stays byte-identical while the mined claim
    // flips to released.
    #[tokio::test]
    async fn claim_meta_oversized_claim_shaped_events_excluded_from_activity_but_mined() {
        let (db, _, _) = protected_fixture().await;
        let run = "otter-field-e748b2";
        crate::control::ensure_agent_run(
            &db,
            run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // SAFETY: same hosted-ingress model as the neighbouring suites.
        let bea_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
                true,
            )
        };
        let alice_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "alice",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                ],
                true,
            )
        };
        // Governed small claim first, so the miner has a baseline open
        // claim on the private record.
        replace_explicit_policy(
            &db,
            "test:claim-meta-mined",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({
                    "record_id": ALICE_PRIVATE_ID,
                    "action": "claim",
                    "run_key": run,
                }),
            )
            .await
            .unwrap();
        let before = query_sql(&db, &bea_activity, "SELECT * FROM agent_activity")
            .await
            .unwrap();

        // Oversized release pair as legacy-shaped raw history: the trigger
        // classifies it at write time (no governed path can mint
        // claim-shaped payloads — start_work owns small ones), the miner
        // reads the holder pre-limit, liveness excludes it.
        let big = "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 4096);
        let big_release = serde_json::json!({
            "body": big,
            "claimed_by_account": serde_json::Value::Null,
            "claimed_run_key": serde_json::Value::Null,
        })
        .to_string();
        sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key, created_at, causal_envelope_version, causal_status)
             VALUES ('big-oos-release', ?, 'record.updated', ?, 'alice', ?, ?, '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
        )
        .bind(ALICE_PRIVATE_ID)
        .bind(&big_release)
        .bind(run)
        .bind(run)
        .execute(db.write_pool())
        .await
        .unwrap();
        let meta: (i64, i64, i64, String) = sqlx::query_as(
            "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
               FROM content_event_claim_meta m
               JOIN content_events e ON e.seq = m.event_seq
              WHERE e.id = 'big-oos-release'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(meta, (1, 1, 0, "release".to_string()));

        // Presence is byte-identical: the release-shaped row feeds no liveness.
        let after = query_sql(&db, &bea_activity, "SELECT * FROM agent_activity")
            .await
            .unwrap();
        assert_eq!(after.rows, before.rows);
        // The mined claim flipped to released; the private record keeps it
        // from every non-holder surface.
        let holder_claims = query_sql(
            &db,
            &alice_activity,
            "SELECT claim_id,record_id,is_current,released_at FROM agent_activity_claims",
        )
        .await
        .unwrap();
        assert_eq!(holder_claims.row_count, 1);
        assert_eq!(holder_claims.rows[0]["record_id"], ALICE_PRIVATE_ID);
        assert_eq!(holder_claims.rows[0]["is_current"], 0);
        assert!(holder_claims.rows[0]["released_at"].is_string());
        let bea_claims = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id FROM agent_activity_claims",
        )
        .await
        .unwrap();
        assert_eq!(bea_claims.row_count, 0);
    }

    // The all-types three-key visibility rule holds past the ceiling:
    // explicit-null keys and released_from-only payloads still count as
    // shaped on every event type, and the actor/holder/trust matrix is
    // unchanged for oversized rows.
    #[tokio::test]
    async fn claim_meta_oversized_rows_keep_three_key_visibility_matrix() {
        let (db, alice, bea) = protected_fixture().await;
        // Same person-visibility admission as the neighbouring suite: bea
        // discloses alice's actor, so plain rows disclose runs to bea while
        // shaped rows hide them.
        replace_explicit_policy(
            &db,
            "test:claim-meta-person",
            ALICE_PRIVATE_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let run = "heron-river-f748b2";
        let big = "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 4096);

        async fn insert_shaped(db: &Db, id: &str, event_type: &str, payload: &str, run: &str) {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key, created_at, causal_envelope_version, causal_status)
                 VALUES (?, ?, ?, ?, 'alice', ?, ?, '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
            )
            .bind(id)
            .bind(COMMON_ID)
            .bind(event_type)
            .bind(payload)
            .bind(run)
            .bind(run)
            .execute(db.write_pool())
            .await
            .unwrap();
        }

        insert_shaped(
            &db,
            "big-plain",
            "record.updated",
            &json!({"body": big}).to_string(),
            run,
        )
        .await;
        let big_claim = serde_json::json!({
            "body": big,
            "claimed_by_account": "alice",
            "claimed_run_key": run,
        })
        .to_string();
        insert_shaped(&db, "big-claim", "record.updated", &big_claim, run).await;
        let big_nullkey = serde_json::json!({
            "body": big,
            "claimed_by_account": serde_json::Value::Null,
        })
        .to_string();
        insert_shaped(&db, "big-nullkey", "record.updated", &big_nullkey, run).await;
        let big_relonly = serde_json::json!({
            "body": big,
            "released_from_run_key": "run-x",
        })
        .to_string();
        insert_shaped(&db, "big-relonly", "record.updated", &big_relonly, run).await;
        insert_shaped(&db, "big-created", "record.created", &big_claim, run).await;

        async fn cells_for(
            db: &Db,
            principal: QueryPrincipal,
        ) -> std::collections::HashMap<String, (Option<String>, Option<String>, Option<String>)>
        {
            let result = query_sql(
                db,
                principal,
                "SELECT id, actor, run_key, parent_key FROM content_events
                  WHERE id LIKE 'big-%' ORDER BY id",
            )
            .await
            .unwrap();
            result
                .rows
                .iter()
                .map(|row| {
                    let row = row.as_object().unwrap();
                    let cell = |column: &str| row[column].as_str().map(str::to_string);
                    (
                        row["id"].as_str().unwrap().to_string(),
                        (cell("actor"), cell("run_key"), cell("parent_key")),
                    )
                })
                .collect()
        }

        let full = (
            Some("alice".to_string()),
            Some(run.to_string()),
            Some(run.to_string()),
        );
        let hidden_run = (Some("alice".to_string()), None, None);
        // Holder-actor: everything disclosed, including shaped rows.
        let as_alice = cells_for(&db, alice).await;
        assert_eq!(as_alice.len(), 5);
        for id in [
            "big-plain",
            "big-claim",
            "big-nullkey",
            "big-relonly",
            "big-created",
        ] {
            assert_eq!(as_alice[id], full, "alice must see {id}");
        }
        // Disclosable non-holder: the plain row discloses, every shaped row
        // hides run and parent while keeping the actor.
        let as_bea = cells_for(&db, bea).await;
        assert_eq!(as_bea.len(), 5);
        assert_eq!(as_bea["big-plain"], full);
        for id in ["big-claim", "big-nullkey", "big-relonly", "big-created"] {
            assert_eq!(as_bea[id], hidden_run, "bea must not see run on {id}");
        }
        // Trusted local sees every stamped run past the ceiling.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let as_local = cells_for(&db, trusted).await;
        assert_eq!(as_local.len(), 5);
        for id in [
            "big-plain",
            "big-claim",
            "big-nullkey",
            "big-relonly",
            "big-created",
        ] {
            assert_eq!(as_local[id], full, "local must see {id}");
        }
        // Hidden actor: no policy admits the record, so the rows are absent
        // rather than redacted — and the read itself succeeds.
        let stranger = QueryPrincipal::authenticated("nobody", false);
        let as_stranger = cells_for(&db, stranger).await;
        assert!(as_stranger.is_empty());
    }

    /// Slice 1 (task 77bd40a): two viewers with different grants read
    /// through the staged visible-id table on the owned path. Bea's
    /// narrower set must hold on rows, facet joins, link endpoints and the
    /// count aggregate — on both the cache-miss and cache-hit passes, and
    /// with bea first, so neither viewer's staged set can leak into the
    /// other's.
    #[tokio::test]
    async fn staged_visible_ids_narrow_two_viewers_without_cross_principal_leak() {
        let (db, alice, bea) = protected_fixture().await;
        let stranger = QueryPrincipal::authenticated("nobody", false);
        async fn ids(db: &Db, principal: &QueryPrincipal, sql: &str) -> Vec<String> {
            first_strings(&query_sql(db, principal, sql).await.unwrap())
        }
        async fn count(db: &Db, principal: &QueryPrincipal) -> i64 {
            let result = query_sql(db, principal, "SELECT count(*) AS n FROM records")
                .await
                .unwrap();
            result.rows[0].as_object().unwrap()["n"].as_i64().unwrap()
        }
        const ROWS: &str = "SELECT id FROM records ORDER BY id";
        const FACETS: &str = "SELECT f.value FROM facet_values f \
            JOIN records r ON r.id = f.record_id \
            WHERE f.key = 'secret' ORDER BY f.value";
        const LINKS: &str = "SELECT id FROM links ORDER BY id";
        // Bea first: her narrower staged set must not leak into alice's.
        let bea_rows = ids(&db, &bea, ROWS).await;
        assert!(bea_rows.contains(&BEA_PRIVATE_ID.to_string()));
        assert!(bea_rows.contains(&COMMON_ID.to_string()));
        assert!(!bea_rows.iter().any(|id| id == ALICE_PRIVATE_ID));
        let alice_rows = ids(&db, &alice, ROWS).await;
        assert!(alice_rows.contains(&ALICE_PRIVATE_ID.to_string()));
        assert!(alice_rows.contains(&COMMON_ID.to_string()));
        assert!(!alice_rows.iter().any(|id| id == BEA_PRIVATE_ID));
        assert_ne!(alice_rows, bea_rows);
        // Facet join, link endpoints and count narrow identically.
        assert_eq!(ids(&db, &bea, FACETS).await, vec!["bea-facet".to_string()]);
        assert_eq!(
            ids(&db, &alice, FACETS).await,
            vec!["alice-facet".to_string()]
        );
        let bea_links = ids(&db, &bea, LINKS).await;
        assert!(bea_links.contains(&"common-bea".to_string()));
        assert!(!bea_links.iter().any(|id| id == "alice-common"));
        let alice_links = ids(&db, &alice, LINKS).await;
        assert!(alice_links.contains(&"alice-common".to_string()));
        assert!(!alice_links.iter().any(|id| id == "common-bea"));
        assert_eq!(count(&db, &bea).await, bea_rows.len() as i64);
        assert_eq!(count(&db, &alice).await, alice_rows.len() as i64);
        // Stranger sees nothing anywhere.
        let stranger = &stranger;
        assert!(ids(&db, stranger, ROWS).await.is_empty());
        assert!(ids(&db, stranger, LINKS).await.is_empty());
        assert_eq!(count(&db, stranger).await, 0);
        // Second pass: cache-hit staging must agree exactly.
        assert_eq!(ids(&db, &alice, ROWS).await, alice_rows);
        assert_eq!(ids(&db, &bea, ROWS).await, bea_rows);
        assert_eq!(
            ids(&db, &alice, FACETS).await,
            vec!["alice-facet".to_string()]
        );
        assert_eq!(ids(&db, &bea, LINKS).await, bea_links);
        let (hits, _) = db.visible_set_cache_stats();
        assert!(hits >= 4, "expected staged reuse, got {hits} hits");
        db.close().await;
    }

    async fn ad_hoc_rows(
        db: &Db,
        principal: &QueryPrincipal,
        sql: &str,
        parameters: Vec<sql_contract::QuerySqlParameter>,
    ) -> Result<SqlResult> {
        query_sql_request_ad_hoc(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: sql.to_owned(),
                parameters,
            },
        )
        .await
    }

    async fn set_json_facet(db: &Db, record_id: &str, value: &str) {
        set_facet(
            db,
            record_id,
            FacetSetPayload {
                key: "jsondata".into(),
                value: Some(value.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }

    /// Native 702de73: ad-hoc online sqlite-local SQL is SQLite's read-only
    /// dialect. The portable entry still refuses the same statements.
    #[tokio::test]
    async fn ad_hoc_sqlite_accepts_json_and_date_functions_the_portable_entry_refuses() {
        let (db, alice, _) = protected_fixture().await;
        set_json_facet(&db, ALICE_PRIVATE_ID, r#"{"tags":["x","y"],"n":3}"#).await;
        let sql = "SELECT json_extract(value, '$.n') AS n, value ->> '$.tags[1]' AS tag, \
                   json_array_length(value, '$.tags') AS len, json_type(value) AS kind, \
                   json_valid(value) AS ok, json_object('k', 1) AS obj, \
                   instr(value, 'tags') AS pos, typeof(value) AS ty, \
                   upper(hex(char(65))) AS hx, printf('%03d', 7) AS pf, \
                   datetime(86400, 'unixepoch') AS dt, strftime('%Y', 0, 'unixepoch') AS yr \
                   FROM facet_values WHERE key = 'jsondata' ORDER BY id";
        let result = ad_hoc_rows(&db, &alice, sql, Vec::new()).await.unwrap();
        let row = result.rows[0].as_object().unwrap();
        assert_eq!(row["n"], json!(3));
        assert_eq!(row["tag"], json!("y"));
        assert_eq!(row["len"], json!(2));
        assert_eq!(row["kind"], json!("object"));
        assert_eq!(row["ok"], json!(1));
        assert_eq!(row["obj"], json!(r#"{"k":1}"#));
        assert_eq!(row["ty"], json!("text"));
        assert_eq!(row["hx"], json!("41"));
        assert_eq!(row["pf"], json!("007"));
        assert_eq!(row["dt"], json!("1970-01-02 00:00:00"));
        assert_eq!(row["yr"], json!("1970"));
        // `now_ms()` is the supported clock and composes with the date set.
        let clock = ad_hoc_rows(
            &db,
            &alice,
            "SELECT datetime(now_ms() / 1000, 'unixepoch') AS now_text",
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(clock.time_dependent);
        // The default ORDER BY still applies to an ad-hoc LIMIT with JSON.
        let limited = ad_hoc_rows(
            &db,
            &alice,
            "SELECT json_extract(value, '$.n') AS n FROM facet_values WHERE key = 'jsondata' LIMIT 5",
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(limited.assumed_order.is_some());
        // The portable entry (library callers, saved-SQL gate) still refuses.
        let portable = query_sql_request_owned(
            db.clone(),
            alice.clone(),
            QuerySqlRequest {
                sql: sql.to_owned(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(portable.contains("is unavailable"), "{portable}");
        assert!(validate(sql).is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn ad_hoc_sqlite_json_each_reads_only_caller_visible_rows() {
        let (db, alice, bea) = protected_fixture().await;
        set_json_facet(&db, ALICE_PRIVATE_ID, r#"["alice-1","alice-2"]"#).await;
        set_json_facet(&db, BEA_PRIVATE_ID, r#"["bea-1"]"#).await;
        const ELEMENTS: &str = "SELECT j.value AS element \
            FROM facet_values AS f JOIN records AS r ON r.id = f.record_id, \
                 json_each(f.value) AS j \
            WHERE f.key = 'jsondata' ORDER BY j.value";
        let strings = |result: &SqlResult| -> Vec<String> {
            result
                .rows
                .iter()
                .map(|row| row["element"].as_str().unwrap().to_owned())
                .collect()
        };
        let alice_rows = ad_hoc_rows(&db, &alice, ELEMENTS, Vec::new())
            .await
            .unwrap();
        assert_eq!(strings(&alice_rows), ["alice-1", "alice-2"]);
        let bea_rows = ad_hoc_rows(&db, &bea, ELEMENTS, Vec::new()).await.unwrap();
        assert_eq!(strings(&bea_rows), ["bea-1"]);
        let stranger = QueryPrincipal::authenticated("nobody", false);
        let none = ad_hoc_rows(&db, &stranger, ELEMENTS, Vec::new())
            .await
            .unwrap();
        assert!(none.rows.is_empty());
        // json_tree walks the same visible column.
        let tree = ad_hoc_rows(
            &db,
            &bea,
            "SELECT t.value AS element FROM facet_values AS f, json_tree(f.value) AS t \
             WHERE f.key = 'jsondata' AND t.type = 'text' ORDER BY t.value",
            Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(strings(&tree), ["bea-1"]);
        db.close().await;
    }

    #[tokio::test]
    async fn ad_hoc_sqlite_hidden_record_json_is_unreachable() {
        let (db, _, bea) = protected_fixture().await;
        set_json_facet(&db, ALICE_PRIVATE_ID, r#"["alice-secret"]"#).await;
        // Addressing the hidden record by id yields no JSON to expand.
        let by_id = ad_hoc_rows(
            &db,
            &bea,
            &format!(
                "SELECT j.value AS element FROM json_each(\
                   (SELECT value FROM facet_values WHERE record_id = '{ALICE_PRIVATE_ID}' \
                    AND key = 'jsondata')) AS j ORDER BY j.value"
            ),
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(by_id.rows.is_empty(), "{:?}", by_id.rows);
        // The raw table behind the view is not a relation json_each can
        // reach: the authorizer still denies the physical read.
        for sql in [
            "SELECT j.value FROM json_each((SELECT value FROM main.facet_values LIMIT 1)) AS j ORDER BY 1",
            "SELECT j.value FROM json_each((SELECT sql FROM sqlite_master LIMIT 1)) AS j ORDER BY 1",
            "SELECT j.value FROM main.records AS r, json_each(r.body) AS j ORDER BY 1",
        ] {
            let error = ad_hoc_rows(&db, &bea, sql, Vec::new())
                .await
                .expect_err(sql)
                .to_string();
            assert!(!error.contains("alice-secret"), "{sql}: {error}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn ad_hoc_sqlite_refuses_clock_reads_and_excluded_functions() {
        let (db, alice, _) = protected_fixture().await;
        for sql in [
            "SELECT date() AS d",
            "SELECT datetime('now') AS d",
            "SELECT date('2026-01-01', 'localtime') AS d",
            "SELECT strftime('%s') AS d",
        ] {
            let error = ad_hoc_rows(&db, &alice, sql, Vec::new())
                .await
                .expect_err(sql)
                .to_string();
            assert!(error.contains("now_ms()"), "{sql}: {error}");
        }
        let text = |value: &str| sql_contract::QuerySqlParameter::Text {
            value: Some(value.to_owned()),
        };
        for clock in ["now", "localtime", "UTC"] {
            let error = ad_hoc_rows(&db, &alice, "SELECT date(?1) AS d", vec![text(clock)])
                .await
                .expect_err(clock)
                .to_string();
            assert!(error.contains("now_ms()"), "{clock}: {error}");
        }
        let ok = ad_hoc_rows(
            &db,
            &alice,
            "SELECT date(?1) AS d",
            vec![text("2026-01-02")],
        )
        .await
        .unwrap();
        assert_eq!(ok.rows[0]["d"], json!("2026-01-02"));
        for sql in [
            "SELECT random() AS x",
            "SELECT hex(randomblob(4)) AS x",
            "SELECT load_extension('x') AS x",
            "SELECT sqlite_version() AS x",
            "SELECT changes() AS x",
            "SELECT total_changes() AS x",
            "SELECT last_insert_rowid() AS x",
            "SELECT length(zeroblob(4)) AS x",
        ] {
            let error = ad_hoc_rows(&db, &alice, sql, Vec::new())
                .await
                .expect_err(sql)
                .to_string();
            assert!(error.contains("is unavailable"), "{sql}: {error}");
        }
        db.close().await;
    }

    /// The authorizer enforces the same list without the classifier in front:
    /// names outside it are denied by default, whatever the shared scanner
    /// would have said.
    #[test]
    fn ad_hoc_authorizers_deny_functions_outside_the_shared_allowlist() {
        let denied = |sql: &str| {
            validate_view_expansion_ad_hoc(sql).is_err() && validate_strict_ad_hoc(sql).is_err()
        };
        for sql in [
            "SELECT random() FROM records",
            "SELECT randomblob(4) FROM records",
            "SELECT zeroblob(4) FROM records",
            "SELECT sqlite_version() FROM records",
            "SELECT soundex(name) FROM records",
            "SELECT unlikely(id) FROM records",
            // Only json_each / json_tree are table functions; any other
            // eponymous virtual table stays a prohibited read.
            "SELECT * FROM pragma_table_info('records')",
            "SELECT * FROM main.records",
        ] {
            assert!(denied(sql), "{sql}");
        }
        for sql in [
            "SELECT json_extract(name, '$.a') FROM records",
            "SELECT name ->> '$.a' FROM records",
            "SELECT j.value FROM records AS r, json_each(r.name) AS j",
            "SELECT datetime(0, 'unixepoch') FROM records",
        ] {
            validate_view_expansion_ad_hoc(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
            validate_strict_ad_hoc(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        // The portable authorizers are untouched.
        assert!(validate_view_expansion("SELECT json_extract(name, '$.a') FROM records").is_err());
        assert!(validate_strict("SELECT json_extract(name, '$.a') FROM records").is_err());
    }

    /// The allowlist excludes `floor`/`ceil`/`ceiling` only because
    /// the pinned SQLite build omits its math functions. If the build gains
    /// them this fails, naming what to add to `SQLITE_AD_HOC_FUNCTIONS`.
    #[test]
    fn ad_hoc_allowlist_tracks_the_pinned_sqlite_math_functions() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for name in ["floor", "ceil", "ceiling", "sign"] {
            let in_build = conn.prepare(&format!("SELECT {name}(1.5)")).is_ok();
            assert_eq!(
                in_build,
                sql_contract::is_sqlite_ad_hoc_extra_function(name),
                "{name}: pinned build has it = {in_build}; keep SQLITE_AD_HOC_FUNCTIONS in step"
            );
        }
    }

    /// Slice 1 (task 77bd40a) opt-in measurement gate, in the style of
    /// `tests/tools/batch_semantic_measurement.rs`: page statement p50 CPU
    /// <= 100 ms and count statement p50 CPU <= 30 ms at 20,000 tasks,
    /// after one visible-set staging step. Reports staging and full-call
    /// CPU separately because index.v1 will share that setup across its
    /// page/count/position statements. Returns immediately
    /// unless `NATIVE_RUN_VISIBLE_SET_MEASUREMENT` is `1`, so the ordinary
    /// suite never pays the 20k seed. CPU (not wall) is summed from
    /// `/proc/self/task/*/schedstat`; timing asserts apply on Linux only.
    /// Seeding uses the real write paths for generation 0 and raw-SQL
    /// replication (same owner, home and policy anchor, no policy writes)
    /// for generations 1-9 — the evidence method of 462f009 section 0.
    /// Measures the owned engine path; the MCP envelope is excluded.
    #[tokio::test]
    async fn slice1_visible_set_once_per_read_measurement() {
        if std::env::var("NATIVE_RUN_VISIBLE_SET_MEASUREMENT").as_deref() != Ok("1") {
            return;
        }
        async fn table_columns(db: &Db, table: &str) -> Vec<String> {
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .fetch_all(db.write_pool())
                .await
                .unwrap()
        }
        let db = crate::create_database(":memory:").await.unwrap();
        for index in 0..2000 {
            let id: String = create_record(
                &db,
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": format!("Measured task {index:05}"),
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
            set_facet(
                &db,
                &id,
                FacetSetPayload {
                    key: "triage".into(),
                    value: Some("untriaged".into()),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        let record_columns = table_columns(&db, "records").await;
        let facet_columns = table_columns(&db, "facet_values").await;
        for copy in 1..=9 {
            // Generation 0 is exactly the seeded tasks; the `-vs` infix is
            // not hexadecimal, so no engine-minted UUID can match it.
            let source_filter = if copy == 1 {
                "type = 'WorkItem' AND kind = 'task' AND id NOT LIKE '%-vs%'".to_string()
            } else {
                format!("id LIKE '%-vs{}'", copy - 1)
            };
            let record_select = record_columns
                .iter()
                .map(|name| {
                    if name == "id" {
                        format!("id || '-vs{copy}'")
                    } else {
                        name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            sqlx::query(&format!(
                "INSERT INTO records ({}) SELECT {record_select} \
                 FROM records WHERE {source_filter}",
                record_columns.join(", "),
            ))
            .execute(db.write_pool())
            .await
            .unwrap();
            let facet_select = facet_columns
                .iter()
                .map(|name| {
                    if name == "id" || name == "record_id" {
                        format!("{name} || '-vs{copy}'")
                    } else {
                        name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            sqlx::query(&format!(
                "INSERT INTO facet_values ({}) SELECT {facet_select} \
                 FROM facet_values WHERE record_id IN \
                 (SELECT id FROM records WHERE {source_filter})",
                facet_columns.join(", "),
            ))
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        async fn timed_owned(
            db: &Db,
            principal: QueryPrincipal,
            sql: &str,
        ) -> (SqlResult, u128, Slice1PhaseCpu) {
            let phases = Arc::new(std::sync::Mutex::new(Slice1PhaseCpu::default()));
            let before = slice1_cpu_ns();
            let result = SLICE1_PHASE_CPU
                .scope(
                    phases.clone(),
                    query_sql_owned(db.clone(), principal, sql.to_string()),
                )
                .await
                .unwrap();
            let total = slice1_cpu_ns() - before;
            let phases = *phases.lock().unwrap();
            (result, total, phases)
        }
        const PAGE_SQL: &str = "SELECT r.id, r.name, f.value FROM records r \
            JOIN facet_values f ON f.record_id = r.id AND f.key = 'triage' \
            ORDER BY r.name LIMIT 100";
        const COUNT_SQL: &str = "SELECT count(*) AS n FROM records";
        // Warmup is excluded; the first statement populates the cache.
        let (warmed, _, _) = timed_owned(&db, trusted.clone(), COUNT_SQL).await;
        let task_total = warmed.rows[0].as_object().unwrap()["n"].as_i64().unwrap();
        assert!(
            (20_000..20_100).contains(&task_total),
            "unexpected task total: {task_total}"
        );
        let mut page_cpu = Vec::with_capacity(15);
        let mut page_full_cpu = Vec::with_capacity(15);
        let mut stage_cpu = Vec::with_capacity(30);
        for _ in 0..15 {
            let (page, full_cpu, phases) = timed_owned(&db, trusted.clone(), PAGE_SQL).await;
            assert_eq!(page.rows.len(), 100);
            page_cpu.push(phases.caller_ns);
            page_full_cpu.push(full_cpu);
            stage_cpu.push(phases.stage_ns);
        }
        let mut count_cpu = Vec::with_capacity(15);
        let mut count_full_cpu = Vec::with_capacity(15);
        for _ in 0..15 {
            let (counted, full_cpu, phases) = timed_owned(&db, trusted.clone(), COUNT_SQL).await;
            assert_eq!(
                counted.rows[0].as_object().unwrap()["n"].as_i64().unwrap(),
                task_total
            );
            count_cpu.push(phases.caller_ns);
            count_full_cpu.push(full_cpu);
            stage_cpu.push(phases.stage_ns);
        }
        page_cpu.sort_unstable();
        count_cpu.sort_unstable();
        page_full_cpu.sort_unstable();
        count_full_cpu.sort_unstable();
        stage_cpu.sort_unstable();
        let page_p50 = page_cpu[7];
        let count_p50 = count_cpu[7];
        let (cache_hits, cache_misses) = db.visible_set_cache_stats();
        println!(
            "{}",
            serde_json::json!({
                "schema": "native.visible-set-measurement.v1",
                "task_total": task_total,
                "timed_runs": 15,
                "timing_scope": "in-crate owned engine path; statement, stage and full-call CPU from /proc/self/task/*/schedstat",
                "page_cpu_p50_ns": page_p50,
                "count_cpu_p50_ns": count_p50,
                "stage_cpu_p50_ns": stage_cpu[15],
                "page_full_call_cpu_p50_ns": page_full_cpu[7],
                "count_full_call_cpu_p50_ns": count_full_cpu[7],
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
            })
        );
        if cfg!(target_os = "linux") {
            assert!(
                page_p50 <= 100_000_000,
                "page p50 CPU {page_p50}ns exceeds 100ms"
            );
            assert!(
                count_p50 <= 30_000_000,
                "count p50 CPU {count_p50}ns exceeds 30ms"
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn same_transaction_executor_removes_every_temp_object_after_success_and_error() {
        let (db, alice, _) = protected_fixture().await;
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        query_sql_request_in(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id LIMIT 1".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap();
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let error = query_sql_request_in(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT abs(-9223372036854775808) AS overflow".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("integer overflow"), "{error}");
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn caller_tx_observed_replay_clock_pins_repeated_now_ms_uses() {
        let (db, alice, _) = protected_fixture().await;
        let request = QuerySqlRequest {
            sql: "SELECT now_ms() AS a, now_ms() AS b".to_string(),
            parameters: Vec::new(),
        };
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let mut first_rows = Vec::new();
        let mut first_columns = Vec::new();
        for _ in 0..2 {
            let mut connection = db.write_pool().acquire().await.unwrap();
            let mut tx = connection.begin().await.unwrap();
            let (result, _) = query_sql_request_in_with_row_limit_observed(
                &mut tx,
                alice.clone(),
                request.clone(),
                200,
                sql_contract::FunctionAllowance::Portable,
                Some(1_234_567),
                None,
                false,
            )
            .await
            .unwrap();
            assert_eq!(result.now_ms_ms, Some(1_234_567));
            assert!(result.time_dependent);
            assert_eq!(result.rows[0]["a"], serde_json::json!(1_234_567));
            assert_eq!(result.rows[0]["b"], serde_json::json!(1_234_567));
            assert!(!result.truncated);
            let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(count, 0);
            if first_rows.is_empty() {
                first_rows = result.rows.clone();
                first_columns = result.columns.clone();
            } else {
                assert_eq!(result.columns, first_columns);
                assert_eq!(result.rows, first_rows);
            }
            tx.rollback().await.unwrap();
        }
        // Clock-free statements ignore the server replay override.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (plain, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id LIMIT 1".into(),
                parameters: Vec::new(),
            },
            200,
            sql_contract::FunctionAllowance::Portable,
            Some(1_234_567),
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(plain.now_ms_ms, None);
        assert!(!plain.time_dependent);
        tx.rollback().await.unwrap();
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn current_principal_binds_each_caller_on_every_sqlite_path() {
        let (db, alice, bea) = protected_fixture().await;
        let sql =
            "SELECT ?1 AS x, now_ms() AS t, current_principal() AS p, CURRENT_PRINCIPAL() AS q";
        let request = || QuerySqlRequest {
            sql: sql.to_string(),
            parameters: vec![sql_contract::QuerySqlParameter::Text {
                value: Some("x".into()),
            }],
        };
        for (principal, expected) in [(alice.clone(), "alice"), (bea.clone(), "bea")] {
            // Ad-hoc `query_sql`.
            let owned = query_sql_request_owned(db.clone(), principal.clone(), request())
                .await
                .unwrap();
            assert_eq!(owned.rows[0]["p"], expected);
            assert_eq!(owned.rows[0]["q"], expected);
            assert_eq!(owned.rows[0]["x"], "x");
            assert!(owned.time_dependent);
            // The caller-transaction path behind saved queries, alpha-tab
            // needs and artifact relation ports, under both allowances.
            for allowance in [
                sql_contract::FunctionAllowance::Portable,
                sql_contract::FunctionAllowance::LegacySavedSql,
            ] {
                let mut connection = db.write_pool().acquire().await.unwrap();
                let mut tx = connection.begin().await.unwrap();
                let (scoped, _) = query_sql_request_in_with_row_limit_observed(
                    &mut tx,
                    principal.clone(),
                    request(),
                    200,
                    allowance,
                    Some(1_234_567),
                    None,
                    false,
                )
                .await
                .unwrap();
                assert_eq!(scoped.rows[0]["p"], expected, "{allowance:?}");
                assert_eq!(scoped.rows[0]["t"], serde_json::json!(1_234_567));
                assert_eq!(
                    scoped.rows,
                    owned
                        .rows
                        .iter()
                        .map(|row| {
                            let mut row = row.clone();
                            row["t"] = serde_json::json!(1_234_567);
                            row
                        })
                        .collect::<Vec<_>>()
                );
                tx.rollback().await.unwrap();
            }
        }
        // Without a clock the principal takes the first hidden slot.
        let plain = query_sql_request_owned(
            db.clone(),
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT current_principal() AS p".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(plain.rows[0]["p"], "alice");
        assert!(!plain.time_dependent);
        // A caller cannot name the hidden slot to substitute another value.
        let spoof = query_sql_request_owned(
            db.clone(),
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT current_principal() AS p, ?2 AS q".into(),
                parameters: vec![sql_contract::QuerySqlParameter::Text {
                    value: Some("bea".into()),
                }],
            },
        )
        .await;
        assert!(spoof.is_err(), "{spoof:?}");
        // Nor on the stored-query path, under either allowance.
        for allowance in [
            sql_contract::FunctionAllowance::Portable,
            sql_contract::FunctionAllowance::LegacySavedSql,
        ] {
            let mut connection = db.write_pool().acquire().await.unwrap();
            let mut tx = connection.begin().await.unwrap();
            let spoof = query_sql_request_in_with_row_limit_observed(
                &mut tx,
                alice.clone(),
                QuerySqlRequest {
                    sql: "SELECT current_principal() AS p, ?2 AS q".into(),
                    parameters: vec![sql_contract::QuerySqlParameter::Text {
                        value: Some("bea".into()),
                    }],
                },
                200,
                allowance,
                None,
                None,
                false,
            )
            .await;
            assert!(spoof.is_err(), "{allowance:?}: {spoof:?}");
            tx.rollback().await.unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn caller_tx_observed_vm_counter_measures_authored_work_identically() {
        let (db, alice, _) = protected_fixture().await;
        let request = QuerySqlRequest {
            sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000) SELECT sum(x) AS n FROM n".to_string(),
            parameters: Vec::new(),
        };
        let callbacks = Arc::new(AtomicU64::new(0));
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (measured, _) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            alice.clone(),
            request.clone(),
            200,
            sql_contract::FunctionAllowance::Portable,
            None,
            Some(Arc::clone(&callbacks)),
            false,
        )
        .await
        .unwrap();
        assert!(callbacks.load(Ordering::Relaxed) > 0);
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
        drop(connection);
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (ordinary, _) = query_sql_request_in_with_row_limit(
            &mut tx,
            alice.clone(),
            request,
            200,
            sql_contract::FunctionAllowance::Portable,
        )
        .await
        .unwrap();
        assert_eq!(measured.columns, ordinary.columns);
        assert_eq!(measured.rows, ordinary.rows);
        assert_eq!(measured.row_count, ordinary.row_count);
        assert_eq!(measured.truncated, ordinary.truncated);
        tx.rollback().await.unwrap();
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn caller_tx_portable_row_limit200_first_delivered_membership_cap_cleanup() {
        let (db, alice, _) = protected_fixture().await;
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','facet_observation_json_nodes','record_body_json_nodes','bindings','blobs','vocabularies','vocabulary_values','vocabulary_value_json_nodes','facet_value_json_nodes','content_event_apps','schema_config_json_nodes','schema_config','effective_relationships','effective_relationship_endpoints','agent_activity','agent_activity_claims','actors','runs','run_intents','messages_awaiting_reply','my_message_state','my_mentions','message_reactions','facet_times','facet_keys','body_task_items','body_blocks','body_block_headings','record_lifecycle_interpretations')";

        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (result, _) = query_sql_request_in_with_row_limit(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id".into(),
                parameters: Vec::new(),
            },
            200,
            sql_contract::FunctionAllowance::Portable,
        )
        .await
        .unwrap();
        assert!(!result.truncated);
        let ids: Vec<&str> = result
            .rows
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&ALICE_PRIVATE_ID));
        assert!(ids.contains(&COMMON_ID));
        assert!(!ids.contains(&BEA_PRIVATE_ID));
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let (capped, _) = query_sql_request_in_with_row_limit(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id".into(),
                parameters: Vec::new(),
            },
            1,
            sql_contract::FunctionAllowance::Portable,
        )
        .await
        .unwrap();
        assert!(capped.truncated);
        assert_eq!(capped.rows.len(), 1);
        assert_eq!(capped.rows[0]["id"], serde_json::json!(ALICE_PRIVATE_ID));
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let (first200, _) = query_sql_request_in_with_row_limit(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 250) SELECT x FROM n ORDER BY x".into(),
                parameters: Vec::new(),
            },
            200,
            sql_contract::FunctionAllowance::Portable,
        )
        .await
        .unwrap();
        assert!(first200.truncated);
        assert_eq!(first200.rows.len(), 200);
        assert_eq!(first200.rows[0]["x"], serde_json::json!(1));
        assert_eq!(first200.rows[199]["x"], serde_json::json!(200));
        assert!(!first200
            .rows
            .iter()
            .any(|row| row["x"] == serde_json::json!(201)));
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
        drop(connection);
        db.close().await;
    }

    async fn create_policy_scoped_note(db: &Db, id: &str, account: &str, body: &str) {
        create_record(
            db,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": id,
                "body": body,
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:policy",
            id,
            vec![AllowEntry::account(account, Capability::View)],
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn app_sql_execution_errors_do_not_disclose_undeclared_diagnostics() {
        use crate::mcp::tools::alpha_tabs::parse_reads_declaration;
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        let declared = parse_reads_declaration(&serde_json::json!({
            "relations": {"records": ["body"]},
        }))
        .unwrap();
        let error = app_query(&db, &declared, alice.clone(), "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "app_sql [syntax_or_type]: app read has an unsupported expression or value"
        );
        for private_detail in [
            TOOBIG_ALICE_ID.to_string(),
            TOOBIG_ALICE_BYTES.to_string(),
            "WHERE records.id NOT IN".to_string(),
            "x".repeat(32),
        ] {
            assert!(!error.contains(&private_detail), "{error}");
        }
        // The same engine failure remains actionable through the direct
        // query surface. The app projection does not weaken its diagnostics.
        let direct = query_sql(&db, alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(direct.contains(TOOBIG_ALICE_ID), "{direct}");
        assert!(
            direct.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{direct}"
        );
        assert!(direct.contains("WHERE records.id NOT IN"), "{direct}");
    }

    #[tokio::test]
    async fn sqlite_toobig_error_names_the_oversized_visible_row() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;

        let ids_only = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id = '{TOOBIG_ALICE_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&ids_only), [TOOBIG_ALICE_ID]);

        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("Offending:"), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(
            error.contains("cannot be read, truncated or matched"),
            "{error}"
        );
        assert!(error.contains("WHERE records.id NOT IN"), "{error}");
        assert!(error.contains("ORDER BY id LIMIT"), "{error}");
        assert!(
            error.contains(&format!("WHERE records.id NOT IN ('{TOOBIG_ALICE_ID}')")),
            "{error}"
        );
        assert!(
            !error.contains(&"x".repeat(32)),
            "oversized payload leaked into the error"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_hint_qualifies_exclusions_per_relation() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        sqlx::query("UPDATE links SET note = ? WHERE id = 'alice-common'")
            .bind("a".repeat(TOOBIG_ALICE_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        // A second alice-visible link with a small note, so the repaired
        // retry below still returns rows after both culprits are excluded.
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("common-alice-small".into()),
                source_id: COMMON_ID.into(),
                target_id: ALICE_PRIVATE_ID.into(),
                relationship: "mentions".into(),
                note: Some("small".into()),
            },
        )
        .await
        .unwrap();

        let error = query_sql(
            &db,
            &alice,
            "SELECT r.body, l.note FROM records r JOIN links l ON l.source_id = r.id",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        // One qualified clause per relation: ids are per-relation id domains,
        // so a single unqualified predicate would mix them and could be
        // ambiguous in the joined statement.
        assert!(
            error.contains(&format!("records.id NOT IN ('{TOOBIG_ALICE_ID}')")),
            "{error}"
        );
        assert!(
            error.contains("links.id NOT IN ('alice-common')"),
            "{error}"
        );
        assert!(!error.contains("WHERE id NOT IN"), "{error}");
        // The repair, applied with the statement's aliases, excludes both
        // oversized rows and lets the join run.
        let retried = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT r.body, l.note FROM records r JOIN links l ON l.source_id = r.id \
                 WHERE r.id NOT IN ('{TOOBIG_ALICE_ID}') AND l.id NOT IN ('alice-common')"
            ),
        )
        .await
        .unwrap();
        // Joined records with no body project as null, so look for the
        // surviving small link row rather than first-column strings.
        let notes: Vec<String> = retried
            .rows
            .iter()
            .filter_map(|row| row.as_object().and_then(|row| row.get("note")))
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
        assert!(
            notes.contains(&"small".to_owned()),
            "repaired join lost the surviving link row: {notes:?}"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_hint_counts_beyond_the_display_cap() {
        let (db, alice, _) = protected_fixture().await;
        // Eleven visible oversized rows: more than the hint's 10-id display
        // cap, fewer than the probe's 12-row stop, so the wired path emits
        // the "(first 10 of 11 oversized rows)" count.
        for index in 0..11 {
            create_policy_scoped_note(
                &db,
                &format!("9e795000-0000-4000-8000-{index:012}"),
                "alice",
                &"x".repeat(TOOBIG_ALICE_BYTES),
            )
            .await;
        }
        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("(first 10 of 11 oversized rows)"), "{error}");
        assert!(error.contains("records.id NOT IN ("), "{error}");
    }

    #[test]
    fn sqlite_facet_advice_requires_an_unknown_column_refusal() {
        let statement = "SELECT area FROM records";
        for detail in [
            "query_sql [unauthorized_relation]: no such column: area",
            "query_sql [syntax_or_type]: bad expression 'no such column: area'",
            "query_sql [syntax_or_type]: no such function: column area does not exist",
        ] {
            assert!(sqlite_records_facet_key_for_refusal(
                statement,
                &crate::Error::Engine(detail.into())
            )
            .is_none());
        }
        assert_eq!(
            sqlite_records_facet_key_for_refusal(
                statement,
                &crate::Error::Engine("query_sql [syntax_or_type]: no such column: area".into())
            )
            .as_deref(),
            Some("area")
        );
    }

    #[tokio::test]
    async fn sqlite_unknown_column_facet_hint_respects_visibility() {
        let (db, alice, bea) = protected_fixture().await;
        for (record_id, key) in [
            (ALICE_PRIVATE_ID, "area"),
            (ALICE_PRIVATE_ID, "triage"),
            (ALICE_PRIVATE_ID, "r"),
            (BEA_PRIVATE_ID, "secret_key"),
        ] {
            set_facet(
                &db,
                record_id,
                FacetSetPayload {
                    key: key.into(),
                    value: Some("now".into()),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        for sql in [
            "SELECT records.area FROM records",
            "SELECT r.area FROM records r",
            "SELECT r.area FROM records r JOIN links f ON f.source_id = r.id",
            "SELECT r.area FROM records r JOIN links f ON f.source_id = r.id JOIN links f2 ON f2.target_id = r.id",
            "SELECT r2.area FROM records r JOIN records r2 ON r2.id = r.id",
            "SELECT id FROM records WHERE triage = 'now'",
        ] {
            let error = query_sql(&db, &alice, sql).await.unwrap_err().to_string();
            let key = if sql.contains("triage") {
                "triage"
            } else {
                "area"
            };
            assert!(error.contains("Hint: valid columns of records"), "{error}");
            assert!(
                error.ends_with(&sql_contract::records_facet_column_hint(sql, &error, key)),
                "{error}"
            );
            if sql.contains("records r") {
                let join = error
                    .split_once(": JOIN facet_values ")
                    .unwrap()
                    .1
                    .split_once(" and filter ")
                    .unwrap()
                    .0;
                let alias = join.split_whitespace().next().unwrap();
                let repaired =
                    sql.replace("r.area", &format!("{alias}.value")).replace("r2.area", &format!("{alias}.value")) + " JOIN facet_values " + join;
                validate(&repaired).unwrap_or_else(|e| panic!("{repaired}: {e}"));
            }
        }
        for (caller, key) in [(&alice, "secret_key"), (&bea, "area")] {
            let sql = format!("SELECT {key} FROM records");
            let expected = validate(&sql).unwrap_err().to_string();
            let actual = query_sql(&db, caller, &sql).await.unwrap_err().to_string();
            assert_eq!(actual, expected, "hidden key must not change the refusal");
        }
        let unicode = query_sql(&db, &alice, "SELECT réalm FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(!unicode.contains("is a facet"), "{unicode}");
        // Real records columns stay ordinary successful reads.
        query_sql(
            &db,
            &alice,
            "SELECT lifecycle, persistence, maturity, archived FROM records",
        )
        .await
        .unwrap();
        // The transaction-owned executor uses the same fence.
        let mut tx = db.governed_pool().begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT r.area FROM records r".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.ends_with(&sql_contract::records_facet_column_hint(
                "SELECT r.area FROM records r",
                &error,
                "area"
            )),
            "{error}"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_unknown_column_names_that_relations_columns() {
        let (db, alice, _) = protected_fixture().await;
        let error = query_sql(&db, &alice, "SELECT titel FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "query_sql [syntax_or_type]: no such column: titel. \
             Hint: valid columns of records are id, type, kind, name, body, home_id, lifecycle, \
             persistence, maturity, summary, is_current, successor_count … (21 total). \
             Full list: SELECT column_name FROM catalog_columns \
             WHERE relation_name = 'records' ORDER BY column_position."
        );
    }

    #[tokio::test]
    async fn sqlite_unknown_column_resolves_aliases_and_joins() {
        let (db, alice, _) = protected_fixture().await;
        let aliased = query_sql(&db, &alice, "SELECT r.nme FROM records r")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            aliased,
            "query_sql [syntax_or_type]: no such column: r.nme. \
             Hint: valid columns of records are id, type, kind, name, body, home_id, lifecycle, \
             persistence, maturity, summary, is_current, successor_count … (21 total). \
             Full list: SELECT column_name FROM catalog_columns \
             WHERE relation_name = 'records' ORDER BY column_position."
        );
        let joined = query_sql(
            &db,
            &alice,
            "SELECT titel FROM records JOIN links ON links.target_id = records.id",
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            joined,
            "query_sql [syntax_or_type]: no such column: titel. \
             Hint: 'titel' is not a column of any relation in scope. \
             Valid columns of records are id, type, kind, name, body, home_id, lifecycle, \
             persistence, maturity, summary, is_current, successor_count … (21 total); \
             valid columns of links are id, source_id, target_id, relationship, note, created_at, \
             created_at_ms. Full list: SELECT relation_name, column_name FROM catalog_columns \
             WHERE relation_name IN ('records', 'links') ORDER BY relation_name, column_position."
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_error_does_not_name_an_invisible_oversized_row() {
        let (db, alice, bea) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"a".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        create_policy_scoped_note(&db, TOOBIG_BEA_ID, "bea", &"b".repeat(TOOBIG_BEA_BYTES)).await;

        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains(TOOBIG_BEA_ID),
            "named a record the caller cannot see: {error}"
        );
        assert!(
            !error.contains(&format!("{TOOBIG_BEA_BYTES} bytes")),
            "named an invisible size: {error}"
        );

        let bea_error = query_sql(&db, &bea, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(bea_error.contains(TOOBIG_BEA_ID), "{bea_error}");
        assert!(
            !bea_error.contains(TOOBIG_ALICE_ID),
            "named a record the caller cannot see: {bea_error}"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_computed_value_hedges_and_keeps_the_engine_detail() {
        let (db, alice, _) = protected_fixture().await;
        let error = query_sql(&db, &alice, COMPUTED_TOOBIG_SQL)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("computed intermediate"), "{error}");
        assert!(error.contains("keyset"), "{error}");
        assert!(!error.contains("Offending:"), "{error}");
        assert!(
            !error.contains("also reads these oversized values"),
            "{error}"
        );
    }

    #[test]
    fn sqlite_toobig_empty_probe_names_the_unprobed_scope() {
        let report = ProbeReport {
            offenders: Vec::new(),
            incomplete: None,
        };
        let relations: std::collections::BTreeSet<String> =
            ["agent_activity".to_string()].into_iter().collect();
        let message = format_sqlite_toobig_detail(
            "error returned from database: (code: 18) string or blob too big",
            &std::collections::HashSet::new(),
            report,
            &relations,
        );
        assert!(message.contains("agent_activity"), "{message}");
        assert!(message.contains("not covered"), "{message}");
        assert!(
            !message.contains("No oversized stored value was found in a probed scope"),
            "{message}"
        );
        // Executable for agent_activity: its stable key, not records.id.
        assert!(message.contains("ORDER BY activity_id"), "{message}");
        assert!(message.contains("WHERE activity_id > ?1"), "{message}");
        assert!(!message.contains("ORDER BY id"), "{message}");
        // Claim relation maps to its own stable key.
        assert_eq!(toobig_stable_key("agent_activity_claims"), "claim_id");
        assert_eq!(toobig_stable_key("records"), "id");
    }

    #[tokio::test]
    async fn sqlite_toobig_does_not_blame_an_unprojected_stored_value() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        let sql = format!("{COMPUTED_TOOBIG_SQL} WHERE (SELECT count(id) FROM records) >= 0");
        let error = query_sql(&db, &alice, &sql).await.unwrap_err().to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(
            error.contains("also reads these oversized values"),
            "{error}"
        );
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(!error.contains("Offending:"), "{error}");
    }

    /// `comment_anchors` applies the comments' own visibility: a row needs both
    /// the comment (visible through its bearer) and the anchored record visible.
    /// Citations, deleted comments and blob anchors never appear.
    #[tokio::test]
    async fn comment_anchors_need_both_the_comment_and_its_record_visible() {
        let (db, alice, bea) = protected_fixture().await;
        const C_COMMON: &str = "9e795000-0000-4000-8000-00000c000001";
        const C_ALICE: &str = "9e795000-0000-4000-8000-00000c000002";
        const C_BEA: &str = "9e795000-0000-4000-8000-00000c000003";
        const C_CROSS: &str = "9e795000-0000-4000-8000-00000c000004";
        const C_CITATION: &str = "9e795000-0000-4000-8000-00000c000005";
        const C_DELETED: &str = "9e795000-0000-4000-8000-00000c000006";
        // (annotation, kind, part_of bearer, anchored record)
        for (id, kind, bearer, anchored) in [
            (C_COMMON, "comment", COMMON_ID, COMMON_ID),
            (C_ALICE, "comment", ALICE_PRIVATE_ID, ALICE_PRIVATE_ID),
            (C_BEA, "comment", BEA_PRIVATE_ID, BEA_PRIVATE_ID),
            // A comment Alice can see whose anchor names a record she cannot.
            (C_CROSS, "comment", COMMON_ID, BEA_PRIVATE_ID),
            (C_CITATION, "citation", COMMON_ID, COMMON_ID),
            (C_DELETED, "comment", COMMON_ID, COMMON_ID),
        ] {
            create_record(
                &db,
                json!({ "id": id, "type": "Annotation", "kind": kind, "name": "Comment",
                "body": "note", "home_id": crate::schema::ROOT_RECORD_ID }),
            )
            .await
            .unwrap();
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(format!("{id}-part")),
                    source_id: id.into(),
                    target_id: bearer.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO annotation_targets (annotation_id, target_record_id, source_slot, source_event_seq,
                   source_sha256, selectors, purpose, created_at, updated_at)
                 VALUES (?, ?, 'body', 1, ?, ?, 'comment_context', 't', 't')")
                .bind(id).bind(anchored).bind("a".repeat(64))
                .bind(r#"[{"type":"text_quote","exact":"sharedterm"}]"#)
                .execute(db.write_pool()).await.unwrap();
        }
        delete_record(&db, C_DELETED).await.unwrap();
        let ids = |rows: Vec<Value>| {
            rows.iter()
                .map(|row| row["annotation_id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        let sql = "SELECT annotation_id, target_record_id, purpose, selectors, source_event_seq, source_sha256 FROM comment_anchors ORDER BY annotation_id";
        let alice_rows = query_sql(&db, &alice, sql).await.unwrap().rows;
        assert_eq!(ids(alice_rows.clone()), vec![C_COMMON, C_ALICE]);
        assert_eq!(
            alice_rows[0]["selectors"],
            r#"[{"type":"text_quote","exact":"sharedterm"}]"#
        );
        assert_eq!(alice_rows[0]["source_event_seq"], 1);
        assert_eq!(alice_rows[0]["source_sha256"], "a".repeat(64));
        assert_eq!(
            ids(query_sql(&db, &bea, sql).await.unwrap().rows),
            vec![C_COMMON, C_BEA, C_CROSS]
        );
        // Aggregates see no more than rows do.
        let count = query_sql(&db, &alice, "SELECT count(*) AS n FROM comment_anchors")
            .await
            .unwrap()
            .rows;
        assert_eq!(count[0]["n"], 2);
        // The physical table stays unreachable.
        assert!(query_sql(
            &db,
            &alice,
            "SELECT annotation_id FROM main.annotation_targets ORDER BY 1"
        )
        .await
        .is_err());
        // An archived bearer stays visible, as records do; a deleted bearer
        // takes its comments' anchors with it.
        sqlx::query("UPDATE records SET archived = 1 WHERE id = ?")
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            ids(query_sql(&db, &alice, sql).await.unwrap().rows),
            vec![C_COMMON, C_ALICE]
        );
        delete_record(&db, ALICE_PRIVATE_ID).await.unwrap();
        assert_eq!(
            ids(query_sql(&db, &alice, sql).await.unwrap().rows),
            vec![C_COMMON]
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_links_require_both_endpoints_visible() {
        let (db, alice, _) = protected_fixture().await;
        sqlx::query("UPDATE links SET note = ? WHERE id = 'alice-common'")
            .bind("a".repeat(TOOBIG_ALICE_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE links SET note = ? WHERE id = 'common-bea'")
            .bind("b".repeat(TOOBIG_BEA_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        // Mirror of common-bea: invisible source, visible target. Without
        // this row, dropping `source_visible` from the probe is a no-op.
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("bea-common".into()),
                source_id: BEA_PRIVATE_ID.into(),
                target_id: COMMON_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE links SET note = ? WHERE id = 'bea-common'")
            .bind("c".repeat(TOOBIG_BEA_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();

        let error = query_sql(&db, &alice, "SELECT note FROM links")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("links.note"), "{error}");
        assert!(error.contains("alice-common"), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains("common-bea"),
            "named a link with an invisible target: {error}"
        );
        assert!(
            !error.contains("bea-common"),
            "named a link with an invisible source: {error}"
        );
        assert!(
            !error.contains(&format!("{TOOBIG_BEA_BYTES} bytes")),
            "named an invisible link size: {error}"
        );
    }

    async fn create_attachment_with_blob(
        db: &Db,
        attachment_id: &str,
        bearer_id: &str,
        grants: &[&str],
        bytes: &[u8],
    ) -> String {
        create_record(
            db,
            json!({
                "id": attachment_id,
                "type": "Document",
                "kind": "attachment",
                "name": format!("{attachment_id}.txt"),
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:policy",
            attachment_id,
            grants
                .iter()
                .map(|account| AllowEntry::account(*account, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
        let blob = crate::blob::insert_blob(
            db,
            bytes,
            Some("text/plain"),
            Some(&format!("{attachment_id}.txt")),
        )
        .await
        .unwrap();
        set_facet(
            db,
            attachment_id,
            FacetSetPayload {
                key: "blob_ref".into(),
                value: Some(blob.id.clone()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            db,
            LinkAddedPayload {
                id: Some(format!("bearer-{attachment_id}")),
                source_id: attachment_id.into(),
                target_id: bearer_id.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        blob.id
    }

    #[tokio::test]
    async fn sqlite_toobig_blobs_require_visible_bearer_and_ignore_external_size() {
        let (db, alice, _) = protected_fixture().await;
        let alice_blob = create_attachment_with_blob(
            &db,
            TOOBIG_ALICE_ATTACHMENT_ID,
            ALICE_PRIVATE_ID,
            &["alice"],
            &vec![b'a'; TOOBIG_ALICE_BYTES],
        )
        .await;
        let hidden_blob = create_attachment_with_blob(
            &db,
            TOOBIG_BEA_ATTACHMENT_ID,
            BEA_PRIVATE_ID,
            &["alice", "bea"],
            &vec![b'b'; TOOBIG_BEA_BYTES],
        )
        .await;

        create_record(
            &db,
            json!({
                "id": TOOBIG_EXTERNAL_ATTACHMENT_ID,
                "type": "Document",
                "kind": "attachment",
                "name": "external.bin",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            TOOBIG_EXTERNAL_ATTACHMENT_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blobs(id, bytes, mime, size_bytes, sha256, original_filename, storage_tier)
             VALUES (?, NULL, 'application/octet-stream', ?, '00', 'external.bin', 'external')",
        )
        .bind(TOOBIG_EXTERNAL_BLOB_ID)
        .bind((MAX_SQLITE_VALUE_BYTES as i64) + 1_000_000)
        .execute(db.write_pool())
        .await
        .unwrap();
        set_facet(
            &db,
            TOOBIG_EXTERNAL_ATTACHMENT_ID,
            FacetSetPayload {
                key: "blob_ref".into(),
                value: Some(TOOBIG_EXTERNAL_BLOB_ID.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("bearer-external-toobig".into()),
                source_id: TOOBIG_EXTERNAL_ATTACHMENT_ID.into(),
                target_id: ALICE_PRIVATE_ID.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        let error = query_sql(&db, &alice, "SELECT bytes FROM blobs")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("blobs.bytes"), "{error}");
        assert!(error.contains(&alice_blob), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains(&hidden_blob),
            "named a blob whose bearer is invisible: {error}"
        );
        assert!(
            !error.contains(TOOBIG_EXTERNAL_BLOB_ID),
            "named an external blob by size_bytes: {error}"
        );
    }
    async fn exact_reaction_event(
        db: &Db,
        id: &str,
        message: &str,
        actor: &str,
        emoji: &str,
        added: bool,
        payload_shape: (bool, bool),
    ) {
        let (sequence, oversized) = payload_shape;
        let reason = if oversized {
            "x".repeat(1024 * 1024)
        } else {
            "reaction fixture".into()
        };
        let key = if oversized {
            "k".repeat(1024 * 1024)
        } else {
            id.into()
        };
        let command = if added {
            "add_reaction"
        } else {
            "remove_reaction"
        };
        let payload = if sequence {
            json!([
                "native.message-reaction.v1",
                emoji,
                key,
                command,
                true,
                actor,
                "authenticated_principal",
                null,
                reason
            ])
        } else {
            json!({"format":"native.message-reaction.v1", "emoji":emoji,
                "idempotency_key":key, "command":command, "changed":true,
                "actor_account_id":actor, "executor_kind":"authenticated_principal",
                "executor_ref":null, "reason":reason})
        };
        serde_json::from_value::<crate::events::MessageReactionPayload>(payload.clone())
            .unwrap()
            .validate(Some(actor))
            .unwrap();
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
                     VALUES(?,?,?,?,?,'2026-10-01T12:00:00.000Z',1,'legacy_unknown')",
        )
        .bind(id)
        .bind(message)
        .bind(if added {
            "message.reaction.added.v1"
        } else {
            "message.reaction.removed.v1"
        })
        .bind(payload.to_string())
        .bind(actor)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_install_keeps_catalog_and_retention_contract() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        // Exercise main's frozen batch installer, also used by app-v2 sessions.
        install_temp_contract(&mut tx).await.unwrap();
        let relations = sqlx::query("SELECT relation_name,comment FROM temp.catalog_relations")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(relations.len(), sql_contract::LOGICAL_RELATIONS.len());
        for (name, _, _, _, _, _, comment) in sql_contract::catalog_relation_rows() {
            let row = relations
                .iter()
                .find(|row| row.get::<String, _>("relation_name") == name)
                .unwrap();
            assert_eq!(row.get::<String, _>("comment"), comment);
        }
        let columns: i64 = sqlx::query_scalar("SELECT count(*) FROM temp.catalog_columns")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(columns as usize, sql_contract::catalog_column_rows().len());

        // This independently pins the stored-column assumptions behind the
        // view's non-filtering retention predicates; do not replace them with
        // nullable test tables or an authorizer population-read exception.
        for (pragma, column) in [
            ("PRAGMA main.table_info(content_events)", "id"),
            ("PRAGMA temp.table_info(_query_sql_principal)", "account_id"),
        ] {
            let schema = sqlx::query(pragma).fetch_all(&mut *tx).await.unwrap();
            let field = schema
                .iter()
                .find(|row| row.get::<String, _>("name") == column)
                .unwrap();
            assert_eq!(field.get::<String, _>("type"), "TEXT");
            assert_eq!(field.get::<i64, _>("notnull"), 1);
        }
        for value in ["", "plain", "世界🙂", "\0embedded"] {
            let retained: i64 = sqlx::query_scalar("SELECT length(?) >= 0")
                .bind(value)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(retained, 1);
        }
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_preserve_legacy_partitions_privacy_and_oversized_payloads() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_event(
            &db,
            "object-old",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (false, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "object-remove",
            D6_M_OPEN,
            "alice",
            "👍",
            false,
            (false, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "object-undo",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (false, true),
        )
        .await;
        exact_reaction_event(
            &db,
            "array-old",
            D6_M_OPEN,
            "alice",
            "😂",
            true,
            (true, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "array-winning",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (true, true),
        )
        .await;
        exact_reaction_event(
            &db,
            "hidden-actor",
            D6_M_OPEN,
            "harriet",
            "🎉",
            true,
            (false, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "unbound-actor",
            D6_M_OPEN,
            "orphan",
            "❤️",
            true,
            (false, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "hidden-message",
            D6_M_BEA_ONLY,
            "bea",
            "👀",
            true,
            (false, true),
        )
        .await;
        let sql = "SELECT * FROM message_reactions ORDER BY reaction_id";
        let alice = QueryPrincipal::authenticated("alice", true);
        let bea = QueryPrincipal::authenticated("bea", true);
        let rows = d6_rows(&db, &alice, sql).await;
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.iter().filter(|r| r["emoji"] == "👍").count(),
            2,
            "object and NULL legacy partition winners must both survive"
        );
        let old = crate::mcp::tools::messaging::reaction_groups_for_projection_test(
            &db, "alice", D6_M_OPEN,
        )
        .await
        .unwrap();
        for group in old {
            assert_eq!(
                rows.iter().filter(|r| r["emoji"] == group["emoji"]).count(),
                group["count"].as_u64().unwrap() as usize
            );
        }
        for r in rows.iter().filter(|r| r["viewer"] == 1) {
            assert_eq!(r["actor_record_id"], D6_P_ALICE);
            assert_eq!(r["executor_kind"], "authenticated_principal");
        }
        let bea_rows = d6_rows(&db, &bea, sql).await;
        assert_eq!(bea_rows.len(), 5);
        let hidden = bea_rows
            .iter()
            .find(|r| r["reaction_id"] == "hidden-actor")
            .unwrap();
        for key in ["actor_record_id", "actor_name", "executor_kind"] {
            assert!(hidden[key].is_null(), "{hidden}");
        }
        let unbound = bea_rows
            .iter()
            .find(|r| r["reaction_id"] == "unbound-actor")
            .unwrap();
        assert!(unbound["executor_kind"].is_null());
        // This test deliberately exercises the existing trusted-local gate.
        let local = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let trusted = d6_rows(&db, &local, sql).await;
        let unbound = trusted
            .iter()
            .find(|r| r["reaction_id"] == "unbound-actor")
            .unwrap();
        assert!(unbound["actor_record_id"].is_null());
        assert_eq!(unbound["executor_kind"], "authenticated_principal");
        // Visible binding and name mutations change attribution without a
        // new reaction. Hidden rows remain present and UUIDs remain stable.
        sqlx::query("UPDATE records SET name='Renamed Alice' WHERE id=?")
            .bind(D6_P_ALICE)
            .execute(db.write_pool())
            .await
            .unwrap();
        let renamed = d6_rows(&db, &alice, sql).await;
        assert_eq!(
            renamed
                .iter()
                .map(|r| &r["reaction_id"])
                .collect::<Vec<_>>(),
            rows.iter().map(|r| &r["reaction_id"]).collect::<Vec<_>>()
        );
        assert!(renamed
            .iter()
            .filter(|r| r["viewer"] == 1)
            .all(|r| r["actor_name"] == "Renamed Alice"));
        for r in renamed {
            for key in r.as_object().unwrap().keys() {
                assert!(
                    !key.contains("seq") && !key.contains("account") && !key.contains("payload"),
                    "{key}"
                );
            }
        }
    }

    #[tokio::test]
    async fn exact_reaction_reads_count_selfjoin_cte_and_app_grants_share_full_population() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        for id in ["a", "b"] {
            exact_reaction_event(&db, id, D6_M_OPEN, id, "👍", true, (false, false)).await;
        }
        let principal = QueryPrincipal::authenticated("alice", true);
        let cases = [
            ("SELECT count(*) AS n FROM message_reactions", 2),
            ("SELECT count(*) AS n FROM message_reactions a CROSS JOIN message_reactions b", 4),
            ("SELECT count(*) AS n FROM message_reactions a INNER JOIN message_reactions b ON 1=1", 4),
            ("WITH r AS (SELECT reaction_id FROM message_reactions) SELECT count(*) AS n FROM r", 2),
            // x.n is the non-null sequence 1,2, so count(x.n) counts all four
            // cross-product rows without a column-less read of the CTE.
            // Plain reaction COUNT(*) remains covered above.
            ("WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<2) SELECT count(x.n) AS n FROM x CROSS JOIN message_reactions", 4),
        ];
        let declared = crate::mcp::tools::alpha_tabs::parse_reads_declaration(
            &json!({"relations":{"message_reactions":["reaction_id"]}}),
        )
        .unwrap();
        for (sql, n) in cases {
            assert!(validated_relation_dependencies(sql)
                .unwrap()
                .contains("message_reactions"));
            assert_eq!(d6_rows(&db, &principal, sql).await[0]["n"], n);
            let result = app_query(&db, &declared, principal.clone(), sql).await;
            // The existing apps analyzer admits INNER/LEFT joins with ON,
            // while CTEs and CROSS joins remain outside reads.v1's shape.
            // Direct query_sql retains every corresponding data assertion.
            if sql.starts_with("WITH") || sql.contains("CROSS JOIN") {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("app_sql [unsupported_sql]"), "{error}");
            } else {
                assert_eq!(result.unwrap().rows[0]["n"], n);
            }
        }
        for sql in [
            "SELECT reaction_id FROM message_reactions WHERE 0",
            "SELECT reaction_id FROM message_reactions ORDER BY reaction_id LIMIT 0",
        ] {
            assert!(validated_relation_dependencies(sql)
                .unwrap()
                .contains("message_reactions"));
            assert!(app_query(&db, &declared, principal.clone(), sql)
                .await
                .unwrap()
                .rows
                .is_empty());
        }
        assert!(app_query(
            &db,
            &app_declared_records(),
            principal.clone(),
            "SELECT count(*) AS n FROM message_reactions"
        )
        .await
        .is_err());
        assert!(app_query(
            &db,
            &declared,
            principal.clone(),
            "SELECT actor_name FROM message_reactions"
        )
        .await
        .is_err());
        let scoped = crate::mcp::tools::alpha_tabs::parse_reads_declaration(
            &json!({"relations":{"message_reactions":["reaction_id"]},"scope":[{"type":"Message"}]})).unwrap();
        assert!(app_query(
            &db,
            &scoped,
            principal.clone(),
            "SELECT reaction_id FROM message_reactions"
        )
        .await
        .is_err());
        let shadow = "WITH message_reactions AS (SELECT id FROM records) SELECT count(*) AS n FROM message_reactions";
        assert!(!validated_relation_dependencies(shadow)
            .unwrap()
            .contains("message_reactions"));
        for sql in [
            "SELECT event_seq FROM _query_sql_reaction_winners",
            "SELECT reaction_id FROM _query_sql_reaction_source",
            "SELECT event_seq FROM content_event_reaction_meta",
            "SELECT seq FROM message_reactions",
            "SELECT payload FROM message_reactions",
        ] {
            assert!(query_sql(&db, &principal, sql).await.is_err(), "{sql}");
        }
        // Successful borrowed app calls tear down the relation and its stage.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name IN ('message_reactions','_query_sql_reaction_winners')")
            .fetch_one(&mut *connection).await.unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn exact_reaction_fold_is_source_free_and_public_identity_reads_only_id_seq() {
        let conn = build_frozen_validator().unwrap();
        conn.execute_batch(
            "INSERT INTO temp._query_sql_visible_ids(id) SELECT id FROM main.records;",
        )
        .unwrap();
        conn.authorizer(Some(|c: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name: "content_events",
                ..
            } = c.action
            {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
        conn.execute(REACTION_WINNER_SQL, [MAX_REACTION_WINNERS + 1])
            .unwrap();
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let seen = Arc::new(std::sync::Mutex::new(BTreeSet::new()));
        let reads = seen.clone();
        conn.authorizer(Some(move |c: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name: "content_events",
                column_name,
            } = c.action
            {
                reads.lock().unwrap().insert(column_name.to_owned());
                if !matches!(column_name, "id" | "seq") {
                    return Authorization::Deny;
                }
            }
            authorize_view_expansion(c)
        }));
        conn.prepare("SELECT * FROM message_reactions ORDER BY reaction_id")
            .unwrap();
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert_eq!(
            *seen.lock().unwrap(),
            BTreeSet::from(["id".into(), "seq".into()])
        );
        // Injecting an accidental payload read into the controlled view must
        // fail the production expansion authorizer, not only a test callback.
        conn.execute_batch("DROP VIEW temp.message_reactions;
             CREATE TEMP VIEW message_reactions AS SELECT e.payload AS reaction_id FROM main.content_events e;").unwrap();
        assert!(prepare_under_authorizer(
            &conn,
            "SELECT reaction_id FROM message_reactions",
            authorize_view_expansion
        )
        .is_err());
        for column in ["type", "actor"] {
            conn.execute_batch(&format!("DROP VIEW temp.message_reactions; CREATE TEMP VIEW message_reactions AS SELECT e.{column} AS reaction_id FROM main.content_events e;")).unwrap();
            assert!(prepare_under_authorizer(
                &conn,
                "SELECT reaction_id FROM message_reactions",
                authorize_view_expansion
            )
            .is_err());
        }
    }
    async fn exact_reaction_bulk(db: &Db, message: &str, prefix: &str, amount: i64) {
        let payload = json!({"format":"native.message-reaction.v1","emoji":"👍",
            "idempotency_key":"bulk","command":"add_reaction","changed":true,
            "actor_account_id":"bulk","executor_kind":"authenticated_principal",
            "executor_ref":null,"reason":"bounded history qualification"})
        .to_string();
        sqlx::query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
            SELECT ?||x,?,'message.reaction.added.v1',?,'bulk','2026-10-01T12:00:00.000Z',1,'legacy_unknown' FROM n",
        )
        .bind(amount)
        .bind(prefix)
        .bind(message)
        .bind(payload)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_session_reuse_clears_previous_viewers_winners() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_event(
            &db,
            "shared",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (false, false),
        )
        .await;
        exact_reaction_event(
            &db,
            "private",
            D6_M_BEA_ONLY,
            "bea",
            "👀",
            true,
            (false, false),
        )
        .await;
        let tx = db.governed_pool().begin().await.unwrap();
        let mut session = GovernedSqlSession::begin(&db, tx).await.unwrap();
        for (viewer, count) in [("bea", 2), ("alice", 1), ("bea", 2), ("alice", 1)] {
            let (rows, _) = session
                .execute(
                    QueryPrincipal::authenticated(viewer, true),
                    QuerySqlRequest {
                        sql: "SELECT count(*) AS n FROM message_reactions".into(),
                        parameters: vec![],
                    },
                    MAX_ROWS,
                    sql_contract::FunctionAllowance::Portable,
                    None,
                    None,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(rows.rows[0]["n"], count, "{viewer}");
            // An unrelated next statement must clear the internal stage too.
            session
                .execute(
                    QueryPrincipal::authenticated(viewer, true),
                    QuerySqlRequest {
                        sql: "SELECT count(*) AS n FROM records".into(),
                        parameters: vec![],
                    },
                    MAX_ROWS,
                    sql_contract::FunctionAllowance::Portable,
                    None,
                    None,
                    false,
                )
                .await
                .unwrap();
            let staged: i64 =
                sqlx::query_scalar("SELECT count(*) FROM temp._query_sql_reaction_winners")
                    .fetch_one(&mut **session.transaction_for_test())
                    .await
                    .unwrap();
            assert_eq!(staged, 0);
        }
        let mut tx = session.finish().await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name IN ('message_reactions','_query_sql_reaction_winners')")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        tx.rollback().await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn exact_reaction_reads_vm_work_bounds_the_visible_history_window() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let principal = QueryPrincipal::authenticated("alice", true);
        exact_reaction_bulk(&db, D6_M_OPEN, "visible-small-", 500).await;
        let measured = |sql: &str| QuerySqlRequest {
            sql: sql.into(),
            parameters: vec![],
        };
        let run = |request| {
            query_sql_request_owned_with_vm_work(
                db.clone(),
                principal.clone(),
                request,
                Some(Arc::new(AtomicU64::new(0))),
                true,
            )
        };
        let before = Arc::new(AtomicU64::new(0));
        let sql = "SELECT count(*) AS n FROM message_reactions";
        assert_eq!(
            query_sql_request_owned_with_vm_work(
                db.clone(),
                principal.clone(),
                measured(sql),
                Some(before.clone()),
                true
            )
            .await
            .unwrap()
            .rows[0]["n"],
            1
        );
        exact_reaction_bulk(&db, D6_M_BEA_ONLY, "hidden-", 10_000).await;
        let hidden = Arc::new(AtomicU64::new(0));
        query_sql_request_owned_with_vm_work(
            db.clone(),
            principal.clone(),
            measured(sql),
            Some(hidden.clone()),
            true,
        )
        .await
        .unwrap();
        assert!(
            hidden.load(Ordering::Relaxed) <= before.load(Ordering::Relaxed) + 3,
            "private reaction work grew with hidden history"
        );
        exact_reaction_bulk(&db, D6_M_OPEN, "visible-large-", 4_000).await;
        let large = Arc::new(AtomicU64::new(0));
        query_sql_request_owned_with_vm_work(
            db.clone(),
            principal.clone(),
            measured(sql),
            Some(large.clone()),
            true,
        )
        .await
        .unwrap();
        assert!(
            large.load(Ordering::Relaxed) > before.load(Ordering::Relaxed) * 3,
            "measurement must include full window work despite the single winning row"
        );
        let capped = Arc::new(AtomicU64::new(0));
        query_sql_request_owned_with_vm_work(
            db.clone(),
            principal.clone(),
            measured("SELECT reaction_id FROM message_reactions ORDER BY reaction_id LIMIT 1"),
            Some(capped.clone()),
            true,
        )
        .await
        .unwrap();
        assert!(
            capped.load(Ordering::Relaxed) + 3 >= large.load(Ordering::Relaxed),
            "output LIMIT must not bypass the history window"
        );
        run(measured(
            "SELECT reaction_id FROM message_reactions WHERE 0",
        ))
        .await
        .unwrap();
        let conn = build_frozen_validator().unwrap();
        let plan: Vec<String> = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {REACTION_WINNER_SQL}"))
            .unwrap()
            .query_map([MAX_REACTION_WINNERS + 1], |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            plan.iter().any(|p| p
                .contains("SEARCH meta USING INDEX idx_content_event_reaction_meta_record")
                && p.contains("record_id=?")),
            "{plan:?}"
        );
        assert!(!plan.iter().any(|p| p.contains("SCAN meta")), "{plan:?}");
        let public_plan: Vec<String> = conn
            .prepare("EXPLAIN QUERY PLAN SELECT * FROM message_reactions")
            .unwrap()
            .query_map([], |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            public_plan
                .iter()
                .any(|p| p.contains("SEARCH identity USING INTEGER PRIMARY KEY")),
            "{public_plan:?}"
        );
        assert!(
            !public_plan.iter().any(|p| p.contains("SCAN actor_binding")),
            "{public_plan:?}"
        );
    }

    #[tokio::test]
    async fn exact_reaction_reads_history_cap_is_visible_complete_or_error_before_fold() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let seed_types: Vec<(String, i64)> = sqlx::query_as(
            "SELECT type,count(*) FROM main.content_events WHERE record_id=? GROUP BY type ORDER BY type",
        )
        .bind(D6_M_BEA_ONLY)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(seed_types, [("record.created".to_owned(), 1)]);
        let source_counts_sql = "SELECT
            (SELECT count(*) FROM main.content_events WHERE record_id=?),
            (SELECT count(*) FROM main.content_events WHERE record_id=?
                AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')),
            (SELECT count(*) FROM main.content_events)";
        let baseline: (i64, i64, i64) = sqlx::query_as(source_counts_sql)
            .bind(D6_M_BEA_ONLY)
            .bind(D6_M_BEA_ONLY)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!((baseline.0, baseline.1), (1, 0));
        let guard_count_sql = "SELECT count(*) FROM main.sqlite_master WHERE type='trigger'
            AND tbl_name='content_events' AND name IN ('content_events_no_update','content_events_no_delete')";
        let guards: i64 = sqlx::query_scalar(guard_count_sql)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(guards, 2);
        exact_reaction_bulk(
            &db,
            D6_M_BEA_ONLY,
            "hidden-bound-",
            MAX_REACTION_SOURCE_EVENTS + 1,
        )
        .await;
        let pre_error: (i64, i64, i64) = sqlx::query_as(source_counts_sql)
            .bind(D6_M_BEA_ONLY)
            .bind(D6_M_BEA_ONLY)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            pre_error,
            (
                baseline.0 + MAX_REACTION_SOURCE_EVENTS + 1,
                MAX_REACTION_SOURCE_EVENTS + 1,
                baseline.2 + MAX_REACTION_SOURCE_EVENTS + 1
            )
        );
        let alice = QueryPrincipal::authenticated("alice", true);
        assert_eq!(
            d6_rows(&db, &alice, "SELECT count(*) AS n FROM message_reactions").await[0]["n"],
            0
        );
        let bea = QueryPrincipal::authenticated("bea", true);
        for sql in [
            "SELECT count(*) AS n FROM message_reactions",
            "SELECT reaction_id FROM message_reactions ORDER BY reaction_id LIMIT 1",
            "SELECT reaction_id FROM message_reactions WHERE 0",
            "WITH r AS (SELECT reaction_id FROM message_reactions) SELECT count(*) AS n FROM r",
        ] {
            let error = query_sql(&db, &bea, sql).await.unwrap_err().to_string();
            assert!(
                error.contains("visible reaction history bound exceeded"),
                "{error}"
            );
            assert!(
                !error.contains(D6_M_BEA_ONLY) && !error.contains("bulk"),
                "{error}"
            );
        }
        // A CTE shadow never creates a reaction dependency or incurs the cap.
        let shadow = "WITH message_reactions(reaction_id) AS (VALUES(1))
            SELECT count(reaction_id) AS n FROM message_reactions";
        assert!(validated_relation_dependencies(shadow).unwrap().is_empty());
        assert_eq!(d6_rows(&db, &bea, shadow).await, [json!({"n": 1})]);
        // A borrowed transaction also refuses before output, then removes all
        // TEMP state while preserving the ordinary domain transaction.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            bea,
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible reaction history bound exceeded"),
            "{error}"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        // Keep the seed and all unrelated/root source rows in the proof.
        // With both append-only guards still installed, unchanged physical
        // counts prove the refused read inserted no partial source history.
        let after_error: (i64, i64, i64) = sqlx::query_as(source_counts_sql)
            .bind(D6_M_BEA_ONLY)
            .bind(D6_M_BEA_ONLY)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(after_error, pre_error);
        let guards: i64 = sqlx::query_scalar(guard_count_sql)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(guards, 2);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_deadline_cancel_and_pool_reuse_clear_winners() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_event(
            &db,
            "deadline-reaction",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (false, true),
        )
        .await;
        let held = hold_all_but_one_governed_slot(&db).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        let busy = "WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<100000000) SELECT sum(x.n) AS n FROM x CROSS JOIN message_reactions";
        let error = query_sql(&db, &alice, busy).await.unwrap_err().to_string();
        assert!(
            error.contains("timeout") || error.contains("deadline"),
            "{error}"
        );
        assert_eq!(
            d6_rows(&db, &alice, "SELECT count(*) AS n FROM message_reactions").await[0]["n"],
            1
        );
        let work = Arc::new(AtomicU64::new(0));
        let future = query_sql_request_owned_with_vm_work(
            db.clone(),
            alice.clone(),
            QuerySqlRequest {
                sql: busy.into(),
                parameters: vec![],
            },
            Some(work.clone()),
            true,
        );
        let task = tokio::spawn(future);
        tokio::time::timeout(Duration::from_secs(30), async {
            while work.load(Ordering::Relaxed) == 0 {
                if task.is_finished() {
                    panic!("query finished before cancellation probe");
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let bea = QueryPrincipal::authenticated("bea", true);
        assert_eq!(
            d6_rows(&db, &bea, "SELECT viewer FROM message_reactions").await[0]["viewer"],
            0
        );
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name IN ('message_reactions','_query_sql_reaction_winners')")
            .fetch_one(&mut *connection).await.unwrap();
        assert_eq!(left, 0);
        drop(connection);
        drop(held);
        // Successful caller-owned execution cleans before rollback/reuse.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        query_sql_request_in(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name IN ('message_reactions','_query_sql_reaction_winners')")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        tx.rollback().await.unwrap();
    }
    async fn exact_reaction_head_fixture_events(
        db: &Db,
        record: &str,
        prefix: &str,
        amount: i64,
        event_type: &str,
    ) {
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
            SELECT ?||x,?,?,'{}','alice','2026-10-01T12:00:00.000Z',1,'legacy_unknown' FROM n")
            .bind(amount).bind(prefix).bind(record).bind(event_type)
            .execute(db.write_pool()).await.unwrap();
    }

    async fn exact_reaction_borrowed_observation(
        db: &Db,
        work: Arc<AtomicU64>,
    ) -> GovernedSqlObservation {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (_, observation) = query_sql_request_in_with_row_limit_observed(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions".into(),
                parameters: vec![],
            },
            200,
            sql_contract::FunctionAllowance::Portable,
            None,
            Some(work),
            false,
        )
        .await
        .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        tx.rollback().await.unwrap();
        observation
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_head_matches_history_and_ignores_hidden_churn() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        for (i, event_type) in [
            "record.updated",
            "occurrence.bound.v1",
            "reconciliation.recorded.v1",
            "unit.superseded.v1",
            "receipt.dependency_audited.v1",
        ]
        .iter()
        .enumerate()
        {
            // Non-Message history contributes, including occurrence.bound.
            exact_reaction_head_fixture_events(
                &db,
                D6_D_REF,
                &format!("head-type-{i}-"),
                1,
                event_type,
            )
            .await;
        }
        let expected: i64 =
            sqlx::query_scalar("SELECT seq FROM content_events WHERE id='head-type-1-1'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let before = Arc::new(AtomicU64::new(0));
        let old_head = d6_rows(
            &db,
            &QueryPrincipal::authenticated("alice", true),
            "SELECT coalesce(max(local_seq),0) AS head FROM content_events",
        )
        .await[0]["head"]
            .as_i64()
            .unwrap();
        assert_eq!(old_head, expected);
        let first = exact_reaction_borrowed_observation(&db, before.clone()).await;
        assert_eq!(first.content_event_seq, Some(old_head));
        exact_reaction_head_fixture_events(
            &db,
            D6_M_BEA_ONLY,
            "head-hidden-",
            10_000,
            "record.updated",
        )
        .await;
        let after = Arc::new(AtomicU64::new(0));
        let second = exact_reaction_borrowed_observation(&db, after.clone()).await;
        assert_eq!(second.content_event_seq, first.content_event_seq);
        assert_eq!(second.authorization_boundary, first.authorization_boundary);
        assert!(
            after.load(Ordering::Relaxed) <= before.load(Ordering::Relaxed) + 2,
            "hidden history grew bounded-stage VM work: before={} after={}",
            before.load(Ordering::Relaxed),
            after.load(Ordering::Relaxed)
        );
        // Owned envelope deliberately retains its existing global head.
        let owned = query_sql(
            &db,
            &QueryPrincipal::authenticated("alice", true),
            "SELECT count(*) AS n FROM message_reactions",
        )
        .await
        .unwrap();
        let global: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(owned.as_of_seq, global);
        assert!(global > expected);
    }

    #[tokio::test]
    async fn exact_reaction_reads_head_preserves_negative_empty_and_minimum_sequences() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE _query_sql_visible_ids(id TEXT PRIMARY KEY)")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            bounded_reaction_visible_head(
                &mut tx,
                &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE)
            )
            .await
            .unwrap(),
            0
        );
        // Isolate a new real record with no positive fixture history.
        // Other records are deliberately absent from this private test stage.
        sqlx::query("INSERT INTO records(id,type,name,policy_anchor_id) VALUES('negative-head-record','Document','Negative',?)")
            .bind(D6_D_REF).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO _query_sql_visible_ids VALUES('negative-head-record')")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            bounded_reaction_visible_head(
                &mut tx,
                &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE)
            )
            .await
            .unwrap(),
            0
        );
        let expired = bounded_reaction_visible_head(&mut tx, &ReactionDeadline::at(Instant::now()))
            .await
            .unwrap_err()
            .to_string();
        assert!(expired.contains("shared deadline exceeded"), "{expired}");
        for (seq, event_type) in [
            (i64::MIN, "record.updated"),
            (-2, "occurrence.bound.v1"),
            (-1, "unit.superseded.v1"),
        ] {
            sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
                VALUES(?,?,'negative-head-record',?,'{}','alice','2026-10-01T12:00:00.000Z',1,'legacy_unknown')")
                .bind(seq).bind(format!("negative-{seq}")).bind(event_type).execute(&mut *tx).await.unwrap();
            let expected: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id='negative-head-record'
                AND type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')")
                .fetch_one(&mut *tx).await.unwrap();
            assert_eq!(
                bounded_reaction_visible_head(
                    &mut tx,
                    &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE)
                )
                .await
                .unwrap(),
                expected
            );
        }
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_envelope_preserves_global_range_and_constant_vm() {
        use sqlx::Connection as _;
        // The actual sqlx SQLite backend and current production schema, with
        // no bootstrap events masking empty/all-negative envelope cases.
        let mut connection = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        for statement in DDL_STATEMENTS {
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .unwrap();
        }
        let schema = sqlx::query("PRAGMA main.table_info(content_events)")
            .fetch_all(&mut connection)
            .await
            .unwrap();
        let record_id = schema
            .iter()
            .find(|row| row.get::<String, _>("name") == "record_id")
            .unwrap();
        assert_eq!(record_id.get::<String, _>("type"), "TEXT");
        assert_eq!(record_id.get::<i64, _>("notnull"), 1);
        for value in ["", "世界🙂", "\0embedded"] {
            let true_for_value: i64 = sqlx::query_scalar("SELECT length(?)>=0")
                .bind(value)
                .fetch_one(&mut connection)
                .await
                .unwrap();
            assert_eq!(true_for_value, 1);
        }
        async fn observed(connection: &mut sqlx::SqliteConnection) -> (i64, u64) {
            let steps = Arc::new(AtomicU64::new(0));
            {
                let mut handle = connection.lock_handle().await.unwrap();
                let counter = steps.clone();
                handle.set_progress_handler(1, move || {
                    counter.fetch_add(1, Ordering::Relaxed);
                    true
                });
            }
            let head: i64 = sqlx::query_scalar(REACTION_BORROWED_ENVELOPE_SQL)
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            connection
                .lock_handle()
                .await
                .unwrap()
                .remove_progress_handler();
            let expected: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
                    .fetch_one(connection)
                    .await
                    .unwrap();
            assert_eq!(head, expected);
            (head, steps.load(Ordering::Relaxed))
        }
        assert_eq!(observed(&mut connection).await.0, 0);
        for (seq, record, expected) in [(i64::MIN, "", i64::MIN), (-5, "世界🙂", -5)] {
            sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,causal_envelope_version,causal_status)
                VALUES(?,?,?,'probe.envelope','{}',1,'legacy_unknown')")
                .bind(seq).bind(format!("envelope-{seq}")).bind(record)
                .execute(&mut connection).await.unwrap();
            assert_eq!(observed(&mut connection).await.0, expected);
        }
        let before = observed(&mut connection).await.1;
        // Other records' history must advance the actual global envelope,
        // while its rightmost lookup stays constant work before the handler.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000)
            INSERT INTO content_events(seq,id,record_id,type,payload,causal_envelope_version,causal_status)
            SELECT x,'envelope-hidden-'||x,'other-hidden-record','probe.envelope','{}',1,'legacy_unknown' FROM n")
            .execute(&mut connection).await.unwrap();
        let (head, after) = observed(&mut connection).await;
        assert_eq!(head, 10000);
        assert!(
            before > 0 && after <= before + 2 && after < 100,
            "envelope VM: {before} -> {after}"
        );
        sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,causal_envelope_version,causal_status)
            VALUES(?,'envelope-max',?,'probe.envelope','{}',1,'legacy_unknown')")
            .bind(i64::MAX).bind("\0embedded").execute(&mut connection).await.unwrap();
        assert_eq!(observed(&mut connection).await.0, i64::MAX);
        let plan = sqlx::query(&format!(
            "EXPLAIN QUERY PLAN {REACTION_BORROWED_ENVELOPE_SQL}"
        ))
        .fetch_all(&mut connection)
        .await
        .unwrap();
        let details: Vec<String> = plan.iter().map(|row| row.get(3)).collect();
        assert!(
            details
                .iter()
                .any(|line| line.contains("SEARCH main.content_events")),
            "{details:?}"
        );
        assert!(
            !details
                .iter()
                .any(|line| line.contains("SCAN") || line.contains("TEMP B-TREE")),
            "{details:?}"
        );
        let bytecode = sqlx::query(&format!("EXPLAIN {REACTION_BORROWED_ENVELOPE_SQL}"))
            .fetch_all(&mut connection)
            .await
            .unwrap();
        assert!(bytecode.iter().any(|row| row.get::<String, _>(1) == "Last"));
        assert!(!bytecode.iter().any(|row| matches!(
            row.get::<String, _>(1).as_str(),
            "Rewind" | "Next" | "SorterOpen" | "Sort"
        )));
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_path_source_authorizer_is_payload_free() {
        use std::ffi::{c_char, c_int, c_void, CStr};
        struct Trace(std::sync::Mutex<Vec<(String, String, String)>>);
        unsafe extern "C" fn authorize(
            data: *mut c_void,
            action: c_int,
            table: *const c_char,
            column: *const c_char,
            database: *const c_char,
            accessor: *const c_char,
        ) -> c_int {
            if action != libsqlite3_sys::SQLITE_READ || table.is_null() || column.is_null() {
                return libsqlite3_sys::SQLITE_OK;
            }
            // SAFETY: SQLite supplies live NUL-terminated callback strings;
            // the test retains Trace until the callback is removed below.
            let table = unsafe { CStr::from_ptr(table) }.to_string_lossy();
            if table != "content_events" {
                return libsqlite3_sys::SQLITE_OK;
            }
            let column = unsafe { CStr::from_ptr(column) }
                .to_string_lossy()
                .into_owned();
            let accessor = if accessor.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(accessor) }
                    .to_string_lossy()
                    .into_owned()
            };
            let database = if database.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(database) }
                    .to_string_lossy()
                    .into_owned()
            };
            unsafe { &*(data as *const Trace) }.0.lock().unwrap().push((
                column.clone(),
                accessor.clone(),
                database,
            ));
            let permitted = if accessor == "message_reactions" {
                matches!(column.as_str(), "id" | "seq")
            } else {
                matches!(column.as_str(), "seq" | "record_id" | "type")
            };
            if permitted {
                libsqlite3_sys::SQLITE_OK
            } else {
                libsqlite3_sys::SQLITE_DENY
            }
        }
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_event(
            &db,
            "borrowed-authorized-winner",
            D6_M_OPEN,
            "alice",
            "👍",
            true,
            (false, true),
        )
        .await;
        // The envelope must retain a later hidden source event, even though
        // the public winning row and visible freshness head exclude it.
        exact_reaction_event(
            &db,
            "borrowed-hidden-envelope",
            D6_M_BEA_ONLY,
            "bea",
            "👍",
            true,
            (false, false),
        )
        .await;
        let trace = Box::new(Trace(std::sync::Mutex::new(vec![])));
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let global_envelope: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: exclusive handle, boxed trace remains live across await.
            assert_eq!(
                unsafe {
                    libsqlite3_sys::sqlite3_set_authorizer(
                        handle.as_raw_handle().as_ptr(),
                        Some(authorize),
                        (&*trace as *const Trace).cast_mut().cast(),
                    )
                },
                libsqlite3_sys::SQLITE_OK
            );
        }
        let result = query_sql_request_in(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT reaction_id,viewer FROM message_reactions".into(),
                parameters: vec![],
            },
        )
        .await;
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: remove callback before dropping its boxed state.
            assert_eq!(
                unsafe {
                    libsqlite3_sys::sqlite3_set_authorizer(
                        handle.as_raw_handle().as_ptr(),
                        None,
                        std::ptr::null_mut(),
                    )
                },
                libsqlite3_sys::SQLITE_OK
            );
        }
        let result = result.unwrap_or_else(|error| {
            panic!(
                "borrowed source-authorizer result: {error}; actual SQLite READ trace: {:?}",
                trace.0.lock().unwrap()
            )
        });
        assert_eq!(result.as_of_seq, global_envelope);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["reaction_id"], "borrowed-authorized-winner");
        {
            let reads = trace.0.lock().unwrap();
            assert!(
                reads
                    .iter()
                    .any(|(column, accessor, _)| column == "type" && accessor.is_empty()),
                "{reads:?}"
            );
            assert!(
                reads
                    .iter()
                    .any(|(column, accessor, _)| column == "id" && accessor == "message_reactions"),
                "{reads:?}"
            );
            assert!(
                !reads.iter().any(|(column, _, _)| matches!(
                    column.as_str(),
                    "payload" | "actor" | "run_key"
                )),
                "{reads:?}"
            );
            assert!(
                reads.iter().all(|(_, _, database)| database == "main"),
                "{reads:?}"
            );
        }
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_excluded_tail_fails_closed_and_reuses_transaction() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_head_fixture_events(
            &db,
            D6_D_REF,
            "head-excluded-",
            MAX_REACTION_HEAD_EVENTS + 1,
            "unit.superseded.v1",
        )
        .await;
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions WHERE 0".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        // A cold/slow machine can reach the SAME absolute deadline before the
        // aggregate cap. Neither path may return a partial head or receipt.
        assert!(
            error.contains("visible freshness history bound exceeded")
                || error.contains("deadline")
                || error.contains("timeout"),
            "{error}"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        let result = query_sql_request_in(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT 42 AS n".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap();
        assert_eq!(result.rows[0]["n"], 42);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_head_budget_is_aggregate_across_all_visible_records() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        for (prefix, record) in [
            ("aggregate-note-", D6_D_REF),
            ("aggregate-message-", D6_M_OPEN),
        ] {
            exact_reaction_head_fixture_events(&db, record, prefix, 2, "unit.superseded.v1").await;
        }
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        sqlx::query("CREATE TEMP TABLE _query_sql_visible_ids(id TEXT PRIMARY KEY)")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO _query_sql_visible_ids VALUES(?),(?)")
            .bind(D6_D_REF)
            .bind(D6_M_OPEN)
            .execute(&mut *tx)
            .await
            .unwrap();
        // Each record needs three inspected rows (two excluded + winner).
        // Five total is insufficient although each record individually fits.
        let error = bounded_reaction_visible_head_with_bounds(
            &mut tx,
            2,
            5,
            &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible freshness history bound exceeded"),
            "{error}"
        );
        let expected: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id IN (?,?)
            AND type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')")
            .bind(D6_D_REF).bind(D6_M_OPEN).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(
            bounded_reaction_visible_head_with_bounds(
                &mut tx,
                2,
                6,
                &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE)
            )
            .await
            .unwrap(),
            expected
        );
        let error = bounded_reaction_visible_head_with_bounds(
            &mut tx,
            1,
            6,
            &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible freshness record bound exceeded"),
            "{error}"
        );
        for statement in [REACTION_HEAD_EVENTS_SQL, REACTION_HEAD_PREVIOUS_EVENT_SQL] {
            // The initial lookup has one bind, the keyset step has two.
            let rows = if statement == REACTION_HEAD_EVENTS_SQL {
                sqlx::query(&format!("EXPLAIN QUERY PLAN {statement}"))
                    .bind(D6_D_REF)
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap()
            } else {
                sqlx::query(&format!("EXPLAIN QUERY PLAN {statement}"))
                    .bind(D6_D_REF)
                    .bind(i64::MAX)
                    .fetch_all(&mut *tx)
                    .await
                    .unwrap()
            };
            let plan: Vec<String> = rows.iter().map(|r| r.get(3)).collect();
            assert!(
                plan.iter()
                    .any(|p| p.contains("SEARCH event USING INDEX idx_content_events_record")),
                "{plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|p| p.contains("SCAN event") || p.contains("TEMP B-TREE")),
                "{plan:?}"
            );
        }
        let steps = Arc::new(AtomicU64::new(0));
        {
            let mut handle = tx.lock_handle().await.unwrap();
            let counter = steps.clone();
            handle.set_progress_handler(1, move || {
                counter.fetch_add(1, Ordering::Relaxed);
                true
            });
        }
        bounded_reaction_visible_head(
            &mut tx,
            &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE),
        )
        .await
        .unwrap();
        let before = steps.swap(0, Ordering::Relaxed);
        // Hidden history is not in the staged record set. It cannot cause
        // work proportional to its size, even though global seq advances.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000)
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
            SELECT 'head-vm-hidden-'||x,?,'record.updated','{}','bea','2026-10-01T12:00:00.000Z',1,'legacy_unknown' FROM n")
            .bind(D6_M_BEA_ONLY).execute(&mut *tx).await.unwrap();
        steps.store(0, Ordering::Relaxed);
        bounded_reaction_visible_head(
            &mut tx,
            &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE),
        )
        .await
        .unwrap();
        let hidden = steps.swap(0, Ordering::Relaxed);
        assert!(
            before > 0 && hidden <= before + 50,
            "head VM grew with hidden history: {before} -> {hidden}"
        );
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10)
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
            SELECT 'head-vm-visible-'||x,?,'unit.superseded.v1','{}','alice','2026-10-01T12:00:00.000Z',1,'legacy_unknown' FROM n")
            .bind(D6_D_REF).execute(&mut *tx).await.unwrap();
        steps.store(0, Ordering::Relaxed);
        bounded_reaction_visible_head(
            &mut tx,
            &ReactionDeadline::at(Instant::now() + QUERY_DEADLINE),
        )
        .await
        .unwrap();
        let visible = steps.load(Ordering::Relaxed);
        assert!(
            visible > hidden && visible <= hidden + 1000,
            "indexed excluded-tail head VM should grow linearly: {hidden} -> {visible}"
        );
        tx.lock_handle().await.unwrap().remove_progress_handler();
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_record_cap_counts_nonmessages_and_cleans_up() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
            INSERT INTO records(id,type,name,policy_anchor_id)
            SELECT 'head-record-cap-'||x,'Document','Head candidate',policy_anchor_id FROM n CROSS JOIN records WHERE records.id=?")
            .bind((MAX_REACTION_HEAD_RECORDS + 1) as i64).bind(D6_D_REF).execute(db.write_pool()).await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions WHERE 0".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible freshness record bound exceeded")
                || error.contains("timeout")
                || error.contains("deadline"),
            "{error}"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        let result = query_sql_request_in(
            &mut tx,
            QueryPrincipal::authenticated("alice", true),
            QuerySqlRequest {
                sql: "SELECT 42 AS n".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap();
        assert_eq!(result.rows[0]["n"], 42);
        tx.rollback().await.unwrap();
    }
    // Request-scoped test probe: authorizer notifications observe preparation
    // only, admit every read, and never issue SQL or inspect source values.
    struct ReactionPhaseProbe {
        claimed: AtomicU64,
        seen: AtomicU64,
        notify: tokio::sync::Notify,
        cancel_phase: u64,
        gate: (std::sync::Mutex<bool>, std::sync::Condvar),
        clock: Option<Arc<ReactionTestClock>>,
        handle: AtomicU64,
        lowered_limit: AtomicU64,
    }

    impl ReactionPhaseProbe {
        fn new(cancel_phase: u64, clock: Option<Arc<ReactionTestClock>>) -> Self {
            Self {
                claimed: AtomicU64::new(0),
                seen: AtomicU64::new(0),
                notify: tokio::sync::Notify::new(),
                cancel_phase,
                gate: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
                clock,
                handle: AtomicU64::new(0),
                lowered_limit: AtomicU64::new(0),
            }
        }
        fn release(&self) {
            *self.gate.0.lock().unwrap() = true;
            self.gate.1.notify_all();
        }
    }

    unsafe extern "C" fn reaction_phase_authorizer(
        data: *mut std::ffi::c_void,
        action: std::ffi::c_int,
        table: *const std::ffi::c_char,
        column: *const std::ffi::c_char,
        _database: *const std::ffi::c_char,
        accessor: *const std::ffi::c_char,
    ) -> std::ffi::c_int {
        use std::ffi::CStr;
        if action != libsqlite3_sys::SQLITE_READ
            || table.is_null()
            || column.is_null()
            || (!accessor.is_null() && !unsafe { CStr::from_ptr(accessor) }.to_bytes().is_empty())
        {
            return libsqlite3_sys::SQLITE_OK;
        }
        // SAFETY: callback strings are live; a retained Arc owns the probe
        // until authorizer removal after the worker/release hook has finished.
        let table = unsafe { CStr::from_ptr(table) }.to_bytes();
        let column = unsafe { CStr::from_ptr(column) }.to_bytes();
        let phase = if table == b"content_events" && column == b"type" {
            1
        } else if table == b"content_event_reaction_meta" && column == b"record_id" {
            2
        } else {
            return libsqlite3_sys::SQLITE_OK;
        };
        let probe = unsafe { &*(data as *const ReactionPhaseProbe) };
        if probe.claimed.fetch_or(phase, Ordering::AcqRel) & phase == 0 {
            let handle =
                probe.handle.load(Ordering::Acquire) as usize as *mut libsqlite3_sys::sqlite3;
            // SAFETY: this is a read of the limit on the same live SQLite
            // worker handle invoking the callback, with no SQL re-entry.
            let limit = unsafe {
                libsqlite3_sys::sqlite3_limit(handle, libsqlite3_sys::SQLITE_LIMIT_LENGTH, -1)
            };
            probe.lowered_limit.store(limit as u64, Ordering::Release);
            if let Some(clock) = &probe.clock {
                // Each phase consumes <2s; together they exceed the SAME
                // request deadline. This is virtual time, never a sleep.
                clock.advance(QUERY_DEADLINE / 5 * 3);
            }
            probe.seen.fetch_or(phase, Ordering::Release);
            probe.notify.notify_one();
            if probe.cancel_phase == phase {
                let mut released = probe.gate.0.lock().unwrap();
                while !*released {
                    released = probe.gate.1.wait(released).unwrap();
                }
            }
        }
        libsqlite3_sys::SQLITE_OK
    }

    async fn install_reaction_phase_probe(
        connection: &mut sqlx::SqliteConnection,
        probe: &Arc<ReactionPhaseProbe>,
    ) -> (usize, i32, usize) {
        let mut handle = connection.lock_handle().await.unwrap();
        let raw = handle.as_raw_handle().as_ptr();
        probe.handle.store(raw as usize as u64, Ordering::Release);
        // Retained raw Arc survives cancellation, including failure paths.
        // A failing test may leak this small probe, never a dangling callback.
        let retained = Arc::into_raw(probe.clone()) as usize;
        // SAFETY: exclusive handle; raw Arc lives until explicit removal.
        let original =
            unsafe { libsqlite3_sys::sqlite3_limit(raw, libsqlite3_sys::SQLITE_LIMIT_LENGTH, -1) };
        assert_eq!(
            unsafe {
                libsqlite3_sys::sqlite3_set_authorizer(
                    raw,
                    Some(reaction_phase_authorizer),
                    retained as *mut std::ffi::c_void,
                )
            },
            libsqlite3_sys::SQLITE_OK
        );
        (raw as usize, original, retained)
    }

    async fn remove_reaction_phase_probe(connection: &mut sqlx::SqliteConnection, retained: usize) {
        let mut handle = connection.lock_handle().await.unwrap();
        // SAFETY: remove callback before releasing the Arc it may reference.
        assert_eq!(
            unsafe {
                libsqlite3_sys::sqlite3_set_authorizer(
                    handle.as_raw_handle().as_ptr(),
                    None,
                    std::ptr::null_mut(),
                )
            },
            libsqlite3_sys::SQLITE_OK
        );
        unsafe { drop(Arc::from_raw(retained as *const ReactionPhaseProbe)) };
    }

    async fn assert_reaction_borrowed_scope_restored(
        tx: &mut sqlx::Transaction<'_, Sqlite>,
        original: i32,
    ) {
        let actual = {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: exclusive live handle, limit read only.
            unsafe {
                libsqlite3_sys::sqlite3_limit(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                    -1,
                )
            }
        };
        assert_eq!(actual, original);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut **tx).await.unwrap();
        assert_eq!(left, 0);
        // >PROGRESS_OPS instructions: an expired retained handler would
        // interrupt ordinary domain work instead of letting it complete.
        let sum: i64 = sqlx::query_scalar("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) SELECT sum(x) FROM n")
            .fetch_one(&mut **tx).await.unwrap();
        assert_eq!(sum, 500500);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exact_reaction_reads_borrowed_cancel_in_head_and_staging_restores_pinned_slot() {
        for phase in [1, 2] {
            let db = crate::create_database(":memory:").await.unwrap();
            d6_fixture(&db).await;
            exact_reaction_event(
                &db,
                "cancel-borrowed-winner",
                D6_M_OPEN,
                "alice",
                "👍",
                true,
                (false, true),
            )
            .await;
            let held = hold_all_but_one_governed_slot(&db).await;
            let clock = Arc::new(ReactionTestClock::new());
            let probe = Arc::new(ReactionPhaseProbe::new(phase, Some(clock.clone())));
            let worker_clock = clock.clone();
            let worker_probe = probe.clone();
            let worker_db = db.clone();
            let (installed_tx, installed_rx) = tokio::sync::oneshot::channel();
            let mut worker = tokio::spawn(async move {
                let mut connection = worker_db.governed_pool().acquire().await.unwrap();
                let installed = install_reaction_phase_probe(&mut connection, &worker_probe).await;
                installed_tx.send(installed).unwrap();
                let mut tx = connection.begin().await.unwrap();
                REACTION_TEST_CLOCK
                    .scope(
                        worker_clock,
                        query_sql_request_in(
                            &mut tx,
                            QueryPrincipal::authenticated("alice", true),
                            QuerySqlRequest {
                                sql: "SELECT count(*) AS n FROM message_reactions".into(),
                                parameters: vec![],
                            },
                        ),
                    )
                    .await
            });
            let (identity, original, retained) = installed_rx.await.unwrap();
            let reached = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let notified = probe.notify.notified();
                    if probe.seen.load(Ordering::Acquire) & phase != 0 {
                        break;
                    }
                    tokio::select! {
                        outcome = &mut worker => {
                            probe.release();
                            panic!("borrowed executor completed before target phase: {outcome:?}");
                        }
                        _ = notified => {}
                    }
                }
            })
            .await;
            if reached.is_err() {
                worker.abort();
                probe.release();
                let _ = worker.await;
                panic!("borrowed executor never prepared the target phase");
            }
            // The SQLite preparation gate prevents reaching output before
            // abort. Release only after cancellation has dropped the future.
            worker.abort();
            let cancelled = worker.await;
            clock.advance(QUERY_DEADLINE);
            probe.release();
            assert!(cancelled.unwrap_err().is_cancelled());
            assert_eq!(
                probe.lowered_limit.load(Ordering::Acquire),
                MAX_SQLITE_VALUE_BYTES as u64
            );
            let mut connection =
                tokio::time::timeout(Duration::from_secs(30), db.governed_pool().acquire())
                    .await
                    .unwrap()
                    .unwrap();
            let reused = {
                let mut handle = connection.lock_handle().await.unwrap();
                handle.as_raw_handle().as_ptr() as usize
            };
            assert_eq!(
                reused, identity,
                "cleanup must reuse the pinned physical slot"
            );
            remove_reaction_phase_probe(&mut connection, retained).await;
            // The cancelled handler's private clock is now expired. Ordinary
            // VM work can complete only if release actually removed it.
            let mut tx = connection.begin().await.unwrap();
            assert_reaction_borrowed_scope_restored(&mut tx, original).await;
            let result = query_sql_request_in(
                &mut tx,
                QueryPrincipal::authenticated("bea", true),
                QuerySqlRequest {
                    sql: "SELECT viewer FROM message_reactions".into(),
                    parameters: vec![],
                },
            )
            .await
            .unwrap();
            assert_eq!(result.rows[0]["viewer"], 0);
            tx.rollback().await.unwrap();
            drop(connection);
            drop(held);
            db.close().await;
        }
    }

    #[tokio::test]
    async fn exact_reaction_reads_borrowed_tiny_seek_deadline_carries_into_staging_and_callback() {
        for history in [1, 500] {
            let db = crate::create_database(":memory:").await.unwrap();
            d6_fixture(&db).await;
            exact_reaction_bulk(&db, D6_M_OPEN, "clock-history-", history).await;
            let held = hold_all_but_one_governed_slot(&db).await;
            let mut connection = db.governed_pool().acquire().await.unwrap();
            let clock = Arc::new(ReactionTestClock::new());
            let probe = Arc::new(ReactionPhaseProbe::new(0, Some(clock.clone())));
            let (identity, original, retained) =
                install_reaction_phase_probe(&mut connection, &probe).await;
            let callbacks = Arc::new(AtomicU64::new(0));
            let mut tx = connection.begin().await.unwrap();
            let result = REACTION_TEST_CLOCK
                .scope(
                    clock.clone(),
                    query_sql_request_in_with_row_limit_observed(
                        &mut tx,
                        QueryPrincipal::authenticated("alice", true),
                        QuerySqlRequest {
                            sql: "SELECT count(*) AS n FROM message_reactions".into(),
                            parameters: vec![],
                        },
                        MAX_ROWS,
                        sql_contract::FunctionAllowance::Portable,
                        None,
                        Some(callbacks.clone()),
                        false,
                    ),
                )
                .await;
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("timeout") || error.contains("deadline"),
                "{error}"
            );
            assert_eq!(
                probe.seen.load(Ordering::Acquire),
                3,
                "both individually sub-budget phases must run"
            );
            assert_eq!(
                clock.nanos.load(Ordering::Acquire),
                (QUERY_DEADLINE / 5 * 6).as_nanos() as u64
            );
            assert_eq!(
                probe.lowered_limit.load(Ordering::Acquire),
                MAX_SQLITE_VALUE_BYTES as u64
            );
            if history == 500 {
                assert!(
                    callbacks.load(Ordering::Acquire) > 0,
                    "shared clock must expire the actual SQLite callback too"
                );
            }
            assert!(
                REACTION_TEST_CLOCK.try_with(|_| ()).is_err(),
                "test clock leaked outside request scope"
            );
            assert_reaction_borrowed_scope_restored(&mut tx, original).await;
            // The old callback's clock remains expired. A subsequent actual
            // borrowed request must have a fresh deadline and principal.
            let (_, observation) = query_sql_request_in_with_row_limit_observed(
                &mut tx,
                QueryPrincipal::authenticated("bea", true),
                QuerySqlRequest {
                    sql: "SELECT count(*) AS n FROM message_reactions".into(),
                    parameters: vec![],
                },
                MAX_ROWS,
                sql_contract::FunctionAllowance::Portable,
                None,
                None,
                false,
            )
            .await
            .unwrap();
            assert!(observation.content_event_seq.is_some());
            tx.rollback().await.unwrap();
            remove_reaction_phase_probe(&mut connection, retained).await;
            drop(connection);
            let mut connection = db.governed_pool().acquire().await.unwrap();
            let reused = {
                let mut handle = connection.lock_handle().await.unwrap();
                handle.as_raw_handle().as_ptr() as usize
            };
            assert_eq!(identity, reused);
            let mut tx = connection.begin().await.unwrap();
            assert_reaction_borrowed_scope_restored(&mut tx, original).await;
            tx.rollback().await.unwrap();
            drop(connection);
            drop(held);
            db.close().await;
        }
    }

    async fn exact_reaction_cap_bulk(
        db: &Db,
        prefix: &str,
        amount: i64,
        actor: &str,
        unique: bool,
    ) {
        let payload = json!({"format":"native.message-reaction.v1","emoji":"👍",
            "idempotency_key":"boundary","command":"add_reaction","changed":true,
            "actor_account_id":actor,"executor_kind":"authenticated_principal",
            "executor_ref":null,"reason":"full-window boundary"})
        .to_string();
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
            SELECT ?||x,?,'message.reaction.added.v1',
                json_set(?,'$.actor_account_id',CASE WHEN ? THEN ?||x ELSE ? END),
                CASE WHEN ? THEN ?||x ELSE ? END,'2026-10-01T12:00:00.000Z',1,'legacy_unknown' FROM n")
            .bind(amount).bind(prefix).bind(D6_M_OPEN).bind(payload)
            .bind(unique).bind(actor).bind(actor).bind(unique).bind(actor).bind(actor)
            .execute(db.write_pool()).await.unwrap();
    }

    async fn exact_reaction_cap_refuses_and_restores(db: &Db, diagnostic: &str) {
        let sql = "SELECT count(*) AS n FROM message_reactions WHERE 0";
        // Admission bounds, rather than wall-clock scheduling, are the subject
        // of these boundary fixtures. Deadline expiry has phase-clock coverage.
        let error = REACTION_TEST_CLOCK
            .scope(Arc::new(ReactionTestClock::new()), async {
                query_sql(db, &QueryPrincipal::authenticated("alice", true), sql).await
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(diagnostic), "{error}");
        let mut connection = db.write_pool().acquire().await.unwrap();
        let original = {
            let mut handle = connection.lock_handle().await.unwrap();
            // SAFETY: exclusive live handle, read only.
            unsafe {
                libsqlite3_sys::sqlite3_limit(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                    -1,
                )
            }
        };
        let mut tx = connection.begin().await.unwrap();
        let clock = Arc::new(ReactionTestClock::new());
        let error = REACTION_TEST_CLOCK
            .scope(
                clock.clone(),
                query_sql_request_in(
                    &mut tx,
                    QueryPrincipal::authenticated("alice", true),
                    QuerySqlRequest {
                        sql: sql.into(),
                        parameters: vec![],
                    },
                ),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(diagnostic), "{error}");
        // Expire the exact handle a stale progress callback would retain.
        clock.advance(QUERY_DEADLINE);
        assert_reaction_borrowed_scope_restored(&mut tx, original).await;
        let (main, ordinary): (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM main.content_events),(SELECT count(*) FROM content_events)")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(
            main, ordinary,
            "domain history must not remain shadowed after failure"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn exact_reaction_reads_visible_message_candidate_boundary_is_complete_or_error() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let alice = QueryPrincipal::authenticated("alice", true);
        let base = d6_rows(
            &db,
            &alice,
            "SELECT count(*) AS n FROM records WHERE type='Message'",
        )
        .await[0]["n"]
            .as_i64()
            .unwrap();
        assert!(base > 0 && base < MAX_REACTION_MESSAGES);
        sqlx::query(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
            INSERT INTO records(id,type,kind,name,policy_anchor_id)
            SELECT 'message-cap-'||x,'Message','message','Boundary Message',policy_anchor_id
              FROM n CROSS JOIN records WHERE records.id=?",
        )
        .bind(MAX_REACTION_MESSAGES - base)
        .bind(D6_M_OPEN)
        .execute(db.write_pool())
        .await
        .unwrap();
        // Raw fixtures still advance the real source head, invalidating the
        // ordinary visibility cache exactly as an admitted source write does.
        exact_reaction_head_fixture_events(
            &db,
            D6_M_OPEN,
            "message-cap-version-",
            1,
            "record.updated",
        )
        .await;
        let admitted = d6_rows(
            &db,
            &alice,
            "SELECT count(*) AS n FROM records WHERE type='Message'",
        )
        .await;
        assert_eq!(admitted[0]["n"], MAX_REACTION_MESSAGES);
        assert_eq!(
            d6_rows(&db, &alice, "SELECT count(*) AS n FROM message_reactions").await[0]["n"],
            0
        );
        sqlx::query("INSERT INTO records(id,type,kind,name,policy_anchor_id)
            SELECT 'message-cap-plus-one','Message','message','Overflow',policy_anchor_id FROM records WHERE id=?")
            .bind(D6_M_OPEN).execute(db.write_pool()).await.unwrap();
        exact_reaction_head_fixture_events(
            &db,
            D6_M_OPEN,
            "message-cap-overflow-version-",
            1,
            "record.updated",
        )
        .await;
        let error = query_sql(
            &db,
            &alice,
            "SELECT count(*) AS n FROM message_reactions WHERE 0",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible Message candidate bound exceeded"),
            "{error}"
        );
        // The borrowed all-visible-record head cap precedes this separate
        // Message-only cap. It truthfully fails its stricter admission first.
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let error = query_sql_request_in(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT count(*) AS n FROM message_reactions".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("visible freshness record bound exceeded"),
            "{error}"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name='message_reactions'")
            .fetch_one(&mut *tx).await.unwrap();
        assert_eq!(left, 0);
        tx.rollback().await.unwrap();
    }

    #[test]
    fn owned_reaction_test_budget_starts_on_first_vm_and_expires_at_deadline() {
        let clock = ReactionTestClock::new();
        let mut started = None;
        // Scheduling before the first callback consumes no VM budget.
        clock.advance(QUERY_DEADLINE);
        assert!(reaction_test_budget_alive(&clock, &mut started));
        clock.advance(QUERY_DEADLINE - Duration::from_nanos(1));
        assert!(reaction_test_budget_alive(&clock, &mut started));
        clock.advance(Duration::from_nanos(1));
        assert!(!reaction_test_budget_alive(&clock, &mut started));
    }

    #[tokio::test]
    async fn exact_reaction_reads_metadata_byte_boundary_counts_superseded_source_rows() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        let actor = "a".repeat(1000);
        exact_reaction_cap_bulk(&db, "metadata-byte-first-", 1, &actor, false).await;
        // Measure UTF-8 fields in the stored projection independently of SQL
        // SUM admission. The 128-byte overhead is the engineering contract.
        let fields: (String, String, Option<String>, String, String, String) = sqlx::query_as(
            "SELECT record_id,actor,legacy_emoji,emoji,executor_kind,created_at FROM content_event_reaction_meta")
            .fetch_one(db.write_pool()).await.unwrap();
        let row_bytes = 128
            + fields.0.len()
            + fields.1.len()
            + fields.2.unwrap().len()
            + fields.3.len()
            + fields.4.len()
            + fields.5.len();
        let fixed = row_bytes - actor.len();
        let regular = (MAX_REACTION_METADATA_BYTES as usize - fixed - 1) / row_bytes;
        assert!(regular > 1 && regular < MAX_REACTION_SOURCE_EVENTS as usize);
        exact_reaction_cap_bulk(
            &db,
            "metadata-byte-regular-",
            (regular - 1) as i64,
            &actor,
            false,
        )
        .await;
        let last_actor =
            "b".repeat(MAX_REACTION_METADATA_BYTES as usize - regular * row_bytes - fixed);
        assert!(!last_actor.is_empty() && last_actor.len() < MAX_SQLITE_VALUE_BYTES as usize);
        exact_reaction_cap_bulk(&db, "metadata-byte-exact-", 1, &last_actor, false).await;
        assert_eq!(
            regular * row_bytes + fixed + last_actor.len(),
            MAX_REACTION_METADATA_BYTES as usize
        );
        // Thousands of superseded additions contribute bytes although only
        // two rows win. At the exact byte boundary both winners survive.
        // This fixture measures byte admission. The phase-clock tests above
        // independently verify deadline expiry and cleanup.
        let clock = Arc::new(ReactionTestClock::new());
        let rows = REACTION_TEST_CLOCK
            .scope(clock.clone(), async {
                d6_rows(
                    &db,
                    &QueryPrincipal::authenticated("alice", true),
                    "SELECT count(*) AS n FROM message_reactions",
                )
                .await
            })
            .await;
        assert_eq!(rows[0]["n"], 2);
        assert!(
            clock.reads.load(Ordering::Relaxed) > 0,
            "owned reaction VM handler must consult the scoped test clock"
        );
        exact_reaction_cap_bulk(&db, "metadata-byte-overflow-", 1, &actor, false).await;
        // Winner cardinality is unchanged; full history must still refuse.
        exact_reaction_cap_refuses_and_restores(&db, "visible metadata byte bound exceeded").await;
    }

    #[tokio::test]
    async fn exact_reaction_reads_winner_boundary_keeps_all_hidden_actor_duplicates_then_refuses() {
        let db = crate::create_database(":memory:").await.unwrap();
        d6_fixture(&db).await;
        exact_reaction_cap_bulk(
            &db,
            "winner-bound-",
            MAX_REACTION_WINNERS,
            "unmapped-actor-",
            true,
        )
        .await;
        let alice = QueryPrincipal::authenticated("alice", true);
        REACTION_TEST_CLOCK.scope(Arc::new(ReactionTestClock::new()), async {
            let rows = d6_rows(&db, &alice, "SELECT count(*) AS n, count(actor_record_id) AS disclosed, count(executor_kind) AS executors FROM message_reactions").await;
            assert_eq!(rows[0]["n"], MAX_REACTION_WINNERS);
            assert_eq!(rows[0]["disclosed"], 0);
            assert_eq!(rows[0]["executors"], 0);
            // All emitted (message,emoji,NULL actor) tuples are identical; exact
            // winning-event identity must keep every row before admission caps.
            let identities = d6_rows(
                &db,
                &alice,
                "SELECT count(DISTINCT reaction_id) AS n FROM message_reactions",
            )
            .await;
            assert_eq!(identities[0]["n"], MAX_REACTION_WINNERS);
        }).await;
        exact_reaction_cap_bulk(&db, "winner-overflow-", 1, "another-unmapped-actor", false).await;
        exact_reaction_cap_refuses_and_restores(&db, "winning row bound exceeded").await;
    }
}

#[cfg(test)]
mod vocabulary_json_node_tests {
    use super::*;
    use serde_json::json;

    // Independent oracle: neither column order nor expected rows comes from
    // the parser, stored projection, or catalog registry under test.
    const COLUMNS: [&str; 12] = [
        "value_id",
        "ordinal",
        "path",
        "parent_path",
        "parent_ordinal",
        "member_key",
        "array_index",
        "depth",
        "node_type",
        "text_value",
        "number_text",
        "bool_value",
    ];
    const VALUE_ID: &str = "vv:test:json-nodes";

    fn local_principal() -> QueryPrincipal {
        crate::mcp::Caller::local().into()
    }

    async fn fixture(source: &str) -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        sqlx::query("INSERT INTO vocabularies(id,name,created_at) VALUES('voc:test:json-nodes','test:json-nodes','2026-10-03T00:00:00.000Z')")
            .execute(&mut *tx).await.unwrap();
        // Raw stored syntax exercises duplicate members and numeric lexemes
        // that a serde_json::Value event payload cannot preserve.
        sqlx::query("INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,metadata) VALUES(?,'voc:test:json-nodes','test','proposed',0,?)")
            .bind(VALUE_ID).bind(source).execute(&mut *tx).await.unwrap();
        crate::json_nodes_projection::replace_sqlite(&mut tx, VALUE_ID, source)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        db
    }

    async fn nodes(db: &Db, caller: QueryPrincipal) -> SqlResult {
        query_sql(db, caller,
            "SELECT * FROM vocabulary_value_json_nodes WHERE value_id='vv:test:json-nodes' ORDER BY ordinal")
            .await.unwrap()
    }

    fn values(result: &SqlResult) -> Value {
        assert_eq!(result.columns, COLUMNS);
        Value::Array(
            result
                .rows
                .iter()
                .map(|row| {
                    Value::Array(COLUMNS.iter().map(|column| row[*column].clone()).collect())
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn vocabulary_json_nodes_literal_occurrences_are_caller_independent() {
        let db = fixture(r#"{"a":{"x":1.00},"a":{"x":2E+09},"~\/":null,"arr":[true,false,null,"line\nquoted",[],{},-0,0.0100e-02],"":{"z":3}}"#).await;
        let expected: Value = serde_json::from_str(
            r#"[
          ["vv:test:json-nodes",0,"",null,null,null,null,0,"object",null,null,null],
          ["vv:test:json-nodes",1,"/a","",0,"a",null,1,"object",null,null,null],
          ["vv:test:json-nodes",2,"/a/x","/a",1,"x",null,2,"number",null,"1.00",null],
          ["vv:test:json-nodes",3,"/a","",0,"a",null,1,"object",null,null,null],
          ["vv:test:json-nodes",4,"/a/x","/a",3,"x",null,2,"number",null,"2E+09",null],
          ["vv:test:json-nodes",5,"/~0~1","",0,"~/",null,1,"null",null,null,null],
          ["vv:test:json-nodes",6,"/arr","",0,"arr",null,1,"array",null,null,null],
          ["vv:test:json-nodes",7,"/arr/0","/arr",6,null,0,2,"boolean",null,null,1],
          ["vv:test:json-nodes",8,"/arr/1","/arr",6,null,1,2,"boolean",null,null,0],
          ["vv:test:json-nodes",9,"/arr/2","/arr",6,null,2,2,"null",null,null,null],
          ["vv:test:json-nodes",10,"/arr/3","/arr",6,null,3,2,"string","line\nquoted",null,null],
          ["vv:test:json-nodes",11,"/arr/4","/arr",6,null,4,2,"array",null,null,null],
          ["vv:test:json-nodes",12,"/arr/5","/arr",6,null,5,2,"object",null,null,null],
          ["vv:test:json-nodes",13,"/arr/6","/arr",6,null,6,2,"number",null,"-0",null],
          ["vv:test:json-nodes",14,"/arr/7","/arr",6,null,7,2,"number",null,"0.0100e-02",null],
          ["vv:test:json-nodes",15,"/","",0,"",null,1,"object",null,null,null],
          ["vv:test:json-nodes",16,"//z","/",15,"z",null,2,"number",null,"3",null]
        ]"#,
        )
        .unwrap();
        for caller in [
            local_principal(),
            QueryPrincipal::authenticated("acct:unrelated", false),
        ] {
            let result = nodes(&db, caller.clone()).await;
            assert_eq!(values(&result), expected);
            assert!(!result.truncated);
            let joined = query_sql(&db, caller,
                "SELECT n.ordinal,p.ordinal AS parent,v.id FROM vocabulary_value_json_nodes n JOIN vocabulary_values v ON v.id=n.value_id LEFT JOIN vocabulary_value_json_nodes p ON p.value_id=n.value_id AND p.ordinal=n.parent_ordinal WHERE n.value_id='vv:test:json-nodes' AND n.path='/a/x' ORDER BY n.ordinal").await.unwrap();
            assert_eq!(
                joined.rows,
                vec![
                    json!({"ordinal":2,"parent":1,"id":VALUE_ID}),
                    json!({"ordinal":4,"parent":3,"id":VALUE_ID})
                ]
            );
        }
    }

    #[tokio::test]
    async fn vocabulary_json_nodes_empty_and_scalar_roots_are_rows() {
        for (source, expected) in [
            (
                "{}",
                json!([[VALUE_ID, 0, "", null, null, null, null, 0, "object", null, null, null]]),
            ),
            (
                "[]",
                json!([[VALUE_ID, 0, "", null, null, null, null, 0, "array", null, null, null]]),
            ),
            (
                "null",
                json!([[VALUE_ID, 0, "", null, null, null, null, 0, "null", null, null, null]]),
            ),
            (
                "false",
                json!([[VALUE_ID, 0, "", null, null, null, null, 0, "boolean", null, null, 0]]),
            ),
            (
                "1e+02",
                json!([[
                    VALUE_ID, 0, "", null, null, null, null, 0, "number", null, "1e+02", null
                ]]),
            ),
            (
                r#""text""#,
                json!(
                    [
                        [
                            VALUE_ID, 0, "", null, null, null, null, 0, "string", "text", null,
                            null
                        ]
                    ]
                ),
            ),
        ] {
            let db = fixture(source).await;
            assert_eq!(
                values(&nodes(&db, local_principal()).await),
                expected,
                "{source}"
            );
        }
    }

    #[tokio::test]
    async fn vocabulary_json_nodes_discovery_default_order_and_sandbox() {
        let db = fixture("[false,true]").await;
        let caller = local_principal();
        let catalog = query_sql(&db, caller.clone(),
            "SELECT identity,semantic_version,caller_relative,completeness,profiles FROM catalog_relations WHERE relation_name='vocabulary_value_json_nodes'").await.unwrap();
        assert_eq!(
            catalog.rows,
            vec![json!({
                "identity":"native.query-sql.vocabulary-value-json-nodes", "semantic_version":1,
                "caller_relative":0, "completeness":"complete", "profiles":"sqlite-local"
            })]
        );
        let columns = query_sql(&db, caller.clone(),
            "SELECT column_name FROM catalog_columns WHERE relation_name='vocabulary_value_json_nodes' ORDER BY column_position").await.unwrap();
        assert_eq!(
            columns.rows,
            COLUMNS.map(|column| json!({"column_name":column}))
        );
        let limited = query_sql(&db, caller.clone(),
            "SELECT value_id,ordinal FROM vocabulary_value_json_nodes WHERE value_id='vv:test:json-nodes' LIMIT 2").await.unwrap();
        assert_eq!(
            limited.rows,
            vec![
                json!({"value_id":VALUE_ID,"ordinal":0}),
                json!({"value_id":VALUE_ID,"ordinal":1})
            ]
        );
        assert!(limited.assumed_order.is_some());
        for sql in [
            "SELECT * FROM main.vocabulary_value_json_nodes",
            "WITH vocabulary_value_json_nodes AS (SELECT * FROM main.vocabulary_value_json_nodes) SELECT * FROM vocabulary_value_json_nodes",
            "SELECT json_extract(metadata,'$') FROM vocabulary_values",
            "DELETE FROM vocabulary_value_json_nodes",
            "UPDATE vocabulary_value_json_nodes SET path='changed'",
        ] {
            assert!(query_sql(&db, caller.clone(), sql).await.is_err(), "accepted {sql}");
        }
        assert_eq!(nodes(&db, caller).await.rows.len(), 3);
    }

    #[tokio::test]
    async fn vocabulary_json_nodes_replacement_failure_rollback_and_delete() {
        use crate::meta::events::MetaEventRow;
        let db = fixture("[true]").await;
        let event = |event_type: &str, metadata: Value| MetaEventRow {
            seq: 1,
            id: "test:json-node-event".into(),
            subject_id: VALUE_ID.into(),
            event_type: event_type.into(),
            payload: Some(json!({"metadata":metadata}).to_string()),
            actor: None,
            created_at: "2026-10-03T00:00:00.000Z".into(),
        };
        let mut tx = db.write_pool().begin().await.unwrap();
        crate::projector::meta::project_meta(
            &mut tx,
            &event("vocab_value.metadata_set", json!({"empty":[]})),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let expected = json!([
            [VALUE_ID, 0, "", null, null, null, null, 0, "object", null, null, null],
            [VALUE_ID, 1, "/empty", "", 0, "empty", null, 1, "array", null, null, null]
        ]);
        assert_eq!(values(&nodes(&db, local_principal()).await), expected);
        let mut tx = db.write_pool().begin().await.unwrap();
        let oversized = json!("x".repeat(crate::json_nodes::MAX_JSON_SOURCE_BYTES));
        let error = crate::projector::meta::project_meta(
            &mut tx,
            &event("vocab_value.metadata_set", oversized),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("JSON source exceeds"), "{error}");
        tx.rollback().await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        assert!(
            crate::json_nodes_projection::replace_sqlite(&mut tx, VALUE_ID, "{")
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        assert_eq!(values(&nodes(&db, local_principal()).await), expected);
        let metadata: String =
            sqlx::query_scalar("SELECT metadata FROM vocabulary_values WHERE id=?")
                .bind(VALUE_ID)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(metadata, r#"{"empty":[]}"#);
        let mut tx = db.write_pool().begin().await.unwrap();
        crate::projector::meta::project_meta(&mut tx, &event("vocab_value.deleted", json!(null)))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(nodes(&db, local_principal()).await.rows.is_empty());
    }

    #[tokio::test]
    async fn vocabulary_json_nodes_keep_result_and_execution_bounds() {
        let source = format!("[{}]", vec!["0"; 1001].join(","));
        let db = fixture(&source).await;
        let result = nodes(&db, local_principal()).await;
        assert_eq!(result.rows.len(), sql_contract::MAX_ROWS);
        assert!(result.truncated);
        let error = query_sql(&db, local_principal(),
            "SELECT count(*) FROM vocabulary_value_json_nodes a CROSS JOIN vocabulary_value_json_nodes b CROSS JOIN vocabulary_value_json_nodes c WHERE a.value_id='vv:test:json-nodes' AND b.value_id=a.value_id AND c.value_id=a.value_id").await.unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error}");
    }

    #[test]
    fn vocabulary_json_nodes_pin_additive_catalog_identity_and_profiles() {
        use native_query_contract::rule_contract::{check_catalog_pin, check_relation_pin};
        let snapshot = current_catalog_snapshot();
        check_catalog_pin(&snapshot, 4, "sqlite-local", 1).unwrap();
        let readset = extract_rule_input_dependencies("SELECT value_id,ordinal FROM vocabulary_value_json_nodes WHERE value_id=?1 ORDER BY ordinal").unwrap();
        let pin = &readset.relations[0];
        assert_eq!(pin.identity, "native.query-sql.vocabulary-value-json-nodes");
        assert_eq!(pin.semantic_version, 1);
        check_relation_pin(&snapshot, pin).unwrap();
        for profile in [
            sql_contract::QuerySqlProfile::TursoLocal,
            sql_contract::QuerySqlProfile::PostgresServer,
        ] {
            assert!(
                sql_contract::logical_columns("vocabulary_value_json_nodes", profile).is_none()
            );
            let mut other = snapshot.clone();
            other.profile_id = profile.contract().id.into();
            let error = check_relation_pin(&other, pin).unwrap_err().to_string();
            assert!(error.contains("unavailable in profile"), "{error}");
        }
        assert_eq!(
            sql_contract::logical_columns(
                "vocabulary_value_json_nodes",
                sql_contract::QuerySqlProfile::SqliteLocal
            )
            .unwrap(),
            COLUMNS
        );
    }
}

#[cfg(test)]
#[path = "schema_config_json_node_tests.rs"]
mod schema_config_json_node_tests;

#[cfg(test)]
#[path = "facet_value_json_node_tests.rs"]
mod facet_value_json_node_tests;

#[cfg(test)]
#[path = "facet_observation_json_node_tests.rs"]
mod facet_observation_json_node_tests;

#[cfg(test)]
#[path = "record_body_json_node_tests.rs"]
mod record_body_json_node_tests;

/// Collect only an already admitted immutable v1 member slice. Reuse its
/// production logical records/facet views, never the canonical visibility fold
/// or excluded policy/history tables. The serialized owner supplies identity.
#[cfg(unix)]
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn member_vault_snapshot(
    db: &Db,
    account: &str,
    origin: &str,
) -> Result<crate::markdown_vault::SourceSnapshot> {
    use crate::markdown_vault::{SourceLink, SourceRecord, SourceSnapshot};
    if db.open_mode() != crate::db::DatabaseOpenMode::MemberReadOnly {
        return Err(crate::Error::engine(
            "vault requires an admitted member copy",
        ));
    }
    let mut connection = db.governed_pool().acquire().await?;
    connection.close_on_drop();
    install_temp_contract(&mut connection).await?;
    for statement in [MEMBER_RECORDS_VIEW_DDL, MEMBER_FACET_VALUES_VIEW_DDL] {
        sqlx::query(statement).execute(&mut *connection).await?;
    }
    sqlx::query("BEGIN").execute(&mut *connection).await?;
    sqlx::query("DELETE FROM temp._query_sql_principal; DELETE FROM temp._query_sql_visible_ids")
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO temp._query_sql_principal(singleton,account_id,trusted_local_bypass,activity_read,is_member,observed_at) VALUES(1,?,0,0,1,?)")
        .bind(account).bind(chrono::Utc::now().to_rfc3339()).execute(&mut *connection).await?;
    sqlx::query("INSERT INTO temp._query_sql_visible_ids(id) SELECT id FROM main.records")
        .execute(&mut *connection)
        .await?;
    let mut snapshot = SourceSnapshot {
        origin: origin.into(),
        account: account.into(),
        // Member profiles have no canonical act or author history. Zero is an
        // internal unused placeholder; the publisher must not report it as act.
        freshness: serde_json::json!({"source":"member_copy","content_act":"not_held","author_history":"not_held"}),
        ..Default::default()
    };
    for row in sqlx::query("SELECT * FROM temp.records ORDER BY created_at,id")
        .fetch_all(&mut *connection)
        .await?
    {
        let mut metadata = BTreeMap::new();
        for key in [
            "summary",
            "lifecycle",
            "maturity",
            "created_at",
            "updated_at",
            "last_activity_at",
        ] {
            let value: Option<String> = row.try_get(key)?;
            if let Some(value) = value {
                metadata.insert(key.into(), Value::String(value));
            }
        }
        if row.try_get::<Option<i64>, _>("is_current")? == Some(0)
            || row.try_get::<i64, _>("successor_count")? > 0
        {
            metadata.insert("superseded".into(), Value::Bool(true));
        }
        let record = SourceRecord {
            id: row.try_get("id")?,
            record_type: row.try_get("type")?,
            kind: row.try_get("kind")?,
            name: row.try_get("name")?,
            body: row.try_get("body")?,
            home_id: row.try_get("home_id")?,
            archived: row.try_get::<i64, _>("archived")? != 0,
            metadata,
            ..Default::default()
        };
        snapshot.records.insert(record.id.clone(), record);
    }
    for row in
        sqlx::query("SELECT record_id,key,value FROM temp.facet_values ORDER BY record_id,key,id")
            .fetch_all(&mut *connection)
            .await?
    {
        if let Some(record) = snapshot
            .records
            .get_mut(&row.try_get::<String, _>("record_id")?)
        {
            record.facets.insert(
                row.try_get("key")?,
                row.try_get::<Option<String>, _>("value")?
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
        }
    }
    for row in sqlx::query("SELECT r.id,p.id AS owner FROM main.records r JOIN temp.records p ON p.id=r.owner_id JOIN temp.records v ON v.id=r.id").fetch_all(&mut *connection).await? {
        if let Some(record) = snapshot.records.get_mut(&row.try_get::<String,_>("id")?) { record.metadata.insert("owner".into(),Value::String(row.try_get("owner")?)); }
    }
    for row in sqlx::query("SELECT a.annotation_id,a.selectors FROM main.annotation_targets a JOIN temp.records annotation ON annotation.id=a.annotation_id JOIN temp.records target ON target.id=a.target_record_id ORDER BY a.annotation_id,a.target_record_id").fetch_all(&mut *connection).await? {
        if let Some(record) = snapshot.records.get_mut(&row.try_get::<String,_>("annotation_id")?) { record.anchors.push(serde_json::from_str(&row.try_get::<String,_>("selectors")?)?); }
    }
    for row in sqlx::query("SELECT source_id,target_id,relationship,note FROM temp.links ORDER BY source_id,relationship,target_id,id").fetch_all(&mut *connection).await? {
        snapshot.links.push(SourceLink { source_id:row.try_get("source_id")?,target_id:row.try_get("target_id")?,relationship:row.try_get("relationship")?,note:row.try_get("note")? });
    }
    sqlx::query("ROLLBACK").execute(&mut *connection).await?;
    Ok(snapshot)
}

/// Internal projection source. Uses the exact production governed views, but
/// does not serialize through the public SQL cell/result/row limits. Every
/// body and facet is returned whole; the caller releases this transaction
/// before rendering. No renderer receives a database handle.
#[cfg(unix)]
pub(crate) async fn projection_snapshot(
    db: &Db,
    principal: QueryPrincipal,
) -> Result<crate::markdown_vault::SourceSnapshot> {
    use crate::markdown_vault::{SourceLink, SourceRecord, SourceSnapshot};
    // The node's accepted-generation owner chooses/opens the engine. Keep
    // this collector independently engine-aware: never run v1 views over NKV2.
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(db.pool())
        .await?;
    if marker == crate::db::V2_APPLICATION_ID {
        #[cfg(feature = "v2-kernel-probe")]
        return crate::markdown_vault::kernel_v2::snapshot(db, principal.credential()).await;
        #[cfg(not(feature = "v2-kernel-probe"))]
        return Err(crate::Error::engine(
            "v2 Markdown vault requires v2-kernel-probe",
        ));
    }
    let mut connection = db.governed_pool().acquire().await?;
    install_temp_contract(&mut connection).await?;
    // Never restore a previous principal when rolling back a pooled session.
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_visible_ids")
        .execute(&mut *connection)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_disclosable_actors")
        .execute(&mut *connection)
        .await?;
    let mut tx = connection.begin().await?;
    let result: Result<SourceSnapshot> = async {
        install_visible_records_in(&mut tx, principal.clone()).await?;
        populate_visible_ids_live(&mut tx).await?;
        let act = crate::act::current_act(&mut tx).await?;
        prepare_disclosable_actors(&mut tx,true).await?;
        let origin = sqlx::query_scalar("SELECT origin_db_id FROM main.database_identity WHERE singleton=1").fetch_one(&mut *tx).await?;
        let mut snapshot = SourceSnapshot { origin, act, account: principal.credential().to_owned(), ..Default::default() };
        let rows = sqlx::query("SELECT * FROM temp.records ORDER BY created_at, id").fetch_all(&mut *tx).await?;
        for row in rows {
            let mut metadata = BTreeMap::new();
            for key in ["summary", "lifecycle", "maturity", "created_at", "updated_at", "last_activity_at"] {
                let value: Option<String> = row.try_get(key)?;
                if let Some(value) = value { metadata.insert(key.to_owned(), Value::String(value)); }
            }
            if row.try_get::<Option<i64>, _>("is_current")? == Some(0) || row.try_get::<i64,_>("successor_count")? > 0 {
                metadata.insert("superseded".into(), Value::Bool(true));
            }
            let record = SourceRecord {
                id: row.try_get("id")?, record_type: row.try_get("type")?, kind: row.try_get("kind")?,
                name: row.try_get("name")?, body: row.try_get("body")?, home_id: row.try_get("home_id")?,
                archived: row.try_get::<i64,_>("archived")? != 0, metadata, ..Default::default()
            };
            snapshot.records.insert(record.id.clone(), record);
        }
        for row in sqlx::query("SELECT record_id, key, value FROM temp.facet_values ORDER BY record_id, key, id").fetch_all(&mut *tx).await? {
            if let Some(record) = snapshot.records.get_mut(&row.try_get::<String,_>("record_id")?) {
                record.facets.insert(row.try_get("key")?, row.try_get::<Option<String>,_>("value")?.map(Value::String).unwrap_or(Value::Null));
            }
        }
        // Related identities are disclosed only through the same visible set.
        for row in sqlx::query("SELECT r.id, p.id AS owner FROM main.records r JOIN temp.records p ON p.id=r.owner_id JOIN temp.records visible ON visible.id=r.id ORDER BY r.id").fetch_all(&mut *tx).await? {
            if let Some(record) = snapshot.records.get_mut(&row.try_get::<String,_>("id")?) {
                record.metadata.insert("owner".into(), Value::String(row.try_get("owner")?));
            }
        }
        for row in sqlx::query("SELECT annotation_id, selectors FROM temp.comment_anchors ORDER BY annotation_id, target_record_id").fetch_all(&mut *tx).await? {
            if let Some(record) = snapshot.records.get_mut(&row.try_get::<String,_>("annotation_id")?) {
                record.anchors.push(serde_json::from_str(&row.try_get::<String,_>("selectors")?)?);
            }
        }
        for row in sqlx::query("SELECT e.record_id, a.person_id FROM temp.content_events e JOIN temp.actors a ON a.actor=e.actor WHERE e.type='record.created' AND e.local_seq=(SELECT MIN(first.local_seq) FROM temp.content_events first WHERE first.record_id=e.record_id AND first.type='record.created') ORDER BY e.record_id").fetch_all(&mut *tx).await? {
            if let (Some(record),Some(author)) = (snapshot.records.get_mut(&row.try_get::<String,_>("record_id")?),row.try_get::<Option<String>,_>("person_id")?) {record.metadata.insert("author".into(),Value::String(author));}
        }
        // Production logical relation. 8134d50 owns standby materialization
        // repair; never union raw relationship/replica tables in a renderer.
        for row in sqlx::query("SELECT source_id, target_id, relationship, note FROM temp.links ORDER BY source_id, relationship, target_id, id").fetch_all(&mut *tx).await? {
            snapshot.links.push(SourceLink { source_id:row.try_get("source_id")?, target_id:row.try_get("target_id")?, relationship:row.try_get("relationship")?, note:row.try_get("note")? });
        }
        Ok(snapshot)
    }.await;
    let rollback = tx.rollback().await;
    if result.is_err() || rollback.is_err() {
        connection.close_on_drop();
    }
    rollback?;
    result
}

#[cfg(test)]
mod imported_catalogue_population_tests {
    use super::*;

    #[test]
    fn column_free_catalogue_reads_are_public_without_admitting_physical_tables() {
        assert!(validate_ad_hoc("SELECT count(*) FROM catalog_operations").is_err());
        validate_ad_hoc("SELECT id FROM vocabularies").unwrap();
        #[cfg(feature = "v2-kernel-probe")]
        for relation in [
            "vocabularies",
            "vocabulary_values",
            "record_lifecycle_interpretations",
            "agent_activity_claims",
        ] {
            let sql = format!("SELECT count(*) AS n FROM {relation}");
            #[cfg(feature = "v2-kernel-probe")]
            {
                validate_kernel_v2_ad_hoc(&sql).unwrap();
                validated_kernel_v2_output_columns(&sql).unwrap();
                let reads = public_reads_ad_hoc(&sql).unwrap();
                assert!(
                    reads.iter().any(|(r, _)| r == relation),
                    "{relation}: {reads:?}"
                );
            }
        }
        for sql in [
            "SELECT count(*) FROM kernel_v1_state",
            "SELECT count(*) FROM main.vocabulary_values",
        ] {
            assert!(validate_ad_hoc(sql).is_err(), "{sql}");
            #[cfg(feature = "v2-kernel-probe")]
            assert!(validate_kernel_v2_ad_hoc(sql).is_err(), "{sql}");
        }
    }
}
