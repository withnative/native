//! Probe-only public SQL over a single kernel authority snapshot.
//!
//! Only TEMP state is written. The physical connection is discarded even on
//! cancellation, so neither scoped rows nor VM guards can reach another caller.
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

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

fn columns(relation: &str) -> Option<&'static [&'static str]> {
    if [
        "records",
        "links",
        "runs",
        "run_intents",
        "actors",
        "comment_anchors",
        "vocabularies",
        "vocabulary_values",
        "record_lifecycle_interpretations",
        "agent_activity_claims",
        "facet_values",
        "my_message_state",
        "messages_awaiting_reply",
        "catalog_relations",
        "catalog_columns",
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
    connection: sqlx::pool::PoolConnection<sqlx::Sqlite>,
    reads: BTreeSet<(String, String)>,
    as_of_seq: i64,
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
    // Retain the governed slot, not an ordinary write-pool slot: enrichment
    // borrows ordinary connections too. Concurrent batches must not each hold
    // one ordinary slot while all wait for a second one.
    let mut connection = db.governed_pool().acquire().await?;
    connection.close_on_drop();
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
    install(&mut connection, actor, &reads).await?;
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
        sqlx::query(&format!(
            "CREATE TEMP TABLE _v2_composed_records AS SELECT {} FROM temp.records",
            record_columns.join(",")
        ))
        .persistent(false)
        .execute(&mut *connection)
        .await?;
        sqlx::query("DROP VIEW temp.records; CREATE TEMP VIEW records AS SELECT * FROM temp._v2_composed_records")
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
    }));
    let result = READ_SESSION.scope(session.clone(), work).await;
    // Roll back TEMP state explicitly on success/error; cancellation closes the
    // owned physical connection, so no TEMP state or VM guard can be borrowed.
    sqlx::query("ROLLBACK")
        .execute(&mut *session.lock().await.connection)
        .await?;
    result
}

struct PreparedRead {
    statement: String,
    parameters: Vec<contract::QuerySqlParameter>,
    output_columns: Vec<String>,
    now_ms_ms: Option<i64>,
    time_dependent: bool,
    assumed_order: Option<contract::AssumedOrder>,
}

pub(super) async fn query_sql(db: &Db, actor: &str, args: Value) -> Result<Value> {
    execute(db, actor, args)
        .await
        .map_err(contract::ensure_categorized)
}
async fn execute(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let request: contract::QuerySqlRequest = parse("query_sql", args).map_err(|error| {
        contract::categorized_error(
            contract::QuerySqlErrorCategory::InvalidArguments,
            error.to_string(),
        )
    })?;
    request.validate()?;
    let profile = contract::QuerySqlProfile::SqliteLocal;
    let statement = contract::classify_sqlite_ad_hoc_statement(&request.sql)?;
    let (statement, assumed_order) = guard::apply_kernel_v2_default_order(&statement)?;
    let reads = guard::public_reads_ad_hoc(&statement)?;
    for (relation, column) in &reads {
        let Some(supported) = columns(relation) else {
            return Err(unsupported(relation, ""));
        };
        if !column.is_empty() && !supported.contains(&column.as_str()) {
            return Err(unsupported(relation, column));
        }
    }
    guard::validate_kernel_v2_ad_hoc(&statement)?;
    let output_columns = guard::validated_kernel_v2_output_columns(&statement)?;
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
    contract::validate_ad_hoc_clock_bound_args(profile, &statement, &request.parameters)?;
    contract::validate_utc_date_label_bound_args(profile, &statement, &request.parameters)?;
    let (statement, clock_uses) = contract::rewrite_now_ms_calls(
        profile,
        &statement,
        &format!("?{}", request.parameters.len() + 1),
    )?;
    let now_ms_ms = (clock_uses > 0).then(|| chrono::Utc::now().timestamp_millis());
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
    if let Some(now) = now_ms_ms {
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
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent: clock_uses > 0,
        assumed_order,
    };
    if let Ok(session) = READ_SESSION.try_with(Clone::clone) {
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

    // An ordinary pool slot, exclusively held and marked for physical close
    // before installing any state. Rollback also covers errors and cancellation.
    let mut connection = db.write_pool().acquire().await?;
    connection.close_on_drop();
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    crate::kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let as_of_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
        .fetch_one(&mut *tx)
        .await?;
    // Exclude pool queue delay; charge all trusted staging and caller VM work.
    let started = Instant::now();
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
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    }
    install(&mut tx, actor, &reads)
        .await
        .map_err(|error| match error {
            crate::Error::Sqlx(error) => guard::map_stream_error(error),
            error => error,
        })?;
    #[cfg(test)]
    let _ = STATS.try_with(|s| {
        s.borrow_mut().staging_vm_ops = progress.load(std::sync::atomic::Ordering::Relaxed)
    });
    // Many individually small SQL statements (or provider decoding in Rust)
    // may never invoke the VM callback. They still consume the same budget.
    if started.elapsed() >= Duration::from_millis(contract::QUERY_DEADLINE_MS) {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "SQL relation staging exceeded query deadline",
        ));
    }
    let result = execute_prepared(&mut tx, prepared, as_of_seq, started).await?;
    tx.rollback().await?;
    Ok(result)
}

async fn execute_prepared(
    connection: &mut sqlx::SqliteConnection,
    prepared: PreparedRead,
    as_of_seq: i64,
    started: Instant,
) -> Result<Value> {
    let PreparedRead {
        statement,
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent,
        assumed_order,
    } = prepared;
    {
        let mut handle = connection.lock_handle().await?;
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    }
    sqlx::query("PRAGMA query_only=ON")
        .execute(&mut *connection)
        .await?;
    {
        let mut handle = connection.lock_handle().await?;
        // SAFETY: exclusive SQLite handle lock, connection never returns to pool.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                guard::MAX_SQLITE_VALUE_BYTES,
            );
        }
    }
    let capped = guard::cap_statement(&statement, contract::MAX_ROWS as i64);
    let query = guard::bind_parameters(sqlx::query(&capped), &parameters)?;
    let mut stream = query.fetch(&mut *connection);
    let mut rows = Vec::new();
    let mut bytes = serde_json::to_vec(&output_columns)?.len() + 2;
    let mut truncated = false;
    while let Some(row) = stream.try_next().await.map_err(guard::map_stream_error)? {
        if rows.len() == contract::MAX_ROWS {
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

#[cfg(test)]
#[derive(Default, Debug)]
pub(super) struct Stats {
    pub staging_vm_ops: u64,
    pub installations: usize,
    pub home_checks: usize,
    pub failed_homes: usize,
    pub staged_records: u64,
    pub staged_metadata_records: u64,
    pub staged_relations: usize,
}
#[cfg(test)]
tokio::task_local! { static STATS: std::cell::RefCell<Stats>; }
#[cfg(test)]
pub(super) async fn measured<T>(work: impl std::future::Future<Output = T>) -> (T, Stats) {
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
    let updated = "(SELECT created_at FROM main.content_events e WHERE e.record_id=r.id ORDER BY seq DESC LIMIT 1)";
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
 coalesce({title},{name}) AS name,
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
        updated_ms = millis(updated)
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
-- Look up logical placement only when its visible record consumes home_id.
-- The indexed provenance header avoids loading unrelated retained app bodies
-- under the caller VM value ceiling. Only the small provenance event is read.
CREATE TEMP VIEW _v2_record_homes AS
 WITH placement AS (
 SELECT r.id,m.record_id,
 coalesce(json_extract(move.payload,'$.logical_home_id'), CASE WHEN m.record_id=r.id AND json_extract(e.payload,'$.legacy.payload.policy_anchor')=r.id
 THEN json_extract(e.payload,'$.legacy.payload.original_home') ELSE coalesce(m.record_id,r.home_id) END) AS candidate
 FROM temp._v2_visible r LEFT JOIN temp._v2_home_map m ON m.home_id=r.home_id
 LEFT JOIN main.content_events move ON move.seq=(SELECT seq FROM main.content_events p WHERE p.record_id=r.id AND p.type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ORDER BY seq DESC LIMIT 1)
 LEFT JOIN main.content_events e ON e.seq=(SELECT seq FROM main.kernel_legacy_sql_events p WHERE p.record_id=r.id AND p.source_stream='snapshot_provenance' ORDER BY seq DESC LIMIT 1))
 SELECT p.id,CASE WHEN EXISTS(SELECT 1 FROM temp._v2_visible v WHERE v.id=p.candidate)
 OR (p.candidate='native:root' AND NOT EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') AND EXISTS(SELECT 1 FROM temp._v2_home_map m JOIN temp._v2_scopes h ON h.home_id=m.home_id WHERE m.record_id='native:root' AND h.home_view))
 OR (NOT EXISTS(SELECT 1 FROM main.kernel_records hidden WHERE hidden.id=p.candidate) AND EXISTS(SELECT 1 FROM temp._v2_scopes h WHERE h.home_id=p.candidate AND h.home_view)) THEN p.candidate ELSE NULL END AS home_id FROM placement p;
CREATE TEMP TABLE catalog_relations(relation_name TEXT, identity TEXT, semantic_version INTEGER, caller_relative INTEGER, completeness TEXT, profiles TEXT, comment TEXT);
CREATE TEMP TABLE catalog_columns(relation_name TEXT,column_name TEXT,column_position INTEGER);
CREATE TEMP TABLE _v2_facet_rows(id TEXT,record_id TEXT,key TEXT,value TEXT,value_num REAL,vocab_ref TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP VIEW facet_values AS SELECT * FROM temp._v2_facet_rows;
CREATE TEMP TABLE _v2_provider_links(source_id TEXT,target_id TEXT);
-- All edge sources pass the same endpoint fence. New sources belong here.
CREATE TEMP VIEW _v2_link_sources AS
 SELECT printf('v2:link:%s:%s:%s',l.source_id,l.target_id,l.relationship) AS id,l.source_id,l.target_id,l.relationship,NULL AS note,e.created_at FROM main.kernel_links l LEFT JOIN main.content_events e ON e.seq=l.created_seq
 UNION ALL SELECT l.edge_id,l.source_id,l.target_id,l.predicate,NULL,e.created_at FROM main.kernel_link4_edges l LEFT JOIN main.content_events e ON e.seq=l.created_seq
 UNION ALL SELECT link_id,source_id,target_id,relationship,note,created_at FROM main.kernel_generic_links WHERE active=1
 UNION ALL SELECT printf('v2:relates_to:%s:%s',source_id,target_id),source_id,target_id,'relates_to',NULL,NULL FROM temp._v2_provider_links;
CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_link_target ON _v2_link_rows(target_id,relationship);
CREATE TEMP VIEW links AS SELECT * FROM temp._v2_link_rows;
CREATE TEMP TABLE _v2_event_disclosure(actor TEXT,root_visible INTEGER);
CREATE TEMP TABLE _v2_disclosed_legacy_actors(actor TEXT PRIMARY KEY);
CREATE TEMP TABLE _v2_event_ids(seq INTEGER PRIMARY KEY);
CREATE TEMP TABLE runs(run_key TEXT PRIMARY KEY,principal_person_id TEXT,started_at_ms INTEGER,ended_at_ms INTEGER,reported_model TEXT,reported_client TEXT,model_assurance TEXT);
CREATE TEMP TABLE run_intents(run_key TEXT,ordinal INTEGER,intent TEXT,declared_at_ms INTEGER);
CREATE TEMP TABLE vocabularies(id TEXT,name TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP TABLE vocabulary_values(id TEXT,vocabulary_id TEXT,value TEXT,gloss TEXT,status TEXT,ordinal REAL,terminality TEXT,metadata TEXT,alias_of TEXT);
CREATE TEMP TABLE record_lifecycle_interpretations(record_id TEXT,status TEXT,raw TEXT,axis_key TEXT,axis_label TEXT,vocabulary_id TEXT,vocabulary_name TEXT,value_id TEXT,canonical TEXT,terminality TEXT,reason TEXT);
CREATE TEMP TABLE agent_activity_claims(claim_id TEXT,activity_id TEXT,record_id TEXT,claimed_at TEXT,claimed_at_ms INTEGER,released_at TEXT,released_at_ms INTEGER,is_current INTEGER);

CREATE TEMP TABLE _v2_runs(id TEXT PRIMARY KEY,run_key TEXT,owner TEXT);
CREATE TEMP TABLE _v2_imported_accounts(principal_id TEXT PRIMARY KEY);
CREATE TEMP TABLE my_message_state(message_id TEXT PRIMARY KEY,stage TEXT,unread INTEGER,is_own INTEGER,mentioned INTEGER,flagged INTEGER,muted INTEGER,archived INTEGER,snoozed_until TEXT,snoozed_until_ms INTEGER,reactable INTEGER);
CREATE TEMP TABLE messages_awaiting_reply(message_id TEXT PRIMARY KEY);

"#;

const FACET_ROWS: &str = r#"INSERT INTO temp._v2_facet_rows SELECT printf('v2:facet:%s:%s',f.record_id,f.key),
 f.record_id,f.key,f.value,f.value_num,f.vocab_ref,strftime('%Y-%m-%dT%H:%M:%fZ',f.as_of),
 CAST(strftime('%s',f.as_of) AS INTEGER)*1000+CAST(substr(strftime('%f',f.as_of),4,3) AS INTEGER)
 FROM main.kernel_facets f JOIN temp._v2_visible v ON v.id=f.record_id WHERE f.value IS NOT NULL"#;
fn events_ddl() -> String {
    format!(
        r#"
CREATE TEMP TABLE _v2_event_rows(local_seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,actor TEXT,run_key TEXT,parent_key TEXT,channel_kind TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_event_record_type ON _v2_event_rows(record_id,type,local_seq);
CREATE TEMP VIEW content_events AS SELECT * FROM temp._v2_event_rows;
CREATE TEMP VIEW actors AS SELECT DISTINCT e.actor,r.id AS person_id,coalesce(json_extract(n.value_json,'$'),p.display_label) AS display_name
 FROM temp.content_events e LEFT JOIN main.kernel_principals p ON p.principal_id=e.actor OR 'v1:'||p.auth_binding=e.actor
 LEFT JOIN main.kernel_v1_state d ON d.section='account_directory' AND d.account_principal=p.principal_id
 LEFT JOIN temp._v2_visible v ON v.id=d.record_id
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

/// Share W5 disclosure checks. Only replayed header facts are read here;
/// source bodies and immutable retained envelopes stay outside ordinary SQL.
async fn install_events(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
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
 CASE WHEN ?1 OR e.actor=?2 THEN e.actor END,
 CASE WHEN ?1 THEN e.run_key END,CASE WHEN ?1 THEN e.parent_key END,
 CASE WHEN ?1 OR e.actor=?2 THEN 'unknown' END,
 strftime('%Y-%m-%dT%H:%M:%fZ',e.created_at),CAST(unixepoch(e.created_at,'subsec')*1000 AS INTEGER)
 FROM main.content_events e JOIN temp._v2_event_ids a ON a.seq=e.seq
 WHERE e.type!='kernel.legacy_recorded.v1' AND e.type NOT GLOB 'kernel.import_*' AND e.type NOT IN ({imported})"#
    );
    sqlx::query(&native_sql)
        .bind(root_visible)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
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
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT m.seq,h.subjects FROM main.kernel_legacy_sql_events m JOIN temp._v2_event_ids a ON a.seq=m.seq JOIN main.kernel_legacy_history h ON h.seq=m.seq JOIN temp._v2_visible r ON r.id=m.record_id WHERE m.source_stream='content_events' AND NOT h.hidden AND (?1 OR NOT h.restricted OR h.owner=?2) ORDER BY m.seq")
        .bind(admin).bind(&binding).fetch_all(&mut *tx).await?;
    let mut visibility = std::collections::BTreeMap::new();
    // Reuse ordinary record visibility already established by S7. Derived records
    // retain W5's independent terminal-bearer check; homes and other subjects
    // also go through its shared authorization helper.
    let ordinary = format!(
        "SELECT v.id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id WHERE NOT {}",
        kernel::sql_is_derived_artifact("r")
    );
    for id in sqlx::query_scalar::<_, String>(&ordinary)
        .fetch_all(&mut *tx)
        .await?
    {
        visibility.insert(id, true);
    }
    let mut admitted = Vec::new();
    for (seq, subjects) in rows {
        let mut allowed = true;
        for subject in serde_json::from_str::<Vec<String>>(&subjects)? {
            if !kernel::legacy_history_visible(&mut *tx, actor, &subject, &mut visibility).await? {
                allowed = false;
                break;
            }
        }
        if allowed {
            admitted.push(seq);
        }
    }
    sqlx::query("CREATE TEMP TABLE _v2_legacy_admitted(seq INTEGER PRIMARY KEY)")
        .execute(&mut *tx)
        .await?;
    for chunk in admitted.chunks(500) {
        let mut insert =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new("INSERT INTO temp._v2_legacy_admitted(seq) ");
        insert.push_values(chunk, |mut values, seq| {
            values.push_bind(*seq);
        });
        insert.build().execute(&mut *tx).await?;
    }
    // Same v1 rule as get_history: self, or an actor's verified Person
    // visible under current policy. Root visibility is not a substitute.
    for principal in kernel::v1_state::disclosed_accounts_on(tx, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_disclosed_legacy_actors SELECT 'v1:'||auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(principal).execute(&mut *tx).await?;
    }
    // Copy admitted headers in one set operation, never one round trip per
    // historical event. No source payload enters the ordinary SQL surface.
    sqlx::query(r#"INSERT INTO temp._v2_event_rows
      SELECT m.seq,m.source_id,m.record_id,
       CASE WHEN m.event_type='receipt.committed.v1' THEN 'record.updated' ELSE m.event_type END,
       CASE WHEN d.actor IS NOT NULL THEN m.actor END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.run_key END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.parent_key END,
       CASE WHEN d.actor IS NOT NULL THEN 'unknown' END,
       strftime('%Y-%m-%dT%H:%M:%fZ',m.created_at),CAST(unixepoch(m.created_at,'subsec')*1000 AS INTEGER)
      FROM main.kernel_legacy_sql_events m JOIN temp._v2_legacy_admitted a ON a.seq=m.seq
      JOIN main.kernel_legacy_history h ON h.seq=m.seq
      LEFT JOIN temp._v2_disclosed_legacy_actors d ON d.actor=m.actor"#)
        .bind(&binding).execute(&mut *tx).await?;
    Ok(())
}

pub(crate) async fn install(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().installations += 1);
    sqlx::query(DDL).persistent(false).execute(&mut *tx).await?;
    sqlx::query(&records_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    sqlx::query(&events_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    let needs = |relation: &str| reads.iter().any(|(r, _)| r == relation);
    let column = |name: &str| reads.contains(&("records".into(), name.into()));
    let needs_events = needs("content_events") || needs("actors");
    let needs_records = [
        "records",
        "links",
        "facet_values",
        "content_events",
        "actors",
        "comment_anchors",
        "record_lifecycle_interpretations",
        "agent_activity_claims",
        "my_message_state",
        "messages_awaiting_reply",
    ]
    .iter()
    .any(|r| needs(r));
    let needs_runs = needs("runs") || needs("run_intents") || needs("agent_activity_claims");
    let mut root_visible = false;
    if needs_records {
        // A pre-upgrade importer may append while this handle stays open.
        // Never serve incomplete logical headers or invented birth times.
        let current: bool = sqlx::query_scalar("SELECT coalesce((SELECT scanned_seq FROM main.kernel_legacy_sql_progress WHERE singleton=1 AND gap_free=1 AND provenance_headers=1),0) = coalesce((SELECT max(seq) FROM main.content_events WHERE type='kernel.legacy_recorded.v1'),0)")
            .fetch_one(&mut *tx).await?;
        if !current {
            return Err(Error::engine(
                "kernel-v2 app read projection needs catchup; run explicit v2 preparation",
            ));
        }

        let scope = kernel::visible_home_anchors_as(tx, actor).await?;
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            let mut s = s.borrow_mut();
            s.home_checks = scope.homes.len();
            s.failed_homes = scope.failed_homes;
        });
        for home in scope.homes {
            if home.home_id == crate::events::KERNEL_ROOT_ID {
                root_visible = home.home_view;
            }
            sqlx::query("INSERT INTO temp._v2_scopes VALUES(?,?,?,?)")
                .bind(home.home_id)
                .bind(home.policy_valid)
                .bind(home.policy_view)
                .bind(home.home_view)
                .execute(&mut *tx)
                .await?;
        }
        // Single set operation; no per-record authority, field reads or inserts.
        let identity = column("type") || column("kind");
        let creation = column("created_at") || column("created_at_ms");
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
        // Derived artifacts never take the record-owner leg: their visibility
        // derives from the terminal bearer. The terminal owner's floor
        // reaches them through the bearer chain even when their home
        // grants nothing; the shared-home policy leg needs no change.
        let derived = kernel::sql_is_derived_artifact("r");
        let derived_visible = kernel::comments_v2::sql_derived_visible(
            "r",
            "?1",
            "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
        );
        // Omit the recursive per-row Message gate only when this same read
        // snapshot proves there are no sealed OR unsealed Message records.
        // The second probe preserves fail-closed reads of missing audience
        // state; it is intentionally independent of the public type carrier.
        let has_messages: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
            .fetch_one(&mut *tx).await?;
        let audience = if has_messages {
            kernel::messaging::sql_guard(
                "r",
                "?1",
                "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
            )
        } else {
            "1".into()
        };
        let staging = format!("INSERT INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE ({audience}) AND NOT EXISTS(SELECT 1 FROM main.kernel_import_tombstones t WHERE t.record_id=r.id) AND (((NOT {derived}) AND EXISTS(SELECT 1 FROM temp._v2_scopes h WHERE h.home_id=r.home_id AND h.valid AND (h.policy_view OR r.owner_id=?1))) OR ({derived} AND {derived_visible}))");
        let count = sqlx::query(&staging)
            .bind(actor)
            .execute(&mut *tx)
            .await?
            .rows_affected();
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
    } else if needs_runs {
        root_visible =
            kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap_or(Capability::None)
                .allows(Capability::View);
    }
    if column("home_id") {
        sqlx::query("INSERT INTO temp._v2_home_map SELECT e.record_id,json_extract(e.payload,'$.source_record_id') FROM main.content_events e JOIN temp._v2_scopes h ON h.home_id=e.record_id WHERE e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id') IS NOT NULL").execute(&mut *tx).await?;
        // The importer does not create a record for the structural v1 root;
        // its sealed root policy import witnesses that logical home mapping.
        sqlx::query("INSERT OR IGNORE INTO temp._v2_home_map SELECT ?1,'native:root' WHERE EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') OR EXISTS(SELECT 1 FROM main.content_events WHERE record_id=?1 AND type='kernel.import_home_policy.v1')").bind(crate::events::KERNEL_ROOT_ID).execute(&mut *tx).await?;
    }
    if needs("facet_values") {
        sqlx::query(FACET_ROWS).execute(&mut *tx).await?;
    }
    if needs("links") {
        // Decode each admitted aggregate once, not once for every record.
        let states: Vec<String> = sqlx::query_scalar("SELECT state_json FROM main.kernel_provider_state p WHERE provider_key='relates_to.v1' AND EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=p.id) AND NOT EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=p.id AND s.subject_id NOT IN (SELECT id FROM temp._v2_visible))").fetch_all(&mut *tx).await?;
        for state in states {
            if let Some((left, right)) = kernel::relates_to_port::active_pair_from_state(&state)? {
                sqlx::query("INSERT INTO temp._v2_provider_links SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?1) AND EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?2) UNION ALL SELECT ?2,?1 WHERE EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?1) AND EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?2)").bind(left).bind(right).execute(&mut *tx).await?;
            }
        }
        sqlx::query("INSERT INTO temp._v2_link_rows SELECT l.id,l.source_id,l.target_id,l.relationship,l.note,strftime('%Y-%m-%dT%H:%M:%fZ',l.created_at),CAST(strftime('%s',l.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',l.created_at),4,3) AS INTEGER) FROM temp._v2_link_sources l JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id").execute(&mut *tx).await?;
    }
    if needs_events {
        sqlx::query("INSERT INTO temp._v2_event_disclosure VALUES(?,?)")
            .bind(actor)
            .bind(root_visible)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id WHERE e.type NOT IN ('kernel.app_state_imported.v1','kernel.import_receipt.v1','kernel.v1_state_imported.v1','kernel.message_state.v1','kernel.message_command_committed.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1','kernel.provider_outcome.v1','kernel.link_added.v2','kernel.link_added.v1','kernel.link_removed.v1') AND e.type NOT LIKE 'kernel.generic_link_%'").execute(&mut *tx).await?;

        sqlx::query("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN main.kernel_link4_edges l ON l.created_seq=e.seq JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE e.type='kernel.link_added.v2'").execute(&mut *tx).await?;
        sqlx::query("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible s ON s.id=e.record_id JOIN temp._v2_visible t ON t.id=json_extract(e.payload,'$.target_id') WHERE e.type IN ('kernel.link_added.v1','kernel.link_removed.v1')").execute(&mut *tx).await?;
        sqlx::query("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN main.kernel_generic_links l ON l.link_id=json_extract(e.payload,'$.link_id') JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE e.type LIKE 'kernel.generic_link_%'").execute(&mut *tx).await?;
        sqlx::query("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible anchor ON anchor.id=e.record_id WHERE e.type='kernel.provider_outcome.v1' AND EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id) AND NOT EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id AND s.subject_id NOT IN (SELECT id FROM temp._v2_visible))").execute(&mut *tx).await?;
    }
    if needs_events {
        install_events(tx, actor, root_visible).await?;
    }
    install_imported_catalogue(tx, actor, reads).await?;
    if needs("my_message_state") || needs("messages_awaiting_reply") {
        install_messaging(
            tx,
            actor,
            needs("my_message_state"),
            needs("messages_awaiting_reply"),
        )
        .await?;
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
            "content_events",
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
    if needs("catalog_relations") || needs("catalog_columns") {
        for relation in contract::LOGICAL_RELATIONS {
            let Some(supported) = columns(relation.name) else {
                continue;
            };
            sqlx::query("INSERT INTO temp.catalog_relations VALUES(?,?,?,?,?,?,?)")
                .bind(relation.name).bind(relation.identity).bind(relation.semantic_version as i64).bind(relation.caller_relative)
                .bind("best_effort").bind("sqlite-local-v2")
                .bind("v2 probe; catalog_columns lists the supported columns. Bodies lazy. Home is the visible logical folder, or native home id. Currency counts visible active supersedes sources; is_current is 1 or NULL. Generic links retain ids/notes/times; provider links are symmetric with NULL note/time: an aggregate may combine directed legacy sources with different original notes and claimed timestamps; no single source is chosen. Facet time uses as_of. Native event attribution uses self/root-directory admission; legacy attribution requires self or View on the verified Person and retains v1:. Logical create/update types and retained content headers are exposed; migration receipts are omitted. channel_kind is unknown until provenance admission. Actor names/person IDs use visible verified imported Persons when available, otherwise labels may be placeholders. Anchor positions retain their source namespace without a coedit cut proof. Native runs use self/root-directory admission and NULL person/model/client fields. Imported runs/intents require self or a visible verified imported Person; known principal_person_id is retained; imported runs preserve declarations, use model_assurance imported_historical and ended_at_ms at the source close or snapshot boundary. Imported claims are historical, is_current=0 and released at the source release or snapshot boundary; they never occupy the live claims lane. Imported creation times retain source birth; native creation time stays separate; deletion times NULL.")
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

async fn install_messaging(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    private: bool,
    awaiting: bool,
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
        if private {
            let value = super::messaging::state_value(conn, actor, &id, &state).await?;
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

type LifecycleSqlRow = (String, String, Option<String>, Option<String>, String);

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
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_visible")
            .fetch_one(&mut *tx)
            .await?;
        if count > 20_000 {
            return Err(crate::Error::engine(
                "record_lifecycle_interpretations exceeds 20000 visible records; use get_record",
            ));
        }
        let interpreter = kernel::v1_state::interpreter_on(tx, actor).await?;
        let rows:Vec<LifecycleSqlRow>=sqlx::query_as("SELECT r.id,coalesce(CASE WHEN r.pin_family='native.v1.record' THEN json_extract(t.value_json,'$') ELSE r.primary_type END,''),CASE WHEN r.pin_family='native.v1.record' THEN json_extract(k.value_json,'$') ELSE r.kind END,json_extract(l.value_json,'$'),r.home_id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id LEFT JOIN main.kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN main.kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' LEFT JOIN main.kernel_record_fields l ON l.record_id=r.id AND l.name='lifecycle'").fetch_all(&mut *tx).await?;
        let mut bearers = std::collections::BTreeMap::new();
        let mut cache = std::collections::BTreeMap::new();
        let mut interpreted = Vec::with_capacity(rows.len());
        for (id, typ, kind, raw, home) in rows {
            if !bearers.contains_key(&home) {
                let bearer = kernel::v1_state::lifecycle_bearer_on(tx, &home, None).await?;
                bearers.insert(home.clone(), bearer);
            }
            let bearer = if bearers[&home] == id {
                kernel::v1_state::lifecycle_bearer_on(tx, &home, Some(&id)).await?
            } else {
                bearers[&home].clone()
            };
            let key = (typ, kind, raw.clone(), bearer);
            let value = cache
                .entry(key)
                .or_insert_with_key(|(typ, kind, raw, bearer)| {
                    serde_json::to_value(interpreter.interpret(
                        typ,
                        kind.as_deref(),
                        Some(bearer),
                        raw.as_deref(),
                    ))
                    .expect("lifecycle interpretation serializes")
                });
            interpreted.push(json!([
                id,
                value["status"],
                raw,
                value["axis"]["key"],
                value["axis"]["label"],
                value["vocabulary"]["id"],
                value["vocabulary"]["name"],
                value["value"]["id"],
                value["value"]["canonical"],
                value["terminality"],
                value["reason"]
            ]));
        }
        sqlx::query("INSERT INTO temp.record_lifecycle_interpretations SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]'),json_extract(value,'$[4]'),json_extract(value,'$[5]'),json_extract(value,'$[6]'),json_extract(value,'$[7]'),json_extract(value,'$[8]'),json_extract(value,'$[9]'),json_extract(value,'$[10]') FROM json_each(?)")
            .bind(serde_json::to_string(&interpreted)?).execute(&mut *tx).await?;
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
