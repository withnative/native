//! The executable spine contract (task 33e5aab) — structural + behavioral
//! assertions that a database honors the frozen v1 contract
//! (`crate::schema::contract`, from spine decision 2e5ed3e). This is the
//! enforcement mechanism for "types closed, additive-only kinds/fields": a
//! forker's install either passes or it doesn't.
//!
//! Check styles, deliberately layered:
//!   - STRUCTURAL — required tables/columns exist (PRAGMA table_info /
//!     sqlite_master). Presence-only: EXTRA tables and columns are tolerated,
//!     because the substrate tier is open (2e5ed3e Am.2 §2).
//!   - BEHAVIORAL PROBES — attempt the write the contract forbids (a new
//!     top-level type, a NULL persistence) and require rejection; attempt the
//!     writes it guarantees (each spine type, each spine relationship, a novel
//!     kind) and require acceptance. Probes run inside a write transaction that
//!     is ALWAYS rolled back — conformance never mutates the database under test.
//!   - DATA SCANS — existing rows must not violate the contract either, so a
//!     database whose schema lost a constraint (or predates it) still fails on
//!     the bad rows themselves.

use std::collections::{HashMap, HashSet};

use futures::future::BoxFuture;
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

use crate::db::Db;
use crate::error::Result;
use crate::events::EventRow;
use crate::schema::{
    spine_facet_column, ARCHIVED_FACET_KEY, CONTENT_EVENT_CAUSAL_CUTOVER_COLUMNS,
    CONTENT_EVENT_CAUSAL_FRONTIER_COLUMNS, CONTENT_EVENT_SOURCE_COLUMNS, CONTROL_EVENT_COLUMNS,
    DERIVATION_EVENT_COLUMNS, DERIVATION_REQUEST_COLUMNS, EVENT_COLUMNS, META_EVENT_COLUMNS,
    PERSISTENCE_VALUES, PROVENANCE_ACTION_OUTPUT_COLUMNS, RELATIONSHIP_ASSERTION_HEAD_COLUMNS,
    RELATIONSHIP_COLUMNS, RELATIONSHIP_ENDPOINT_COLUMNS, RELATIONSHIP_EVENT_COLUMNS,
    RELATIONSHIP_LEGACY_LINK_COLUMNS, REQUIRED_TABLES, ROOT_RECORD_ID, SPINE_FACET_KEYS,
    SPINE_RELATIONSHIPS, SPINE_TYPES, UNFILED_RECORD_ID,
};

/// One check's outcome in the conformance report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    pub check: String,
    pub ok: bool,
    pub violations: Vec<String>,
}

/// Run a probe inside a write transaction that is always rolled back. Returns
/// the error message if the probe failed, `None` if it completed.
async fn probe<F>(db: &Db, f: F) -> Result<Option<String>>
where
    F: for<'c> FnOnce(&'c mut SqliteConnection) -> BoxFuture<'c, Result<()>>,
{
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let outcome = f(&mut tx).await;
    // Rollback errors are ignored: an aborted transaction may already be
    // closed; either way nothing committed.
    let _ = tx.rollback().await;
    Ok(outcome.err().map(|e| e.to_string()))
}

async fn table_names(db: &Db) -> Result<HashSet<String>> {
    let rows = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table'")
        .fetch_all(db.write_pool())
        .await?;
    // try_get throughout this module: values read from the database under test
    // are database-controlled, and the suite's contract is a report + exit
    // code, never a decode panic.
    rows.into_iter()
        .map(|r| Ok(r.try_get::<String, _>("name")?))
        .collect()
}

#[derive(Debug, Clone)]
struct ColumnInfo {
    notnull: bool,
    dflt: Option<String>,
}

async fn columns(db: &Db, table: &str) -> Result<HashMap<String, ColumnInfo>> {
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(db.write_pool())
        .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.try_get::<String, _>("name")?,
                ColumnInfo {
                    notnull: r.try_get::<i64, _>("notnull")? == 1,
                    dflt: r.try_get::<Option<String>, _>("dflt_value")?,
                },
            ))
        })
        .collect()
}

fn sql_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

fn in_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|v| sql_quote(v))
        .collect::<Vec<_>>()
        .join(", ")
}

fn probe_id() -> String {
    format!("probe:{}", Uuid::new_v4())
}

async fn insert_record_probe(
    conn: &mut SqliteConnection,
    id: &str,
    record_type: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO records (id, type) VALUES (?, ?)")
        .bind(id)
        .bind(record_type)
        .execute(conn)
        .await?;
    Ok(())
}

// ---- Checks --------------------------------------------------------------

/// Required tables present. Presence-only by design: the substrate tier is open
/// (Am.2 §2), so extra tables never fail conformance.
pub async fn check_required_tables(db: &Db) -> Result<CheckResult> {
    let names = table_names(db).await?;
    let violations: Vec<String> = REQUIRED_TABLES
        .iter()
        .filter(|t| !names.contains(**t))
        .map(|t| format!("required table missing: {t}"))
        .collect();
    Ok(CheckResult {
        check: "required-tables".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// The content log has the replay contract's shape — `content_events` is the
/// authoritative table the content projections are folded from, so its columns
/// are contract-fixed.
pub async fn check_event_log_shape(db: &Db) -> Result<CheckResult> {
    let cols = columns(db, "content_events").await?;
    let mut violations: Vec<String> = EVENT_COLUMNS
        .iter()
        .filter(|c| !cols.contains_key(**c))
        .map(|c| format!("content_events column missing: {c}"))
        .collect();
    let source_cols = columns(db, "content_event_sources").await?;
    violations.extend(
        CONTENT_EVENT_SOURCE_COLUMNS
            .iter()
            .filter(|c| !source_cols.contains_key(**c))
            .map(|c| format!("content_event_sources column missing: {c}")),
    );
    for (table, expected) in [
        (
            "content_event_causal_frontier",
            CONTENT_EVENT_CAUSAL_FRONTIER_COLUMNS.as_slice(),
        ),
        (
            "content_event_causal_cutover",
            CONTENT_EVENT_CAUSAL_CUTOVER_COLUMNS.as_slice(),
        ),
    ] {
        let actual = columns(db, table).await?;
        violations.extend(
            expected
                .iter()
                .filter(|column| !actual.contains_key(**column))
                .map(|column| format!("{table} column missing: {column}")),
        );
    }
    for (table, expected) in [
        ("relationship_events", RELATIONSHIP_EVENT_COLUMNS.as_slice()),
        (
            "provenance_action_outputs",
            PROVENANCE_ACTION_OUTPUT_COLUMNS.as_slice(),
        ),
        ("relationships", RELATIONSHIP_COLUMNS.as_slice()),
        (
            "relationship_endpoints",
            RELATIONSHIP_ENDPOINT_COLUMNS.as_slice(),
        ),
        (
            "relationship_legacy_links",
            RELATIONSHIP_LEGACY_LINK_COLUMNS.as_slice(),
        ),
        (
            "relationship_assertion_heads",
            RELATIONSHIP_ASSERTION_HEAD_COLUMNS.as_slice(),
        ),
    ] {
        let actual = columns(db, table).await?;
        violations.extend(
            expected
                .iter()
                .filter(|column| !actual.contains_key(**column))
                .map(|column| format!("{table} column missing: {column}")),
        );
    }
    Ok(CheckResult {
        check: "event-log-shape".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// Stored causal facts remain coherent with the database-local cutover and
/// retained import provenance. Parent ids may be absent locally, but the
/// locally present portion of the graph must be acyclic.
pub async fn check_content_event_causality(db: &Db) -> Result<CheckResult> {
    let mut violations = Vec::new();
    let cutover_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_event_causal_cutover")
        .fetch_one(db.write_pool())
        .await?;
    if cutover_rows != 1 {
        violations.push(format!(
            "content_event_causal_cutover must contain exactly one row, found {cutover_rows}"
        ));
        return Ok(CheckResult {
            check: "content-event-causality".into(),
            ok: false,
            violations,
        });
    }

    for (sql, message) in [
        (
            "SELECT COUNT(*) FROM content_events event
              JOIN content_event_causal_cutover cutover ON cutover.singleton=1
             WHERE event.causal_status='legacy_unknown'
               AND event.seq > cutover.last_legacy_local_seq",
            "legacy_unknown event exists after the causal cutover",
        ),
        (
            "SELECT COUNT(*) FROM content_events event
              JOIN content_event_causal_cutover cutover ON cutover.singleton=1
             WHERE event.seq <= cutover.last_legacy_local_seq
               AND event.causal_status <> 'legacy_unknown'",
            "pre-cutover event is not classified legacy_unknown",
        ),
        (
            "SELECT COUNT(*) FROM content_events event
              JOIN content_event_causal_frontier frontier ON frontier.event_id=event.id
             WHERE event.causal_status='legacy_unknown'",
            "legacy_unknown event carries causal frontier edges",
        ),
        (
            "SELECT COUNT(*) FROM content_events event
              JOIN content_event_causal_cutover cutover ON cutover.singleton=1
              LEFT JOIN content_event_sources source ON source.event_id=event.id
             WHERE event.seq > cutover.last_legacy_local_seq
               AND source.event_id IS NULL
               AND event.causal_status <> 'complete'",
            "post-cutover locally authored event is not complete",
        ),
        (
            "SELECT COUNT(*) FROM content_events event
              LEFT JOIN content_event_sources source ON source.event_id=event.id
             WHERE event.causal_status='import_incomplete'
               AND source.event_id IS NULL",
            "import_incomplete event lacks retained source provenance",
        ),
        (
            "SELECT COUNT(*) FROM content_events event
              LEFT JOIN content_event_sources source ON source.event_id=event.id
             WHERE event.causal_status='complete'
               AND NOT EXISTS (
                    SELECT 1 FROM content_event_causal_frontier frontier
                     WHERE frontier.event_id=event.id
               )
               AND NOT (
                    (source.event_id IS NULL AND event.seq=1)
                    OR source.source_seq=1
               )",
            "complete empty frontier is not a genuine local or source genesis",
        ),
    ] {
        let count: i64 = sqlx::query_scalar(sql).fetch_one(db.write_pool()).await?;
        if count != 0 {
            violations.push(format!("{message}: {count} row(s)"));
        }
    }

    let has_cycle: bool = sqlx::query_scalar(
        "WITH RECURSIVE reach(start_event_id,event_id) AS (
             SELECT event_id,parent_event_id FROM content_event_causal_frontier
             UNION
             SELECT reach.start_event_id,frontier.parent_event_id
               FROM reach
               JOIN content_event_causal_frontier frontier
                 ON frontier.event_id=reach.event_id
         )
         SELECT EXISTS(
             SELECT 1 FROM reach WHERE start_event_id=event_id
         )",
    )
    .fetch_one(db.write_pool())
    .await?;
    if has_cycle {
        violations.push("locally present causal frontier graph contains a cycle".into());
    }

    Ok(CheckResult {
        check: "content-event-causality".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// The META log has ITS replay contract's shape (ba9f97e). A separate check, not
/// an extension of the one above: the two logs differ in exactly one column
/// (`record_id` vs `subject_id`), and a shared check would have to be loose
/// enough to accept either — which is precisely the shape that lets a real
/// mistake through.
pub async fn check_meta_event_log_shape(db: &Db) -> Result<CheckResult> {
    let cols = columns(db, "meta_events").await?;
    let violations: Vec<String> = META_EVENT_COLUMNS
        .iter()
        .filter(|c| !cols.contains_key(**c))
        .map(|c| format!("meta_events column missing: {c}"))
        .collect();
    Ok(CheckResult {
        check: "meta-event-log-shape".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// The two command-style logs share an envelope but not an authority. Check
/// both explicitly so either tier can evolve without silently loosening the
/// other's replay contract.
pub async fn check_command_event_log_shapes(db: &Db) -> Result<CheckResult> {
    let control = columns(db, "control_events").await?;
    let derivation = columns(db, "derivation_events").await?;
    let mut violations: Vec<String> = CONTROL_EVENT_COLUMNS
        .iter()
        .filter(|column| !control.contains_key(**column))
        .map(|column| format!("control_events column missing: {column}"))
        .collect();
    violations.extend(
        DERIVATION_EVENT_COLUMNS
            .iter()
            .filter(|column| !derivation.contains_key(**column))
            .map(|column| format!("derivation_events column missing: {column}")),
    );
    Ok(CheckResult {
        check: "command-event-log-shapes".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// Operational request rows are deliberately excluded from projection replay,
/// but losing a lease/fence column would break distributed execution safety.
pub async fn check_derivation_request_shape(db: &Db) -> Result<CheckResult> {
    let cols = columns(db, "derivation_requests").await?;
    let violations = DERIVATION_REQUEST_COLUMNS
        .iter()
        .filter(|column| !cols.contains_key(**column))
        .map(|column| format!("derivation_requests column missing: {column}"))
        .collect::<Vec<_>>();
    Ok(CheckResult {
        check: "derivation-request-shape".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// CLOSED TYPES — the load-bearing rule. A new top-level type must be
/// unrepresentable, and so must a NULL (untyped) record — a SQLite CHECK passes
/// NULL, so the closed set needs NOT NULL asserted separately; every one of the
/// 10 spine types must be representable; and no existing row may violate (the
/// scan must name NULL explicitly, because `NOT IN` never matches NULL rows).
pub async fn check_closed_types(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();

    match columns(db, "records").await?.get("type") {
        None => violations.push("records.type column missing".into()),
        Some(col) if !col.notnull => violations.push(
            "records.type must be NOT NULL (a CHECK alone passes NULL — untyped records would conform)"
                .into(),
        ),
        Some(_) => {}
    }

    let rogue = probe(db, |tx| {
        Box::pin(async move {
            insert_record_probe(tx, &probe_id(), Some("XConformanceProbeType")).await
        })
    })
    .await?;
    if rogue.is_none() {
        violations.push(
            "a non-spine top-level type was accepted (records.type CHECK missing or widened) — the type tier must be CLOSED at the 10 spine types"
                .into(),
        );
    }

    let null_type = probe(db, |tx| {
        Box::pin(async move { insert_record_probe(tx, &probe_id(), None).await })
    })
    .await?;
    if null_type.is_none() {
        violations.push(
            "a NULL type was accepted — every record must carry one of the 10 spine types".into(),
        );
    }

    let accepted = probe(db, |tx| {
        Box::pin(async move {
            for spine_type in SPINE_TYPES {
                insert_record_probe(tx, &probe_id(), Some(spine_type)).await?;
            }
            Ok(())
        })
    })
    .await?;
    if let Some(message) = accepted {
        violations.push(format!("a spine type was rejected: {message}"));
    }

    let bad = sqlx::query(&format!(
        "SELECT type, COUNT(*) AS n FROM records
         WHERE type IS NULL OR type NOT IN ({})
         GROUP BY type",
        in_list(&SPINE_TYPES)
    ))
    .fetch_all(db.write_pool())
    .await?;
    for row in bad {
        let record_type: Option<String> = row.try_get("type")?;
        let n: i64 = row.try_get("n")?;
        let label = match record_type {
            None => "NULL (untyped)".to_string(),
            Some(t) => format!("'{t}'"),
        };
        violations.push(format!(
            "{n} existing record(s) carry non-spine type {label}"
        ));
    }

    Ok(CheckResult {
        check: "closed-types".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// OPEN KIND — `kind` is the additive extension surface, so a never-seen kind
/// value must be storable on a spine type without any schema change. NULL means
/// the record is uncharacterised; it does not select a type-level default.
pub async fn check_open_kind(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();
    match columns(db, "records").await?.get("kind") {
        None => violations.push("records.kind column missing".into()),
        Some(col) if col.notnull => {
            violations.push("records.kind must be nullable (NULL = uncharacterised)".into());
        }
        Some(_) => {}
    }

    let novel = probe(db, |tx| {
        Box::pin(async move {
            sqlx::query("INSERT INTO records (id, type, kind) VALUES (?, ?, ?)")
                .bind(probe_id())
                .bind("Document")
                .bind(format!("x-conformance-probe-{}", Uuid::new_v4()))
                .execute(tx)
                .await?;
            Ok(())
        })
    })
    .await?;
    if let Some(message) = novel {
        violations.push(format!(
            "a novel kind value was rejected — kind must be open-additive: {message}"
        ));
    }

    Ok(CheckResult {
        check: "open-kind".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// REQUIRED KIND — every supported content genesis event must carry a
/// non-empty kind. These probes intentionally cross the projector seam rather
/// than relying on the nullable physical column, which remains part of the
/// direct-SQL/open-kind interop floor.
pub async fn check_required_kind(db: &Db) -> Result<CheckResult> {
    let mut violations = Vec::new();
    for (label, payload) in [
        ("missing", serde_json::json!({ "type": "Document" })),
        (
            "null",
            serde_json::json!({ "type": "Document", "kind": null }),
        ),
        (
            "empty",
            serde_json::json!({ "type": "Document", "kind": "" }),
        ),
    ] {
        let rejected = probe(db, |tx| {
            Box::pin(async move {
                let event = EventRow {
                    local_seq: 0,
                    id: probe_id(),
                    record_id: probe_id(),
                    event_type: "record.created".into(),
                    payload: Some(payload.to_string()),
                    actor: None,
                    run_key: None,
                    parent_key: None,
                    intent: None,
                    created_at: "2026-01-01T00:00:00.000Z".into(),
                    causal_envelope: crate::events::CausalEnvelopeV1::default(),
                };
                crate::projector::project(tx, &event).await
            })
        })
        .await?;
        if rejected.is_none() {
            violations.push(format!(
                "projector accepted a record.created payload with {label} kind"
            ));
        }
    }

    Ok(CheckResult {
        check: "required-kind".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// The 4 spine facet keys exist as columns on `records` (Fork B), with
/// `persistence` NON-NULL, defaulted, enumerated (Am.2 §3 / Am.4) — behaviorally
/// and on existing data.
pub async fn check_spine_facets(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();
    let cols = columns(db, "records").await?;

    for key in SPINE_FACET_KEYS {
        let col = spine_facet_column(key);
        if !col.map(|c| cols.contains_key(c)).unwrap_or(false) {
            violations.push(format!(
                "spine facet '{key}' has no column on records (expected '{}')",
                col.unwrap_or(key)
            ));
        }
    }

    let Some(persistence) = cols.get("persistence") else {
        // The missing column is already a violation above; the persistence probes
        // and scan below would only throw `no such column` on top of it.
        return Ok(CheckResult {
            check: "spine-facets".into(),
            ok: false,
            violations,
        });
    };
    if !persistence.notnull {
        violations.push(
            "records.persistence must be NOT NULL (2e5ed3e Am.2 §3 — dedup/merge fails-wrong without it)"
                .into(),
        );
    }
    if persistence.dflt.as_deref() != Some("'enduring'") {
        violations.push(format!(
            "records.persistence must default to 'enduring' (found {})",
            persistence.dflt.as_deref().unwrap_or("no default")
        ));
    }

    let null_rejected = probe(db, |tx| {
        Box::pin(async move {
            sqlx::query("INSERT INTO records (id, type, persistence) VALUES (?, ?, NULL)")
                .bind(probe_id())
                .bind("Entity")
                .execute(tx)
                .await?;
            Ok(())
        })
    })
    .await?;
    if null_rejected.is_none() {
        violations
            .push("a NULL persistence was accepted — persistence is a required spine facet".into());
    }

    let enum_rejected = probe(db, |tx| {
        Box::pin(async move {
            sqlx::query("INSERT INTO records (id, type, persistence) VALUES (?, ?, ?)")
                .bind(probe_id())
                .bind("Entity")
                .bind("x-not-a-persistence")
                .execute(tx)
                .await?;
            Ok(())
        })
    })
    .await?;
    if enum_rejected.is_none() {
        violations.push(format!(
            "a persistence value outside ({}) was accepted",
            PERSISTENCE_VALUES.join(" | ")
        ));
    }

    let n: i64 = sqlx::query(&format!(
        "SELECT COUNT(*) AS n FROM records WHERE persistence IS NULL OR persistence NOT IN ({})",
        in_list(&PERSISTENCE_VALUES)
    ))
    .fetch_one(db.write_pool())
    .await?
    .try_get("n")?;
    if n > 0 {
        violations.push(format!(
            "{n} existing record(s) carry an invalid persistence value"
        ));
    }

    Ok(CheckResult {
        check: "spine-facets".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// The 9 spine relationships are storable (the interop floor shared skills
/// dispatch on), and the relationship string stays open-additive.
pub async fn check_spine_relationships(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();
    let failure = probe(db, |tx| {
        Box::pin(async move {
            let a = probe_id();
            let b = probe_id();
            for id in [&a, &b] {
                insert_record_probe(tx, id, Some("Document")).await?;
            }
            let novel = format!("x-conformance-probe-{}", Uuid::new_v4());
            for rel in SPINE_RELATIONSHIPS.iter().copied().chain([novel.as_str()]) {
                sqlx::query(
                    "INSERT INTO links (id, source_id, target_id, relationship) VALUES (?, ?, ?, ?)",
                )
                .bind(probe_id())
                .bind(&a)
                .bind(&b)
                .bind(rel)
                .execute(&mut *tx)
                .await?;
            }
            Ok(())
        })
    })
    .await?;
    if let Some(message) = failure {
        violations.push(format!(
            "a spine (or additive) relationship could not be stored: {message}"
        ));
    }
    Ok(CheckResult {
        check: "spine-relationships".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// Every live content record has one typed browse address, except the single
/// engine root. This is a data scan rather than only a write-path probe so
/// imported/corrupt projections fail conformance explicitly.
pub async fn check_home_contract(db: &Db) -> Result<CheckResult> {
    let mut violations = Vec::new();

    let null_homes: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM records
          WHERE deleted_at IS NULL AND home_id IS NULL
          ORDER BY id",
    )
    .fetch_all(db.write_pool())
    .await?;
    if null_homes != [ROOT_RECORD_ID] {
        violations.push(format!(
            "exactly the engine root must have a null home_id; found {null_homes:?}"
        ));
    }

    for (id, expected_home) in [
        (ROOT_RECORD_ID, None),
        (UNFILED_RECORD_ID, Some(ROOT_RECORD_ID)),
    ] {
        let row = sqlx::query(
            "SELECT type, kind, name, home_id, persistence, deleted_at,
                    EXISTS(SELECT 1 FROM facet_values a
                           WHERE a.record_id = records.id AND a.key = ?) AS archived
               FROM records WHERE id = ?",
        )
        .bind(ARCHIVED_FACET_KEY)
        .bind(id)
        .fetch_optional(db.write_pool())
        .await?;
        match row {
            None => violations.push(format!("engine filing record {id} is missing")),
            Some(row) => {
                let valid = row.try_get::<String, _>("type")? == "Collection"
                    && row.try_get::<Option<String>, _>("kind")?.as_deref() == Some("folder")
                    && row.try_get::<Option<String>, _>("home_id")?.as_deref() == expected_home
                    && row.try_get::<String, _>("persistence")? == "enduring"
                    && row.try_get::<Option<String>, _>("deleted_at")?.is_none()
                    && row.try_get::<i64, _>("archived")? == 0;
                if !valid {
                    violations.push(format!(
                        "engine filing record {id} must be a live, unarchived, enduring Collection kind:folder with home {expected_home:?}"
                    ));
                }
            }
        }
    }

    let bad_homes: Vec<String> = sqlx::query_scalar(
        "SELECT r.id
           FROM records r
           LEFT JOIN records h ON h.id = r.home_id
          WHERE r.deleted_at IS NULL AND r.id <> ? AND (
                r.home_id IS NULL OR h.id IS NULL OR h.type <> 'Collection'
                OR h.kind IS NOT 'folder' OR h.persistence <> 'enduring'
                OR h.deleted_at IS NOT NULL
                OR EXISTS(SELECT 1 FROM facet_values a
                          WHERE a.record_id = h.id AND a.key = ?)
          ) ORDER BY r.id",
    )
    .bind(ROOT_RECORD_ID)
    .bind(ARCHIVED_FACET_KEY)
    .fetch_all(db.write_pool())
    .await?;
    if !bad_homes.is_empty() {
        violations.push(format!(
            "records have missing or invalid typed home targets: {bad_homes:?}"
        ));
    }

    let cycles: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE walk(origin, id, path, cycle) AS (
             SELECT id, home_id, ',' || id || ',', 0
               FROM records
              WHERE deleted_at IS NULL AND id <> ? AND home_id IS NOT NULL
             UNION ALL
             SELECT w.origin, r.home_id, w.path || r.id || ',',
                    instr(w.path, ',' || r.id || ',') > 0
               FROM walk w JOIN records r ON r.id = w.id
              WHERE w.id IS NOT NULL AND w.cycle = 0
         )
         SELECT DISTINCT origin FROM walk WHERE cycle = 1 ORDER BY origin",
    )
    .bind(ROOT_RECORD_ID)
    .fetch_all(db.write_pool())
    .await?;
    if !cycles.is_empty() {
        violations.push(format!("home cycles detected for records: {cycles:?}"));
    }

    Ok(CheckResult {
        check: "home-contract".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// SUBSTRATE BOUNDARY (Am.2 §2) — closing the type tier is cheap because the
/// substrate tier stays open. Executably: (a) the full substrate-primitive set
/// is present, including `blobs`, the 5th primitive, so hard-shaped data has a
/// substrate home to land in; (b) a new top-level type stays unrepresentable
/// even though new tables are representable — which is exactly why the suite
/// tolerates extra tables (see `check_required_tables`) while `check_closed_types`
/// rejects the rogue type. The pairing IS the boundary test.
pub async fn check_substrate_boundary(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();
    let names = table_names(db).await?;
    for t in [
        "content_events",
        "records",
        "links",
        "facet_values",
        "blobs",
    ] {
        if !names.contains(t) {
            violations.push(format!("substrate primitive table missing: {t}"));
        }
    }
    // The closed edge of the boundary, re-asserted from the substrate side: a
    // hard-shaped newcomer must not be admissible as a records.type.
    let rogue = probe(db, |tx| {
        Box::pin(async move { insert_record_probe(tx, &probe_id(), Some("Observation")).await })
    })
    .await?;
    if rogue.is_none() {
        violations.push(
            "hard-shaped data can land as a new top-level type ('Observation' was accepted) — it must land as a substrate primitive instead"
                .into(),
        );
    }
    Ok(CheckResult {
        check: "substrate-boundary".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// TYPE IS RIGID — the invariant the whole closed-type extension model rests on
/// (2e5ed3e), promoted here from a tool-surface convention to a checked property
/// of the engine (task 1ed2c74, closing F6a of the OntoClean verdict 6285fa8).
///
/// Why it needs its own check rather than riding on `closed-types`: that check
/// asserts a record's type *is one of the 8*, which the `records.type` CHECK
/// already enforces. It says nothing about whether a record *stays* the one it
/// was — and SQLite cannot express "this column never changes" without a trigger
/// the frozen DDL does not carry. The invariant therefore lives in the fold, so
/// this is the only place it can be asserted.
///
/// Four parts, all load-bearing:
///   - BEHAVIORAL — ask the projector to apply a `record.updated` carrying
///     `type` and require rejection. This is the invariant itself.
///   - POSITIVE CONTROL — an ordinary `record.updated` must still APPLY.
///     Without it the probe above would be satisfied by an engine that had
///     broken updates entirely, which is the classic way an assertion of the
///     form "the bad thing failed" rots into a tautology.
///   - GOVERNED EXCEPTION — a structurally valid `record.type_corrected.v1`
///     must apply, while malformed correction evidence must fail closed.
///   - DATA SCAN — a log written by a permissive older build carries the
///     violation regardless of what today's binary would refuse, so a database
///     cannot pass merely by being validated with a newer conformance runner.
pub async fn check_type_immutability(db: &Db) -> Result<CheckResult> {
    let mut violations: Vec<String> = Vec::new();

    let rejected = probe(db, |tx| {
        Box::pin(async move {
            let id = probe_id();
            insert_record_probe(tx, &id, Some("Document")).await?;
            crate::projector::project(tx, &update_probe_event(&id, r#"{"type":"Entity"}"#)).await
        })
    })
    .await?;
    if rejected.is_none() {
        violations.push(
            "a `record.updated` carrying `type` was APPLIED — a record must keep its spine type for life; there is no cross-type promotion path"
                .into(),
        );
    }

    let control = probe(db, |tx| {
        Box::pin(async move {
            let id = probe_id();
            insert_record_probe(tx, &id, Some("Document")).await?;
            crate::projector::project(tx, &update_probe_event(&id, r#"{"kind":"note"}"#)).await
        })
    })
    .await?;
    if let Some(message) = control {
        violations.push(format!(
            "an ordinary `record.updated` was rejected, so the type-immutability probe proves nothing: {message}"
        ));
    }

    let governed_control = probe(db, |tx| {
        Box::pin(async move {
            let id = probe_id();
            insert_record_probe(tx, &id, Some("Document")).await?;
            sqlx::query("UPDATE records SET kind='note' WHERE id=?")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            crate::projector::project(tx, &type_correction_probe_event(&id, true)).await
        })
    })
    .await?;
    if let Some(message) = governed_control {
        violations.push(format!(
            "a valid `record.type_corrected.v1` was rejected, so the governed correction exception is unavailable: {message}"
        ));
    }

    let malformed = probe(db, |tx| {
        Box::pin(async move {
            let id = probe_id();
            insert_record_probe(tx, &id, Some("Document")).await?;
            sqlx::query("UPDATE records SET kind='note' WHERE id=?")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            crate::projector::project(tx, &type_correction_probe_event(&id, false)).await
        })
    })
    .await?;
    if malformed.is_none() {
        violations.push(
            "a malformed `record.type_corrected.v1` without governed plan evidence was applied"
                .into(),
        );
    }

    // `json_type` rather than `json_extract`: an explicit `"type": null` is a
    // present key and must count, and `json_extract` would report it as absent.
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM content_events
          WHERE type = 'record.updated'
            AND json_valid(payload)
            AND json_type(payload, '$.type') IS NOT NULL",
    )
    .fetch_one(db.write_pool())
    .await?;
    let n: i64 = row.try_get("n")?;
    if n > 0 {
        violations.push(format!(
            "{n} `record.updated` event(s) in the log carry `type` — replaying this log would change a record's type"
        ));
    }

    Ok(CheckResult {
        check: "type-immutability".into(),
        ok: violations.is_empty(),
        violations,
    })
}

/// A synthetic `record.updated` for the probes above. The three annotation
/// columns are `None` on purpose — the projector ignores them by contract
/// (`tests/records/annotations.rs`), so feeding them here would test nothing.
fn update_probe_event(record_id: &str, payload: &str) -> EventRow {
    EventRow {
        local_seq: 0,
        id: probe_id(),
        record_id: record_id.to_string(),
        event_type: "record.updated".into(),
        payload: Some(payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".into(),
        causal_envelope: crate::events::CausalEnvelopeV1::default(),
    }
}

fn type_correction_probe_event(record_id: &str, valid: bool) -> EventRow {
    let mut payload = serde_json::json!({
        "from": {"type": "Document", "kind": "note"},
        "to": {"type": "Resolution", "kind": "decision"},
        "mode": "confirmed",
        "reason": "Conformance probe for the governed correction event.",
        "plan_id": "plan:conformance-probe",
        "effect_digest": format!("sha256:{}", "a".repeat(64)),
        "schema_state_revision": "schema-state-v1:meta:0:content:0",
        "confirmation_required": true,
    });
    if !valid {
        payload.as_object_mut().unwrap().remove("effect_digest");
    }
    EventRow {
        local_seq: 0,
        id: probe_id(),
        record_id: record_id.to_string(),
        event_type: "record.type_corrected.v1".into(),
        payload: Some(payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".into(),
        causal_envelope: crate::events::CausalEnvelopeV1::default(),
    }
}

/// A check that cannot run against a malformed database (missing table, missing
/// column) must still land in the report as a violation — the suite's contract
/// is a report + exit code, never a crash.
fn guarded(name: &str, result: Result<CheckResult>) -> CheckResult {
    match result {
        Ok(check) => check,
        Err(err) => CheckResult {
            check: name.into(),
            ok: false,
            violations: vec![format!("check could not run: {err}")],
        },
    }
}

/// All spine-contract checks, in report order (rebuild-and-diff is folded in by the suite runner).
pub async fn run_spine_checks(db: &Db) -> Vec<CheckResult> {
    vec![
        guarded("required-tables", check_required_tables(db).await),
        guarded("event-log-shape", check_event_log_shape(db).await),
        guarded(
            "content-event-causality",
            check_content_event_causality(db).await,
        ),
        guarded("meta-event-log-shape", check_meta_event_log_shape(db).await),
        guarded(
            "command-event-log-shapes",
            check_command_event_log_shapes(db).await,
        ),
        guarded(
            "derivation-request-shape",
            check_derivation_request_shape(db).await,
        ),
        guarded("closed-types", check_closed_types(db).await),
        guarded("type-immutability", check_type_immutability(db).await),
        guarded("open-kind", check_open_kind(db).await),
        guarded("required-kind", check_required_kind(db).await),
        guarded("spine-facets", check_spine_facets(db).await),
        guarded("spine-relationships", check_spine_relationships(db).await),
        guarded("home-contract", check_home_contract(db).await),
        guarded("substrate-boundary", check_substrate_boundary(db).await),
    ]
}

#[cfg(test)]
mod causal_conformance_tests {
    use super::*;

    #[tokio::test]
    async fn post_cutover_local_incomplete_event_fails_conformance() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let first_local_event_id: String =
            sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq LIMIT 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        sqlx::query("UPDATE content_events SET causal_status='import_incomplete' WHERE id=?")
            .bind(first_local_event_id)
            .execute(db.write_pool())
            .await
            .unwrap();

        let result = check_content_event_causality(&db).await.unwrap();
        assert!(!result.ok);
        assert!(result
            .violations
            .iter()
            .any(|violation| violation
                .contains("post-cutover locally authored event is not complete")));
    }
}
