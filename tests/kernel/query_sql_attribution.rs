//! Governed `content_events` attribution parity with `get_history`: the new
//! `actor`/`run_key` columns follow the SQLite history disclosure rule, so a
//! run-scoped governed query returns exactly what `get_history({for_run})`
//! shows the same viewer.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};

const SELF: &str = "account:self";
const OTHER: &str = "account:other";
const HIDDEN: &str = "account:hidden";
const RUN: &str = "scout-chair-a748b2";
const OTHER_RUN: &str = "otter-field-c748b2";

async fn db() -> Db {
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn insert_record(db: &Db, id: &str) {
    sqlx::query(
        "INSERT INTO records
            (id, type, kind, name, policy_anchor_id, persistence, created_at, updated_at)
         VALUES (?, 'Document', 'note', ?, ?, 'enduring',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.000Z')",
    )
    .bind(id)
    .bind(id)
    .bind(id)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_policies (record_id) VALUES (?)")
        .bind(id)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
            (policy_anchor_id, subject_kind, subject_id, effect, capability)
         VALUES (?, 'members', 'native:members', 'allow', 'view')",
    )
    .bind(id)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

/// A person record bound to `account` and visible to members, so `account`
/// is a disclosable actor to any member caller. An actor with no such
/// binding stays hidden.
async fn insert_visible_person(db: &Db, person_id: &str, account: &str) {
    insert_record(db, person_id).await;
    sqlx::query(
        "INSERT INTO bindings(record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person_id)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn insert_event(
    db: &Db,
    record_id: &str,
    payload: Value,
    actor: Option<&str>,
    run_key: Option<&str>,
) {
    let id = format!(
        "event:{}",
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) + 1 FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, run_key, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'record.updated', ?, ?, ?,
                 strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || (SELECT COUNT(*) FROM content_events) || ' seconds'), 1, 'legacy_unknown')",
    )
    .bind(id)
    .bind(record_id)
    .bind(payload.to_string())
    .bind(actor)
    .bind(run_key)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn governed_rows(db: &Db, caller: &Caller, sql: &str) -> Vec<Value> {
    native_ce::query::sql::query_sql(db, caller, sql)
        .await
        .unwrap()
        .rows
}

fn attribution(row: &Value) -> (String, String, String, String) {
    let cell = |column: &str| {
        row.get(column)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (
        cell("record_id"),
        cell("type"),
        cell("actor"),
        cell("run_key"),
    )
}

/// `SELECT record_id, type, actor, run_key ... WHERE run_key = ?` shows one
/// viewer exactly the DISCLOSED rows `get_history({record_id, for_run})`
/// shows them: history returns every raw run match redacted, while the
/// governed view nulls hidden attribution before the predicate runs, so the
/// SQL set equals the history subset whose `run_key` survived redaction.
/// The fixture pins both gates on the same run: an event by an undisclosed
/// actor, and a claim-shaped event by a disclosed non-holder. Without
/// redaction the SQL filter would return all four rows with the raw run.
#[tokio::test]
async fn governed_content_events_matches_get_history_for_run() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:parity").await;
    insert_visible_person(&db, "person:other", OTHER).await;
    insert_event(
        &db,
        "record:parity",
        json!({"summary": "one"}),
        Some(SELF),
        Some(RUN),
    )
    .await;
    insert_event(
        &db,
        "record:parity",
        json!({"summary": "two"}),
        Some(SELF),
        Some(RUN),
    )
    .await;
    insert_event(
        &db,
        "record:parity",
        json!({"summary": "other"}),
        Some(SELF),
        Some(OTHER_RUN),
    )
    .await;
    // Same record, same run, undisclosed actor: redaction must hide the run.
    insert_event(
        &db,
        "record:parity",
        json!({"summary": "hidden"}),
        Some(HIDDEN),
        Some(RUN),
    )
    .await;
    // Same record, same run, disclosed actor, claim-shaped payload: the
    // claim-holder gate must hide the run from this non-holder viewer.
    insert_event(
        &db,
        "record:parity",
        json!({"summary": "claimed", "claimed_by_account": OTHER}),
        Some(OTHER),
        Some(RUN),
    )
    .await;
    let caller = Caller::authenticated(SELF);
    let history = registry
        .call(
            db.clone(),
            caller.clone(),
            "get_history",
            json!({"record_id": "record:parity", "for_run": RUN}),
        )
        .await
        .unwrap();
    let history_rows: Vec<_> = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(attribution)
        .collect();
    // History matches the raw run (four events) with attribution redacted:
    // the hidden actor's row carries no actor and no run, and the claim
    // row names its actor but carries no run.
    assert_eq!(history_rows.len(), 4);
    assert!(
        history_rows.iter().any(|row| row
            == &(
                "record:parity".to_string(),
                "record.updated".to_string(),
                String::new(),
                String::new()
            )),
        "hidden-actor row must be present fully redacted: {history_rows:?}"
    );
    assert!(
        history_rows.iter().any(|row| row
            == &(
                "record:parity".to_string(),
                "record.updated".to_string(),
                OTHER.to_string(),
                String::new()
            )),
        "claim row must name its actor but hide the run: {history_rows:?}"
    );
    // SQL agrees on exactly the disclosed subset: the two self rows.
    let mut expected: Vec<_> = history_rows
        .into_iter()
        .filter(|row| !row.3.is_empty())
        .collect();
    expected.sort();
    let result = native_ce::query::sql::query_sql(
        &db,
        &caller,
        &format!(
            "SELECT record_id, type, actor, run_key FROM content_events \
             WHERE run_key = '{RUN}' ORDER BY local_seq"
        ),
    )
    .await
    .unwrap();
    let mut actual: Vec<_> = result.rows.iter().map(attribution).collect();
    actual.sort();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 2);
    assert!(
        actual.iter().all(|row| row.2 == SELF && row.3 == RUN),
        "no row may attribute the run to anyone but self: {actual:?}"
    );
    db.close().await;
}

const SNOOP_RUN: &str = "lark-pond-e748b2";
const SNOOP_OTHER: &str = "account:snoop-bea";
const SNOOP_OTHER_RUN: &str = "heron-marsh-f748b2";

/// Predicates, grouping and joins observe the redacted projection, not the
/// raw columns: as a caller who cannot see `SNOOP_OTHER`, probing by actor
/// or run finds nothing, grouping collapses the hidden events into the NULL
/// group, and a self-join on `run_key` never pairs them (`NULL = NULL` is
/// not true). Without redaction every assertion below fails.
#[tokio::test]
async fn governed_content_events_predicates_cannot_probe_hidden_attribution() {
    let db = db().await;
    insert_record(&db, "record:snoop").await;
    for summary in ["self-one", "self-two"] {
        insert_event(
            &db,
            "record:snoop",
            json!({"summary": summary}),
            Some(SELF),
            Some(SNOOP_RUN),
        )
        .await;
    }
    for summary in ["hidden-one", "hidden-two"] {
        insert_event(
            &db,
            "record:snoop",
            json!({"summary": summary}),
            Some(SNOOP_OTHER),
            Some(SNOOP_OTHER_RUN),
        )
        .await;
    }
    let caller = Caller::authenticated(SELF);

    // Probing by the hidden actor or its run returns nothing: the view
    // already nulled both, so the predicates compare against NULL.
    assert!(
        governed_rows(
            &db,
            &caller,
            &format!("SELECT id FROM content_events WHERE actor = '{SNOOP_OTHER}'"),
        )
        .await
        .is_empty(),
        "WHERE actor = hidden must match only NULL"
    );
    assert!(
        governed_rows(
            &db,
            &caller,
            &format!("SELECT id FROM content_events WHERE run_key = '{SNOOP_OTHER_RUN}'"),
        )
        .await
        .is_empty(),
        "WHERE run_key = hidden-run must match only NULL"
    );

    // Grouping collapses both hidden events into the NULL group; no group
    // names the hidden actor.
    let grouped = governed_rows(
        &db,
        &caller,
        "SELECT actor, COUNT(*) AS n FROM content_events \
         WHERE record_id = 'record:snoop' GROUP BY actor ORDER BY n, actor",
    )
    .await;
    assert_eq!(
        grouped.len(),
        2,
        "self group plus one NULL group: {grouped:?}"
    );
    let group = |row: &Value| {
        (
            row.get("actor").and_then(Value::as_str).map(str::to_string),
            row.get("n").and_then(Value::as_i64).unwrap_or(-1),
        )
    };
    assert!(
        grouped
            .iter()
            .any(|row| group(row) == (Some(SELF.to_string()), 2)),
        "self group must hold both self events: {grouped:?}"
    );
    assert!(
        grouped.iter().any(|row| group(row) == (None, 2)),
        "hidden events must collapse into the NULL group: {grouped:?}"
    );

    // A self-join on run_key pairs only the two self events: NULL run keys
    // never join, so the hidden pair is invisible to the join.
    let joined = governed_rows(
        &db,
        &caller,
        "SELECT a.id AS x, b.id AS y FROM content_events AS a \
         JOIN content_events AS b ON a.run_key = b.run_key \
         WHERE a.record_id = 'record:snoop' AND b.record_id = 'record:snoop' \
           AND a.id < b.id ORDER BY x, y",
    )
    .await;
    assert_eq!(joined.len(), 1, "only the self pair joins: {joined:?}");
    db.close().await;
}
