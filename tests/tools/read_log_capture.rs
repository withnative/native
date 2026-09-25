//! PR A capture filtering for task 8a6377f: stop future disposable pure-read
//! growth while preserving raw action and declaration evidence.
//!
//! These are behavior tests through the registry, not pins of the retention
//! predicate: every assertion reads back `read_log_calls` /
//! `read_log_touches` / `content_events` / `agent_runs` or a live consumer
//! (`get_run_activity`, discovery) after real calls.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

const RUN: &str = "scout-chair-a748b2";
const CHILD_RUN: &str = "pilot-river-b748b2";
const ACCOUNT: &str = "acct:capture-test";
const PERSON: &str = "test:capture-test-person";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn ensure_account_binding(db: &Db) {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query(
        "INSERT OR IGNORE INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence)
         VALUES (?, 'Entity', 'person', 'Test account', ?, ?, 'enduring')",
    )
    .bind(PERSON)
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT OR IGNORE INTO bindings
            (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(PERSON)
    .bind(ACCOUNT)
    .execute(&pool)
    .await
    .unwrap();
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    ensure_account_binding(db).await;
    let result = registry
        .call(
            db.clone(),
            Caller::authenticated(ACCOUNT),
            tool,
            crate::common::with_test_reason(tool, arguments),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    result
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> String {
    ensure_account_binding(db).await;
    let error = registry
        .call(
            db.clone(),
            Caller::authenticated(ACCOUNT),
            tool,
            crate::common::with_test_reason(tool, arguments),
        )
        .await
        .unwrap_err();
    db.drain_captures_for_tests().await;
    error.to_string()
}

async fn call_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn touch_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn create_target(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": name }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn pure_reads_leave_no_new_rows_and_retained_rows_store_null_exhaust() {
    let db = db().await;
    let registry = registry();
    let target = create_target(&registry, &db, "Capture target").await;
    let baseline_calls = call_count(&db).await;
    let baseline_touches = touch_count(&db).await;
    assert!(baseline_calls >= 1, "the create must be retained");

    // Ordinary reads: each succeeds and each is disposable exhaust.
    let reads = [
        (
            "get_record",
            json!({ "ids": [target.clone()], "run_key": RUN }),
        ),
        ("search", json!({ "query": "capture", "run_key": RUN })),
        (
            "query_record",
            json!({ "steps": [{"step": "filter", "ids": [target.clone()]}], "run_key": RUN }),
        ),
        (
            "render_record",
            json!({ "id": target.clone(), "run_key": RUN }),
        ),
        (
            "get_history",
            json!({ "record_id": target.clone(), "run_key": RUN }),
        ),
    ];
    for (tool, arguments) in reads {
        call(&registry, &db, tool, arguments).await;
    }
    // A failed pure read is an attempt with no consumer: also dropped.
    let missing = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["missing-record"], "run_key": RUN }),
    )
    .await;
    assert_eq!(missing["records"][0]["status"], "not_found");

    assert_eq!(call_count(&db).await, baseline_calls);
    assert_eq!(touch_count(&db).await, baseline_touches);

    // The retained create row stores NULLs where the unused exhaust columns
    // were: no production reader selects them, and the schema is unchanged.
    let row = sqlx::query(
        "SELECT result_count, result_bytes FROM read_log_calls WHERE tool = 'create_record'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(row
        .try_get::<Option<i64>, _>("result_count")
        .unwrap()
        .is_none());
    assert!(row
        .try_get::<Option<i64>, _>("result_bytes")
        .unwrap()
        .is_none());
    let ranks: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches WHERE result_rank IS NOT NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(ranks, 0);
    db.close().await;
}

#[tokio::test]
async fn successful_set_intent_is_retained_without_touches() {
    let db = db().await;
    let registry = registry();
    let intent = "Hold the capture boundary while reads come and go.";

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": intent, "run_key": RUN }),
    )
    .await;
    assert_eq!(result["accepted_intent"], intent);

    let row = sqlx::query(
        "SELECT intent, outcome, result_count, result_bytes
           FROM read_log_calls WHERE tool = 'set_intent'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("intent"), intent);
    assert_eq!(row.get::<String, _>("outcome"), "ok");
    assert!(row
        .try_get::<Option<i64>, _>("result_count")
        .unwrap()
        .is_none());
    assert!(row
        .try_get::<Option<i64>, _>("result_bytes")
        .unwrap()
        .is_none());
    let touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'set_intent'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(touches, 0);
    db.close().await;
}

#[tokio::test]
async fn action_calls_keep_verbatim_arguments_mutated_touches_and_parent_child_order() {
    let db = db().await;
    let registry = registry();
    let parent_record = create_target(&registry, &db, "Ordering parent").await;
    let target = create_target(&registry, &db, "Ordering target").await;

    // Material work on the root run.
    let update_arguments = json!({
        "id": target.clone(),
        "name": "Ordering target, worked on",
        "run_key": RUN,
    });
    call(&registry, &db, "update_record", update_arguments.clone()).await;

    // Coordination with verbatim structure the evaluator reads.
    let link_arguments = json!({
        "action": "add",
        "source_id": target.clone(),
        "target_id": parent_record.clone(),
        "relationship": "part_of",
        "run_key": RUN,
    });
    call(&registry, &db, "manage_links", link_arguments.clone()).await;

    // Material work on the child run, parented to the root.
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": parent_record.clone(),
            "name": "Ordering parent, worked on",
            "run_key": CHILD_RUN,
            "parent_key": RUN,
        }),
    )
    .await;

    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT seq, tool, arguments FROM read_log_calls
          WHERE run_key IN (?, ?)
          ORDER BY seq",
    )
    .bind(RUN)
    .bind(CHILD_RUN)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 3, "action calls were folded: {rows:?}");
    assert_eq!(rows[0].1, "update_record");
    assert_eq!(rows[1].1, "manage_links");
    assert_eq!(rows[2].1, "update_record");
    assert!(rows[0].0 < rows[1].0 && rows[1].0 < rows[2].0);

    let stored_update: Value = serde_json::from_str(&rows[0].2).unwrap();
    assert_eq!(stored_update["id"], target);
    assert_eq!(stored_update["run_key"], RUN);
    let stored_link: Value = serde_json::from_str(&rows[1].2).unwrap();
    assert_eq!(stored_link, link_arguments);

    for (seq, tool) in [(rows[0].0, "update_record"), (rows[1].0, "manage_links")] {
        let mutated: Vec<String> = sqlx::query_scalar(
            "SELECT dictionary.record_id
               FROM read_log_touches touch
               JOIN read_log_record_ids dictionary
                 ON dictionary.record_ref = touch.record_ref
              WHERE touch.call_seq = ? AND touch.interaction = 'mutated'
              ORDER BY dictionary.record_id",
        )
        .bind(seq)
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert!(
            mutated.contains(&target),
            "{tool} lost its own mutated touch: {mutated:?}"
        );
    }

    // The aggregate still walks parentage across the retained rows.
    let tree = call(
        &registry,
        &db,
        "get_run_activity",
        json!({
            "for_run": RUN,
            "include_child_runs": true,
            "run_key": RUN,
        }),
    )
    .await;
    assert_eq!(tree["availability"]["status"], "available");
    let activity = tree["read_activity"].as_array().unwrap();
    assert_eq!(activity.len(), 2);
    assert_eq!(activity[0]["run_key"], RUN);
    assert_eq!(activity[1]["run_key"], CHILD_RUN);
    assert_eq!(activity[1]["parent_key"], RUN);
    db.close().await;
}

#[tokio::test]
async fn failed_action_attempts_and_unknown_mixed_actions_are_kept() {
    let db = db().await;
    let registry = registry();
    let target = create_target(&registry, &db, "Attempt target").await;
    let baseline = call_count(&db).await;

    // A failed coordination attempt keeps its verbatim arguments: the attempt
    // is evidence even though nothing was touched.
    let link_arguments = json!({
        "action": "add",
        "source_id": target.clone(),
        "target_id": "missing-record",
        "relationship": "part_of",
        "run_key": RUN,
    });
    let error = call_err(&registry, &db, "manage_links", link_arguments.clone()).await;
    assert!(!error.is_empty(), "fixture no longer fails the bad link");
    let row: (String, String) = sqlx::query_as(
        "SELECT outcome, arguments FROM read_log_calls
          WHERE tool = 'manage_links' AND outcome = 'error'
          ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.0, "error");
    assert_eq!(
        serde_json::from_str::<Value>(&row.1).unwrap(),
        link_arguments
    );

    // An unknown mixed action fails closed: it is kept rather than treated
    // as another read name. `manage_schema_config` is outside the
    // action-evidence carve-out, so this exercises the per-argument rule.
    let unknown = json!({ "action": "future_read_like_name", "run_key": RUN });
    let error = call_err(&registry, &db, "manage_schema_config", unknown).await;
    assert!(
        !error.is_empty(),
        "fixture no longer rejects the unknown action"
    );
    let kept: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_calls
          WHERE tool = 'manage_schema_config' AND outcome = 'error'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(kept, 1, "unknown mixed actions must fail closed (keep)");

    // The known read action of the same tool is disposable exhaust.
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read", "run_key": RUN }),
    )
    .await;
    let reads: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_calls
          WHERE tool = 'manage_schema_config' AND outcome = 'ok'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(reads, 0, "read actions must leave no rows");

    assert_eq!(call_count(&db).await, baseline + 2);
    db.close().await;
}

#[tokio::test]
async fn legacy_undeclared_writes_keep_evidence_with_honest_intent_and_ownership() {
    let db = db().await;
    let registry = registry();
    // No declaration on this run: a legacy write without a basis.
    let created = call(
        &registry,
        &db,
        "create_record",
        json!(
            { "type": "Document", "kind": "note", "name": "Undeclared", "run_key": RUN }),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();

    // The write's evidence is retained with its mutated touch.
    let seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM read_log_calls WHERE run_key = ? AND tool = 'create_record'",
    )
    .bind(RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let mutated: Vec<String> = sqlx::query_scalar(
        "SELECT dictionary.record_id
           FROM read_log_touches touch
           JOIN read_log_record_ids dictionary
             ON dictionary.record_ref = touch.record_ref
          WHERE touch.call_seq = ? AND touch.interaction = 'mutated'",
    )
    .bind(seq)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(mutated, vec![id.clone()]);

    // The run has activity while its rows survive the purge shape.
    let activity = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": RUN, "run_key": RUN }),
    )
    .await;
    assert_eq!(activity["availability"]["status"], "available");
    assert_eq!(activity["read_activity"].as_array().unwrap().len(), 1);

    // Discovery is honest about the missing declaration: a run that was
    // never declared has no durable `agent_runs` row, so it is not listed.
    // (The declared-run half below covers the available / not_retained
    // distinction for runs that are.)
    let discovery = call(&registry, &db, "get_run_activity", json!({})).await;
    assert!(
        !discovery
            .to_string()
            .contains(&format!("\"run_key\":\"{RUN}\"")),
        "undeclared run must not appear in discovery: {discovery}"
    );

    // Simulate the post-purge shape: read rows gone, durable declaration
    // state (`agent_runs`, `content_events`) intact.
    sqlx::query("DELETE FROM read_log_calls WHERE run_key = ?")
        .bind(RUN)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    // Ownership resolves through the durable state, not the purged rows: an
    // available run with no retained activity, not a missing run.
    let purged = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": RUN, "run_key": RUN }),
    )
    .await;
    assert_eq!(purged["availability"]["status"], "available");
    assert_eq!(purged["read_activity"], json!([]));

    // Permission filtering still holds: another account owns nothing here.
    ensure_account_binding(&db).await;
    let stranger = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:stranger"),
            "get_run_activity",
            json!({ "for_run": RUN }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        stranger.contains("run does not exist"),
        "unexpected stranger result: {stranger}"
    );
    db.close().await;
}

#[tokio::test]
async fn declared_runs_keep_honest_intent_through_selective_retention() {
    const DECLARED_RUN: &str = "heron-chair-d949c3";
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "A declared run.", "run_key": DECLARED_RUN }),
    )
    .await;
    create_target(&registry, &db, "Declared target").await;

    // Purging everything but the declaration (the PR B shape) keeps the
    // intent available: the declaration is the read-only run's record.
    sqlx::query("DELETE FROM read_log_calls WHERE tool != 'set_intent'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let discovery = call(&registry, &db, "get_run_activity", json!({})).await;
    let run = discovery["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["run_key"] == DECLARED_RUN)
        .unwrap_or_else(|| panic!("declared run missing from discovery: {discovery}"))
        .clone();
    assert_eq!(run["intent"]["status"], "available");
    assert_eq!(run["intent"]["value"], "A declared run.");

    // Losing the declaration too is reported honestly, not as an error.
    sqlx::query("DELETE FROM read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let discovery = call(&registry, &db, "get_run_activity", json!({})).await;
    let run = discovery["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["run_key"] == DECLARED_RUN)
        .unwrap_or_else(|| panic!("declared run missing from discovery: {discovery}"))
        .clone();
    assert_eq!(run["intent"]["status"], "not_retained");
    db.close().await;
}

#[tokio::test]
async fn run_issuance_survives_without_capturing_bootstrap_or_mint_reads() {
    let db = db().await;
    let registry = registry();
    let target = create_target(&registry, &db, "Issuance target").await;

    call(&registry, &db, "bootstrap", json!({})).await;
    let bootstrap_seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM read_log_calls WHERE tool = 'bootstrap' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let bootstrap_touches: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches WHERE call_seq = ?")
            .bind(bootstrap_seq)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        bootstrap_touches, 0,
        "issuance must not retain orientation touches"
    );

    let response = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target.clone()], "run_key": "new:scout-chair" }),
    )
    .await;
    let minted = response["run_context"]["run_key"].as_str().unwrap();
    assert!(minted.starts_with("scout-chair-"));
    let (arguments, touches): (String, i64) = sqlx::query_as(
        "SELECT c.arguments,
                (SELECT COUNT(*) FROM read_log_touches t WHERE t.call_seq = c.seq)
           FROM read_log_calls c WHERE c.tool = 'get_record' AND c.run_key = ?",
    )
    .bind(minted)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&arguments).unwrap(),
        json!({"run_key":"new:scout-chair"})
    );
    assert!(
        !arguments.contains(&target),
        "mint row retained read arguments"
    );
    assert_eq!(touches, 0);

    let activity = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": minted, "run_key": minted }),
    )
    .await;
    assert_eq!(activity["availability"]["status"], "available");
    db.close().await;
}

#[tokio::test]
async fn rejected_bootstrap_keeps_only_issuance_attempt_evidence() {
    let db = db().await;
    let registry = registry();
    let error = call_err(
        &registry,
        &db,
        "bootstrap",
        json!({ "run_key": RUN, "unknown": "private-read-detail" }),
    )
    .await;
    assert!(!error.is_empty());
    let row: (String, String, String) = sqlx::query_as(
        "SELECT run_key, arguments, outcome FROM read_log_calls
          WHERE tool='bootstrap' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.0, RUN);
    assert_eq!(row.1, json!({"run_key": RUN}).to_string());
    assert_eq!(row.2, "error");
    assert!(!row.1.contains("private-read-detail"));
    db.close().await;
}
