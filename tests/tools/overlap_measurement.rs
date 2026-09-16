use chrono::{Duration, SecondsFormat, Utc};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const ACTOR: &str = "local";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

fn timestamp(minutes_ago: i64) -> String {
    (Utc::now() - Duration::minutes(minutes_ago)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn record_id(label: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in label.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("00000000-0000-4000-8000-{:012x}", hash & 0xffffffffffff)
}

fn annotation(surface: &str, anchor: &str, overlaps: &[&str], total: i64) -> String {
    let anchor = record_id(anchor);
    let overlaps = overlaps.iter().map(|id| record_id(id)).collect::<Vec<_>>();
    serde_json::to_string(&json!({
        "kind": "work_overlap_emission",
        "version": 1,
        "surface": surface,
        "anchors": [{
            "record_id": anchor,
            "overlap_record_ids": overlaps,
            "overlap_item_count": overlaps.len(),
            "overlap_total_count": total,
            "truncated": total > overlaps.len() as i64,
        }],
    }))
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn insert_call(
    db: &Db,
    id: &str,
    tool: &str,
    run_key: &str,
    parent_key: Option<&str>,
    actor: &str,
    arguments: Value,
    ended_at: &str,
    result_annotation: Option<&str>,
) -> i64 {
    let fixture_pool = crate::common::fixture_write_pool(db).await;
    let result = sqlx::query(
        "INSERT INTO read_log_calls
         (id,tool,run_key,parent_key,actor,arguments,outcome,result_count,result_bytes,
          started_at,ended_at,result_annotation)
         VALUES (?,?,?,?,?,?,'ok',1,1,?,?,?)",
    )
    .bind(id)
    .bind(tool)
    .bind(run_key)
    .bind(parent_key)
    .bind(actor)
    .bind(serde_json::to_string(&arguments).unwrap())
    .bind(ended_at)
    .bind(ended_at)
    .bind(result_annotation)
    .execute(&fixture_pool)
    .await
    .unwrap();
    result.last_insert_rowid()
}

async fn mutated(db: &Db, call_seq: i64, record_label: &str) {
    let record_id = record_id(record_label);
    let fixture_pool = crate::common::fixture_write_pool(db).await;
    sqlx::query("INSERT OR IGNORE INTO read_log_record_ids (record_id) VALUES (?)")
        .bind(&record_id)
        .execute(&fixture_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO read_log_touches(call_seq,record_ref,interaction,result_rank)
         VALUES (?,(SELECT record_ref FROM read_log_record_ids WHERE record_id = ?),'mutated',NULL)",
    )
    .bind(call_seq)
    .bind(&record_id)
    .execute(&fixture_pool)
    .await
    .unwrap();
}

async fn record(db: &Db, id: &str) {
    let id = record_id(id);
    native_ce::store::create_record(
        db,
        json!({
            "id": id,
            "type": "WorkItem",
            "kind": "task",
            "name": id,
            "lifecycle": "in_progress",
        }),
    )
    .await
    .unwrap();
}

async fn evaluate(registry: &ToolRegistry, db: &Db, scope: &str) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "get_run_activity",
            json!({
                "overlap_evaluation": {"scope": scope},
                "run_key": "metric-reader-a748b2",
            }),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn overlap_evaluation_uses_call_denominators_and_earliest_same_account_run_tree_action() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    for id in [
        "anchor-release",
        "overlap-release",
        "anchor-coordinate",
        "overlap-coordinate",
        "anchor-proceed",
        "overlap-proceed",
        "anchor-none",
        "overlap-none",
        "anchor-pending",
        "overlap-pending",
        "anchor-create",
        "overlap-create",
        "anchor-intent",
        "overlap-intent",
    ] {
        record(&db, id).await;
    }

    let mature = timestamp(40);
    let action = timestamp(39);
    let release_annotation = annotation("claim", "anchor-release", &["overlap-release"], 1);
    let release_notice = insert_call(
        &db,
        "notice-release",
        "start_work",
        "release-root-a748b2",
        None,
        ACTOR,
        json!({"record_id":"anchor-release","action":"claim"}),
        &mature,
        Some(&release_annotation),
    )
    .await;
    let released = insert_call(
        &db,
        "release-first",
        "start_work",
        "release-child-a748b2",
        Some("release-root-a748b2"),
        ACTOR,
        json!({"record_id":"anchor-release","action":"release"}),
        &mature,
        None,
    )
    .await;
    assert!(released > release_notice);
    mutated(&db, released, "anchor-release").await;
    let later_progress = insert_call(
        &db,
        "release-later-progress",
        "update_record",
        "release-child-a748b2",
        Some("release-root-a748b2"),
        ACTOR,
        json!({"id":"anchor-release"}),
        &timestamp(38),
        None,
    )
    .await;
    mutated(&db, later_progress, "anchor-release").await;

    let coordinate_annotation =
        annotation("claim", "anchor-coordinate", &["overlap-coordinate"], 1);
    insert_call(
        &db,
        "notice-coordinate",
        "start_work",
        "coordinate-root-a748b2",
        None,
        ACTOR,
        json!({"record_id":"anchor-coordinate","action":"claim"}),
        &mature,
        Some(&coordinate_annotation),
    )
    .await;
    let coordinated = insert_call(
        &db,
        "coordinate-first",
        "manage_links",
        "coordinate-child-a748b2",
        Some("coordinate-root-a748b2"),
        ACTOR,
        json!({
            "action":"add",
            "source_id":"anchor-coordinate",
            "target_id":"overlap-coordinate",
            "relationship":"relates_to"
        }),
        &action,
        None,
    )
    .await;
    mutated(&db, coordinated, "anchor-coordinate").await;
    mutated(&db, coordinated, "overlap-coordinate").await;

    let proceed_annotation = annotation("claim", "anchor-proceed", &["overlap-proceed"], 1);
    insert_call(
        &db,
        "notice-proceed",
        "start_work",
        "proceed-root-a748b2",
        None,
        ACTOR,
        json!({"record_id":"anchor-proceed","action":"claim"}),
        &mature,
        Some(&proceed_annotation),
    )
    .await;
    let proceeded = insert_call(
        &db,
        "proceed-first",
        "update_record",
        "proceed-child-a748b2",
        Some("proceed-root-a748b2"),
        ACTOR,
        json!({"id":"overlap-proceed"}),
        &action,
        None,
    )
    .await;
    mutated(&db, proceeded, "overlap-proceed").await;
    let late_coordination = insert_call(
        &db,
        "proceed-late-coordinate",
        "manage_links",
        "proceed-child-a748b2",
        Some("proceed-root-a748b2"),
        ACTOR,
        json!({
            "action":"add",
            "source_id":"anchor-proceed",
            "target_id":"overlap-proceed",
            "relationship":"relates_to"
        }),
        &timestamp(38),
        None,
    )
    .await;
    mutated(&db, late_coordination, "anchor-proceed").await;

    let none_annotation = annotation("claim", "anchor-none", &["overlap-none"], 1);
    insert_call(
        &db,
        "notice-none",
        "start_work",
        "none-root-a748b2",
        None,
        ACTOR,
        json!({"record_id":"anchor-none","action":"claim"}),
        &mature,
        Some(&none_annotation),
    )
    .await;
    let unrelated = insert_call(
        &db,
        "none-unrelated-run",
        "update_record",
        "unrelated-run-a748b2",
        None,
        ACTOR,
        json!({"id":"anchor-none"}),
        &action,
        None,
    )
    .await;
    mutated(&db, unrelated, "anchor-none").await;
    let cross_account = insert_call(
        &db,
        "none-cross-account",
        "update_record",
        "none-child-a748b2",
        Some("none-root-a748b2"),
        "other-account",
        json!({"id":"overlap-none"}),
        &action,
        None,
    )
    .await;
    mutated(&db, cross_account, "overlap-none").await;

    let pending_annotation = annotation("claim", "anchor-pending", &["overlap-pending"], 1);
    insert_call(
        &db,
        "notice-pending",
        "start_work",
        "pending-root-a748b2",
        None,
        ACTOR,
        json!({"record_id":"anchor-pending","action":"claim"}),
        &timestamp(5),
        Some(&pending_annotation),
    )
    .await;
    let create_annotation = annotation("create", "anchor-create", &["overlap-create"], 3);
    insert_call(
        &db,
        "notice-create",
        "create_record",
        "create-root-a748b2",
        None,
        ACTOR,
        json!({"id":"anchor-create"}),
        &mature,
        Some(&create_annotation),
    )
    .await;
    let intent_annotation = annotation("set_intent", "anchor-intent", &["overlap-intent"], 1);
    insert_call(
        &db,
        "notice-intent",
        "set_intent",
        "intent-root-a748b2",
        None,
        ACTOR,
        json!({"intent":"coordinate"}),
        &mature,
        Some(&intent_annotation),
    )
    .await;

    let result = evaluate(&registry, &db, "own").await;
    assert_eq!(result["availability"]["status"], "partial");
    assert_eq!(result["observation_window_seconds"], 1800);
    assert_eq!(result["emissions"]["notice_bearing_call_count"], 7);
    assert_eq!(
        result["emissions"]["by_surface"],
        json!({
            "claim": 5, "create": 1, "set_intent": 1
        })
    );
    assert_eq!(result["emissions"]["anchor_count"], 7);
    assert_eq!(result["emissions"]["overlap_item_count"], 9);
    assert_eq!(result["emissions"]["disclosed_overlap_item_count"], 7);
    assert_eq!(
        result["claim_outcomes"],
        json!({
            "unit": "mature_notice_bearing_claim_call",
            "mature_denominator": 4,
            "pending_count": 1,
            "released": 1,
            "coordinated": 1,
            "proceeded": 1,
            "no_observed_outcome": 1,
        })
    );
    assert_eq!(result["observations"].as_array().unwrap().len(), 7);
    assert!(result["observations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| {
            item.get("holder_identity").is_none()
                && item.get("holder_intent").is_none()
                && item.get("holder_run_key").is_none()
        }));
}

#[tokio::test]
async fn explicit_root_closure_matures_a_claim_early_and_workspace_scope_is_aggregate_only() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    record(&db, "closed-anchor").await;
    record(&db, "closed-overlap").await;

    registry
        .call(
            db.clone(),
            Caller::local(),
            "set_intent",
            json!({"intent":"close early","run_key":"scout-chair-c748b2"}),
        )
        .await
        .unwrap();
    let closed_annotation = annotation("claim", "closed-anchor", &["closed-overlap"], 1);
    insert_call(
        &db,
        "notice-closed",
        "start_work",
        "scout-chair-c748b2",
        None,
        ACTOR,
        json!({"record_id":"closed-anchor","action":"claim"}),
        &timestamp(5),
        Some(&closed_annotation),
    )
    .await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "close_run",
            json!({"run_key":"scout-chair-c748b2"}),
        )
        .await
        .unwrap();

    let other_annotation = annotation("create", "closed-anchor", &["closed-overlap"], 1);
    insert_call(
        &db,
        "notice-other-account",
        "create_record",
        "other-root-a748b2",
        None,
        "other-account",
        json!({"id":"closed-anchor"}),
        &timestamp(40),
        Some(&other_annotation),
    )
    .await;

    let own = evaluate(&registry, &db, "own").await;
    assert_eq!(own["emissions"]["notice_bearing_call_count"], 1);
    assert_eq!(own["claim_outcomes"]["mature_denominator"], 1);
    assert_eq!(own["claim_outcomes"]["pending_count"], 0);
    assert_eq!(own["claim_outcomes"]["no_observed_outcome"], 1);

    let workspace = evaluate(&registry, &db, "workspace").await;
    assert_eq!(workspace["emissions"]["notice_bearing_call_count"], 2);
    assert!(workspace.get("observations").is_none());
    let serialized = serde_json::to_string(&workspace).unwrap();
    for forbidden in [
        "scout-chair-c748b2".to_owned(),
        "other-root-a748b2".to_owned(),
        record_id("closed-anchor"),
        record_id("closed-overlap"),
        "other-account".to_owned(),
    ] {
        assert!(
            !serialized.contains(&forbidden),
            "workspace leaked {forbidden}"
        );
    }
}

#[tokio::test]
async fn missing_measurement_storage_is_unavailable_not_zero() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let result = evaluate(&registry, &db, "own").await;
    assert_eq!(result["availability"]["status"], "unavailable");
    assert_eq!(result["emissions"], Value::Null);
    assert_eq!(result["claim_outcomes"], Value::Null);
}
