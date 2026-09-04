//! Stage 4 of the tool surface (tools 11–16): history, links, facets —
//! exercised through the registry, the way both transports dispatch.

use native_ce::events::FacetSetPayload;
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::meta::{
    alias_value, create_vocabulary, promote_value, propose_value,
    propose_value_with_kind_metadata_as, propose_value_with_metadata_as, seed_pack_schema_config,
    write_user_schema_config, KindMetadataV1, SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::store::{create_record, set_facet, update_record};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    // Facet-resolution fixtures install their own pack and vocabularies.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    db
}

async fn govern_kind(db: &Db, record_type: &str, token: &str) {
    let vocabulary = format!("kind:{record_type}");
    let vocabulary_id = format!("voc:kind:{record_type}");
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vocabularies WHERE id = ?)")
        .bind(&vocabulary_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    if !exists {
        create_vocabulary(db, &vocabulary, Some(&vocabulary_id))
            .await
            .unwrap();
    }
    let id = propose_value_with_kind_metadata_as(
        db,
        &vocabulary,
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string()
}

fn facet(key: &str, value: &str) -> FacetSetPayload {
    FacetSetPayload {
        key: key.into(),
        value: Some(value.into()),
        vocab_ref: None,
        as_of: None,
        observation_only: false,
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stage4_tools_register_alongside_builtins() {
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    let names: Vec<&str> = registry.specs().map(|t| t.name.as_str()).collect();
    for tool in [
        "get_history",
        "whats_changed",
        "manage_links",
        "manage_facet_observations",
        "resolve_facets",
        "suggest_facet_values",
    ] {
        assert!(names.contains(&tool), "missing {tool}");
    }
}

// ---------------------------------------------------------------------------
// Tool 11 — get_history
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_history_defaults_to_metadata_and_full_preserves_parsed_payloads() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "first" }),
    )
    .await
    .unwrap();
    update_record(&db, &id, json!({ "name": "second" }))
        .await
        .unwrap();
    let other = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "noise" }),
    )
    .await
    .unwrap();

    let out = call(&registry, &db, "get_history", json!({ "record_id": id })).await;
    let events = out["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["type"], "record.created");
    assert!(events[0].get("payload").is_none());
    assert_eq!(events[0]["payload_omitted"], true);
    assert_eq!(
        events[0]["changed_fields"],
        json!(["home_id", "kind", "name", "type"])
    );
    assert_eq!(events[1]["type"], "record.updated");
    assert!(events[1].get("payload").is_none());
    assert_eq!(events[1]["changed_fields"], json!(["name"]));
    assert_eq!(out["representation"]["detail"], "metadata");
    assert_eq!(out["representation"]["omitted_field"], "events[].payload");
    assert_eq!(
        out["representation"]["full_detail"],
        json!({ "detail": "full" })
    );
    assert_eq!(out["next_after_local_seq"], Value::Null);

    let full = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "detail": "full" }),
    )
    .await;
    assert_eq!(full["events"][0]["payload"]["name"], "first");
    assert_eq!(full["events"][1]["payload"]["name"], "second");
    assert_eq!(full["representation"]["detail"], "full");
    assert_eq!(
        events[0]["payload_json_utf8_bytes"],
        serde_json::to_vec(&full["events"][0]["payload"])
            .unwrap()
            .len()
    );

    // Keyset paging: one event per page, cursor threads through.
    let page1 = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "limit": 1 }),
    )
    .await;
    assert_eq!(page1["events"].as_array().unwrap().len(), 1);
    let cursor = page1["next_after_local_seq"].as_i64().unwrap();
    let page2 = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "after_local_seq": cursor, "limit": 1 }),
    )
    .await;
    assert_eq!(page2["events"][0]["type"], "record.updated");
    assert_eq!(page2["next_after_local_seq"], Value::Null);

    // Whole-log mode sees every record's events.
    let all = call(&registry, &db, "get_history", json!({})).await;
    assert_eq!(all["events"].as_array().unwrap().len(), 5);
    assert!(all["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["record_id"] == json!(other)));

    // Unknown arguments are a caller bug, surfaced.
    let err = call_err(&registry, &db, "get_history", json!({ "recordid": "x" })).await;
    assert!(err.contains("invalid arguments for get_history"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "detail": "summary" }),
    )
    .await;
    assert!(err.contains("invalid arguments for get_history"), "{err}");
}

#[tokio::test]
async fn get_history_metadata_keeps_a_long_revision_stream_agent_sized() {
    let db = db().await;
    let registry = registry();
    let body = |revision: usize| format!("revision-{revision}:{}", "x".repeat(16 * 1024));
    let id = create_record(
        &db,
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "long history",
            "body": body(0),
        }),
    )
    .await
    .unwrap();
    for revision in 1..77 {
        update_record(&db, &id, json!({ "body": body(revision) }))
            .await
            .unwrap();
    }

    let metadata = call(&registry, &db, "get_history", json!({ "record_id": id })).await;
    let metadata_json = serde_json::to_string(&metadata).unwrap();
    assert_eq!(metadata["events"].as_array().unwrap().len(), 77);
    assert!(metadata["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event.get("payload").is_none()));
    assert!(!metadata_json.contains("revision-76:"));
    assert!(
        metadata_json.len() < 64 * 1024,
        "{} bytes",
        metadata_json.len()
    );

    let full = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "detail": "full" }),
    )
    .await;
    let full_json = serde_json::to_string(&full).unwrap();
    assert!(full_json.len() > 1_000_000, "{} bytes", full_json.len());
    assert!(full_json.contains("revision-76:"));
    for (metadata_event, full_event) in metadata["events"]
        .as_array()
        .unwrap()
        .iter()
        .zip(full["events"].as_array().unwrap())
    {
        assert_eq!(
            metadata_event["payload_json_utf8_bytes"],
            serde_json::to_vec(&full_event["payload"]).unwrap().len(),
            "metadata size must describe the same post-redaction payload returned by full detail"
        );
    }
}

#[tokio::test]
async fn get_history_filters_an_exact_run_without_confusing_caller_correlation() {
    const CALLER_RUN: &str = "scout-chair-a748b2";
    const TARGET_RUN: &str = "heron-river-c748b2";
    const UNSEEN_RUN: &str = "scout-bread-g748b2";

    let db = db().await;
    let registry = registry();
    let target_id = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "target", "run_key": TARGET_RUN }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": target_id, "summary": "second target event", "run_key": TARGET_RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "caller noise", "run_key": CALLER_RUN }),
    )
    .await;

    // `run_key` is lifted as caller context before handler deserialization;
    // `for_run` must survive independently as the history selector.
    let first = call(
        &registry,
        &db,
        "get_history",
        json!({ "run_key": CALLER_RUN, "for_run": TARGET_RUN, "limit": 1 }),
    )
    .await;
    assert_eq!(first["run_context"]["run_key"], CALLER_RUN);
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    assert_eq!(first["events"][0]["run_key"], TARGET_RUN);
    let cursor = first["next_after_local_seq"].as_i64().unwrap();

    let second = call(
        &registry,
        &db,
        "get_history",
        json!({
            "run_key": CALLER_RUN,
            "for_run": TARGET_RUN,
            "after_local_seq": cursor,
            "limit": 1
        }),
    )
    .await;
    assert_eq!(second["events"].as_array().unwrap().len(), 1);
    assert!(second["events"][0]["local_seq"].as_i64().unwrap() > cursor);
    assert_eq!(second["events"][0]["run_key"], TARGET_RUN);
    assert_eq!(second["next_after_local_seq"], Value::Null);

    let unseen = call(
        &registry,
        &db,
        "get_history",
        json!({ "run_key": CALLER_RUN, "for_run": UNSEEN_RUN }),
    )
    .await;
    assert!(unseen["events"].as_array().unwrap().is_empty());
    assert_eq!(unseen["next_after_local_seq"], Value::Null);

    for malformed in ["new", "not-a-key"] {
        let err = call_err(
            &registry,
            &db,
            "get_history",
            json!({ "run_key": CALLER_RUN, "for_run": malformed }),
        )
        .await;
        assert!(err.contains("invalid for_run"), "{malformed}: {err}");
    }
    let err = call_err(
        &registry,
        &db,
        "get_history",
        json!({ "run_key": CALLER_RUN, "for_run": null }),
    )
    .await;
    assert!(err.contains("invalid arguments for get_history"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "get_history",
        json!({ "run_key": CALLER_RUN, "include_child_runs": true }),
    )
    .await;
    assert!(err.contains("include_child_runs requires for_run"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn get_history_recurses_through_child_runs_and_composes_with_record_filter() {
    const ROOT_RUN: &str = "heron-river-c748b2";
    const CHILD_RUN: &str = "scout-chair-a748b2";
    const GRANDCHILD_RUN: &str = "pilot-river-b748b2";
    const UNRELATED_RUN: &str = "envoy-dune-h748b2";

    let db = db().await;
    let registry = registry();
    let target_id = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "root target", "run_key": ROOT_RUN }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": target_id,
            "summary": "child event",
            "run_key": CHILD_RUN,
            "parent_key": ROOT_RUN
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": target_id,
            "summary": "grandchild event",
            "run_key": GRANDCHILD_RUN,
            "parent_key": CHILD_RUN
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "same root, other record", "run_key": ROOT_RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "name": "unrelated",
            "run_key": UNRELATED_RUN
        }),
    )
    .await;

    let exact = call(
        &registry,
        &db,
        "get_history",
        json!({ "run_key": UNRELATED_RUN, "for_run": ROOT_RUN }),
    )
    .await;
    let exact_events = exact["events"].as_array().unwrap();
    assert_eq!(exact_events.len(), 2);
    assert!(exact_events
        .iter()
        .all(|event| event["run_key"] == ROOT_RUN));

    let tree = call(
        &registry,
        &db,
        "get_history",
        json!({
            "run_key": UNRELATED_RUN,
            "for_run": ROOT_RUN,
            "include_child_runs": true
        }),
    )
    .await;
    let tree_events = tree["events"].as_array().unwrap();
    assert_eq!(tree_events.len(), 4);
    assert!(tree_events.windows(2).all(
        |pair| pair[0]["local_seq"].as_i64().unwrap() < pair[1]["local_seq"].as_i64().unwrap()
    ));
    assert_eq!(tree_events[0]["run_key"], ROOT_RUN);
    assert_eq!(tree_events[0]["parent_key"], Value::Null);
    assert_eq!(tree_events[1]["run_key"], CHILD_RUN);
    assert_eq!(tree_events[1]["parent_key"], ROOT_RUN);
    assert_eq!(tree_events[2]["run_key"], GRANDCHILD_RUN);
    assert_eq!(tree_events[2]["parent_key"], CHILD_RUN);
    assert!(tree_events
        .iter()
        .all(|event| event["run_key"] != UNRELATED_RUN));

    let intersection = call(
        &registry,
        &db,
        "get_history",
        json!({
            "record_id": target_id,
            "run_key": UNRELATED_RUN,
            "for_run": ROOT_RUN,
            "include_child_runs": true
        }),
    )
    .await;
    let intersection_events = intersection["events"].as_array().unwrap();
    assert_eq!(intersection_events.len(), 3);
    assert!(intersection_events
        .iter()
        .all(|event| event["record_id"] == target_id));
    db.close().await;
}

#[tokio::test]
async fn get_run_activity_is_per_run_aggregate_only_and_degrades_to_empty() {
    const ROOT_RUN: &str = "heron-river-c748b2";
    const CHILD_RUN: &str = "scout-chair-a748b2";
    const SECRET_QUERY: &str = "failed-private-query-that-must-never-escape";

    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "name": "activity target",
            "run_key": ROOT_RUN,
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "search",
        json!({ "query": "activity", "run_key": ROOT_RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "search",
        json!({ "query": SECRET_QUERY, "run_key": ROOT_RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "search",
        json!({
            "query": "activity",
            "run_key": CHILD_RUN,
            "parent_key": ROOT_RUN,
        }),
    )
    .await;
    // A later assertion must not replace the first lineage edge surfaced by
    // the aggregate. This run deliberately has no content event of its own.
    let missing_history = call_err(
        &registry,
        &db,
        "get_history",
        json!({
            "record_id": "missing-record",
            "run_key": CHILD_RUN,
            "parent_key": "pilot-river-b748b2",
        }),
    )
    .await;
    assert!(
        missing_history.contains("get_history: record missing-record does not exist"),
        "{missing_history}"
    );

    // Read-log touches deliberately have no record foreign key: a record may
    // disappear after a real interaction. The aggregate must suppress that
    // dangling correlation rather than fail or disclose its existence.
    let root_search_seq: i64 = sqlx::query_scalar(
        "SELECT MIN(seq) FROM read_log_calls WHERE run_key = ? AND tool = 'search'",
    )
    .bind(ROOT_RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO read_log_touches(call_seq,record_id,interaction,result_rank)
         VALUES(?,'missing-record','opened',NULL)",
    )
    .bind(root_search_seq)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let exact = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": ROOT_RUN, "run_key": CHILD_RUN }),
    )
    .await;
    let exact_rows = exact["read_activity"].as_array().unwrap();
    assert_eq!(exact["for_run"], ROOT_RUN);
    assert_eq!(exact["include_child_runs"], false);
    assert_eq!(exact["availability"]["status"], "available");
    assert!(exact["availability"]["reason"].is_null());
    assert_eq!(exact["availability"]["visibility_filtered"], true);
    assert_eq!(exact_rows.len(), 1);
    assert_eq!(exact_rows[0]["run_key"], ROOT_RUN);
    assert_eq!(exact_rows[0]["parent_key"], Value::Null);
    assert_eq!(exact_rows[0]["searches"], 2);
    assert!(exact_rows[0]["surfaced"].as_i64().unwrap() >= 1);
    assert_eq!(exact_rows[0]["opened"], 0);
    assert!(!exact.to_string().contains(SECRET_QUERY));
    let exact_text = render::render("get_run_activity", &exact).unwrap();
    assert!(exact_text.contains(ROOT_RUN), "{exact_text}");
    assert!(
        exact_text.contains(&serde_json::to_string(&exact_rows[0]).unwrap()),
        "{exact_text}"
    );
    assert!(!exact_text.contains(SECRET_QUERY), "{exact_text}");

    let tree = call(
        &registry,
        &db,
        "get_run_activity",
        json!({
            "for_run": ROOT_RUN,
            "include_child_runs": true,
            "run_key": ROOT_RUN,
        }),
    )
    .await;
    let tree_rows = tree["read_activity"].as_array().unwrap();
    assert_eq!(tree["for_run"], ROOT_RUN);
    assert_eq!(tree["include_child_runs"], true);
    assert_eq!(tree["availability"]["status"], "available");
    assert_eq!(tree["availability"]["visibility_filtered"], true);
    assert_eq!(tree_rows.len(), 2);
    assert_eq!(tree_rows[0]["run_key"], ROOT_RUN);
    assert_eq!(tree_rows[1]["run_key"], CHILD_RUN);
    assert_eq!(tree_rows[1]["parent_key"], ROOT_RUN);
    assert_eq!(tree_rows[1]["searches"], 1);
    for row in tree_rows {
        assert_eq!(row.as_object().unwrap().len(), 6);
    }
    let tree_text = render::render("get_run_activity", &tree).unwrap();
    assert!(tree_text.contains(ROOT_RUN), "{tree_text}");
    assert!(tree_text.contains(CHILD_RUN), "{tree_text}");
    for row in tree_rows {
        assert!(
            tree_text.contains(&serde_json::to_string(row).unwrap()),
            "{tree_text}"
        );
    }

    sqlx::query("DROP TABLE read_log_touches")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query("DROP TABLE read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let without_log = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": ROOT_RUN, "include_child_runs": true }),
    )
    .await;
    assert_eq!(without_log["read_activity"], json!([]));
    assert_eq!(without_log["for_run"], ROOT_RUN);
    assert_eq!(without_log["include_child_runs"], true);
    assert_eq!(without_log["availability"]["status"], "unavailable");
    assert_eq!(
        without_log["availability"]["reason"],
        "read_log_unavailable"
    );
    assert!(without_log["availability"]["visibility_filtered"].is_null());
    let unavailable_text = render::render("get_run_activity", &without_log).unwrap();
    assert!(
        unavailable_text.contains("read_log_unavailable"),
        "{unavailable_text}"
    );
    assert!(
        !unavailable_text.contains("No aggregate read activity"),
        "{unavailable_text}"
    );

    let malformed = call_err(
        &registry,
        &db,
        "get_run_activity",
        json!({ "for_run": "new" }),
    )
    .await;
    assert!(malformed.contains("invalid for_run"), "{malformed}");
    db.close().await;
}

// ---------------------------------------------------------------------------
// Historical get_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_record_as_of_replays_the_prefix() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "v1 name" }),
    )
    .await
    .unwrap();
    update_record(&db, &id, json!({ "name": "v2 name" }))
        .await
        .unwrap();
    set_facet(&db, &id, facet("lifecycle", "in_progress"))
        .await
        .unwrap();
    let created_seq: i64 =
        sqlx::query_scalar("SELECT MIN(seq) FROM content_events WHERE record_id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let latest_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();

    let v1 = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "as_of": { "content_seq": created_seq } }),
    )
    .await;
    assert_eq!(v1["records"][0]["name"], "v1 name");
    assert_eq!(
        v1["records"][0]["lifecycle_interpretation"]["status"],
        "absent"
    );
    assert!(v1["records"][0].get("lifecycle").is_none());
    assert_eq!(v1["resolved_content_seq"], created_seq);

    let v3 = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "as_of": { "content_seq": latest_seq } }),
    )
    .await;
    assert_eq!(v3["records"][0]["name"], "v2 name");
    assert_eq!(
        v3["records"][0]["lifecycle_interpretation"]["status"],
        "unclassified"
    );
    assert_eq!(
        v3["records"][0]["lifecycle_interpretation"]["raw"],
        "in_progress"
    );

    // Before the record existed: no state to reconstruct.
    let before_other = latest_seq;
    let other = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "late" }),
    )
    .await
    .unwrap();
    let missing = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [other], "as_of": { "content_seq": before_other } }),
    )
    .await;
    assert_eq!(missing["records"][0]["status"], "not_found");

    let empty = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "as_of": { "content_seq": 0 } }),
    )
    .await;
    assert_eq!(empty["records"][0]["status"], "not_found");
}

// ---------------------------------------------------------------------------
// Tool 13 — manage_links
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manage_links_adds_lists_and_removes() {
    let db = db().await;
    let registry = registry();
    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "task" }),
    )
    .await
    .unwrap();
    let goal = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "goal" }),
    )
    .await
    .unwrap();

    let added = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": task, "target_id": goal,
                "relationship": "implements", "note": "stage 4 test" }),
    )
    .await;
    assert_eq!(added["action"], "add");
    assert_eq!(added["format"], "native.manage-links-write.v1");
    assert_eq!(added["status"], "added");
    assert!(added["previous_seq"].as_i64().is_some());
    assert_eq!(added["write_receipt"]["kind"], "relationship_assertion");
    for key in [
        "relationship_origin_db_id",
        "relationship_id",
        "assertion_id",
        "action_attestation_id",
        "output_events",
    ] {
        assert_eq!(added["write_receipt"][key], added[key], "{key}: {added}");
    }
    assert_eq!(added["output_events"].as_array().unwrap().len(), 2);
    let rendered_added = render::render("manage_links", &added).unwrap();
    assert!(
        rendered_added.starts_with("Link add write committed via \"relationship_assertion\"."),
        "{rendered_added}"
    );
    for key in [
        "source_id",
        "target_id",
        "relationship_id",
        "assertion_id",
        "action_attestation_id",
    ] {
        let expected = added[key].as_str().unwrap();
        assert!(
            rendered_added.contains(expected),
            "missing {key}={expected}: {rendered_added}"
        );
    }
    for event in added["output_events"].as_array().unwrap() {
        assert!(
            rendered_added.contains(event["event_id"].as_str().unwrap()),
            "missing output event: {rendered_added}"
        );
    }

    // Both directions from the list action.
    let from_task = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": task }),
    )
    .await;
    assert_eq!(from_task["action"], "list");
    assert_eq!(from_task["format"], "native.manage-links-list.v1");
    assert_eq!(from_task["viewer_relative"], true);
    assert_eq!(from_task["query_basis"], "live_at_each_page_read");
    assert_eq!(
        from_task["scope"],
        "opposite_endpoint_viewable_at_read_time"
    );
    assert_eq!(from_task["limit"], 50);
    assert!(from_task["cursor"].is_null());
    assert!(from_task.get("candidate_window_returned").is_none());
    assert!(from_task.get("candidates_evaluated").is_none());
    assert_eq!(from_task["returned"], 1);
    assert_eq!(from_task["has_more"], false);
    assert!(from_task["next_cursor"].is_null());
    assert!(from_task["next_call"].is_null());
    assert_eq!(from_task["links_out"].as_array().unwrap().len(), 1);
    assert_eq!(from_task["links_out"][0]["source_id"], task);
    assert_eq!(from_task["links_out"][0]["target_id"], goal);
    assert_eq!(from_task["links_out"][0]["relationship"], "implements");
    assert_eq!(from_task["links_out"][0]["note"], "stage 4 test");
    assert!(from_task["links_out"][0]["id"].as_str().is_some());
    assert!(from_task["links_out"][0]["created_at"].as_str().is_some());
    assert!(from_task["links_in"].as_array().unwrap().is_empty());
    let rendered_from_task = render::render("manage_links", &from_task).unwrap();
    assert!(
        rendered_from_task.starts_with("Link list returned 1 caller-visible row(s)"),
        "{rendered_from_task}"
    );
    for expected in [
        "Live page controls:",
        "Rows are authorization-filtered by opposite-endpoint visibility at this read",
        "No continuation cursor was issued; this live candidate scan is exhausted.",
        "- Link row:",
        task.as_str(),
        goal.as_str(),
        "implements",
        "stage 4 test",
    ] {
        assert!(
            rendered_from_task.contains(expected),
            "missing {expected}: {rendered_from_task}"
        );
    }
    let from_goal = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": goal }),
    )
    .await;
    assert_eq!(from_goal["action"], "list");
    assert_eq!(from_goal["format"], "native.manage-links-list.v1");
    assert_eq!(from_goal["returned"], 1);
    assert_eq!(from_goal["links_in"].as_array().unwrap().len(), 1);
    assert_eq!(from_goal["links_in"][0]["source_id"], task);
    assert_eq!(from_goal["links_in"][0]["target_id"], goal);

    // A duplicate add is an accepted operation with a new durable support
    // assertion, while the compatibility projection remains one link.
    let duplicate = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": task, "target_id": goal,
                "relationship": "implements" }),
    )
    .await;
    assert_eq!(duplicate["action"], "add");
    assert_eq!(duplicate["status"], "added");
    assert_eq!(duplicate["write_receipt"]["kind"], "relationship_assertion");
    assert_eq!(
        duplicate["relationship_id"], added["relationship_id"],
        "a repeated accepted operation supports the same relationship"
    );
    assert_ne!(duplicate["assertion_id"], added["assertion_id"]);
    assert_ne!(
        duplicate["action_attestation_id"],
        added["action_attestation_id"]
    );
    assert_eq!(duplicate["output_events"].as_array().unwrap().len(), 1);
    let rendered_duplicate = render::render("manage_links", &duplicate).unwrap();
    assert!(
        rendered_duplicate.starts_with("Link add write committed via \"relationship_assertion\"."),
        "{rendered_duplicate}"
    );
    for key in ["relationship_id", "assertion_id", "action_attestation_id"] {
        assert!(
            rendered_duplicate.contains(duplicate[key].as_str().unwrap()),
            "missing {key}: {rendered_duplicate}"
        );
    }
    assert!(
        rendered_duplicate.contains(duplicate["output_events"][0]["event_id"].as_str().unwrap())
    );
    let still_one = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": task }),
    )
    .await;
    assert_eq!(still_one["action"], "list");
    assert_eq!(still_one["returned"], 1);
    assert_eq!(still_one["links_out"].as_array().unwrap().len(), 1);

    let second_goal = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "second goal" }),
    )
    .await
    .unwrap();
    let second_added = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "add", "source_id": task, "target_id": second_goal,
                "relationship": "relates_to" }),
    )
    .await;
    assert_eq!(second_added["action"], "add");
    let first_page = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": task, "limit": 1 }),
    )
    .await;
    assert_eq!(first_page["action"], "list");
    assert_eq!(first_page["limit"], 1);
    assert_eq!(first_page["returned"], 1);
    assert_eq!(first_page["has_more"], true);
    let cursor = first_page["next_cursor"].as_str().unwrap();
    assert_eq!(first_page["next_call"]["action"], "list");
    assert_eq!(first_page["next_call"]["record_id"], task);
    assert_eq!(first_page["next_call"]["limit"], 1);
    assert_eq!(first_page["next_call"]["cursor"], cursor);
    let rendered_first_page = render::render("manage_links", &first_page).unwrap();
    for expected in [
        "Link list returned 1 caller-visible row(s)",
        "Live page controls:",
        "Next manage_links request:",
        cursor,
        "not a claim about inaccessible links or a frozen cross-page snapshot",
    ] {
        assert!(
            rendered_first_page.contains(expected),
            "missing {expected}: {rendered_first_page}"
        );
    }
    let second_page = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": task, "limit": 1, "cursor": cursor }),
    )
    .await;
    assert_eq!(second_page["action"], "list");
    assert_eq!(second_page["cursor"], cursor);
    assert_eq!(second_page["returned"], 1);
    assert_eq!(second_page["has_more"], false);
    assert!(second_page["next_cursor"].is_null());
    let rendered_second_page = render::render("manage_links", &second_page).unwrap();
    assert!(
        rendered_second_page
            .contains("No continuation cursor was issued; this live candidate scan is exhausted."),
        "{rendered_second_page}"
    );
    let paged_targets = [
        first_page["links_out"][0]["target_id"].as_str().unwrap(),
        second_page["links_out"][0]["target_id"].as_str().unwrap(),
    ];
    assert!(paged_targets.contains(&goal.as_str()));
    assert!(paged_targets.contains(&second_goal.as_str()));
    let second_removed = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "remove", "source_id": task, "target_id": second_goal,
                "relationship": "relates_to" }),
    )
    .await;
    assert_eq!(second_removed["action"], "remove");

    let removed = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "remove", "source_id": task, "target_id": goal,
                "relationship": "implements" }),
    )
    .await;
    assert_eq!(removed["action"], "remove");
    assert_eq!(removed["format"], "native.manage-links-write.v1");
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["write_receipt"]["kind"], "relationship_assertion");
    for key in [
        "relationship_origin_db_id",
        "relationship_id",
        "assertion_id",
        "action_attestation_id",
        "output_events",
    ] {
        assert_eq!(
            removed["write_receipt"][key], removed[key],
            "{key}: {removed}"
        );
    }
    assert_eq!(removed["relationship_id"], added["relationship_id"]);
    assert_eq!(removed["output_events"].as_array().unwrap().len(), 1);
    let rendered_removed = render::render("manage_links", &removed).unwrap();
    assert!(
        rendered_removed.starts_with("Link remove write committed via \"relationship_assertion\"."),
        "{rendered_removed}"
    );
    for key in ["relationship_id", "assertion_id", "action_attestation_id"] {
        assert!(
            rendered_removed.contains(removed[key].as_str().unwrap()),
            "missing {key}: {rendered_removed}"
        );
    }
    assert!(rendered_removed.contains(removed["output_events"][0]["event_id"].as_str().unwrap()));
    let after = call(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": task }),
    )
    .await;
    assert_eq!(after["action"], "list");
    assert_eq!(after["returned"], 0);
    assert!(after["links_out"].as_array().unwrap().is_empty());

    let err = call_err(
        &registry,
        &db,
        "manage_links",
        json!({ "action": "list", "record_id": "nope" }),
    )
    .await;
    assert_eq!(err, "record nope does not exist");

    let err = call_err(&registry, &db, "manage_links", json!({ "action": "merge" })).await;
    assert!(err.contains("invalid arguments for manage_links"), "{err}");

    let content_rebuild = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(content_rebuild.equal, "{content_rebuild:#?}");
    let relationship_rebuild = native_ce::conformance::rebuild_and_diff_relationship(&db)
        .await
        .unwrap();
    assert!(relationship_rebuild.equal, "{relationship_rebuild:#?}");
}

// ---------------------------------------------------------------------------
// Tools 15–16 — resolve_facets / suggest_facet_values
// ---------------------------------------------------------------------------

/// Pack shapes WorkItem with a vocab-governed facet + a values-listed one; user
/// widens the values-listed one. The cascade fixture tools 14 and 15 share.
async fn seed_shapes(db: &Db) {
    seed_pack_schema_config(
        db,
        "@native/recommended",
        json!({ "shapes": {
            "WorkItem": { "facets": { "confidence": { "vocab": "confidence" },
                                  "effort": { "values": ["s", "m", "l"] } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        db,
        json!({ "shapes": {
            "WorkItem": { "facets": { "effort": { "values": ["s", "m", "l", "xl"] } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn resolve_facets_returns_spine_cascade_and_values() {
    let db = db().await;
    let registry = registry();
    seed_shapes(&db).await;
    create_vocabulary(&db, "confidence", None).await.unwrap();
    let likely = propose_value(&db, "confidence", "likely", None)
        .await
        .unwrap();
    promote_value(&db, &likely).await.unwrap();

    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "task" }),
    )
    .await
    .unwrap();
    set_facet(&db, &task, facet("lifecycle", "in_progress"))
        .await
        .unwrap();
    set_facet(&db, &task, facet("confidence", "likely"))
        .await
        .unwrap();

    let by_record = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": task }),
    )
    .await;
    assert_eq!(by_record["type"], "WorkItem");
    assert_eq!(by_record["spine"]["lifecycle"], "in_progress");
    assert_eq!(by_record["spine"]["persistence"], "enduring");
    assert_eq!(by_record["archived"], false);
    // Resolved shape carries the user override; pack view stays pristine.
    assert_eq!(
        by_record["shape"]["effort"]["values"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        by_record["pack_shape"]["effort"]["values"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // Current open values ride along (spine facets are columns, not values).
    let values = by_record["values"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["key"], "confidence");

    let by_type = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "type": "WorkItem" }),
    )
    .await;
    assert_eq!(
        by_type["spine"],
        json!(["lifecycle", "owner", "persistence", "maturity"])
    );
    assert!(by_type.get("values").is_none());

    let err = call_err(&registry, &db, "resolve_facets", json!({})).await;
    assert!(err.contains("exactly one of record_id or type"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": task, "type": "WorkItem" }),
    )
    .await;
    assert!(err.contains("exactly one of record_id or type"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": "nope" }),
    )
    .await;
    assert_eq!(err, "record nope does not exist");
}

#[tokio::test]
async fn resolve_facets_merges_kind_shapes_with_pack_floor_and_provenance() {
    let db = db().await;
    let registry = registry();
    govern_kind(&db, "Outcome", "objective").await;
    govern_kind(&db, "Outcome", "key_result").await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": {
            "Outcome": {
                "facets": {
                    "confidence": { "required": false, "source": "pack-base" }
                }
            },
            "Outcome:key_result": {
                "facets": {
                    "confidence": { "required": true, "source": "pack-kind" },
                    "effort": { "values": ["s", "m", "l"], "source": "pack-kind" }
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": {
            "Outcome": {
                "facets": {
                    "confidence": { "required": false, "source": "user-base" }
                }
            },
            "Outcome:key_result": {
                "facets": {
                    "effort": { "values": ["xs", "s", "m", "l"], "source": "user-kind" }
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let goal = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "key_result", "name": "Ship it" }),
    )
    .await
    .unwrap();

    let by_record = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": goal }),
    )
    .await;
    assert_eq!(by_record["kind"], "key_result");
    assert_eq!(by_record["shape"]["confidence"]["source"], "pack-kind");
    assert_eq!(by_record["shape"]["effort"]["source"], "user-kind");
    // The comparison view is the pack's base ⊕ kind floor, not just pack:Outcome.
    assert_eq!(by_record["pack_shape"]["confidence"]["source"], "pack-kind");
    assert_eq!(
        by_record["provenance"],
        json!({
            "confidence": "pack:Outcome:key_result",
            "effort": "user:Outcome:key_result"
        })
    );

    // Type-only resolution stays base-only, while advertising the available
    // kind-specific shapes as a separate response field.
    let base = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "type": "Outcome" }),
    )
    .await;
    assert_eq!(base["shape"]["confidence"]["source"], "user-base");
    assert!(base["shape"].get("effort").is_none());
    assert_eq!(base["kind_shapes"], json!(["key_result"]));
    assert_eq!(base["provenance"]["confidence"], "user:Outcome");

    let by_kind = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "type": "Outcome", "kind": "key_result" }),
    )
    .await;
    assert_eq!(by_kind["shape"], by_record["shape"]);
    assert_eq!(by_kind["pack_shape"], by_record["pack_shape"]);
    assert!(by_kind.get("kind_shapes").is_none());
}

#[tokio::test]
async fn suggest_facet_values_lists_active_alias_resolved_values() {
    let db = db().await;
    let registry = registry();
    seed_shapes(&db).await;
    create_vocabulary(&db, "confidence", None).await.unwrap();
    let likely = propose_value(&db, "confidence", "likely", None)
        .await
        .unwrap();
    let probable = propose_value(&db, "confidence", "probable", None)
        .await
        .unwrap();
    let speculative = propose_value(&db, "confidence", "speculative", None)
        .await
        .unwrap();
    promote_value(&db, &likely).await.unwrap();
    promote_value(&db, &probable).await.unwrap();
    // Aliasing deprecates the alias row — so "probable" drops out of the
    // active listing and "likely" is the one suggestable value.
    alias_value(&db, &probable, &likely).await.unwrap();
    // `speculative` stays proposed — must not be suggested.
    let _ = speculative;

    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "task" }),
    )
    .await
    .unwrap();

    let out = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "record_id": task, "facet_key": "confidence" }),
    )
    .await;
    assert_eq!(out["vocabulary"]["name"], "confidence");
    let suggestions = out["suggestions"].as_array().unwrap();
    assert_eq!(suggestions.len(), 1); // active only: no proposed, no deprecated alias
    assert_eq!(suggestions[0]["value"], "likely");

    // A facet with no governing vocabulary is an empty answer, not an error.
    let none = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "type": "WorkItem", "facet_key": "effort" }),
    )
    .await;
    assert_eq!(none["vocabulary"], Value::Null);
    assert!(none["suggestions"].as_array().unwrap().is_empty());

    let err = call_err(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "facet_key": "confidence" }),
    )
    .await;
    assert!(err.contains("exactly one of record_id or type"), "{err}");
}

#[tokio::test]
async fn suggest_facet_values_returns_ordinal_order_and_terminality() {
    let db = db().await;
    let registry = registry();
    seed_shapes(&db).await;
    create_vocabulary(&db, "confidence", None).await.unwrap();
    let won = propose_value_with_metadata_as(
        &db,
        "confidence",
        "won",
        None,
        300.0,
        VocabularyValueTerminality::TerminalPositive,
        None,
    )
    .await
    .unwrap();
    let lead = propose_value_with_metadata_as(
        &db,
        "confidence",
        "lead",
        None,
        100.0,
        VocabularyValueTerminality::Open,
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &won).await.unwrap();
    promote_value(&db, &lead).await.unwrap();

    let out = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "type": "WorkItem", "facet_key": "confidence" }),
    )
    .await;
    assert_eq!(out["suggestions"][0]["value"], "lead");
    assert_eq!(out["suggestions"][0]["ordinal"], 100.0);
    assert_eq!(out["suggestions"][0]["terminality"], "open");
    assert_eq!(out["suggestions"][1]["value"], "won");
    assert_eq!(out["suggestions"][1]["terminality"], "terminal_positive");
}

#[tokio::test]
async fn work_item_lifecycle_suggestions_are_exact_ordered_and_kind_isolated() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Legacy task bearer" }),
    )
    .await
    .unwrap();
    let epic = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "Legacy epic bearer" }),
    )
    .await
    .unwrap();
    let expected = json!(["open", "in_progress", "blocked", "completed", "closed"]);

    for arguments in [
        json!({ "record_id": task, "facet_key": "lifecycle" }),
        json!({ "record_id": epic, "facet_key": "lifecycle" }),
        json!({ "type": "WorkItem", "kind": "task", "facet_key": "lifecycle" }),
        json!({ "type": "WorkItem", "kind": "epic", "facet_key": "lifecycle" }),
    ] {
        let out = call(&registry, &db, "suggest_facet_values", arguments).await;
        let tokens = out["suggestions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["value"].clone())
            .collect::<Vec<_>>();
        assert_eq!(Value::Array(tokens), expected);
    }

    for arguments in [
        json!({ "type": "WorkItem", "facet_key": "lifecycle" }),
        json!({ "type": "Outcome", "kind": "target", "facet_key": "lifecycle" }),
    ] {
        let out = call(&registry, &db, "suggest_facet_values", arguments).await;
        assert!(out["suggestions"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn suggest_facet_values_uses_explicit_or_record_kind() {
    let db = db().await;
    let registry = registry();
    govern_kind(&db, "WorkItem", "chore").await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": {
            "WorkItem": {
                "facets": { "confidence": { "vocab": "confidence" } }
            },
            "WorkItem:chore": {
                "facets": { "confidence": { "vocab": "chore-confidence" } }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    for vocabulary in ["confidence", "chore-confidence"] {
        create_vocabulary(&db, vocabulary, None).await.unwrap();
        let value = propose_value(&db, vocabulary, vocabulary, None)
            .await
            .unwrap();
        promote_value(&db, &value).await.unwrap();
    }
    let chore = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "chore", "name": "task" }),
    )
    .await
    .unwrap();

    let by_type = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "type": "WorkItem", "kind": "chore", "facet_key": "confidence" }),
    )
    .await;
    assert_eq!(by_type["kind"], "chore");
    assert_eq!(by_type["vocabulary"]["name"], "chore-confidence");

    let by_record = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({ "record_id": chore, "facet_key": "confidence" }),
    )
    .await;
    assert_eq!(by_record["kind"], "chore");
    assert_eq!(by_record["vocabulary"]["name"], "chore-confidence");
}
