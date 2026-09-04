//! Acceptance coverage for typed historical structured reads.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

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
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap_err()
        .to_string()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn head(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn all_structured_reads_share_one_pinned_historical_projection() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "a50f0000-0000-4000-8000-000000000001", "type": "Collection", "kind": "folder", "name": "Old" }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "a50f0000-0000-4000-8000-000000000002", "type": "Collection", "kind": "folder", "name": "New" }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000003",
            "type": "WorkItem",
            "kind": "x-historical-kind",
            "name": "Before",
            "home_id": "a50f0000-0000-4000-8000-000000000001",
            "facets": { "confidence": "tentative" }
        }),
    )
    .await;
    let pinned = head(&db).await;

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000003",
            "name": "After",
            "home_id": "a50f0000-0000-4000-8000-000000000002",
            "facets": { "confidence": "likely" }
        }),
    )
    .await;

    let batch = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": ["a50f0000-0000-4000-8000-000000000003", "a50f0000-0000-4000-8000-000000000001", "missing"],
            "as_of": { "content_seq": pinned }
        }),
    )
    .await;
    assert_eq!(batch["records"][0]["name"], "Before");
    assert_eq!(
        batch["records"][0]["home_id"],
        "a50f0000-0000-4000-8000-000000000001"
    );
    assert_eq!(batch["records"][0]["facets"][0]["value"], "tentative");
    assert_eq!(batch["records"][2]["status"], "not_found");
    assert_eq!(batch["resolved_content_seq"], pinned);
    assert!(batch["content_head_seq"].as_i64().unwrap() > pinned);

    let query = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "home_id": "a50f0000-0000-4000-8000-000000000001" }],
            "as_of": { "content_seq": pinned }
        }),
    )
    .await;
    assert_eq!(query["records"].as_array().unwrap().len(), 1);
    assert_eq!(
        query["records"][0]["id"],
        "a50f0000-0000-4000-8000-000000000003"
    );
    assert_eq!(query["resolved_content_seq"], pinned);

    let tree = call(
        &registry,
        &db,
        "get_structure",
        json!({
            "root_id": "a50f0000-0000-4000-8000-000000000001",
            "max_depth": 1,
            "as_of": { "content_seq": pinned }
        }),
    )
    .await;
    assert!(tree["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|node| node["id"] == "a50f0000-0000-4000-8000-000000000003"));

    let empty = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "as_of": { "content_seq": 0 }
        }),
    )
    .await;
    assert_eq!(empty["total"], 0);
    db.close().await;
}

#[tokio::test]
async fn live_record_query_returns_a_reusable_snapshot_and_versioned_continuation() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let home = "a50f0000-0000-4000-8000-000000000010";
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": home, "type": "Collection", "kind": "folder", "name": "Page root" }),
    )
    .await;
    for (id, name) in [
        ("a50f0000-0000-4000-8000-000000000011", "A"),
        ("a50f0000-0000-4000-8000-000000000012", "B"),
        ("a50f0000-0000-4000-8000-000000000013", "C"),
    ] {
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": name, "home_id": home }),
        )
        .await;
    }

    let first = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "home_id": home }],
            "order": "name_asc",
            "limit": 2,
            "include_coordination": true
        }),
    )
    .await;
    let pinned = first["resolved_content_seq"].as_i64().unwrap();
    let local_database_id = first["local_database_id"].as_str().unwrap().to_string();
    assert_eq!(first["as_of"]["content_seq"], pinned);
    assert_eq!(first["content_head_seq"], pinned);
    assert!(first["observed_at"].is_string());
    assert_eq!(first["returned"], 2);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["records"][0]["name"], "A");
    assert_eq!(first["records"][1]["name"], "B");
    assert!(first["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| record["version"].as_str().unwrap().starts_with("rec:")));
    assert_eq!(first["next_request"]["offset"], 2);
    assert_eq!(first["next_request"]["as_of"]["content_seq"], pinned);
    assert_eq!(first["next_request"]["include_coordination"], true);
    assert!(first["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| record["work_state"] == json!({ "state": "unclaimed" })));

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000013",
            "name": "AA",
        }),
    )
    .await;
    let live_head = head(&db).await;
    assert!(live_head > pinned);

    let second = call(
        &registry,
        &db,
        "query_record",
        first["next_request"].clone(),
    )
    .await;
    assert_eq!(second["resolved_content_seq"], pinned);
    assert_eq!(second["local_database_id"], local_database_id);
    assert_eq!(second["content_head_seq"], live_head);
    assert!(second["observed_at"].is_string());
    assert_eq!(second["records"].as_array().unwrap().len(), 1);
    assert_eq!(second["records"][0]["name"], "C");
    assert!(second["records"][0]["version"]
        .as_str()
        .unwrap()
        .starts_with("rec:"));
    assert!(second["next_request"].is_null());

    let counts = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "home_id": home }],
            "count_by": "type"
        }),
    )
    .await;
    assert!(counts.get("observed_at").is_none());
    assert!(counts.get("next_request").is_none());
    db.close().await;
}

#[tokio::test]
async fn record_page_continuation_rejects_a_changed_authorized_basis() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let home = "a50f0000-0000-4000-8000-000000000020";
    let ids = [
        "a50f0000-0000-4000-8000-000000000021",
        "a50f0000-0000-4000-8000-000000000022",
        "a50f0000-0000-4000-8000-000000000023",
    ];
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": home, "type": "Collection", "kind": "folder", "name": "Guard root" }),
    )
    .await;
    for (id, name) in ids.iter().zip(["A", "B", "C"]) {
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": id, "type": "WorkItem", "kind": "task", "name": name, "home_id": home }),
        )
        .await;
    }
    for id in std::iter::once(home).chain(ids.iter().copied()) {
        replace_explicit_policy(
            &db,
            "test:page-basis",
            id,
            vec![AllowEntry::account("acct:viewer", Capability::View)],
        )
        .await
        .unwrap();
    }
    let viewer = Caller::authenticated("acct:viewer")
        .with_hosting_context("host:viewer", "db:test")
        .with_hosting_owner(false);
    let first = call_as(
        &registry,
        &db,
        viewer.clone(),
        "query_record",
        json!({
            "steps": [{ "step": "filter", "home_id": home }],
            "order": "name_asc",
            "limit": 2
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["records"][0]["name"], "A");
    assert_eq!(first["records"][1]["name"], "B");
    assert!(first["next_request"]["if_page_basis_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));

    replace_explicit_policy(&db, "test:page-basis", ids[0], vec![])
        .await
        .unwrap();
    let error = call_as(
        &registry,
        &db,
        viewer,
        "query_record",
        first["next_request"].clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("page basis changed"), "{error}");
    assert!(error.contains("restart from offset 0"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn coordination_projection_pins_claims_but_observes_authorized_targets_live() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = "a50f0000-0000-4000-8000-000000000014";
    let holder_run = "scout-chair-a748b2";
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": id, "type": "WorkItem", "kind": "task", "name": "Claimed candidate" }),
    )
    .await;
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Qualify the claimed candidate.", "run_key": holder_run }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "run_key": holder_run }),
    )
    .await;

    let owned = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [id] }],
            "include_coordination": true,
            "run_key": holder_run
        }),
    )
    .await;
    let pinned = owned["resolved_content_seq"].as_i64().unwrap();
    assert_eq!(owned["records"][0]["work_state"]["state"], "claimed");
    assert_eq!(
        owned["records"][0]["work_state"]["target"]["visibility"],
        "visible"
    );
    assert_eq!(
        owned["records"][0]["work_state"]["target"]["run_key"],
        holder_run
    );
    assert_eq!(
        owned["coordination_observation"]["claim_content_boundary"],
        "response_as_of"
    );
    assert_eq!(
        owned["coordination_observation"]["run_target_boundary"],
        "live"
    );
    assert_eq!(
        owned["coordination_observation"]["authorization_boundary"],
        "current"
    );

    let withheld = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [id] }],
            "include_coordination": true,
            "run_key": "pilot-river-b748b2"
        }),
    )
    .await;
    assert_eq!(
        withheld["records"][0]["work_state"],
        json!({
            "state": "claimed",
            "details": { "visibility": "withheld" },
            "target": { "visibility": "withheld" }
        })
    );

    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release", "run_key": holder_run }),
    )
    .await;
    let historical = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [id] }],
            "include_coordination": true,
            "as_of": { "content_seq": pinned },
            "run_key": holder_run
        }),
    )
    .await;
    assert_eq!(historical["records"][0]["work_state"]["state"], "claimed");
    assert_eq!(
        historical["records"][0]["work_state"]["details"]["visibility"],
        "visible"
    );
    assert!(historical["records"][0]["work_state"]["details"]["claim_id"].is_string());
    assert!(historical["records"][0]["work_state"]["details"]["claimed_at"].is_string());
    assert_eq!(
        historical["records"][0]["work_state"]["target"]["run_state"],
        "open"
    );
    assert_eq!(historical["resolved_content_seq"], pinned);

    let historical_withheld = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [id] }],
            "include_coordination": true,
            "as_of": { "content_seq": pinned },
            "run_key": "pilot-river-b748b2"
        }),
    )
    .await;
    assert_eq!(
        historical_withheld["records"][0]["work_state"],
        json!({
            "state": "claimed",
            "details": { "visibility": "withheld" },
            "target": { "visibility": "withheld" }
        })
    );

    let live = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "ids": [id] }],
            "include_coordination": true,
            "run_key": holder_run
        }),
    )
    .await;
    assert_eq!(
        live["records"][0]["work_state"],
        json!({ "state": "unclaimed" })
    );

    let overflow = call_err(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter" }],
            "include_coordination": true,
            "limit": 51
        }),
    )
    .await;
    assert!(overflow.contains("include_coordination requires limit <= 50"));
    db.close().await;
}

#[tokio::test]
async fn selectors_validate_boundaries_and_equal_timestamp_ties() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000004",
            "type": "WorkItem",
            "name": "Timed",
            "facets": { "a": "1", "b": "2" }
        }),
    )
    .await;
    let current_head = head(&db).await;
    let timestamp: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq = ?")
            .bind(current_head)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let tie_max: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE created_at = ?")
            .bind(&timestamp)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let exact = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["a50f0000-0000-4000-8000-000000000004"], "as_of": { "timestamp": timestamp } }),
    )
    .await;
    assert_eq!(exact["resolved_content_seq"], tie_max);

    let before = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["a50f0000-0000-4000-8000-000000000004"], "as_of": { "timestamp": "1970-01-01T00:00:00Z" } }),
    )
    .await;
    assert_eq!(before["resolved_content_seq"], 0);
    assert_eq!(before["records"][0]["status"], "not_found");

    let after = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["a50f0000-0000-4000-8000-000000000004"], "as_of": { "timestamp": "2999-01-01T00:00:00Z" } }),
    )
    .await;
    assert_eq!(after["resolved_content_seq"], current_head);
    assert_eq!(after["content_head_seq"], current_head);

    let future = call_err(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["a50f0000-0000-4000-8000-000000000004"], "as_of": { "content_seq": current_head + 1 } }),
    )
    .await;
    assert!(future.contains("beyond current content head"), "{future}");
    let ambiguous = call_err(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": ["a50f0000-0000-4000-8000-000000000004"],
            "as_of": { "content_seq": current_head, "timestamp": "2999-01-01T00:00:00Z" }
        }),
    )
    .await;
    assert!(
        ambiguous.contains("invalid arguments for get_record"),
        "{ambiguous}"
    );
    db.close().await;
}

#[tokio::test]
async fn historical_content_uses_live_schema_and_kind_governance() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000005",
            "type": "Collection",
            "kind": "folder",
            "name": "Lens root"
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000006",
            "type": "WorkItem",
            "kind": "later-governed",
            "name": "Historical member",
            "home_id": "a50f0000-0000-4000-8000-000000000005"
        }),
    )
    .await;
    let pinned = head(&db).await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({
            "action": "write",
            "id": "lens-shape",
            "applies_to_collection_id": "a50f0000-0000-4000-8000-000000000005",
            "data": { "shapes": { "WorkItem": { "facets": {} } } }
        }),
    )
    .await;
    crate::common::govern_kind(&db, "WorkItem", "later-governed").await;

    let historical = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": ["a50f0000-0000-4000-8000-000000000005", "a50f0000-0000-4000-8000-000000000006"],
            "as_of": { "content_seq": pinned }
        }),
    )
    .await;
    assert_eq!(historical["records"][0]["bears_shape"], true);
    assert_eq!(
        historical["records"][1]["kind_governance"]["quarantined"],
        false
    );

    let shaped = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "bears_shape": true }],
            "as_of": { "content_seq": pinned }
        }),
    )
    .await;
    assert_eq!(
        shaped["records"][0]["id"],
        "a50f0000-0000-4000-8000-000000000005"
    );
    db.close().await;
}

#[tokio::test]
async fn saved_views_resolve_against_the_same_historical_lens() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "a50f0000-0000-4000-8000-000000000007", "type": "WorkItem", "name": "Alpha" }),
    )
    .await;
    let envelope = json!({
        "v": "0.2",
        "query": {
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "order": "name_asc"
        }
    });
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "a50f0000-0000-4000-8000-000000000008",
            "type": "Collection",
            "kind": "query",
            "name": "Historical view",
            "facets": { "query": envelope.to_string() }
        }),
    )
    .await;
    let pinned = head(&db).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "a50f0000-0000-4000-8000-000000000009", "type": "WorkItem", "name": "Beta" }),
    )
    .await;

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["a50f0000-0000-4000-8000-000000000008"], "as_of": { "content_seq": pinned } }),
    )
    .await;
    let resolved = &out["records"][0]["query_resolution"]["output"];
    assert_eq!(resolved["total"], 1);
    assert_eq!(
        resolved["records"][0]["id"],
        "a50f0000-0000-4000-8000-000000000007"
    );
    db.close().await;
}

#[tokio::test]
async fn newest_first_history_pages_without_gaps_or_duplicates() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "a50f0000-0000-4000-8000-00000000000a", "type": "WorkItem", "name": "v1" }),
    )
    .await;
    for name in ["v2", "v3", "v4"] {
        call(
            &registry,
            &db,
            "update_record",
            json!({ "id": "a50f0000-0000-4000-8000-00000000000a", "name": name }),
        )
        .await;
    }
    let mut cursor: Option<i64> = None;
    let mut seen = Vec::new();
    loop {
        let mut args = json!({
            "record_id": "a50f0000-0000-4000-8000-00000000000a",
            "order": "newest_first",
            "limit": 2
        });
        if let Some(seq) = cursor {
            args["after_local_seq"] = seq.into();
        }
        let page = call(&registry, &db, "get_history", args).await;
        seen.extend(
            page["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["local_seq"].as_i64().unwrap()),
        );
        cursor = page["next_after_local_seq"].as_i64();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 4);
    assert!(seen.windows(2).all(|pair| pair[0] > pair[1]));
    let unique = seen.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), seen.len());
    db.close().await;
}
