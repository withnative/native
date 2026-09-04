use native_ce::events::FacetSetPayload;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{create_record, set_facet};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn record(db: &Db, record_type: &str, name: &str) -> String {
    create_record(
        db,
        json!({ "type": record_type, "kind": "x-test-fixture", "name": name }),
    )
    .await
    .unwrap()
}

async fn record_with_kind(db: &Db, record_type: &str, kind: &str, name: &str) -> String {
    create_record(
        db,
        json!({ "type": record_type, "kind": kind, "name": name }),
    )
    .await
    .unwrap()
}

async fn set_query(db: &Db, id: &str, envelope: Value) {
    set_facet(
        db,
        id,
        FacetSetPayload {
            key: "query".into(),
            value: Some(envelope.to_string()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
}

fn without_run_context(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("run_context");
    value
}

fn without_direct_page_receipt(mut value: Value) -> Value {
    let object = value.as_object_mut().unwrap();
    for key in [
        "as_of",
        "observed_at",
        "resolved_content_seq",
        "content_head_seq",
        "local_database_id",
        "page_basis_digest",
        "next_request",
    ] {
        object.remove(key);
    }
    if let Some(records) = object.get_mut("records").and_then(Value::as_array_mut) {
        for record in records {
            if let Some(record) = record.as_object_mut() {
                record.remove("version");
            }
        }
    }
    value
}

#[tokio::test]
async fn saved_queries_dispatch_by_capability_with_direct_output_parity() {
    let db = db().await;
    let registry = registry();
    for name in ["alpha", "beta", "gamma"] {
        record(&db, "WorkItem", name).await;
    }
    // The stored query defines membership for the canonical Collection
    // kind:query; the capability path itself remains facet-derived.
    let query = record_with_kind(&db, "Collection", "query", "Paged query").await;
    let collection = record_with_kind(&db, "Collection", "folder", "Smart collection").await;
    create_record(
        &db,
        json!({ "type": "Resolution", "kind": "decision", "name": "Contained but not queried", "home_id": collection }),
    )
    .await
    .unwrap();
    let aggregate = record(&db, "Document", "Work count").await;
    let inner = json!({
        "steps": [{ "step": "filter", "types": ["WorkItem"] }],
        "order": "name_asc",
        "limit": 1,
        "offset": 1
    });
    let envelope = json!({ "v": "0.2", "query": inner });
    set_query(&db, &query, envelope.clone()).await;
    set_query(&db, &collection, envelope).await;
    set_query(
        &db,
        &aggregate,
        json!({
            "v": "0.2",
            "query": {
                "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                "aggregate": { "op": "count" }
            }
        }),
    )
    .await;

    // Saved-query resolution shares the semantic execution engine with direct
    // query_record, but the reusable page receipt belongs to the direct tool
    // operation rather than to nested capability output.
    let direct = without_direct_page_receipt(without_run_context(
        call(
            &registry,
            &db,
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                "order": "name_asc",
                "limit": 1,
                "offset": 1
            }),
        )
        .await,
    ));
    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&query, &collection, &aggregate] }),
    )
    .await;
    let rendered = native_ce::mcp::render::render("get_record", &out).unwrap();
    assert!(rendered.contains("[has-query]"), "{rendered}");
    assert!(rendered.contains("Query resolution v0.2"), "{rendered}");
    let records = out["records"].as_array().unwrap();
    for item in &records[..2] {
        assert_eq!(item["has_query"], true);
        assert_eq!(item["query_resolution"]["status"], "resolved");
        assert_eq!(item["query_resolution"]["version"], "0.2");
        assert_eq!(item["query_resolution"]["output"], direct);
        assert_eq!(
            item["query_resolution"]["output"]["records"][0]["name"],
            "beta"
        );
    }
    assert_eq!(records[2]["has_query"], true);
    assert_eq!(
        records[2]["query_resolution"]["output"]["shape"],
        "aggregate"
    );
    assert_eq!(records[2]["query_resolution"]["output"]["value"], 3);

    let definition = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&query], "resolve": false }),
    )
    .await;
    assert_eq!(definition["records"][0]["has_query"], true);
    assert!(definition["records"][0].get("query_resolution").is_none());

    let get_schema = &registry.get("get_record").unwrap().input_schema;
    assert_eq!(get_schema["properties"]["resolve"]["type"], "boolean");
    let query_schema = &registry.get("query_record").unwrap().input_schema;
    assert_eq!(
        query_schema["properties"]["steps"]["items"]["oneOf"][0]["properties"]["has_query"]["type"],
        json!(["boolean", "null"])
    );
    for writable in ["create_record", "update_record"] {
        assert!(
            registry.get(writable).unwrap().input_schema["properties"]
                .get("has_query")
                .is_none(),
            "{writable} must not expose a stored capability flag"
        );
    }
}

#[tokio::test]
async fn invalid_specs_are_per_record_and_has_query_filters_use_validation() {
    let db = db().await;
    let registry = registry();
    let valid = record(&db, "Collection", "Valid saved query").await;
    let malformed = record(&db, "Collection", "Malformed saved query").await;
    let unsupported = record(&db, "Collection", "Old smart collection").await;
    let zero_limit = record(&db, "Collection", "Zero limit").await;
    let negative_offset = record(&db, "Collection", "Negative offset").await;
    let starts_with_traverse = record(&db, "Collection", "Traverse first").await;
    let aggregate_collection =
        record_with_kind(&db, "Collection", "query", "Aggregate smart collection").await;
    let aggregate_document = record(&db, "Document", "Aggregate computation").await;
    let plain = record(&db, "Document", "Plain").await;
    set_query(
        &db,
        &valid,
        json!({ "v": "0.2", "query": { "steps": [{ "step": "filter" }] } }),
    )
    .await;
    set_facet(
        &db,
        &malformed,
        FacetSetPayload {
            key: "query".into(),
            value: Some("{not-json".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    set_query(
        &db,
        &unsupported,
        json!({ "v": "0.1", "query": { "steps": [{ "step": "filter" }] } }),
    )
    .await;
    set_query(
        &db,
        &zero_limit,
        json!({
            "v": "0.2",
            "query": { "steps": [{ "step": "filter" }], "limit": 0 }
        }),
    )
    .await;
    set_query(
        &db,
        &negative_offset,
        json!({
            "v": "0.2",
            "query": { "steps": [{ "step": "filter" }], "offset": -1 }
        }),
    )
    .await;
    set_query(
        &db,
        &starts_with_traverse,
        json!({
            "v": "0.2",
            "query": {
                "steps": [{ "step": "traverse", "target": "children" }]
            }
        }),
    )
    .await;
    let aggregate_envelope = json!({
        "v": "0.2",
        "query": {
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "aggregate": { "op": "count" }
        }
    });
    set_query(&db, &aggregate_collection, aggregate_envelope.clone()).await;
    set_query(&db, &aggregate_document, aggregate_envelope).await;

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [
                &valid,
                &malformed,
                &unsupported,
                &zero_limit,
                &negative_offset,
                &starts_with_traverse,
                &aggregate_collection,
                &aggregate_document,
                &plain,
                "missing"
            ]
        }),
    )
    .await;
    let records = out["records"].as_array().unwrap();
    assert_eq!(records[0]["query_resolution"]["status"], "resolved");
    assert_eq!(records[1]["has_query"], false);
    assert_eq!(records[1]["query_resolution"]["status"], "invalid");
    assert_eq!(records[2]["has_query"], false);
    assert_eq!(
        records[2]["query_resolution"]["status"],
        "unsupported_version"
    );
    for item in &records[3..6] {
        assert_eq!(item["has_query"], false);
        assert_eq!(item["query_resolution"]["status"], "invalid");
    }
    assert_eq!(records[6]["has_query"], false);
    assert_eq!(records[6]["query_resolution"]["status"], "invalid");
    assert_eq!(records[7]["has_query"], true);
    assert_eq!(records[7]["query_resolution"]["status"], "resolved");
    assert_eq!(
        records[7]["query_resolution"]["output"]["shape"],
        "aggregate"
    );
    assert_eq!(records[8]["has_query"], false);
    assert!(records[8].get("query_resolution").is_none());
    assert_eq!(records[9]["status"], "not_found");

    let capable = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "has_query": true }],
            "order": "name_asc"
        }),
    )
    .await;
    let capable_ids: Vec<&str> = capable["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(capable_ids.len(), 2);
    assert!(capable_ids.contains(&valid.as_str()));
    assert!(capable_ids.contains(&aggregate_document.as_str()));
    assert!(!capable_ids.contains(&aggregate_collection.as_str()));

    let incapable = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{ "step": "filter", "has_query": false }],
            "order": "name_asc"
        }),
    )
    .await;
    let ids: Vec<&str> = incapable["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&malformed.as_str()));
    assert!(ids.contains(&unsupported.as_str()));
    assert!(ids.contains(&zero_limit.as_str()));
    assert!(ids.contains(&negative_offset.as_str()));
    assert!(ids.contains(&starts_with_traverse.as_str()));
    assert!(ids.contains(&aggregate_collection.as_str()));
    assert!(!ids.contains(&aggregate_document.as_str()));
    assert!(ids.contains(&plain.as_str()));
    assert!(!ids.contains(&valid.as_str()));
}

#[tokio::test]
async fn resolution_is_one_level_and_runtime_failure_preserves_the_capability() {
    let db = db().await;
    let registry = registry();
    let first = record_with_kind(&db, "Collection", "query", "First query").await;
    let second = record_with_kind(&db, "Collection", "query", "Second query").await;
    for id in [&first, &second] {
        set_query(
            &db,
            id,
            json!({
                "v": "0.2",
                "query": { "steps": [{ "step": "filter", "types": ["Collection"], "kinds": ["query"] }] }
            }),
        )
        .await;
    }
    let out = call(&registry, &db, "get_record", json!({ "ids": [&first] })).await;
    let returned = out["records"][0]["query_resolution"]["output"]["records"]
        .as_array()
        .unwrap();
    assert_eq!(returned.len(), 2);
    assert!(returned.iter().all(|item| item.get("has_query").is_none()));
    assert!(returned
        .iter()
        .all(|item| item.get("query_resolution").is_none()));

    let ledger = record_with_kind(&db, "Collection", "folder", "Overflow ledger").await;
    for name in ["non-finite"] {
        let id = create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": name, "home_id": ledger }),
        )
        .await
        .unwrap();
        set_facet(
            &db,
            &id,
            FacetSetPayload {
                key: "amount".into(),
                value: Some("1e999".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }
    let failure_carrier = record(&db, "Document", "Runtime failure carrier").await;
    set_query(
        &db,
        &failure_carrier,
        json!({
            "v": "0.2",
            "query": {
                "steps": [{ "step": "filter", "home_id": ledger }],
                "aggregate": { "op": "sum", "facet_key": "amount" }
            }
        }),
    )
    .await;
    // The inner grammar remains valid, but a non-finite numeric projection is
    // rejected when the aggregate executes. Runtime failure is not a
    // capability change.
    let failed = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&failure_carrier] }),
    )
    .await;
    assert_eq!(failed["records"][0]["has_query"], true);
    assert_eq!(
        failed["records"][0]["query_resolution"]["status"],
        "execution_error"
    );
}
