//! Collection-scoped schema declarations remain discoverable metadata, but a
//! record's browse home never participates in facet resolution.

use native_ce::conformance::rebuild_and_diff_meta;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    promote_value, propose_value_with_kind_metadata_as, KindMetadataV1, VocabularyValueTerminality,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

// Record ids must be canonical v4/v7 UUIDs, so the browse homes and the two
// records are pinned literals. `"payment"` also names a governed WorkItem kind
// and the schema-config ids below are not record ids, so both stay readable.
const HOME_A: &str = "bea45a9e-0000-4000-8000-000000000001";
const HOME_B: &str = "bea45a9e-0000-4000-8000-000000000002";
const ITEM: &str = "bea45a9e-0000-4000-8000-000000000003";
const PAYMENT: &str = "bea45a9e-0000-4000-8000-000000000004";

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

async fn folder(registry: &ToolRegistry, db: &Db, id: &str) {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": id, "type": "Collection", "kind": "folder", "name": id }),
    )
    .await;
}

async fn govern_kind(db: &Db, token: &str) {
    let id = propose_value_with_kind_metadata_as(
        db,
        "kind:WorkItem",
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("WorkItem", token)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

async fn write_schema(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    applies_to_collection_id: Option<&str>,
    data: Value,
) {
    call(
        registry,
        db,
        "manage_schema_config",
        json!({
            "action": "write",
            "id": id,
            "applies_to_collection_id": applies_to_collection_id,
            "data": data,
        }),
    )
    .await;
}

#[tokio::test]
async fn collection_scoped_declarations_are_discoverable_but_not_product_facet_context() {
    let db = db().await;
    let registry = registry();
    folder(&registry, &db, HOME_A).await;
    folder(&registry, &db, HOME_B).await;

    write_schema(
        &registry,
        &db,
        "home-a-domain-schema",
        Some(HOME_A),
        json!({ "shapes": { "WorkItem": { "facets": {
            "domain_lane": { "values": ["private-a"] }
        } } } }),
    )
    .await;

    let records = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [HOME_A, HOME_B] }),
    )
    .await;
    assert_eq!(records["records"][0]["bears_shape"], true);
    assert_eq!(records["records"][1]["bears_shape"], false);

    let yes = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "bears_shape": true }] }),
    )
    .await;
    assert_eq!(yes["returned"], 1);
    assert_eq!(yes["records"][0]["id"], HOME_A);

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ITEM,
            "type": "WorkItem",
            "name": "Item",
            "home_id": HOME_A,
            "facets": { "domain_lane": "any-domain-value" },
        }),
    )
    .await;
    let resolved = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": ITEM }),
    )
    .await;
    assert!(resolved["shape"].get("domain_lane").is_none());
    assert!(resolved.get("shape_bearer_id").is_none());
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
}

#[tokio::test]
async fn moving_home_is_facet_invariant_and_global_type_kind_rules_still_apply() {
    let db = db().await;
    let registry = registry();
    govern_kind(&db, "payment").await;
    folder(&registry, &db, HOME_A).await;
    folder(&registry, &db, HOME_B).await;

    write_schema(
        &registry,
        &db,
        "global-payment",
        None,
        json!({ "shapes": { "WorkItem:payment": { "facets": {
            "processor": { "values": ["global"] },
            "amount": { "type": "number" }
        } } } }),
    )
    .await;
    write_schema(
        &registry,
        &db,
        "home-a-private",
        Some(HOME_A),
        json!({ "shapes": { "WorkItem:payment": { "facets": {
            "processor": { "values": ["private-a"] }
        } } } }),
    )
    .await;
    write_schema(
        &registry,
        &db,
        "home-b-private",
        Some(HOME_B),
        json!({ "shapes": { "WorkItem:payment": { "facets": {
            "processor": { "values": ["private-b"] }
        } } } }),
    )
    .await;

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": PAYMENT,
            "type": "WorkItem",
            "kind": "payment",
            "name": "Payment",
            "home_id": HOME_A,
            "facets": { "processor": "global", "amount": 12 },
        }),
    )
    .await;
    let before = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": PAYMENT }),
    )
    .await;

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": PAYMENT, "home_id": HOME_B }),
    )
    .await;
    let after = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": PAYMENT }),
    )
    .await;
    assert_eq!(before["shape"], after["shape"]);
    assert_eq!(before["provenance"], after["provenance"]);
    assert_eq!(after["shape"]["processor"]["values"], json!(["global"]));

    let private_error = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": PAYMENT, "facets": { "processor": "private-b" } }),
    )
    .await;
    assert!(private_error.contains("not in the declared values set"));
}
