//! Declared facet types (decision 37de348 / task cff3075).
//!
//! The supported tool surface preserves the caller's JSON type until the
//! shape guard runs. Accepted numbers still project through the existing TEXT
//! representation, and `value_num` must agree with every accepted write.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    promote_value, propose_value_with_kind_metadata_as, seed_pack_schema_config, seed_vocabularies,
    KindMetadataV1, SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. Pinned literals, never generated.
const HISTORICAL_STRING: &str = "71fed000-0000-4000-8000-000000000001";
const STRING_FIFTY: &str = "71fed000-0000-4000-8000-000000000002";
const NUMBER_FIFTY: &str = "71fed000-0000-4000-8000-000000000003";
const GOAL: &str = "71fed000-0000-4000-8000-000000000004";
const ROOT: &str = "71fed000-0000-4000-8000-000000000005";

/// Per-index ids for the accepted and rejected numeric tables. The two
/// families use different leading digits so a rejected write can never collide
/// with an accepted record, which is what makes "no event was written" mean
/// what it says.
fn accepted_numeric_id(index: usize) -> String {
    format!("71fed010-0000-4000-8000-{index:012}")
}

fn rejected_numeric_id(index: usize) -> String {
    format!("71fed011-0000-4000-8000-{index:012}")
}

async fn db() -> Db {
    // Typed-facet tests own the pack payload they are validating.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    seed_vocabularies(&db).await.unwrap();
    db
}

async fn govern_outcome_kind(db: &Db, token: &str) {
    let id = propose_value_with_kind_metadata_as(
        db,
        "kind:Outcome",
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Outcome", token)),
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

async fn write_user_shape(registry: &ToolRegistry, db: &Db, data: Value) -> Value {
    call(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": data }),
    )
    .await
}

#[tokio::test]
async fn schema_config_accepts_supported_types_and_floors_pack_types_on_open_facets() {
    let db = db().await;
    let registry = registry();
    govern_outcome_kind(&db, "key_result").await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": {
            "Outcome": {
                "facets": {
                    "target": { "type": "number" },
                    "confidence": {}
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    for unsupported in ["string", "boolean", "date"] {
        let err = call_err(
            &registry,
            &db,
            "manage_schema_config",
            json!({ "action": "write", "data": {
                "shapes": { "Outcome": { "facets": {
                    "confidence": { "type": unsupported }
                } } }
            } }),
        )
        .await;
        assert!(
            err.contains("supported declared types are `number` and `object`"),
            "{err}"
        );
    }

    for spine in ["lifecycle", "owner", "persistence", "maturity"] {
        let err = call_err(
            &registry,
            &db,
            "manage_schema_config",
            json!({ "action": "write", "data": { "shapes": { "Outcome": {
                "facets": { spine: { "type": "number" } }
            } } } }),
        )
        .await;
        assert!(err.contains("string carriers"), "{err}");
        assert!(err.contains(spine), "{err}");
    }
    let err = seed_pack_schema_config(
        &db,
        "bad-spine-type",
        json!({ "shapes": { "Outcome": { "facets": {
            "maturity": { "type": "number" }
        } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("string carriers"), "{err}");

    // Adding a type where the pack has none tightens.
    write_user_shape(
        &registry,
        &db,
        json!({ "shapes": { "Outcome": { "facets": {
            "confidence": { "type": "number" }
        } } } }),
    )
    .await;

    // A whole-facet override must restate the nominal floor, including on an
    // open key and in a kind-specific view.
    let err = call_err(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": {
            "shapes": { "Outcome:key_result": { "facets": {
                "target": { "description": "delivery target" }
            } } }
        } }),
    )
    .await;
    assert!(err.contains("cannot loosen declared type"), "{err}");
    assert!(err.contains("target"), "{err}");
    assert!(err.contains("Outcome:key_result"), "{err}");

    write_user_shape(
        &registry,
        &db,
        json!({ "shapes": { "Outcome:key_result": { "facets": {
            "target": { "type": "number", "description": "delivery target" }
        } } } }),
    )
    .await;
}

#[tokio::test]
async fn schema_write_reports_historical_nonconformance_without_refusing_it() {
    let db = db().await;
    let registry = registry();

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": HISTORICAL_STRING,
            "type": "Outcome",
            "facets": { "target": "not-a-number" }
        }),
    )
    .await;

    let response = write_user_shape(
        &registry,
        &db,
        json!({ "shapes": { "Outcome": { "facets": {
            "target": { "type": "number" }
        } } } }),
    )
    .await;
    assert_eq!(response["nonconforming_stored_values"], 1);
    assert!(response["type_enforcement"]
        .as_str()
        .unwrap()
        .contains("forward-only"));
}

#[tokio::test]
async fn numeric_type_preserves_wire_json_type_and_agrees_with_value_num() {
    let db = db().await;
    let registry = registry();
    govern_outcome_kind(&db, "key_result").await;
    write_user_shape(
        &registry,
        &db,
        json!({ "shapes": {
            "Outcome:key_result": { "facets": { "target": { "type": "number" } } }
        } }),
    )
    .await;

    // The accepted half of 234721a §1c. Each caller value is a JSON number;
    // the tool stores its canonical textual form and SQLite must project it.
    for (index, raw) in ["100", "-3", "12.5", "1e3", "1E-3", "0", "-0.25", " 42 "]
        .into_iter()
        .enumerate()
    {
        let value: Value = serde_json::from_str(raw).unwrap();
        let id = accepted_numeric_id(index);
        call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "Outcome",
                "kind": "key_result",
                "facets": { "target": value }
            }),
        )
        .await;
        let row = sqlx::query(
            "SELECT value, value_num FROM facet_values WHERE record_id = ? AND key = 'target'",
        )
        .bind(accepted_numeric_id(index))
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(
            row.try_get::<Option<f64>, _>("value_num")
                .unwrap()
                .is_some(),
            "accepted JSON number {raw} had no numeric projection; stored={:?}",
            row.try_get::<Option<String>, _>("value").unwrap()
        );
    }

    // The rejected half of the same table. Valid non-number JSON is passed in
    // its native type; invalid JSON spellings are strings, exactly as an MCP
    // caller supplies them. No rejected value reaches the log/projection.
    let rejected = [
        Value::String("abc".into()),
        Value::String(String::new()),
        Value::String("  ".into()),
        Value::String("0x10".into()),
        Value::String("inf".into()),
        Value::String("50%".into()),
        Value::String("1.2.3".into()),
        Value::String("1 2".into()),
        Value::String("+5".into()),
        Value::String(".5".into()),
        Value::String("5.".into()),
        Value::String("01".into()),
        Value::Bool(true),
        Value::String("7".into()),
        json!([1]),
    ];
    for (index, value) in rejected.into_iter().enumerate() {
        let id = rejected_numeric_id(index);
        let err = call_err(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "Outcome",
                "kind": "key_result",
                "facets": { "target": value }
            }),
        )
        .await;
        assert!(
            err.contains("requires a JSON number")
                || err.contains("must be a string, number")
                || err.contains("needs a string or number"),
            "{err}"
        );
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id = ?")
                .bind(id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(count, 0, "rejected input wrote an event");
    }

    // The collapse bug explicitly: the string is rejected, while the number
    // with identical rendered text is accepted and gets a numeric projection.
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": STRING_FIFTY,
            "type": "Outcome",
            "kind": "key_result",
            "facets": { "target": "50" }
        }),
    )
    .await;
    assert!(err.contains("got a JSON string"), "{err}");
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": NUMBER_FIFTY,
            "type": "Outcome",
            "kind": "key_result",
            "facets": { "target": 50 }
        }),
    )
    .await;
}

#[tokio::test]
async fn update_uses_resulting_kind_and_attachment_creation_enforces_types() {
    let db = db().await;
    let registry = registry();
    govern_outcome_kind(&db, "objective").await;
    govern_outcome_kind(&db, "key_result").await;
    write_user_shape(
        &registry,
        &db,
        json!({ "shapes": {
            "Outcome:key_result": { "facets": { "target": { "type": "number" } } },
            "Document:attachment": { "facets": { "score": { "type": "number" } } }
        } }),
    )
    .await;

    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": GOAL, "type": "Outcome", "kind": "objective" }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": GOAL,
            "kind": "key_result",
            "facets": { "target": 75 }
        }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": GOAL, "facets": { "target": "80" } }),
    )
    .await;
    assert!(err.contains("requires a JSON number"), "{err}");

    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ROOT, "type": "Collection" }),
    )
    .await;
    let blobs_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({
            "record_id": ROOT,
            "text": "bad",
            "facets": { "score": "0.5" }
        }),
    )
    .await;
    assert!(err.contains("requires a JSON number"), "{err}");
    let blobs_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        blobs_after, blobs_before,
        "type rejection must happen before blob insertion"
    );

    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({
            "record_id": ROOT,
            "text": "good",
            "facets": { "score": 0.5 }
        }),
    )
    .await;
    let value_num: Option<f64> = sqlx::query_scalar(
        "SELECT value_num FROM facet_values WHERE record_id = ? AND key = 'score'",
    )
    .bind(attachment["attachment_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(value_num, Some(0.5));
}

#[tokio::test]
async fn facet_resolution_surfaces_declared_type_and_honest_scope() {
    let db = db().await;
    let registry = registry();
    govern_outcome_kind(&db, "key_result").await;
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": {
            "Outcome:key_result": { "facets": { "target": { "type": "number" } } }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let resolved = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "type": "Outcome", "kind": "key_result" }),
    )
    .await;
    assert_eq!(resolved["shape"]["target"]["type"], "number");
    assert_eq!(resolved["pack_shape"]["target"]["type"], "number");
    let notice = resolved["shape_guarantee"].as_str().unwrap();
    assert!(notice.contains("forward-only"), "{notice}");
    assert!(notice.contains("store::append"), "{notice}");
    assert!(notice.contains("not a standing"), "{notice}");
    assert!(
        notice.contains("type, values, and governing vocabulary"),
        "{notice}"
    );
    assert!(
        notice.contains("required is enforced post-batch and comparatively"),
        "{notice}"
    );
    assert!(notice.contains("multi is rejected"), "{notice}");
    assert!(
        notice.contains("same write-transaction snapshot"),
        "{notice}"
    );
    assert!(notice.contains("string-carried spine facets"), "{notice}");

    let suggested = call(
        &registry,
        &db,
        "suggest_facet_values",
        json!({
            "type": "Outcome",
            "kind": "key_result",
            "facet_key": "target"
        }),
    )
    .await;
    assert_eq!(suggested["declared_type"], "number");
    assert!(suggested["shape_guarantee"]
        .as_str()
        .unwrap()
        .contains("forward-only"));
}
