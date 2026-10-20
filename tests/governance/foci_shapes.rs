//! The approved Foci configuration shapes (task 5b5bfa5) must be accepted by
//! the engine exactly as written. They live as evidence under
//! `docs/evidence/foci-hosted-v1/` and are not registered; this proves the
//! schema validation and the engine's own facet-value validation take them, so
//! registration will not stumble on the schemas themselves. Enforcement on real
//! records starts only once the kinds are registered, which is a separate step.
//!
//! The file is read at run time rather than included at compile time: product
//! source must not depend on evidence under `docs/` (see `docs/source-boundary.md`).
//! A tree without `docs/evidence` at all, such as the public projection, skips
//! these tests; a tree that has it but lacks the file fails.

use native_ce::create_database;
use native_ce::meta::schema_config::{
    assert_valid_object_facet_schemas, validate_object_facet_value, write_user_schema_config,
    SchemaConfigOptions,
};
use serde_json::{json, Value};
use std::path::PathBuf;

const VIEW_ID: &str = "8f14e45f-ceea-467a-9575-5d4a5a8b3f0e";

fn shapes() -> Option<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/evidence");
    if !root.is_dir() {
        eprintln!("skipping: no docs/evidence in this tree");
        return None;
    }
    let path = root.join("foci-hosted-v1/configuration-shapes.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "approved Foci shapes missing at {}: {error}",
            path.display()
        )
    });
    let document: Value = serde_json::from_str(&text).unwrap();
    Some(json!({ "shapes": document["shapes"].clone() }))
}

fn facet(data: &Value, shape_key: &str, facet_key: &str) -> Value {
    data["shapes"][shape_key]["facets"][facet_key].clone()
}

/// (shape, facet, a valid value, an invalid value)
fn cases() -> Vec<(&'static str, &'static str, Value, Value)> {
    vec![
        (
            "Collection:focus",
            "focus.settings",
            json!({ "version": 1, "colour": "#a1b2c3" }),
            json!({ "version": 1, "colour": "red" }),
        ),
        (
            "Collection:focus",
            "focus.view_order",
            json!({ "version": 1, "saved_view_ids": [VIEW_ID] }),
            json!({ "version": 1, "saved_view_ids": ["not-a-record-id"] }),
        ),
        (
            "Configuration:record_view",
            "view.definition",
            json!({ "version": 1, "app": "native.docs", "target": { "record_id": "native:root" } }),
            json!({ "version": 1, "app": "Docs", "target": { "record_id": "native:root" } }),
        ),
        (
            "Configuration:query_view",
            "view.definition",
            json!({
                "version": 1,
                "app": "native.tracker",
                "format": "tracker-query/1",
                "filter": {
                    "combine": "all",
                    "terms": [{ "field": "status", "op": "eq", "value": "open" }]
                },
                "sort": [{ "field": "updated_at", "direction": "desc" }]
            }),
            json!({
                "version": 1,
                "app": "native.tracker",
                "format": "tracker-query/1",
                "filter": {
                    "combine": "all",
                    "terms": [{ "field": "status", "op": "gt", "value": "open" }]
                },
                "sort": []
            }),
        ),
        (
            "Configuration:focus_preferences",
            "focus.preferences",
            json!({ "version": 1, "foci": [{ "focus_id": VIEW_ID, "tier": "now", "hidden": false }] }),
            json!({ "version": 1, "foci": [{ "focus_id": VIEW_ID, "tier": "later", "hidden": false }] }),
        ),
    ]
}

#[test]
fn engine_accepts_the_approved_foci_shapes() {
    let Some(data) = shapes() else { return };
    assert_eq!(data["shapes"].as_object().unwrap().len(), 4);
    assert_valid_object_facet_schemas(&data).unwrap();
}

#[test]
fn each_foci_facet_accepts_a_valid_value_and_refuses_an_invalid_one() {
    let Some(data) = shapes() else { return };
    for (shape_key, facet_key, valid, invalid) in cases() {
        let declaration = facet(&data, shape_key, facet_key);
        validate_object_facet_value(&declaration, &valid)
            .unwrap_or_else(|error| panic!("{shape_key} {facet_key} valid: {error}"));
        assert!(
            validate_object_facet_value(&declaration, &invalid).is_err(),
            "{shape_key} {facet_key} must refuse its invalid value"
        );
    }
}

/// The same shapes pass the full user-layer write funnel (reserved-key guard,
/// lifecycle axes, object-facet schemas) and are stored.
#[tokio::test]
async fn foci_shapes_pass_the_user_layer_schema_config_write() {
    let Some(data) = shapes() else { return };
    let db = create_database(":memory:").await.unwrap();
    write_user_schema_config(&db, data, SchemaConfigOptions::default())
        .await
        .unwrap();
    db.close().await;
}
