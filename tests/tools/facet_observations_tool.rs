//! Supported valid-time observation author/read contract (task df2f228).

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::FacetSetPayload;
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::meta::{
    create_vocabulary, promote_value, propose_value, seed_pack_schema_config, SchemaConfigOptions,
};
use native_ce::store::{create_record, set_facet};
use native_ce::{apply_schema, create_database, open_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

#[test]
fn advertised_schema_is_action_discriminated() {
    let registry = registry();
    let schema = &registry
        .get("manage_facet_observations")
        .unwrap()
        .input_schema;
    let branches = schema["oneOf"].as_array().unwrap();
    assert_eq!(branches.len(), 3);
    let by_action = |action: &str| {
        branches
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == action)
            .unwrap_or_else(|| panic!("missing {action} schema branch"))
    };

    let set = by_action("set");
    assert_eq!(
        set["required"],
        json!([
            "action",
            "record_id",
            "key",
            "value",
            "as_of",
            "reason",
            "run_key"
        ])
    );
    assert!(set["properties"].get("vocab_ref").is_some());
    assert!(set["properties"].get("from_as_of").is_none());

    let unset = by_action("unset");
    assert_eq!(
        unset["required"],
        json!(["action", "record_id", "key", "as_of", "reason", "run_key"])
    );
    assert!(unset["properties"].get("value").is_none());
    assert!(unset["properties"].get("vocab_ref").is_none());

    let list = by_action("list");
    assert_eq!(
        list["required"],
        json!(["action", "record_id", "key", "run_key"])
    );
    for field in ["from_as_of", "to_as_of", "after_as_of", "limit"] {
        assert!(list["properties"].get(field).is_some(), "missing {field}");
    }
    for field in ["value", "vocab_ref", "as_of", "reason"] {
        assert!(
            list["properties"].get(field).is_none(),
            "list permits {field}"
        );
    }

    assert!(schema["properties"].get("format").is_none());
    for branch in schema["oneOf"].as_array().unwrap() {
        assert!(
            branch["properties"].get("format").is_none(),
            "closed action branches must not duplicate the legacy format argument"
        );
    }
}

async fn call(registry: &ToolRegistry, db: &Db, args: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_facet_observations",
            args,
        )
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_facet_observations",
            args,
        )
        .await
        .unwrap_err()
        .to_string()
}

fn set_args(record_id: &str, value: Value, as_of: &str) -> Value {
    json!({
        "action": "set",
        "record_id": record_id,
        "key": "current",
        "value": value,
        "as_of": as_of,
        "reason": "Backfill the measurement captured at this valid time.",
    })
}

#[test]
fn observation_rendering_keeps_the_callable_cursor_and_provenance() {
    let rendered = render::render(
        "manage_facet_observations",
        &json!({
            "record_id": "rec-full-id",
            "key": "current",
            "observations": [{
                "value": "11",
                "op": "set",
                "vocab_ref": null,
                "as_of": "2026-08-01T00:00:00.000Z",
                "observed_at": "2026-08-02T00:00:00.000Z",
                "event_seq": 42
            }],
            "next_after_as_of": "2026-08-01T00:00:00.000Z"
        }),
    )
    .unwrap();
    for expected in [
        "rec-full-id",
        "current",
        "2026-08-01T00:00:00.000Z",
        "event 42",
        "after_as_of=2026-08-01T00:00:00.000Z",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected}: {rendered}"
        );
    }
}

#[tokio::test]
async fn observation_writes_disclose_that_current_state_did_not_move() {
    // Five separate sessions read `status: "set"` as a current-state write and
    // left records unfindable for hours. The write is correct; the response is
    // what has to say so.
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &record_id,
        FacetSetPayload {
            key: "current".into(),
            value: Some("12".into()),
            vocab_ref: None,
            as_of: Some("2026-08-03T09:00:00.000Z".into()),
            observation_only: false,
        },
    )
    .await
    .unwrap();

    let set = call(
        &registry,
        &db,
        set_args(&record_id, json!(10), "2026-08-01T00:00:00Z"),
    )
    .await;
    assert_eq!(set["status"], "set");
    assert_eq!(set["current_value_unchanged"], true);
    assert_eq!(set["current_value_written_by"], "update_record.facets");

    // Both halves of the write surface behave identically, so the disclosure
    // has to cover both. `unset` silently not unsetting is the same trap.
    let unset = call(
        &registry,
        &db,
        json!({
            "action": "unset",
            "record_id": record_id,
            "key": "current",
            "as_of": "2026-08-02T00:00:00Z",
            "reason": "Retract the reading captured at this valid time.",
        }),
    )
    .await;
    assert_eq!(unset["status"], "unset");
    assert_eq!(unset["current_value_unchanged"], true);
    assert_eq!(unset["current_value_written_by"], "update_record.facets");

    // The marker is true because the fold genuinely did not move — neither the
    // set nor the unset touched it.
    let current: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'current'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(current, "12");

    let rendered = render::render("manage_facet_observations", &set).unwrap();
    assert!(
        rendered.contains("Current facet value unchanged")
            && rendered.contains("update_record.facets"),
        "the rendered write must disclose the split too: {rendered}"
    );
}

#[tokio::test]
async fn friday_backfill_and_correction_do_not_change_monday_current() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();
    // Ordinary current-state writes keep current-plus-observe semantics.
    set_facet(
        &db,
        &record_id,
        FacetSetPayload {
            key: "current".into(),
            value: Some("12".into()),
            vocab_ref: None,
            as_of: Some("2026-08-03T09:00:00.000Z".into()),
            observation_only: false,
        },
    )
    .await
    .unwrap();

    let first = call(
        &registry,
        &db,
        set_args(&record_id, json!(10), "2026-08-01T01:00:00+01:00"),
    )
    .await;
    assert_eq!(first["as_of"], "2026-08-01T00:00:00.000Z");
    let correction = call(
        &registry,
        &db,
        set_args(&record_id, json!(11), "2026-08-01T00:00:00Z"),
    )
    .await;
    assert!(correction["event_seq"].as_i64() > first["event_seq"].as_i64());

    let current: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'current'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(current, "12", "historical correction changed current state");

    let listed = call(
        &registry,
        &db,
        json!({ "action": "list", "record_id": record_id, "key": "current" }),
    )
    .await;
    assert_eq!(listed["observations"].as_array().unwrap().len(), 2);
    assert_eq!(listed["observations"][0]["value"], "11");
    assert_eq!(
        listed["observations"][0]["as_of"],
        "2026-08-01T00:00:00.000Z"
    );
    assert_eq!(listed["observations"][1]["value"], "12");
    assert_eq!(listed["next_after_as_of"], Value::Null);

    let events = sqlx::query(
        "SELECT seq, json_extract(payload, '$.value') AS value
           FROM content_events
          WHERE record_id = ? AND type = 'facet.set'
          ORDER BY seq",
    )
    .bind(&record_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        events.len(),
        3,
        "same-time correction lost event provenance"
    );
    assert_eq!(events[1].get::<String, _>("value"), "10");
    assert_eq!(events[2].get::<String, _>("value"), "11");

    let rebuilt = rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{:?}", rebuilt.tables);
    db.close().await;
}

#[tokio::test]
async fn list_is_windowed_oldest_first_and_keyset_paged() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &record_id,
        FacetSetPayload {
            key: "current".into(),
            value: Some("99".into()),
            vocab_ref: None,
            as_of: Some("2026-08-01T00:00:00.000Z".into()),
            observation_only: false,
        },
    )
    .await
    .unwrap();
    for (day, value) in [(1, 10), (2, 20), (3, 30), (4, 40)] {
        call(
            &registry,
            &db,
            set_args(
                &record_id,
                json!(value),
                &format!("2026-08-{day:02}T00:00:00Z"),
            ),
        )
        .await;
    }

    let page_one = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "current", "limit": 2
        }),
    )
    .await;
    assert_eq!(page_one["observations"][0]["value"], "10");
    assert_eq!(page_one["observations"][1]["value"], "20");
    let cursor = page_one["next_after_as_of"].as_str().unwrap();
    let page_two = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "current",
            "after_as_of": cursor, "limit": 2
        }),
    )
    .await;
    assert_eq!(page_two["observations"][0]["value"], "30");
    assert_eq!(page_two["observations"][1]["value"], "40");
    assert_eq!(page_two["next_after_as_of"], Value::Null);

    let window = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "current",
            "from_as_of": "2026-08-02T01:00:00+01:00",
            "to_as_of": "2026-08-03T00:00:00Z"
        }),
    )
    .await;
    assert_eq!(window["observations"].as_array().unwrap().len(), 2);
    assert_eq!(window["observations"][0]["value"], "20");
    assert_eq!(window["observations"][1]["value"], "30");

    let unset = call(
        &registry,
        &db,
        json!({
            "action": "unset", "record_id": record_id, "key": "current",
            "as_of": "2026-08-05T00:00:00Z",
            "reason": "Record that the measurement was absent at this valid time."
        }),
    )
    .await;
    assert_eq!(unset["status"], "unset");
    let final_page = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "current",
            "after_as_of": "2026-08-04T00:00:00Z"
        }),
    )
    .await;
    assert_eq!(final_page["observations"][0]["op"], "unset");
    assert_eq!(final_page["observations"][0]["value"], Value::Null);
    let current: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'current'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        current, "99",
        "observation-only unset deleted current state"
    );
    db.close().await;
}

#[tokio::test]
async fn returned_legacy_date_only_cursor_round_trips_unchanged() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "legacy metric" }),
    )
    .await
    .unwrap();
    for (as_of, value) in [("2026-07-01", "10"), ("2026-07-02", "20")] {
        set_facet(
            &db,
            &record_id,
            FacetSetPayload {
                key: "legacy".into(),
                value: Some(value.into()),
                vocab_ref: None,
                as_of: Some(as_of.into()),
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }

    let first = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "legacy", "limit": 1
        }),
    )
    .await;
    assert_eq!(first["observations"][0]["value"], "10");
    assert_eq!(first["next_after_as_of"], "2026-07-01");

    let second = call(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "legacy",
            "after_as_of": first["next_after_as_of"], "limit": 1
        }),
    )
    .await;
    assert_eq!(second["observations"][0]["value"], "20");
    assert_eq!(second["next_after_as_of"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn supported_shape_and_vocabulary_guards_apply_in_observation_transaction() {
    // This fixture supplies its own recommended pack and confidence lifecycle.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    let registry = registry();
    seed_pack_schema_config(
        &db,
        "@native/recommended",
        json!({ "shapes": { "WorkItem": { "facets": {
            "score": { "type": "number" },
            "effort": { "values": ["s", "m"] },
            "confidence": { "vocab": "confidence" }
        } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    create_vocabulary(&db, "confidence", None).await.unwrap();
    create_vocabulary(&db, "other", None).await.unwrap();
    let active = propose_value(&db, "confidence", "likely", None)
        .await
        .unwrap();
    promote_value(&db, &active).await.unwrap();
    let _proposed = propose_value(&db, "confidence", "speculative", None)
        .await
        .unwrap();
    let record_id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "guarded" }),
    )
    .await
    .unwrap();

    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "score", "value": "42",
            "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
        }),
    )
    .await;
    assert!(err.contains("requires a JSON number"), "{err}");
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "effort", "value": "xl",
            "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
        }),
    )
    .await;
    assert!(err.contains("declared values set"), "{err}");
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "confidence",
            "value": "speculative", "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
        }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "confidence", "value": "likely",
            "vocab_ref": "other", "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
        }),
    )
    .await;
    assert!(err.contains("conflicting vocab_ref"), "{err}");

    let accepted = call(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "confidence", "value": "likely",
            "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
        }),
    )
    .await;
    assert_eq!(accepted["status"], "set");
    let stored_ref: String = sqlx::query_scalar(
        "SELECT vocab_ref FROM facet_observations WHERE record_id = ? AND key = 'confidence'",
    )
    .bind(&record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(stored_ref.starts_with("rec:"), "{stored_ref}");

    for key in ["lifecycle", "archived", "blob_ref", "canvas.promoted_from"] {
        let err = call_err(
            &registry,
            &db,
            json!({
                "action": "set", "record_id": record_id, "key": key, "value": "x",
                "as_of": "2026-08-01T00:00:00Z", "reason": "Fixture"
            }),
        )
        .await;
        assert!(
            err.contains("spine facet") || err.contains("engine-reserved"),
            "{err}"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn timestamps_and_write_contract_fail_closed() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let record_id = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "metric" }),
    )
    .await
    .unwrap();

    for bad in ["2026-08-01", "not-a-time"] {
        let err = call_err(&registry, &db, set_args(&record_id, json!(10), bad)).await;
        assert!(err.contains("RFC3339 timestamp"), "{err}");
    }
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "current", "value": 10,
            "as_of": "2026-08-01T00:00:00Z"
        }),
    )
    .await;
    assert!(err.contains("missing field `reason`"), "{err}");
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "set", "record_id": record_id, "key": "current", "value": 10,
            "as_of": "2026-08-01T00:00:00Z", "reason": "   "
        }),
    )
    .await;
    assert!(err.contains("non-whitespace"), "{err}");
    let err = call_err(
        &registry,
        &db,
        json!({
            "action": "list", "record_id": record_id, "key": "current", "limit": 1001
        }),
    )
    .await;
    assert!(err.contains("between 1 and 1000"), "{err}");
    db.close().await;
}
