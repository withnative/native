// Record ids must be canonical v4/v7 UUIDs, so every fixture id here is a
// pinned `0c70e000-0000-4000-8000-<counter>` literal.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
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

fn impact() -> Value {
    json!({
        "claim": "Approximately 50 additional members per month can participate",
        "method": "declared",
        "effective_at": "2026-08-03T00:00:00Z",
        "magnitude": {
            "value": 50,
            "unit": "members",
            "per": "month"
        },
        "measurement_window": {
            "start": "2026-07-01T00:00:00Z",
            "end": "2026-07-31T23:59:59Z"
        }
    })
}

#[tokio::test]
async fn governed_impact_shape_is_atomic_validated_and_read_as_an_object() {
    let db = db().await;
    let registry = registry();

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000007",
            "type": "Outcome",
            "kind": "impact",
            "name": "Matching participation",
            "persistence": "occurrent",
            "facets": { "impact": impact() }
        }),
    )
    .await;
    assert_eq!(created["kind"], "impact");
    assert_eq!(created["facets"][0]["key"], "impact");
    assert_eq!(created["facets"][0]["value"], impact());

    let date_only = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000004",
            "type": "Outcome",
            "kind": "impact",
            "facets": { "impact": {
                "claim": "Approximately 50 additional members per month can participate",
                "method": "declared",
                "effective_at": "2026-08-03",
                "measurement_window": {
                    "start": "2026-07-01",
                    "end": "2026-07-31"
                }
            } }
        }),
    )
    .await;
    assert_eq!(
        date_only["facets"][0]["value"]["effective_at"],
        "2026-08-03"
    );

    let legacy = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000001",
            "type": "Document",
            "kind": "note",
            "facets": { "legacy": "{\"foo\":\"bar\"}" }
        }),
    )
    .await;
    assert_eq!(legacy["facets"][0]["value"], "{\"foo\":\"bar\"}");

    let cases = [
        (
            "missing-claim",
            json!({
                "method": "declared", "effective_at": "2026-08-03T00:00:00Z"
            }),
        ),
        (
            "blank-claim",
            json!({
                "claim": "  ", "method": "declared", "effective_at": "2026-08-03T00:00:00Z"
            }),
        ),
        (
            "bad-method",
            json!({
                "claim": "A change", "method": "guessed", "effective_at": "2026-08-03T00:00:00Z"
            }),
        ),
        (
            "bad-effective-at",
            json!({
                "claim": "A change", "method": "declared", "effective_at": "03/08/2026"
            }),
        ),
        (
            "bad-magnitude",
            json!({
                "claim": "A change", "method": "declared", "effective_at": "2026-08-03T00:00:00Z",
                "magnitude": { "value": 50, "unit": " " }
            }),
        ),
        (
            "reversed-window",
            json!({
                "claim": "A change", "method": "derived", "effective_at": "2026-08-03T00:00:00Z",
                "measurement_window": {
                    "start": "2026-08-02T00:00:00Z", "end": "2026-08-01T00:00:00Z"
                }
            }),
        ),
    ];
    // Record ids must be canonical v4/v7 UUIDs, so the readable case name stays
    // the assertion label while the id is a pinned per-case counter.
    for (ordinal, (label, invalid)) in cases.into_iter().enumerate() {
        let error = call_err(
            &registry,
            &db,
            "create_record",
            json!({
                "id": format!("0c70e001-0000-4000-8000-{ordinal:012}"),
                "type": "Outcome",
                "kind": "impact",
                "facets": { "impact": invalid }
            }),
        )
        .await;
        assert!(
            error.contains("facet 'impact' does not conform"),
            "{label}: {error}"
        );
    }

    db.close().await;
}

#[tokio::test]
async fn user_schema_cannot_loosen_a_pack_object_contract() {
    let db = db().await;
    let registry = registry();

    let error = call_err(
        &registry,
        &db,
        "manage_schema_config",
        json!({
            "action": "write",
            "data": { "shapes": { "Outcome:impact": { "facets": {
                "impact": { "type": "object" }
            } } } }
        }),
    )
    .await;
    assert!(
        error.contains("cannot loosen object facet 'impact'"),
        "{error}"
    );

    let resolved = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read" }),
    )
    .await;
    let exact = resolved["pack"]["shapes"]["Outcome:impact"]["facets"]["impact"].clone();
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({
            "action": "write",
            "data": { "shapes": { "Outcome:impact": { "facets": {
                "impact": exact
            } } } }
        }),
    )
    .await;

    db.close().await;
}

#[tokio::test]
async fn object_ordering_is_enforced_without_a_json_schema() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({
            "action": "write",
            "data": { "shapes": { "Document:note": { "facets": {
                "period": {
                    "type": "object",
                    "temporal_order": [{ "earlier": "start", "later": "end" }]
                }
            } } } }
        }),
    )
    .await;

    let error = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000002",
            "type": "Document",
            "kind": "note",
            "facets": { "period": {
                "start": "2026-08-02T00:00:00Z",
                "end": "2026-08-01T00:00:00Z"
            } }
        }),
    )
    .await;
    assert!(
        error.contains("'start' must not be later than 'end'"),
        "{error}"
    );

    db.close().await;
}

#[tokio::test]
async fn impact_corrections_use_ordinary_update_and_history() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000003",
            "type": "Outcome",
            "kind": "impact",
            "facets": { "impact": impact() }
        }),
    )
    .await;

    let mut corrected = impact();
    corrected["claim"] = json!("Approximately 32 additional members per month can participate");
    corrected["magnitude"]["value"] = json!(32);
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000003",
            "facets": { "impact": corrected }
        }),
    )
    .await;
    assert_eq!(updated["facets"][0]["value"]["magnitude"]["value"], 32);

    let history = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": "0c70e000-0000-4000-8000-000000000003", "detail": "full" }),
    )
    .await;
    let events = history["events"].as_array().unwrap();
    let impact_sets = events
        .iter()
        .filter(|event| event["type"] == "facet.set" && event["payload"]["key"] == "impact")
        .collect::<Vec<_>>();
    assert_eq!(impact_sets.len(), 2);
    let first: Value =
        serde_json::from_str(impact_sets[0]["payload"]["value"].as_str().unwrap()).unwrap();
    let second: Value =
        serde_json::from_str(impact_sets[1]["payload"]["value"].as_str().unwrap()).unwrap();
    assert_eq!(first["magnitude"]["value"], 50);
    assert_eq!(second["magnitude"]["value"], 32);

    db.close().await;
}

#[tokio::test]
async fn impacts_family_uses_event_time_kind_and_preserves_pinned_paging() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000005",
            "type": "Outcome",
            "kind": "impact",
            "facets": { "impact": impact() }
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000005", "maturity": "verified" }),
    )
    .await;

    let first = call(
        &registry,
        &db,
        "whats_changed",
        json!({ "event_families": ["impacts"], "limit": 1 }),
    )
    .await;
    assert_eq!(first["matched_event_count"], 1);
    assert_eq!(
        first["changes"][0]["event_families"],
        json!(["created", "impacts"])
    );
    let pinned = first["high_water_local_seq"].as_i64().unwrap();
    let next = first["next_request"].clone();
    assert_eq!(next["event_families"], json!(["impacts"]));

    // A later correction is outside the caller's pinned traversal.
    let mut late = impact();
    late["claim"] = json!("A later correction");
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000005", "facets": { "impact": late } }),
    )
    .await;

    let mut cursor = next;
    let mut seen = 1;
    loop {
        let page = call(&registry, &db, "whats_changed", cursor).await;
        assert_eq!(page["high_water_local_seq"], pinned);
        seen += page["matched_event_count"].as_i64().unwrap();
        if page["next_request"].is_null() {
            break;
        }
        cursor = page["next_request"].clone();
    }
    assert_eq!(
        seen, 3,
        "creation, initial impact facet and maturity update"
    );

    // Once the record changes kind, later events no longer belong to impacts.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000005", "kind": "target" }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000005", "summary": "No longer impact" }),
    )
    .await;
    let after = call(
        &registry,
        &db,
        "whats_changed",
        json!({ "after_local_seq": pinned, "event_families": ["impacts"] }),
    )
    .await;
    assert_eq!(
        after["matched_event_count"], 1,
        "only the late correction precedes the kind change"
    );
    assert_eq!(
        after["changes"][0]["changed_fields"],
        json!(["facet:impact"])
    );

    db.close().await;
}

#[tokio::test]
async fn impact_links_and_deletion_remain_ordinary_impact_events() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000008", "type": "WorkItem", "kind": "task" }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "0c70e000-0000-4000-8000-000000000006",
            "type": "Outcome",
            "kind": "impact",
            "facets": { "impact": impact() },
            "links": [{
                "target_id": "0c70e000-0000-4000-8000-000000000008",
                "relationship": "derived_from"
            }]
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": "0c70e000-0000-4000-8000-000000000006" }),
    )
    .await;

    let changes = call(
        &registry,
        &db,
        "whats_changed",
        json!({ "event_families": ["impacts"] }),
    )
    .await;
    assert_eq!(changes["matched_event_count"], 4);
    let types = changes["changes"][0]["event_types"].as_array().unwrap();
    assert!(types.contains(&json!("link.added")));
    assert!(types.contains(&json!("record.deleted")));
    assert!(changes["changes"][0]["event_families"]
        .as_array()
        .unwrap()
        .contains(&json!("impacts")));

    db.close().await;
}
