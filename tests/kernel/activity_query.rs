//! Composable `query_record.activity` terminal.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::events::{FacetSetPayload, LinkAddedPayload, LinkRemovedPayload};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{
    add_link, append, create_record, create_record_as, remove_link, set_facet, update_record,
    AppendSpec,
};
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

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            "query_record",
            crate::common::with_test_reason("query_record", args),
        )
        .await
}

async fn call(registry: &ToolRegistry, db: &Db, args: Value) -> Value {
    call_as(registry, db, Caller::local(), args).await.unwrap()
}

fn link(source: &str, target: &str, relationship: &str) -> LinkAddedPayload {
    LinkAddedPayload {
        id: None,
        source_id: source.into(),
        target_id: target.into(),
        relationship: relationship.into(),
        note: None,
    }
}

fn event_clause() -> Value {
    json!({ "kind": "event", "event_types": ["record.updated"] })
}

#[tokio::test]
async fn activity_clauses_return_one_event_with_all_typed_evidence() {
    let db = db().await;
    let registry = registry();
    native_ce::meta::create_vocabulary(&db, "test-lifecycle", None)
        .await
        .unwrap();
    for (value, terminality) in [
        ("active", native_ce::meta::VocabularyValueTerminality::Open),
        (
            "completed",
            native_ce::meta::VocabularyValueTerminality::TerminalPositive,
        ),
    ] {
        let value_id = native_ce::meta::propose_value_with_metadata_as(
            &db,
            "test-lifecycle",
            value,
            None,
            0.0,
            terminality,
            None,
        )
        .await
        .unwrap();
        native_ce::meta::promote_value(&db, &value_id)
            .await
            .unwrap();
    }
    native_ce::meta::create_vocabulary(&db, "unrelated-lifecycle", None)
        .await
        .unwrap();
    let conflicting = native_ce::meta::propose_value_with_metadata_as(
        &db,
        "unrelated-lifecycle",
        "completed",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::TerminalNegative,
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &conflicting)
        .await
        .unwrap();
    native_ce::meta::write_user_schema_config(
        &db,
        json!({
            "shapes": {
                "WorkItem": {
                    "facets": {
                        "lifecycle": { "vocab_ref": "test-lifecycle",
                            "axis": { "key": "test_status", "label": "Test status" } }
                    }
                }
            }
        }),
        native_ce::meta::SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    let anchor = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "Anchor" }),
    )
    .await
    .unwrap();
    let task = create_record(
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Task",
            "lifecycle": "active"
        }),
    )
    .await
    .unwrap();
    update_record(
        &db,
        &task,
        json!({ "lifecycle": "completed", "summary": "Shipped" }),
    )
    .await
    .unwrap();
    let delivery_vocabulary = native_ce::meta::create_vocabulary(&db, "delivery-vocabulary", None)
        .await
        .unwrap();
    let released = native_ce::meta::propose_value_with_metadata_as(
        &db,
        "delivery-vocabulary",
        "released",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::TerminalPositive,
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &released)
        .await
        .unwrap();
    native_ce::meta::create_vocabulary(&db, "unrelated-delivery", None)
        .await
        .unwrap();
    let conflicting_release = native_ce::meta::propose_value_with_metadata_as(
        &db,
        "unrelated-delivery",
        "released",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::TerminalNegative,
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &conflicting_release)
        .await
        .unwrap();
    set_facet(
        &db,
        &task,
        FacetSetPayload {
            key: "delivery".into(),
            value: Some("released".into()),
            vocab_ref: Some(native_ce::meta::vocab_ref(&delivery_vocabulary)),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    add_link(&db, link(&task, &anchor, "part_of"))
        .await
        .unwrap();

    let out = call(
        &registry,
        &db,
        json!({
            "steps": [
                { "step": "filter", "ids": [&task] }
            ],
            "activity": {
                "actions": { "any": [
                    { "kind": "event", "event_types": ["record.updated"], "changed_fields_all": ["lifecycle", "summary"] },
                    { "kind": "field_transition", "field": "lifecycle", "from": "active", "to_terminality": "terminal_positive" }
                ] }
            }
        }),
    )
    .await;
    assert_eq!(out["matched_event_count"], 1);
    assert_eq!(out["activities"][0]["event"]["record_id"], task);
    assert_eq!(out["activities"][0]["matches"].as_array().unwrap().len(), 2);
    assert_eq!(out["activities"][0]["matches"][1]["before"], "active");
    assert_eq!(out["activities"][0]["matches"][1]["after"], "completed");
    assert_eq!(
        out["activities"][0]["matches"][1]["after_terminality"],
        "terminal_positive"
    );
    let rendered = native_ce::mcp::render::render("query_record", &out).unwrap();
    for sentinel in [
        "field_transition",
        "active",
        "completed",
        "terminal_positive",
    ] {
        assert!(
            rendered.contains(sentinel),
            "missing {sentinel}:\n{rendered}"
        );
    }

    // The same token in an unrelated, conflicting vocabulary cannot suppress
    // the governed WorkItem result, and cannot create a result for a type with
    // no governing lifecycle vocabulary.
    let ungoverned = create_record(
        &db,
        json!({
            "type": "Outcome", "kind": "result", "name": "Ungoverned",
            "lifecycle": "active"
        }),
    )
    .await
    .unwrap();
    update_record(&db, &ungoverned, json!({ "lifecycle": "completed" }))
        .await
        .unwrap();
    let ungoverned_out = call(
        &registry,
        &db,
        json!({
            "steps": [{ "step": "filter", "ids": [&ungoverned] }],
            "activity": { "actions": { "any": [{
                "kind": "field_transition", "field": "lifecycle",
                "to_terminality": "terminal_positive"
            }] } }
        }),
    )
    .await;
    assert_eq!(ungoverned_out["matched_event_count"], 0);

    let facets = call(
        &registry,
        &db,
        json!({
            "steps": [{ "step": "filter", "ids": [&task] }],
            "activity": { "actions": { "any": [{
                "kind": "facet_transition", "key": "delivery", "from": null, "to": "released",
                "to_terminality": "terminal_positive"
            }] } }
        }),
    )
    .await;
    assert_eq!(facets["matched_event_count"], 1);
    assert_eq!(
        facets["activities"][0]["matches"][0]["kind"],
        "facet_transition"
    );
    assert_eq!(
        facets["activities"][0]["matches"][0]["after_terminality"],
        "terminal_positive"
    );

    let links = call(
        &registry,
        &db,
        json!({
            "steps": [{ "step": "filter", "ids": [&anchor] }],
            "activity": { "actions": { "any": [{
                "kind": "link_change", "change": "added", "relationship": "part_of", "direction": "in"
            }] } }
        }),
    )
    .await;
    assert_eq!(links["matched_event_count"], 1);
    assert_eq!(links["activities"][0]["matches"][0]["direction"], "in");
}

#[tokio::test]
async fn activity_membership_is_at_pinned_window_end_and_continuation_is_stable() {
    let db = db().await;
    let registry = registry();
    let anchor = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "epic", "name": "Anchor" }),
    )
    .await
    .unwrap();
    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Task" }),
    )
    .await
    .unwrap();
    // The first matching event predates classification under the anchor. It is
    // nevertheless in scope because membership is evaluated at window end.
    update_record(&db, &task, json!({ "summary": "first" }))
        .await
        .unwrap();
    add_link(&db, link(&task, &anchor, "part_of"))
        .await
        .unwrap();
    update_record(&db, &task, json!({ "summary": "second" }))
        .await
        .unwrap();
    let detached = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Detached" }),
    )
    .await
    .unwrap();
    add_link(&db, link(&detached, &anchor, "part_of"))
        .await
        .unwrap();
    update_record(
        &db,
        &detached,
        json!({ "summary": "not in cutoff membership" }),
    )
    .await
    .unwrap();
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: detached,
            target_id: anchor.clone(),
            relationship: "part_of".into(),
        },
    )
    .await
    .unwrap();

    let first = call(
        &registry,
        &db,
        json!({
            "steps": [
                { "step": "filter", "ids": [&anchor] },
                { "step": "traverse", "target": "links", "relationship": "part_of", "direction": "in" }
            ],
            "activity": { "actions": { "any": [event_clause()] }, "limit": 1 }
        }),
    )
    .await;
    assert_eq!(first["matched_event_count"], 1);
    assert_eq!(first["has_more"], true);
    assert_eq!(
        first["subject_as_of_local_seq"],
        first["high_water_local_seq"]
    );
    assert!(first["local_database_id"].as_str().is_some());
    assert!(first["activities"][0]["event"]["local_seq"]
        .as_i64()
        .is_some());
    assert!(first["activities"][0]["event"].get("seq").is_none());
    assert!(first["next_request"]["activity"]["after_local_seq"]
        .as_i64()
        .is_some());
    assert!(first["next_request"]["activity"].get("after_seq").is_none());
    let pinned = first["high_water_local_seq"].as_i64().unwrap();

    update_record(&db, &task, json!({ "summary": "after the pin" }))
        .await
        .unwrap();
    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: task.clone(),
            target_id: anchor,
            relationship: "part_of".into(),
        },
    )
    .await
    .unwrap();
    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["high_water_local_seq"], pinned);
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(
        second["activities"][0]["event"]["payload"]["summary"],
        "second"
    );
    assert_eq!(second["has_more"], false);
    assert!(second["next_request"].is_null());
}

#[tokio::test]
async fn activity_terminal_is_exclusive_and_saved_v02_rejects_it() {
    let db = db().await;
    let registry = registry();
    let error = call_as(
        &registry,
        &db,
        Caller::local(),
        json!({
            "steps": [{ "step": "filter" }],
            "order": "name_asc",
            "activity": { "actions": { "any": [event_clause()] } }
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("reject record ordering and paging"),
        "{error}"
    );
    let schema = &registry.get("query_record").unwrap().input_schema;
    assert_eq!(
        schema["properties"]["activity"]["properties"]["actions"]["properties"]["any"]["minItems"],
        1
    );
    let action =
        &schema["properties"]["activity"]["properties"]["actions"]["properties"]["any"]["items"];
    assert_eq!(
        action["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        action["properties"]["from"]["type"],
        json!(["string", "number", "null"])
    );

    let collection = create_record(
        &db,
        json!({ "type": "Collection", "kind": "query", "name": "Saved activity" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &collection,
        FacetSetPayload {
            key: "query".into(),
            value: Some(
                json!({
                    "v": "0.2",
                    "query": {
                        "steps": [{ "step": "filter" }],
                        "activity": { "actions": { "any": [event_clause()] } }
                    }
                })
                .to_string(),
            ),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let resolved = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_record",
            json!({ "ids": [&collection] }),
        )
        .await
        .unwrap();
    assert_eq!(resolved["records"][0]["has_query"], false);
    assert_eq!(
        resolved["records"][0]["query_resolution"]["status"],
        "invalid"
    );
    assert!(resolved["records"][0]["query_resolution"]["diagnostic"]
        .as_str()
        .unwrap()
        .contains("must return records"));
}

#[tokio::test]
async fn activity_transition_selectors_use_the_declared_scalar_contract() {
    let db = db().await;
    let registry = registry();
    let record = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Numeric facet" }),
    )
    .await
    .unwrap();
    for value in ["1.5", "2.5"] {
        set_facet(
            &db,
            &record,
            FacetSetPayload {
                key: "score".into(),
                value: Some(value.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }
    let numeric = call(
        &registry,
        &db,
        json!({
            "steps": [{ "step": "filter", "ids": [&record] }],
            "activity": { "actions": { "any": [{
                "kind": "facet_transition", "key": "score",
                "from": 1.5, "to": 2.5
            }] } }
        }),
    )
    .await;
    assert_eq!(numeric["matched_event_count"], 1);
    assert_eq!(numeric["activities"][0]["matches"][0]["before"], "1.5");
    assert_eq!(numeric["activities"][0]["matches"][0]["after"], "2.5");

    for invalid in [json!(true), json!({ "value": "x" }), json!(["x"])] {
        let error = call_as(
            &registry,
            &db,
            Caller::local(),
            json!({
                "steps": [{ "step": "filter", "ids": [&record] }],
                "activity": { "actions": { "any": [{
                    "kind": "facet_transition", "key": "score", "from": invalid
                }] } }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("activity transition values must be a string, number, or null"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn authorization_and_redaction_precede_activity_page_occupancy() {
    let db = db().await;
    let registry = registry();
    let visible = create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Visible" }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    let hidden = create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Hidden" }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    append(
        &db,
        AppendSpec {
            record_id: visible.clone(),
            event_type: "record.updated".into(),
            payload: json!({ "summary": "visible update" }),
            actor: Some("acct:other".into()),
        },
    )
    .await
    .unwrap();
    update_record(&db, &hidden, json!({ "summary": "hidden update" }))
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity",
        &visible,
        vec![AllowEntry::account("acct:viewer", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity",
        &hidden,
        vec![AllowEntry::account("acct:other", Capability::Manage)],
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("acct:viewer")
        .with_hosting_context("host:viewer", "db:test")
        .with_hosting_owner(false);
    let out = call_as(
        &registry,
        &db,
        caller.clone(),
        json!({
            "steps": [{ "step": "filter", "ids": [&visible, &hidden] }],
            "activity": { "actions": { "any": [event_clause()] }, "limit": 1 }
        }),
    )
    .await
    .unwrap();
    assert_eq!(out["matched_event_count"], 1);
    assert_eq!(out["activities"][0]["event"]["record_id"], visible);
    assert_eq!(out["activities"][0]["event"]["actor"], Value::Null);
    assert_eq!(out["has_more"], false);

    // A hidden actor token cannot be tested through the accounts predicate.
    let filtered = call_as(
        &registry,
        &db,
        caller,
        json!({
            "steps": [{ "step": "filter", "ids": [&visible] }],
            "activity": {
                "actors": { "accounts": ["acct:other"] },
                "actions": { "any": [event_clause()] }
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(filtered["matched_event_count"], 0);
}

#[tokio::test]
async fn activity_redacts_hidden_link_endpoints_from_event_and_match_evidence() {
    let db = db().await;
    let registry = registry();
    let visible = create_record_as(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Visible subject" }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    let hidden_endpoint = create_record_as(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Hidden endpoint" }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    add_link(&db, link(&visible, &hidden_endpoint, "relates_to"))
        .await
        .unwrap();
    update_record(&db, &visible, json!({ "summary": "later visible event" }))
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity-link-redaction",
        &visible,
        vec![AllowEntry::account("acct:viewer", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity-link-redaction",
        &hidden_endpoint,
        vec![AllowEntry::account("acct:other", Capability::Manage)],
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("acct:viewer")
        .with_hosting_context("host:viewer", "db:test")
        .with_hosting_owner(false);
    let out = call_as(
        &registry,
        &db,
        caller,
        json!({
            "steps": [{ "step": "filter", "ids": [&visible] }],
            "activity": {
                "actions": { "any": [
                    {
                        "kind": "link_change", "change": "added",
                        "relationship": "relates_to", "direction": "out"
                    },
                    { "kind": "event", "event_types": ["record.updated"] }
                ] },
                "limit": 1
            }
        }),
    )
    .await
    .unwrap();

    assert_eq!(out["matched_event_count"], 1);
    assert_eq!(out["has_more"], true);
    assert_eq!(out["activities"][0]["event"]["record_id"], visible);
    assert_eq!(
        out["activities"][0]["event"]["payload"]["target_id"],
        Value::Null
    );
    assert_eq!(out["activities"][0]["matches"][0]["target_id"], Value::Null);
    assert_eq!(out["activities"][0]["matches"][0]["source_id"], visible);
    assert!(!out["next_request"].to_string().contains(&hidden_endpoint));
    assert!(!out.to_string().contains(&hidden_endpoint));
    let rendered = native_ce::mcp::render::render("query_record", &out).unwrap();
    assert!(!rendered.contains(&hidden_endpoint), "{rendered}");
    assert!(rendered.contains("relates_to"), "{rendered}");
    assert!(rendered.contains("link_change"), "{rendered}");
    assert!(rendered.contains(&visible), "{rendered}");
    let rendered_next = rendered
        .lines()
        .find_map(|line| line.strip_prefix("next_request: "))
        .expect("rendered activity page must carry its replayable next_request");
    assert_eq!(
        serde_json::from_str::<Value>(rendered_next).unwrap(),
        out["next_request"]
    );
}

#[tokio::test]
async fn activity_terminality_cannot_infer_schema_anchored_to_a_hidden_home() {
    let db = db().await;
    let registry = registry();
    let home = create_record_as(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Hidden home" }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    native_ce::meta::create_vocabulary(&db, "hidden-home-lifecycle", None)
        .await
        .unwrap();
    let mut finished_id = None;
    for (value, terminality) in [
        ("working", native_ce::meta::VocabularyValueTerminality::Open),
        (
            "finished",
            native_ce::meta::VocabularyValueTerminality::TerminalPositive,
        ),
    ] {
        let id = native_ce::meta::propose_value_with_metadata_as(
            &db,
            "hidden-home-lifecycle",
            value,
            None,
            0.0,
            terminality,
            None,
        )
        .await
        .unwrap();
        native_ce::meta::promote_value(&db, &id).await.unwrap();
        if value == "finished" {
            finished_id = Some(id);
        }
    }
    let alias_id = native_ce::meta::propose_value(&db, "hidden-home-lifecycle", "done", None)
        .await
        .unwrap();
    native_ce::meta::promote_value(&db, &alias_id)
        .await
        .unwrap();
    native_ce::meta::alias_value(&db, &alias_id, &finished_id.unwrap())
        .await
        .unwrap();
    native_ce::meta::write_user_schema_config(
        &db,
        json!({
            "shapes": {
                "WorkItem": {
                    "facets": {
                        "lifecycle": { "vocab_ref": "hidden-home-lifecycle",
                            "axis": { "key": "hidden_status", "label": "Hidden status" } }
                    }
                }
            }
        }),
        native_ce::meta::SchemaConfigOptions {
            applies_to_collection_id: Some(home.clone()),
            ..native_ce::meta::SchemaConfigOptions::default()
        },
    )
    .await
    .unwrap();
    let task = create_record_as(
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Visible exception",
            "home_id": &home, "lifecycle": "working"
        }),
        Some("acct:other"),
    )
    .await
    .unwrap();
    update_record(&db, &task, json!({ "lifecycle": "finished" }))
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity-hidden-schema-home",
        &home,
        vec![
            AllowEntry::account("acct:other", Capability::Manage),
            AllowEntry::account("acct:allowed", Capability::View),
        ],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:activity-hidden-schema-home",
        &task,
        vec![
            AllowEntry::account("acct:viewer", Capability::View),
            AllowEntry::account("acct:allowed", Capability::View),
        ],
    )
    .await
    .unwrap();
    let request = json!({
        "steps": [{ "step": "filter", "ids": [&task] }],
        "activity": { "actions": { "any": [{
            "kind": "field_transition", "field": "lifecycle",
            "to_terminality": "terminal_positive"
        }] }, "limit": 1 }
    });

    let hidden = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:viewer")
            .with_hosting_context("host:viewer", "db:test")
            .with_hosting_owner(false),
        request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(hidden["matched_event_count"], 0);
    assert_eq!(hidden["has_more"], false);
    assert!(hidden["next_request"].is_null());
    assert!(!hidden.to_string().contains("hidden-home-lifecycle"));

    let hidden_record = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:viewer")
            .with_hosting_context("host:viewer", "db:test")
            .with_hosting_owner(false),
        json!({ "steps": [{ "step": "filter", "ids": [&task] }] }),
    )
    .await
    .unwrap();
    assert_eq!(
        hidden_record["records"][0]["lifecycle_interpretation"]["status"],
        "unclassified"
    );
    assert!(!hidden_record.to_string().contains("hidden-home-lifecycle"));
    let hidden_get = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:viewer")
                .with_hosting_context("host:viewer", "db:test")
                .with_hosting_owner(false),
            "get_record",
            crate::common::with_test_reason("get_record", json!({ "ids": [&task] })),
        )
        .await
        .unwrap();
    assert_eq!(
        hidden_get["records"][0]["lifecycle_interpretation"]["status"],
        "unclassified"
    );
    assert!(!hidden_get.to_string().contains("hidden-home-lifecycle"));
    let hidden_alias_filter = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:viewer")
            .with_hosting_context("host:viewer", "db:test")
            .with_hosting_owner(false),
        json!({ "steps": [{ "step": "filter", "ids": [&task], "lifecycle": ["done"] }] }),
    )
    .await
    .unwrap();
    assert!(hidden_alias_filter["records"]
        .as_array()
        .unwrap()
        .is_empty());

    let allowed = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:allowed")
            .with_hosting_context("host:allowed", "db:test")
            .with_hosting_owner(false),
        request,
    )
    .await
    .unwrap();
    assert_eq!(allowed["matched_event_count"], 1);
    assert_eq!(
        allowed["activities"][0]["matches"][0]["vocab_ref"],
        "hidden-home-lifecycle"
    );
    assert_eq!(
        allowed["activities"][0]["matches"][0]["after_terminality"],
        "terminal_positive"
    );

    let allowed_record = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:allowed")
            .with_hosting_context("host:allowed", "db:test")
            .with_hosting_owner(false),
        json!({ "steps": [{ "step": "filter", "ids": [&task] }] }),
    )
    .await
    .unwrap();
    assert_eq!(
        allowed_record["records"][0]["lifecycle_interpretation"]["axis"]["key"],
        "hidden_status"
    );
    assert_eq!(
        allowed_record["records"][0]["lifecycle_interpretation"]["vocabulary"]["name"],
        "hidden-home-lifecycle"
    );
    let allowed_alias_filter = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:allowed")
            .with_hosting_context("host:allowed", "db:test")
            .with_hosting_owner(false),
        json!({ "steps": [{ "step": "filter", "ids": [&task], "lifecycle": ["done"] }] }),
    )
    .await
    .unwrap();
    assert_eq!(allowed_alias_filter["records"][0]["id"], task);
}
