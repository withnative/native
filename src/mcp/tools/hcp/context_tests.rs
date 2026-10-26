//! Slice 4a checks for `searchContext` and `traceContextItem`: envelopes,
//! authorised candidates, model-answer validation, status rules, fields,
//! lexical fallbacks and caps, trace sections and refusals, and the setup
//! gate. The model is always the local TCP mock (`claude::mock`) pointed at
//! through the thread-local test override — never a real API call.

use std::time::Duration;

use serde_json::{json, Value};

use super::claude::{mock, TestModel};
use super::context_search::{INTERPRETATION_MAX_CHARS, WHY_MAX_CHARS};
use super::tests::{alice, caller, harness, onboard, unconfigured_harness, Harness};
use super::{SEARCH_CONTEXT, TOOL_NAMES, TRACE_CONTEXT_ITEM};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::provenance::Channel;

async fn search(harness: &Harness, args: Value) -> Value {
    harness.call(&alice(), SEARCH_CONTEXT, args).await
}

async fn trace(harness: &Harness, args: Value) -> Value {
    harness.call(&alice(), TRACE_CONTEXT_ITEM, args).await
}

fn point_at(server: &mock::MockServer) -> TestModel {
    TestModel::point_at("test-key", &server.base_url, Duration::from_secs(10))
}

fn ranking(items: &[(&str, &str)], interpretation: &str) -> String {
    mock::ranking_response(items, interpretation)
}

pub(super) fn web() -> Caller {
    Caller::authenticated("acct:alice").with_channel(Channel::Web)
}

pub(super) fn bob() -> Caller {
    caller("acct:bob", Some("client_bob_app"))
}

async fn native(db: &crate::db::Db, who: &Caller, tool: &str, arguments: Value) -> Value {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(db.clone(), who.clone(), tool, arguments))
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

/// Create an ordinary record as `who`; returns its id.
async fn make(
    harness: &Harness,
    who: &Caller,
    record_type: &str,
    kind: &str,
    name: &str,
    body: &str,
    extra: Value,
) -> String {
    let mut arguments = json!({
        "type": record_type,
        "kind": kind,
        "name": name,
        "body": body,
        "reason": "slice 4a fixture",
        "sources": [],
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        arguments[key] = value;
    }
    let created = native(&harness.db, who, "create_record", arguments).await;
    assert!(created["id"].is_string(), "{created}");
    created["id"].as_str().unwrap().to_string()
}

async fn note(harness: &Harness, name: &str, body: &str) -> String {
    make(harness, &alice(), "Document", "note", name, body, json!({})).await
}

/// A note with one outgoing link of `relationship` to `target`.
async fn linked_note(
    harness: &Harness,
    name: &str,
    body: &str,
    target: &str,
    relationship: &str,
) -> String {
    make(
        harness,
        &alice(),
        "Document",
        "note",
        name,
        body,
        json!({ "links": [{ "target_id": target, "relationship": relationship }] }),
    )
    .await
}

async fn decision(harness: &Harness, name: &str, body: &str) -> String {
    make(
        harness,
        &alice(),
        "Resolution",
        "decision",
        name,
        body,
        json!({}),
    )
    .await
}

/// An open suggestion record on `target`, as the workbench writes one.
async fn suggest_on(harness: &Harness, who: &Caller, target: &str, body: &str) -> String {
    let record = native(
        &harness.db,
        &alice(),
        "get_record",
        json!({ "ids": [target] }),
    )
    .await;
    let digest = record["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let created = native(
        &harness.db,
        who,
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": body,
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "facets": {
                "proposal.precondition": "digest",
                "anchor.base_digest": digest,
            },
            "reason": "slice 4a fixture",
            "sources": [],
        }),
    )
    .await;
    assert!(created["id"].is_string(), "{created}");
    created["id"].as_str().unwrap().to_string()
}

/// Search with the model forced off: the lexical path, no `why`.
async fn lexical(harness: &Harness, args: Value) -> Value {
    let _model = TestModel::not_configured();
    search(harness, args).await
}

#[test]
fn both_context_tools_are_advertised_read_only() {
    assert!(TOOL_NAMES.contains(&SEARCH_CONTEXT));
    assert!(TOOL_NAMES.contains(&TRACE_CONTEXT_ITEM));
    let descriptors = super::hcp_tool_descriptors();
    for name in [SEARCH_CONTEXT, TRACE_CONTEXT_ITEM] {
        let descriptor = descriptors
            .iter()
            .find(|d| d["name"] == name)
            .expect("descriptor");
        assert_eq!(descriptor["annotations"]["readOnlyHint"], true);
        assert_eq!(descriptor["annotations"]["openWorldHint"], false);
    }
    let search = descriptors
        .iter()
        .find(|d| d["name"] == SEARCH_CONTEXT)
        .unwrap();
    assert_eq!(search["inputSchema"]["required"], json!(["task"]));
    let trace = descriptors
        .iter()
        .find(|d| d["name"] == TRACE_CONTEXT_ITEM)
        .unwrap();
    assert_eq!(trace["inputSchema"]["required"], json!(["ref"]));
}

#[tokio::test]
async fn short_refs_round_trip_through_trace_and_scope() {
    let h = harness().await;
    let folder = make(
        &h,
        &alice(),
        "Collection",
        "folder",
        "sycamore project",
        "",
        json!({}),
    )
    .await;
    make(
        &h,
        &alice(),
        "Document",
        "note",
        "sycamore note",
        "Sycamore standup notes",
        json!({ "home_id": folder }),
    )
    .await;
    let found = lexical(&h, json!({ "task": "sycamore standup" })).await;
    let item = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["title"] == "sycamore note")
        .unwrap_or_else(|| panic!("{found}"))
        .clone();
    let short = item["ref"].as_str().unwrap().to_string();
    assert!(short.len() < folder.len(), "{short}");
    // The returned short ref traces directly.
    let traced = trace(&h, json!({ "ref": short })).await;
    assert_eq!(traced["success"], true, "{traced}");
    assert_eq!(traced["item"]["title"], "sycamore note", "{traced}");
    // And scopes by short ref too.
    let folder_ref = hcp_short_ref(&h, &folder).await;
    let scoped = lexical(
        &h,
        json!({ "task": "sycamore standup", "scope": { "project": folder_ref } }),
    )
    .await;
    let titles: Vec<&str> = scoped["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["sycamore note"], "{titles:?}");
}

async fn hcp_short_ref(harness: &Harness, id: &str) -> String {
    let record = native(&harness.db, &alice(), "get_record", json!({ "ids": [id] })).await;
    record["records"][0]["display_reference"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn preference_provenance_matches_layer_one() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("concise")).await;
    let layer1 = h.search(&alice(), json!({})).await["active"]["preferences"][0].clone();
    let found = lexical(&h, json!({ "task": "writing length", "limit": 50 })).await;
    let item = found["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "Resolution/preference")
        .unwrap_or_else(|| panic!("{found}"))
        .clone();
    assert_eq!(item["assertedBy"], layer1["native"]["assertedBy"], "{item}");
    assert_eq!(item["recordedBy"], layer1["native"]["recordedBy"], "{item}");
}

#[tokio::test]
async fn closed_suggestions_are_neither_proposed_nor_sources() {
    let h = harness().await;
    let target = decision(&h, "elm decision", "Elm lumber tariffs").await;
    let suggestion = suggest_on(&h, &alice(), &target, "\"elm zero tariffs\"").await;
    let rejected = native(
        &h.db,
        &alice(),
        "resolve_suggestions",
        json!({ "action": "reject", "suggestion_ids": [suggestion], "reason": "no" }),
    )
    .await;
    assert_eq!(rejected["status"], "rejected", "{rejected}");
    // The suggestion record survives unarchived but closed.
    let record = native(
        &h.db,
        &alice(),
        "get_record",
        json!({ "ids": [suggestion] }),
    )
    .await;
    assert_eq!(record["records"][0]["archived"], false, "{record}");
    let body = lexical(
        &h,
        json!({ "task": "elm tariffs", "limit": 50, "include": { "proposed": true } }),
    )
    .await;
    let titles: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect();
    assert!(
        !titles.iter().any(|title| title.contains("zero tariffs")),
        "{titles:?}"
    );
    for item in body["items"].as_array().unwrap() {
        assert_ne!(item["status"], "proposed", "{item}");
    }
}

#[tokio::test]
async fn setup_gate_refuses_both_tools_until_the_kind_is_defined() {
    let h = unconfigured_harness().await;
    let _model = TestModel::not_configured();
    for (tool, args) in [
        (SEARCH_CONTEXT, json!({ "task": "anything" })),
        (TRACE_CONTEXT_ITEM, json!({ "ref": "anything" })),
    ] {
        let body = h.call(&alice(), tool, args).await;
        assert_eq!(body["success"], false, "{body}");
        assert_eq!(body["code"], "HCP_NOT_CONFIGURED", "{body}");
    }
}

#[tokio::test]
async fn task_is_required_and_bounds_are_checked() {
    let h = harness().await;
    for args in [json!({}), json!({"task": ""}), json!({"task": 3})] {
        let body = lexical(&h, args).await;
        assert_eq!(body["success"], false, "{body}");
        assert_eq!(body["code"], "INVALID_CONTEXT_INPUT", "{body}");
    }
    for args in [
        json!({"task": "x", "limit": 0}),
        json!({"task": "x", "limit": 51}),
        json!({"task": "x", "limit": "many"}),
        json!({"task": "x", "kinds": "Resolution/decision"}),
        json!({"task": "x", "include": {"proposed": "yes"}}),
        json!({"task": "x", "scope": "project"}),
    ] {
        let body = lexical(&h, args).await;
        assert_eq!(body["success"], false, "{body}");
        assert_eq!(body["code"], "INVALID_CONTEXT_INPUT", "{body}");
    }
    let body = trace(&h, json!({})).await;
    assert_eq!(body["code"], "INVALID_CONTEXT_INPUT", "{body}");
    let body = trace(&h, json!({"ref": "x", "historyLimit": 0})).await;
    assert_eq!(body["code"], "INVALID_CONTEXT_INPUT", "{body}");
    let body = trace(&h, json!({"ref": "x", "include": ["future"]})).await;
    assert_eq!(body["code"], "INVALID_CONTEXT_INPUT", "{body}");
}

#[tokio::test]
async fn lexical_fallback_marks_ranking_and_omits_why() {
    let h = harness().await;
    note(&h, "garden plan", "Plant moonwort hedgerows before frost").await;
    let body = lexical(&h, json!({ "task": "moonwort hedgerows" })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["ranking"], "lexical");
    assert_eq!(body["interpretation"], Value::Null);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["title"], "garden plan");
    assert_eq!(items[0]["why"], Value::Null);
    assert_eq!(items[0]["kind"], "Document/note");
    assert_eq!(items[0]["status"], Value::Null);
}

#[tokio::test]
async fn model_failure_falls_back_to_lexical_without_erroring() {
    let h = harness().await;
    note(&h, "garden plan", "Plant moonwort hedgerows before frost").await;
    let server = mock::MockServer::start(vec![(500, "boom".to_string())], None).await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "moonwort hedgerows" })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["ranking"], "lexical", "{body}");
    assert_eq!(body["interpretation"], Value::Null, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
}

#[tokio::test]
async fn model_request_is_bounded_and_names_its_limit() {
    let h = harness().await;
    let long_title = "t".repeat(300);
    let long_body = "b".repeat(3000);
    let mut ids = Vec::new();
    for index in 0..6 {
        ids.push(
            note(
                &h,
                &format!("{long_title}-{index}"),
                &format!("Wombat burrows {long_body}"),
            )
            .await,
        );
    }
    let server = mock::MockServer::start(
        vec![(200, ranking(&[(ids[0].as_str(), "first")], "wombat"))],
        None,
    )
    .await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "wombat burrows" })).await;
    assert_eq!(body["ranking"], "model", "{body}");
    let (_, _, sent) = server.seen().into_iter().next().unwrap();
    let user: Value =
        serde_json::from_str(sent["messages"][0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(user["max_items"], 10, "{user}");
    assert_eq!(user["task"], "wombat burrows", "{user}");
    let candidates = user["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty(), "{user}");
    for candidate in candidates {
        assert!(
            candidate["title"].as_str().unwrap().chars().count() <= 200,
            "{candidate}"
        );
    }
    assert!(
        user.to_string().len() <= 32 * 1024,
        "{}",
        user.to_string().len()
    );
}

#[tokio::test]
async fn empty_model_list_falls_back_to_lexical() {
    let h = harness().await;
    note(&h, "wombat note", "Wombat burrows run deep").await;
    let server = mock::MockServer::start(vec![(200, ranking(&[], "nothing relevant"))], None).await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "wombat burrows" })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["ranking"], "lexical", "{body}");
    assert_eq!(body["interpretation"], Value::Null, "{body}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["items"][0]["why"], Value::Null, "{body}");
}

#[tokio::test]
async fn model_order_and_why_survive_with_caps() {
    let h = harness().await;
    let first = note(&h, "alpha notes", "Quince orchard yields").await;
    let second = note(&h, "beta notes", "Quince jam recipe").await;
    let long_why = "w".repeat(WHY_MAX_CHARS + 50);
    let long_interpretation = "i".repeat(INTERPRETATION_MAX_CHARS + 50);
    let server = mock::MockServer::start(
        vec![(
            200,
            ranking(
                &[
                    (second.as_str(), long_why.as_str()),
                    (first.as_str(), "short"),
                ],
                long_interpretation.as_str(),
            ),
        )],
        None,
    )
    .await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "quince" })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["ranking"], "model", "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");
    assert_eq!(items[0]["title"], "beta notes", "{body}");
    assert_eq!(
        items[0]["why"].as_str().unwrap().chars().count(),
        WHY_MAX_CHARS,
        "{body}"
    );
    assert_eq!(
        body["interpretation"].as_str().unwrap().chars().count(),
        INTERPRETATION_MAX_CHARS,
        "{body}"
    );
}

#[tokio::test]
async fn unknown_model_refs_are_dropped_and_duplicates_kept_once() {
    let h = harness().await;
    let kept = note(&h, "kelp survey", "Kelp forests shelter otters").await;
    let server = mock::MockServer::start(
        vec![(
            200,
            ranking(
                &[
                    ("no-such-record", "invented"),
                    (kept.as_str(), "real"),
                    (kept.as_str(), "again"),
                ],
                "kelp",
            ),
        )],
        None,
    )
    .await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "kelp otters" })).await;
    assert_eq!(body["ranking"], "model", "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["title"], "kelp survey", "{body}");
}

#[tokio::test]
async fn status_rules_cover_accepted_proposed_superseded_and_null() {
    let h = harness().await;
    let accepted = decision(&h, "ship decision", "Ship the wobblewort demo").await;
    let proposed_target = decision(&h, "pending decision", "Pending wobblewort pricing").await;
    let proposal = suggest_on(&h, &alice(), &proposed_target, "\"wobblewort half price\"").await;
    let old = note(&h, "old claim", "Wobblewort costs ten").await;
    let new = linked_note(
        &h,
        "new claim",
        "Wobblewort costs twelve",
        &old,
        "supersedes",
    )
    .await;
    let plain = note(&h, "plain note", "Wobblewort trivia").await;
    let _ = (accepted, proposal, new, plain);

    // Default: accepted and null only.
    let body = lexical(&h, json!({ "task": "wobblewort", "limit": 50 })).await;
    let titles: Vec<String> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap().to_string())
        .collect();
    assert!(titles.contains(&"ship decision".to_string()), "{titles:?}");
    assert!(
        titles.contains(&"pending decision".to_string()),
        "{titles:?}"
    );
    assert!(titles.contains(&"plain note".to_string()), "{titles:?}");
    assert!(!titles.contains(&"old claim".to_string()), "{titles:?}");
    assert!(
        !titles.iter().any(|title| title.contains("half price")),
        "{titles:?}"
    );
    for item in body["items"].as_array().unwrap() {
        match item["title"].as_str().unwrap() {
            "ship decision" | "pending decision" => {
                assert_eq!(item["status"], "accepted", "{item}")
            }
            "plain note" | "new claim" => assert_eq!(item["status"], Value::Null, "{item}"),
            other => panic!("unexpected item {other}"),
        }
    }

    // Proposed and superseded are opt-in.
    let body = lexical(
        &h,
        json!({ "task": "wobblewort", "limit": 50, "include": { "proposed": true, "superseded": true } }),
    )
    .await;
    let by_title: std::collections::HashMap<String, Value> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (item["title"].as_str().unwrap().to_string(), item.clone()))
        .collect();
    let proposed = by_title.values().find(|item| item["status"] == "proposed");
    assert!(proposed.is_some(), "{by_title:?}");
    assert_eq!(
        by_title["old claim"]["status"], "superseded",
        "{by_title:?}"
    );

    // Sources opt out keeps only status-bearing items.
    let body = lexical(
        &h,
        json!({ "task": "wobblewort", "limit": 50, "include": { "proposed": true, "superseded": true, "sources": false } }),
    )
    .await;
    for item in body["items"].as_array().unwrap() {
        assert!(item["status"].is_string(), "{item}");
    }
    let titles: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect();
    assert!(!titles.contains(&"plain note"), "{titles:?}");
}

#[tokio::test]
async fn status_bearing_items_rank_first_in_model_order() {
    let h = harness().await;
    let noteworthy = note(&h, "zebra note", "Zebra migration corridors").await;
    let weighty = decision(&h, "zebra decision", "Zebra corridors stay open").await;
    let server = mock::MockServer::start(
        vec![(
            200,
            ranking(
                &[
                    (noteworthy.as_str(), "source first"),
                    (weighty.as_str(), "status second"),
                ],
                "zebra",
            ),
        )],
        None,
    )
    .await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "zebra corridors" })).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{body}");
    assert_eq!(items[0]["title"], "zebra decision", "{body}");
    assert_eq!(items[1]["title"], "zebra note", "{body}");
}

#[tokio::test]
async fn summary_falls_back_to_body_and_lifecycle_passes_through() {
    let h = harness().await;
    let long_body = "Yak wool grading ".repeat(60);
    make(&h, &alice(), "Document", "note", "", &long_body, json!({})).await;
    let task = make(
        &h,
        &alice(),
        "WorkItem",
        "task",
        "yak task",
        "Yak wool grading begins",
        json!({ "lifecycle": "open" }),
    )
    .await;
    let _ = task;
    let body = lexical(&h, json!({ "task": "yak wool", "limit": 50 })).await;
    let items = body["items"].as_array().unwrap();
    let fallback = items
        .iter()
        .find(|item| {
            item["title"]
                .as_str()
                .unwrap()
                .starts_with("Yak wool grading")
        })
        .unwrap_or_else(|| panic!("{body}"));
    assert_eq!(fallback["status"], Value::Null, "{fallback}");
    assert!(
        fallback["summary"].as_str().unwrap().len() <= 500,
        "{fallback}"
    );
    assert!(
        long_body.starts_with(fallback["summary"].as_str().unwrap()),
        "{fallback}"
    );
    let task_item = items
        .iter()
        .find(|item| item["title"] == "yak task")
        .unwrap_or_else(|| panic!("{body}"));
    assert_eq!(task_item["lifecycle"], "open", "{task_item}");
    assert_eq!(task_item["status"], Value::Null, "{task_item}");
}
#[tokio::test]
async fn unreadable_records_never_appear_or_reach_the_model() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    // Bob's note is account-private: Alice's authorised reads exclude it.
    make(
        &h,
        &bob(),
        "Document",
        "note",
        "bob secret",
        "Bob hides quokka anecdotes here",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    let hers = note(&h, "alice note", "Alice keeps quokka anecdotes too").await;
    let server = mock::MockServer::start(
        vec![(200, ranking(&[(hers.as_str(), "hers")], "quokka"))],
        None,
    )
    .await;
    let _model = point_at(&server);
    let body = search(&h, json!({ "task": "quokka anecdotes" })).await;
    assert_eq!(body["ranking"], "model", "{body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["title"], "alice note", "{body}");
    // Nothing of Bob's reached the model: not the id, title or body words.
    let (_, _, sent) = server.seen().into_iter().next().unwrap();
    let sent_text = sent.to_string();
    assert!(!sent_text.contains("bob secret"), "{sent_text}");
    assert!(!sent_text.contains("hides"), "{sent_text}");
}

#[tokio::test]
async fn project_scope_restricts_to_the_subtree() {
    let h = harness().await;
    let folder = make(
        &h,
        &alice(),
        "Collection",
        "folder",
        "ember project",
        "",
        json!({}),
    )
    .await;
    make(
        &h,
        &alice(),
        "Document",
        "note",
        "inside note",
        "Ember standup notes",
        json!({ "home_id": folder }),
    )
    .await;
    note(&h, "outside note", "Ember standup notes").await;
    let body = lexical(
        &h,
        json!({ "task": "ember standup", "scope": { "project": folder } }),
    )
    .await;
    let titles: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["inside note"], "{titles:?}");
}

#[tokio::test]
async fn subject_scope_restricts_to_linked_records() {
    let h = harness().await;
    let person = make(
        &h,
        &alice(),
        "Entity",
        "person",
        "Zoe Example",
        "",
        json!({}),
    )
    .await;
    linked_note(&h, "about zoe", "Zoe prefers oat milk", &person, "subject").await;
    note(&h, "unrelated", "Oat milk latte art").await;
    let body = lexical(
        &h,
        json!({ "task": "oat milk", "scope": { "subject": person }, "limit": 50 }),
    )
    .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["title"], "about zoe", "{body}");
    assert_eq!(items[0]["subject"]["name"], "Zoe Example", "{body}");
}

#[tokio::test]
async fn kinds_filter_and_limit_apply() {
    let h = harness().await;
    decision(&h, "mango decision", "Mango launch date").await;
    note(&h, "mango note", "Mango launch checklist").await;
    let body = lexical(
        &h,
        json!({ "task": "mango launch", "kinds": ["Resolution/decision"] }),
    )
    .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{body}");
    assert_eq!(items[0]["kind"], "Resolution/decision", "{body}");
    let body = lexical(&h, json!({ "task": "mango launch", "limit": 1 })).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
}

#[tokio::test]
async fn preference_items_carry_value_and_recorded_provenance() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("concise")).await;
    let body = lexical(&h, json!({ "task": "writing length", "limit": 50 })).await;
    let item = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "Resolution/preference")
        .unwrap_or_else(|| panic!("{body}"))
        .clone();
    assert_eq!(item["value"], "concise", "{item}");
    assert_eq!(item["status"], "accepted", "{item}");
    assert_eq!(item["assertedBy"], Value::Null, "{item}");
    assert_eq!(item["recordedBy"]["kind"], "agent", "{item}");
    assert_eq!(item["acceptedBy"], Value::Null, "{item}");
    assert!(
        item["revision"]
            .as_str()
            .is_some_and(|revision| !revision.is_empty()),
        "{item}"
    );
}

#[tokio::test]
async fn acceptance_records_accepted_by_with_a_time() {
    let h = harness().await;
    let id = decision(&h, "fig decision", "Fig season opens").await;
    let suggestion = suggest_on(&h, &web(), &id, "fig season opens now").await;
    // The owner accepts in the workbench: the acceptance names them.
    let accepted = native(
        &h.db,
        &web(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let body = trace(&h, json!({ "ref": id })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["item"]["acceptedBy"]["kind"], "person", "{body}");
    assert_eq!(body["item"]["acceptedBy"]["name"], "acct:alice", "{body}");
    assert!(body["item"]["acceptedBy"]["at"].is_string(), "{body}");
}
#[tokio::test]
async fn trace_reports_evidence_history_and_supersession() {
    let h = harness().await;
    let old = note(&h, "plum claim", "Plums ripen in June").await;
    let uma = make(
        &h,
        &alice(),
        "Entity",
        "person",
        "Uma Example",
        "",
        json!({}),
    )
    .await;
    let new = make(
        &h,
        &alice(),
        "Document",
        "note",
        "plum correction",
        "Plums ripen in July",
        json!({ "links": [
            { "target_id": old, "relationship": "supersedes" },
            { "target_id": uma, "relationship": "subject" },
        ] }),
    )
    .await;
    linked_note(
        &h,
        "plum survey",
        "County plum survey, page 3",
        &new,
        "evidence",
    )
    .await;
    // One edit after creation, so history has depth.
    let record = native(&h.db, &alice(), "get_record", json!({ "ids": [new] })).await;
    native(
        &h.db,
        &alice(),
        "update_record",
        json!({
            "id": new,
            "body_set": "Plums ripen in late July",
            "if_body_digest": record["records"][0]["body_digest"],
            "reason": "slice 4a fixture",
            "sources": [],
        }),
    )
    .await;

    let body = trace(&h, json!({ "ref": new })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["item"]["title"], "plum correction", "{body}");
    assert_eq!(body["item"]["subject"]["name"], "Uma Example", "{body}");
    let evidence = body["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 1, "{body}");
    assert_eq!(evidence[0]["title"], "plum survey", "{body}");
    assert_eq!(evidence[0]["role"], "basis", "{body}");
    assert!(evidence[0]["excerpt"].is_string(), "{body}");
    let history = body["history"].as_array().unwrap();
    assert!(history.len() >= 2, "{body}");
    for entry in history {
        assert!(entry["revision"].is_string(), "{entry}");
        assert!(entry["at"].is_string(), "{entry}");
        assert!(entry["change"].is_string(), "{entry}");
    }
    let supersedes = body["supersession"]["supersedes"].as_array().unwrap();
    assert_eq!(supersedes.len(), 1, "{body}");
    assert_eq!(supersedes[0]["title"], "plum claim", "{body}");

    // From the older record: the correction shows as supersededBy.
    let body = trace(&h, json!({ "ref": old })).await;
    assert_eq!(body["item"]["status"], "superseded", "{body}");
    assert_eq!(
        body["supersession"]["supersededBy"]["title"], "plum correction",
        "{body}"
    );

    // Sections are opt-out individually.
    let body = trace(
        &h,
        json!({ "ref": new, "include": ["history"], "historyLimit": 1 }),
    )
    .await;
    assert!(body.get("evidence").is_none(), "{body}");
    assert!(body.get("supersession").is_none(), "{body}");
    assert_eq!(body["history"].as_array().unwrap().len(), 1, "{body}");
}

/// Bind `account` to an existing person record without making that
/// record visible to anyone else: used for a writer alice cannot name.
async fn bind_only(db: &crate::db::Db, account: &str, person: &str) {
    for identifier in [account.to_string(), format!("native/{account}")] {
        let system = if identifier.starts_with("native/") {
            "native-principal"
        } else {
            "account"
        };
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, ?, ?, 1)",
        )
        .bind(person)
        .bind(system)
        .bind(identifier)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn links_to_unreadable_records_reveal_nothing() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    // Alice's note first: bob's hidden records can then point at it (the
    // reverse — alice linking to something she cannot read — is refused at
    // write time, so incoming links are the constructible case).
    let control = note(&h, "runner control", "Runner beans need light").await;
    let exposed = make(
        &h,
        &alice(),
        "Document",
        "note",
        "runner note",
        "Runner beans need water",
        json!({ "links": [{ "target_id": control, "relationship": "evidence" }] }),
    )
    .await;
    make(
        &h,
        &bob(),
        "Document",
        "note",
        "runner secret",
        "Runner beans need frost",
        json!({
            "access_policy": "account_only",
            "links": [{ "target_id": exposed, "relationship": "evidence" }],
        }),
    )
    .await;
    make(
        &h,
        &bob(),
        "Document",
        "note",
        "runner override",
        "Runner beans need shade",
        json!({
            "access_policy": "account_only",
            "links": [{ "target_id": exposed, "relationship": "supersedes" }],
        }),
    )
    .await;
    let hidden_person = make(
        &h,
        &bob(),
        "Entity",
        "person",
        "Runner Hidden",
        "",
        json!({
            "access_policy": "account_only",
            "links": [{ "target_id": exposed, "relationship": "subject" }],
        }),
    )
    .await;
    let _ = hidden_person;
    let body = lexical(
        &h,
        json!({ "task": "runner beans", "limit": 50, "include": { "superseded": true } }),
    )
    .await;
    let item = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["title"] == "runner note")
        .unwrap_or_else(|| panic!("{body}"))
        .clone();
    // Only the readable control link counts; the hidden successor, evidence
    // and person reveal nothing — not even that they exist.
    assert_eq!(item["evidenceCount"], 1, "{item}");
    assert_eq!(item["supersedes"], json!([]), "{item}");
    assert_eq!(item["supersededBy"], Value::Null, "{item}");
    assert_eq!(item["status"], Value::Null, "{item}");
    assert_eq!(item["subject"], Value::Null, "{item}");
    let flat = item.to_string();
    assert!(!flat.contains("runner secret"), "{flat}");
    assert!(!flat.contains("runner override"), "{flat}");
    assert!(!flat.contains("Runner Hidden"), "{flat}");
}

#[tokio::test]
async fn unreadable_suggestions_on_readable_targets_stay_hidden() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let hidden_target = make(
        &h,
        &bob(),
        "Resolution",
        "decision",
        "nectar secret",
        "Nectar flow at midnight",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    // Suggestions take their policy boundary from their bearer, so an
    // unreadable suggestion lives on an unreadable target: neither the
    // target nor its proposal may surface through the expansion.
    let record = native(
        &h.db,
        &bob(),
        "get_record",
        json!({ "ids": [hidden_target] }),
    )
    .await;
    let digest = record["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    native(
        &h.db,
        &bob(),
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": "\"nectar at dawn\"",
            "links": [{ "target_id": hidden_target, "relationship": "part_of" }],
            "facets": {
                "proposal.precondition": "digest",
                "anchor.base_digest": digest,
            },
            "reason": "slice 4a fixture",
            "sources": [],
        }),
    )
    .await;
    decision(&h, "nectar decision", "Nectar flow timing").await;
    let body = lexical(
        &h,
        json!({ "task": "nectar flow", "limit": 50, "include": { "proposed": true } }),
    )
    .await;
    for item in body["items"].as_array().unwrap() {
        assert_ne!(item["status"], "proposed", "{item}");
        assert!(!item["title"].as_str().unwrap().contains("dawn"), "{item}");
        assert!(
            !item["title"].as_str().unwrap().contains("midnight"),
            "{item}"
        );
    }
}

#[tokio::test]
async fn unreadable_and_missing_scopes_read_like_empty_ones() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let hidden_folder = make(
        &h,
        &bob(),
        "Collection",
        "folder",
        "hidden corner",
        "",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    let empty_folder = make(
        &h,
        &alice(),
        "Collection",
        "folder",
        "empty room",
        "",
        json!({}),
    )
    .await;
    note(&h, "stray memo", "Unscoped memo words").await;
    let empty = lexical(
        &h,
        json!({ "task": "memo words", "scope": { "project": empty_folder } }),
    )
    .await;
    assert_eq!(empty["items"], json!([]), "{empty}");
    for scope in [
        json!({ "project": hidden_folder }),
        json!({ "project": "00000000-0000-4000-8000-000000000000" }),
        json!({ "subject": hidden_folder }),
        json!({ "subject": "00000000-0000-4000-8000-000000000000" }),
    ] {
        let body = lexical(&h, json!({ "task": "memo words", "scope": scope })).await;
        assert_eq!(body, empty, "{scope} {body}");
    }
}

#[tokio::test]
async fn trace_hides_unreadable_evidence_and_supersession() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let control = note(&h, "quince control", "Quince needs light").await;
    let exposed = make(
        &h,
        &alice(),
        "Document",
        "note",
        "quince note",
        "Quince needs water",
        json!({ "links": [{ "target_id": control, "relationship": "evidence" }] }),
    )
    .await;
    let hidden = make(
        &h,
        &bob(),
        "Document",
        "note",
        "quince secret",
        "Quince needs frost",
        json!({
            "access_policy": "account_only",
            "links": [
                { "target_id": exposed, "relationship": "evidence" },
                { "target_id": exposed, "relationship": "supersedes" },
            ],
        }),
    )
    .await;
    let _ = hidden;
    let body = trace(&h, json!({ "ref": exposed })).await;
    assert_eq!(body["success"], true, "{body}");
    // Only the readable control survives, as evidence and in the count.
    assert_eq!(body["evidence"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["evidence"][0]["title"], "quince control", "{body}");
    assert_eq!(body["item"]["evidenceCount"], 1, "{body}");
    assert_eq!(body["item"]["supersedes"], json!([]), "{body}");
    assert_eq!(body["item"]["status"], Value::Null, "{body}");
    assert_eq!(body["supersession"]["supersedes"], json!([]), "{body}");
    assert_eq!(body["supersession"]["supersededBy"], Value::Null, "{body}");
    assert!(!body.to_string().contains("quince secret"), "{body}");
}

#[tokio::test]
async fn history_actor_from_another_account_is_hidden() {
    let h = harness().await;
    // Bob writes while bound, then his person record is tombstoned: the
    // bindings cascade nothing (soft delete), but disclosure — which names
    // only accounts bound to a person the caller can see — hides him.
    let person = native(
        &h.db,
        &crate::mcp::registry::Caller::local(),
        "create_record",
        json!({
            "type": "Entity", "kind": "person", "name": "acct:bob",
            "reason": "slice 4a fixture", "sources": [],
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    bind_only(&h.db, "acct:bob", &person).await;
    native(
        &h.db,
        &crate::mcp::registry::Caller::local(),
        "delete_record",
        json!({ "id": person, "reason": "slice 4a fixture" }),
    )
    .await;
    let shared = make(
        &h,
        &bob(),
        "Document",
        "note",
        "parsnip note",
        "Parsnips need frost",
        json!({}),
    )
    .await;
    let body = trace(&h, json!({ "ref": shared })).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["item"]["recordedBy"], Value::Null, "{body}");
    for entry in body["history"].as_array().unwrap() {
        assert_eq!(entry["actor"], Value::Null, "{entry}");
    }
}

#[tokio::test]
async fn trace_refuses_missing_and_unreadable_records_alike() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let secret = make(
        &h,
        &bob(),
        "Document",
        "note",
        "bob secret",
        "Bob hides rhubarb anecdotes",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    let _ = secret;
    for reference in ["does-not-exist", secret.as_str()] {
        let body = trace(&h, json!({ "ref": reference })).await;
        assert_eq!(body["success"], false, "{body}");
        assert_eq!(body["code"], "NOT_FOUND", "{body}");
        assert_eq!(body["error"], "Context item not found", "{body}");
    }
}
