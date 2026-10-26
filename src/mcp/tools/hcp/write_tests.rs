//! Slice 4b checks for `proposeContextItem` and `resolveContextItem`.
//!
//! Each test drives the tools through the same registry `/hcp` dispatches, as a
//! caller on the channel under test (an MCP agent, or the person in the web
//! workbench), so every write is attested exactly as in production. Concurrent
//! Native edits are reproduced with the pause hook: the edit lands after the
//! tool's last read and before its single guarded write.

use serde_json::{json, Value};

use super::claude::TestModel;
use super::context_write::{FAULT_AFTER_WRITE, PAUSE_BEFORE_RESOLVE_WRITE};
use super::store::sha256_hex;
use super::tests::{alice, caller, harness, onboard, unconfigured_harness, Harness};
use super::{
    arm_fault, arm_pause, PROPOSE_CONTEXT_ITEM, RESOLVE_CONTEXT_ITEM, SEARCH_CONTEXT,
    TRACE_CONTEXT_ITEM,
};
use crate::db::Db;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::provenance::Channel;

fn web() -> Caller {
    Caller::authenticated("acct:alice").with_channel(Channel::Web)
}

fn bob() -> Caller {
    caller("acct:bob", Some("client_bob_app"))
}

async fn native(db: &Db, who: &Caller, tool: &str, arguments: Value) -> Value {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(db.clone(), who.clone(), tool, arguments))
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

/// Create an ordinary record as `who`; returns its id.
async fn make(
    h: &Harness,
    who: &Caller,
    record_type: &str,
    kind: &str,
    name: &str,
    body: &str,
    extra: Value,
) -> String {
    let mut arguments = json!({
        "type": record_type, "kind": kind, "name": name, "body": body,
        "reason": "slice 4b fixture", "sources": [], "confirm": true,
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        arguments[key] = value;
    }
    let created = native(&h.db, who, "create_record", arguments).await;
    assert!(created["id"].is_string(), "{created}");
    created["id"].as_str().unwrap().to_string()
}

async fn decision(h: &Harness, name: &str, body: &str) -> String {
    make(h, &alice(), "Resolution", "decision", name, body, json!({})).await
}

async fn propose(h: &Harness, who: &Caller, args: Value) -> Value {
    h.call(who, PROPOSE_CONTEXT_ITEM, args).await
}

async fn resolve(h: &Harness, who: &Caller, args: Value) -> Value {
    h.call(who, RESOLVE_CONTEXT_ITEM, args).await
}

async fn lexical(h: &Harness, who: &Caller, args: Value) -> Value {
    let _model = TestModel::not_configured();
    h.call(who, SEARCH_CONTEXT, args).await
}

async fn trace(h: &Harness, id: &str) -> Value {
    h.call(&alice(), TRACE_CONTEXT_ITEM, json!({ "ref": id }))
        .await
}

async fn record(db: &Db, id: &str) -> Value {
    native(db, &alice(), "get_record", json!({ "ids": [id] })).await["records"][0].clone()
}

async fn count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn scalar(db: &Db, sql: &str, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(sql)
        .bind(id)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .flatten()
}

async fn body_of(db: &Db, id: &str) -> String {
    scalar(db, "SELECT body FROM records WHERE id = ?", id)
        .await
        .unwrap_or_default()
}

async fn maturity_of(db: &Db, id: &str) -> Option<String> {
    scalar(db, "SELECT maturity FROM records WHERE id = ?", id).await
}

async fn lifecycle_of(db: &Db, id: &str) -> Option<String> {
    scalar(db, "SELECT lifecycle FROM records WHERE id = ?", id).await
}

/// The id behind a short reference the tools returned.
async fn id_of(h: &Harness, reference: &str) -> String {
    let record = record(&h.db, reference).await;
    record["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no record for {reference}: {record}"))
        .to_string()
}

/// A guarded hand edit of a record's body, as `who`.
async fn edit_body(db: &Db, who: &Caller, id: &str, from: &str, to: &str) {
    native(
        db,
        who,
        "update_record",
        json!({
            "id": id, "body_set": to, "if_body_digest": sha256_hex(from),
            "reason": "concurrent edit", "sources": [],
        }),
    )
    .await;
}

fn find<'a>(search: &'a Value, title: &str) -> &'a Value {
    search["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["title"] == title)
        .unwrap_or_else(|| panic!("no item {title:?} in {search}"))
}

fn digest(text: &str) -> String {
    sha256_hex(text)
}

// ---- proposeContextItem: a change to an existing record -----------------

#[tokio::test]
async fn a_change_proposal_is_one_suggestion_anchored_to_the_revision_read() {
    let h = harness().await;
    let target = decision(&h, "frame wood", "Frames use oak").await;
    let before = count(&h.db).await;
    let reply = propose(
        &h,
        &alice(),
        json!({
            "statement": "Frames use pearwood",
            "target": { "ref": target, "expectedRevision": digest("Frames use oak") },
        }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    assert_eq!(reply["outcome"], "proposed", "{reply}");
    assert_eq!(reply["proposal"]["status"], "proposed", "{reply}");
    assert!(reply["proposal"]["targetRef"].is_string(), "{reply}");
    // Exactly one record was created and the target was not touched.
    assert_eq!(count(&h.db).await, before + 1);
    assert_eq!(body_of(&h.db, &target).await, "Frames use oak");

    let suggestion = id_of(&h, reply["proposal"]["ref"].as_str().unwrap()).await;
    let record = record(&h.db, &suggestion).await;
    assert_eq!(record["type"], "Annotation");
    assert_eq!(record["kind"], "suggestion");
    assert_eq!(record["body"], "Frames use pearwood");
    assert_eq!(
        lifecycle_of(&h.db, &suggestion).await.as_deref(),
        Some("open")
    );
    let facets: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM facet_values WHERE record_id = ? ORDER BY key")
            .bind(&suggestion)
            .fetch_all(h.db.pool())
            .await
            .unwrap();
    let facet = |key: &str| {
        facets
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    // The precondition the engine enforces when the proposal is resolved.
    assert_eq!(facet("proposal.precondition"), Some("digest"));
    let anchor = digest("Frames use oak");
    assert_eq!(facet("anchor.base_digest"), Some(anchor.as_str()));
    // Provenance: the caller's client.
    assert_eq!(facet("hcp.client"), Some("client_alice_app"));
    let linked: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&suggestion)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert_eq!(linked, vec![target.clone()]);

    // searchContext shows it as proposed, with the anchor as its revision. A
    // proposal is found through the record it is about (suggestion bodies are
    // not full-text indexed), so the task names the target's words.
    let search = lexical(
        &h,
        &alice(),
        json!({ "task": "frames", "include": { "proposed": true } }),
    )
    .await;
    let item = search["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["status"] == "proposed")
        .unwrap_or_else(|| panic!("{search}"));
    assert_eq!(item["revision"], anchor, "{item}");
    assert_eq!(item["assertedBy"], Value::Null, "{item}");
    assert_eq!(item["recordedBy"]["kind"], "agent", "{item}");
    assert_eq!(item["recordedBy"]["client"], "client_alice_app", "{item}");
}

#[tokio::test]
async fn a_change_proposal_against_a_stale_revision_creates_nothing() {
    let h = harness().await;
    let target = decision(&h, "frame wood", "Frames use oak").await;
    let before = count(&h.db).await;
    let reply = propose(
        &h,
        &alice(),
        json!({
            "statement": "Frames use pearwood",
            "target": { "ref": target, "expectedRevision": digest("Frames use ash") },
        }),
    )
    .await;
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["code"], "STALE_REVISION", "{reply}");
    assert_eq!(reply["changed"], false, "{reply}");
    assert_eq!(reply["current"]["revision"], digest("Frames use oak"));
    assert_eq!(count(&h.db).await, before);
}

#[tokio::test]
async fn proposals_that_cannot_be_made_safely_are_refused_before_any_write() {
    let h = harness().await;
    let target = decision(&h, "frame wood", "Frames use oak").await;
    let rev = digest("Frames use oak");
    h.define(&alice(), "writing.length", "STRING", json!({}))
        .await;
    let set = h.set(&alice(), "writing.length", json!("concise")).await;
    let preference = set["preference"]["id"].as_str().unwrap().to_string();
    let before = count(&h.db).await;
    let cases = [
        // A preference is proposed with mutatePreferences.
        (
            json!({ "kind": "preference", "statement": "x" }),
            "INVALID_CONTEXT_INPUT",
        ),
        (
            json!({ "kind": "Resolution/preference", "statement": "x" }),
            "INVALID_CONTEXT_INPUT",
        ),
        (
            json!({ "kind": "decision", "statement": "x", "value": "concise" }),
            "INVALID_CONTEXT_INPUT",
        ),
        (json!({ "statement": "x" }), "INVALID_CONTEXT_INPUT"),
        (
            json!({ "kind": "WorkItem/task", "statement": "x" }),
            "INVALID_CONTEXT_INPUT",
        ),
        (json!({ "kind": "decision" }), "INVALID_CONTEXT_INPUT"),
        (
            json!({ "statement": "x", "target": { "ref": target, "expectedRevision": "nope" } }),
            "INVALID_CONTEXT_INPUT",
        ),
        (
            json!({ "statement": "x", "subject": target,
                    "target": { "ref": target, "expectedRevision": rev } }),
            "INVALID_CONTEXT_INPUT",
        ),
        (
            json!({ "statement": "x", "kind": "Document/note",
                    "target": { "ref": target, "expectedRevision": rev } }),
            "INVALID_CONTEXT_INPUT",
        ),
        // A change to a preference is made with mutatePreferences.
        (
            json!({ "statement": "\"warm\"",
                    "target": { "ref": preference, "expectedRevision": digest("\"concise\"") } }),
            "UNSUPPORTED_TARGET",
        ),
        (
            json!({ "kind": "decision", "statement": "x", "subject": target }),
            "INVALID_CONTEXT_INPUT",
        ),
    ];
    for (args, code) in cases {
        let reply = propose(&h, &alice(), args.clone()).await;
        assert_eq!(reply["success"], false, "{args} => {reply}");
        assert_eq!(reply["code"], code, "{args} => {reply}");
        assert_eq!(reply["changed"], false, "{args} => {reply}");
    }
    assert_eq!(count(&h.db).await, before, "nothing was written");
}

// ---- proposeContextItem: a new item -------------------------------------

#[tokio::test]
async fn a_new_item_is_proposed_never_accepted_and_its_links_commit_with_it() {
    let h = harness().await;
    let person = make(
        &h,
        &alice(),
        "Entity",
        "person",
        "Dana Subject",
        "",
        json!({}),
    )
    .await;
    let folder = make(
        &h,
        &alice(),
        "Collection",
        "folder",
        "Furniture",
        "",
        json!({}),
    )
    .await;
    let evidence = make(
        &h,
        &alice(),
        "Document",
        "note",
        "workshop notes",
        "Pearwood warps less",
        json!({}),
    )
    .await;
    let before = count(&h.db).await;
    let reply = propose(
        &h,
        &alice(),
        json!({
            "kind": "Resolution/decision",
            "statement": "Use quincewood for the frames\nIt warps less than oak.",
            "subject": person,
            "appliesTo": [folder],
            "evidence": [{ "ref": evidence }, { "text": "Dana: pick the stable one" }],
        }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    assert_eq!(reply["outcome"], "proposed", "{reply}");
    assert_eq!(reply["proposal"]["status"], "proposed", "{reply}");
    assert!(reply["proposal"].get("targetRef").is_none(), "{reply}");
    assert_eq!(count(&h.db).await, before + 1, "exactly one record");
    let id = id_of(&h, reply["proposal"]["ref"].as_str().unwrap()).await;

    let created = record(&h.db, &id).await;
    assert_eq!(created["type"], "Resolution");
    assert_eq!(created["kind"], "decision");
    assert_eq!(created["name"], "Use quincewood for the frames");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));
    let mut links: Vec<(String, String)> = sqlx::query_as(
        "SELECT relationship, target_id FROM links WHERE source_id = ? ORDER BY relationship",
    )
    .bind(&id)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    links.sort();
    assert_eq!(
        links,
        vec![
            ("applies_to".to_string(), folder.clone()),
            ("evidence".to_string(), evidence.clone()),
            ("subject".to_string(), person.clone()),
        ]
    );
    // The record and all three links were written by one attested action.
    let actions: Vec<(String, i64)> = sqlx::query_as(
        "SELECT a.id, COUNT(*) FROM provenance_action_attestations a \
           JOIN provenance_action_outputs o ON o.action_attestation_id = a.id \
          WHERE a.operation = 'proposeContextItem' GROUP BY a.id",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert!(
        actions[0].1 >= 4,
        "record + 3 links in one action: {actions:?}"
    );

    // searchContext: proposed only when asked, and never accepted.
    let default = lexical(&h, &alice(), json!({ "task": "quincewood frames" })).await;
    assert!(
        default["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["title"] != "Use quincewood for the frames"),
        "{default}"
    );
    let with = lexical(
        &h,
        &alice(),
        json!({ "task": "quincewood frames", "include": { "proposed": true } }),
    )
    .await;
    let item = find(&with, "Use quincewood for the frames");
    assert_eq!(item["status"], "proposed", "{item}");
    assert_eq!(item["kind"], "Resolution/decision", "{item}");
    assert_eq!(item["subject"]["name"], "Dana Subject", "{item}");
    assert_eq!(item["evidenceCount"], 1, "{item}");
    assert!(
        item["appliesTo"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Furniture"),
        "{item}"
    );
    assert_eq!(item["assertedBy"], Value::Null, "{item}");
    assert_eq!(item["acceptedBy"], Value::Null, "{item}");
    assert_eq!(item["recordedBy"]["client"], "client_alice_app", "{item}");
    let traced = trace(&h, &id).await;
    assert_eq!(traced["item"]["status"], "proposed", "{traced}");
    // Text evidence is kept on the proposal.
    let texts = scalar(
        &h.db,
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'hcp.evidence_text'",
        &id,
    )
    .await
    .unwrap();
    assert!(texts.contains("pick the stable one"), "{texts}");
}

#[tokio::test]
async fn a_link_to_something_unreadable_refuses_the_whole_proposal() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let secret = make(
        &h,
        &bob(),
        "Document",
        "note",
        "bob secret",
        "hidden",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    let before = count(&h.db).await;
    let hidden = propose(
        &h,
        &alice(),
        json!({ "kind": "decision", "statement": "x", "evidence": [{ "ref": secret }] }),
    )
    .await;
    let missing = propose(
        &h,
        &alice(),
        json!({ "kind": "decision", "statement": "x",
                "evidence": [{ "ref": "00000000-0000-4000-8000-000000000000" }] }),
    )
    .await;
    assert_eq!(hidden["code"], "NOT_FOUND", "{hidden}");
    assert_eq!(hidden, missing, "unreadable reads exactly like missing");
    assert_eq!(count(&h.db).await, before);
}

// ---- resolveContextItem: change proposals are resolved in Native ---------

/// A decision with `body`, and an open proposal to change it to `proposed`,
/// anchored to `body`. Returns `(target id, proposal ref, proposal id)`.
async fn proposal_on(h: &Harness, body: &str, proposed: &str) -> (String, String, String) {
    let target = decision(h, "pear decision", body).await;
    let reply = propose(
        h,
        &alice(),
        json!({
            "statement": proposed,
            "target": { "ref": target, "expectedRevision": digest(body) },
        }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    let reference = reply["proposal"]["ref"].as_str().unwrap().to_string();
    let id = id_of(h, &reference).await;
    (target, reference, id)
}

// ---- resolveContextItem: a proposed new item -----------------------------

async fn proposed_item(h: &Harness, title: &str, statement: &str) -> (String, String) {
    let reply = propose(
        h,
        &alice(),
        json!({ "kind": "Resolution/decision", "statement": format!("{title}\n{statement}") }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    let reference = reply["proposal"]["ref"].as_str().unwrap().to_string();
    let id = id_of(h, &reference).await;
    (reference, id)
}

fn statement_of(title: &str, statement: &str) -> String {
    format!("{title}\n{statement}")
}

/// A new item that was proposed and then accepted (by the agent).
async fn accepted_item(h: &Harness, title: &str, statement: &str) -> (String, String) {
    let (reference, id) = proposed_item(h, title, statement).await;
    let reply = resolve(
        h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "reason": "fixture",
                "expectedRevision": digest(&statement_of(title, statement)) }),
    )
    .await;
    assert_eq!(reply["outcome"], "accepted", "{reply}");
    (reference, id)
}

#[tokio::test]
async fn accepting_a_proposed_item_makes_it_accepted_and_names_the_agent() {
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let revision = digest(&statement_of("Ship the kiln", "Order it in March"));
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "expectedRevision": revision,
                "reason": "agreed in standup" }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    assert_eq!(reply["outcome"], "accepted", "{reply}");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("decided"));
    let item = &reply["item"];
    assert_eq!(item["status"], "accepted", "{reply}");
    assert_eq!(item["acceptedBy"]["kind"], "agent", "{reply}");
    assert_eq!(item["assertedBy"], Value::Null, "{reply}");
    // The body was written by the proposer, who is not the acceptor.
    assert_eq!(item["recordedBy"]["client"], "client_alice_app", "{reply}");
    // Searchable as accepted by default now.
    let search = lexical(&h, &alice(), json!({ "task": "kiln" })).await;
    assert_eq!(
        find(&search, "Ship the kiln")["status"],
        "accepted",
        "{search}"
    );
}

#[tokio::test]
async fn the_owner_accepting_a_proposed_item_in_the_workbench_is_endorsed() {
    let h = harness().await;
    let (reference, _) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let revision = digest(&statement_of("Ship the kiln", "Order it in March"));
    let reply = resolve(
        &h,
        &web(),
        json!({ "ref": reference, "action": "accept", "expectedRevision": revision, "reason": "yes" }),
    )
    .await;
    assert_eq!(reply["outcome"], "accepted", "{reply}");
    let item = &reply["item"];
    assert_eq!(item["acceptedBy"]["kind"], "person", "{reply}");
    assert_eq!(item["assertedBy"]["basis"], "endorsed", "{reply}");
    // The proposer was the agent, and stays recorded as the body's writer.
    assert_eq!(item["recordedBy"]["kind"], "agent", "{reply}");
}

#[tokio::test]
async fn a_stale_revision_does_not_accept_a_proposed_item() {
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept",
                "expectedRevision": digest("an older text"), "reason": "ok" }),
    )
    .await;
    assert_eq!(reply["outcome"], "conflict", "{reply}");
    assert_eq!(reply["code"], "STALE_REVISION", "{reply}");
    assert_eq!(
        reply["current"]["revision"],
        digest(&statement_of("Ship the kiln", "Order it in March"))
    );
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));
}

#[tokio::test]
async fn a_concurrent_edit_cannot_slip_past_accepting_a_proposed_item() {
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let original = statement_of("Ship the kiln", "Order it in March");
    let revision = digest(&original);

    // A body edit lands between the read and the write.
    let (db, edited) = (h.db.clone(), id.clone());
    let original_for_edit = original.clone();
    arm_pause(PAUSE_BEFORE_RESOLVE_WRITE, async move {
        edit_body(
            &db,
            &web(),
            &edited,
            &original_for_edit,
            "Ship the kiln\nOrder it in May",
        )
        .await;
    });
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "expectedRevision": revision, "reason": "ok" }),
    )
    .await;
    assert_eq!(reply["outcome"], "conflict", "{reply}");
    assert_eq!(reply["code"], "STALE_REVISION", "{reply}");
    assert_eq!(
        reply["current"]["revision"],
        digest("Ship the kiln\nOrder it in May")
    );
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));

    // A change that is not to the body (here a rename) also stops it: the
    // record is accepted only if it is exactly as it was read.
    let (reference, id) = proposed_item(&h, "Hire a potter", "Start in June").await;
    let revision = digest(&statement_of("Hire a potter", "Start in June"));
    let (db, renamed) = (h.db.clone(), id.clone());
    arm_pause(PAUSE_BEFORE_RESOLVE_WRITE, async move {
        native(
            &db,
            &web(),
            "update_record",
            json!({ "id": renamed, "name": "Hire two potters", "reason": "rename" }),
        )
        .await;
    });
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "expectedRevision": revision, "reason": "ok" }),
    )
    .await;
    assert_eq!(reply["outcome"], "conflict", "{reply}");
    assert_eq!(reply["code"], "CONCURRENT_CHANGE", "{reply}");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));
}

#[tokio::test]
async fn a_proposed_item_cannot_be_rejected_or_superseded_and_nothing_changes() {
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    for action in ["reject", "supersede"] {
        let reply = resolve(
            &h,
            &alice(),
            json!({ "ref": reference, "action": action, "reason": "no",
                    "expectedRevision": digest(&statement_of("Ship the kiln", "Order it in March")) }),
        )
        .await;
        assert_eq!(reply["outcome"], "refused", "{action}: {reply}");
        assert_eq!(reply["code"], "UNSUPPORTED_ACTION", "{action}: {reply}");
        assert_eq!(reply["changed"], false, "{reply}");
    }
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));
}

// ---- resolveContextItem: supersede ----------------------------------------

#[tokio::test]
async fn superseding_marks_the_old_item_and_accepts_the_replacement_in_one_write() {
    let h = harness().await;
    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let (replacement, new_id) = accepted_item(&h, "kiln supplier v2", "Buy from Baker").await;
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede",
                "expectedRevision": digest("Buy from Acme"),
                "replacement": { "ref": replacement },
                "reason": "Acme closed" }),
    )
    .await;
    assert_eq!(reply["success"], true, "{reply}");
    assert_eq!(reply["outcome"], "superseded", "{reply}");
    assert!(reply["superseded"].is_string(), "{reply}");
    assert_eq!(reply["item"]["status"], "accepted", "{reply}");
    assert_eq!(reply["item"]["acceptedBy"]["kind"], "agent", "{reply}");
    assert_eq!(
        reply["item"]["supersedes"].as_array().unwrap().len(),
        1,
        "{reply}"
    );

    let linked: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'supersedes'",
    )
    .bind(&new_id)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert_eq!(linked, vec![old.clone()]);
    assert_eq!(
        maturity_of(&h.db, &new_id).await.as_deref(),
        Some("decided")
    );
    assert_eq!(
        maturity_of(&h.db, &old).await.as_deref(),
        Some("superseded")
    );
    // The old item's maturity change is attested to this one resolution; the
    // link is written by the same `batch_write` transaction (its all-or-nothing
    // behaviour is shown by the raced case in the next test).
    let attested: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.operation FROM provenance_action_outputs o \
           JOIN provenance_action_attestations a ON a.id = o.action_attestation_id \
           JOIN content_events e ON e.id = o.output_event_id \
          WHERE e.record_id = ? AND e.payload LIKE '%\"superseded\"%'",
    )
    .bind(&old)
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    assert_eq!(attested, vec!["resolveContextItem".to_string()]);

    // Search and trace both show the old item as superseded.
    let search = lexical(
        &h,
        &alice(),
        json!({ "task": "kiln supplier", "include": { "superseded": true } }),
    )
    .await;
    assert_eq!(
        find(&search, "kiln supplier")["status"],
        "superseded",
        "{search}"
    );
    assert_eq!(
        find(&search, "kiln supplier v2")["status"],
        "accepted",
        "{search}"
    );
    let traced = trace(&h, &old).await;
    assert_eq!(traced["item"]["status"], "superseded", "{traced}");
    assert_eq!(
        traced["supersession"]["supersededBy"]["title"], "kiln supplier v2",
        "{traced}"
    );
    // Hidden from the default search.
    let default = lexical(&h, &alice(), json!({ "task": "kiln supplier" })).await;
    assert!(default["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["title"] != "kiln supplier"));
}

#[tokio::test]
async fn a_stale_supersede_changes_nothing() {
    let h = harness().await;
    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let (replacement, new_id) = accepted_item(&h, "kiln supplier v2", "Buy from Baker").await;
    let before = count(&h.db).await;
    let stale = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede", "expectedRevision": digest("Buy from Zed"),
                "replacement": { "ref": replacement }, "reason": "x" }),
    )
    .await;
    assert_eq!(stale["outcome"], "conflict", "{stale}");
    assert_eq!(stale["code"], "STALE_REVISION", "{stale}");
    assert_eq!(stale["current"]["revision"], digest("Buy from Acme"));

    // The old item changing between the read and the write is refused by the
    // one batch, which then changes nothing at all.
    let (db, id) = (h.db.clone(), old.clone());
    arm_pause(PAUSE_BEFORE_RESOLVE_WRITE, async move {
        edit_body(&db, &web(), &id, "Buy from Acme", "Buy from Acme Ltd").await;
    });
    let raced = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede", "expectedRevision": digest("Buy from Acme"),
                "replacement": { "ref": replacement }, "reason": "x" }),
    )
    .await;
    assert_eq!(raced["outcome"], "conflict", "{raced}");
    assert_eq!(raced["code"], "STALE_REVISION", "{raced}");
    assert_eq!(raced["current"]["revision"], digest("Buy from Acme Ltd"));
    assert_eq!(count(&h.db).await, before, "nothing was created");
    assert_eq!(
        maturity_of(&h.db, &new_id).await.as_deref(),
        Some("decided"),
        "the replacement is untouched"
    );
    assert_eq!(maturity_of(&h.db, &old).await, None);
    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE relationship = 'supersedes'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(links, 0);
}

#[tokio::test]
async fn an_inline_replacement_is_refused_and_nothing_is_created() {
    let h = harness().await;
    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let before = count(&h.db).await;
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede", "expectedRevision": digest("Buy from Acme"),
                "replacement": { "statement": "Buy from Baker" }, "reason": "x" }),
    )
    .await;
    assert_eq!(reply["outcome"], "refused", "{reply}");
    assert_eq!(reply["code"], "UNSUPPORTED_INLINE_REPLACEMENT", "{reply}");
    assert_eq!(count(&h.db).await, before);
    assert_eq!(maturity_of(&h.db, &old).await, None);
}

// ---- access ---------------------------------------------------------------

/// A decision alice owns that bob may read but not edit.
async fn view_only_for_bob(h: &Harness, body: &str) -> String {
    onboard(&h.db, "acct:bob").await;
    let id = decision(h, "shared decision", body).await;
    crate::authorization::replace_explicit_policy(
        &h.db,
        "test:view-only",
        &id,
        vec![
            crate::authorization::AllowEntry::account(
                "acct:alice",
                crate::authorization::Capability::Manage,
            ),
            crate::authorization::AllowEntry::account(
                "acct:bob",
                crate::authorization::Capability::View,
            ),
        ],
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn unreadable_references_read_exactly_like_missing_ones() {
    let h = harness().await;
    onboard(&h.db, "acct:bob").await;
    let secret = make(
        &h,
        &bob(),
        "Resolution",
        "decision",
        "bob secret",
        "hidden plan",
        json!({ "access_policy": "account_only" }),
    )
    .await;
    let before = count(&h.db).await;
    for id in [
        secret.clone(),
        "00000000-0000-4000-8000-000000000000".to_string(),
        "ffffff1".to_string(),
    ] {
        let resolved = resolve(
            &h,
            &alice(),
            json!({ "ref": id, "action": "accept",
                    "expectedRevision": digest("hidden plan"), "reason": "x" }),
        )
        .await;
        assert_eq!(resolved["code"], "NOT_FOUND", "{resolved}");
        assert_eq!(resolved["outcome"], "refused", "{resolved}");
        let proposed = propose(
            &h,
            &alice(),
            json!({ "statement": "x",
                    "target": { "ref": id, "expectedRevision": digest("hidden plan") } }),
        )
        .await;
        assert_eq!(proposed["code"], "NOT_FOUND", "{proposed}");
    }
    assert_eq!(count(&h.db).await, before);
    assert_eq!(body_of(&h.db, &secret).await, "hidden plan");
    // Identical bodies for hidden and missing.
    let a = resolve(
        &h,
        &alice(),
        json!({ "ref": secret, "action": "reject", "reason": "x" }),
    )
    .await;
    let b = resolve(
        &h,
        &alice(),
        json!({ "ref": "00000000-0000-4000-8000-000000000000", "action": "reject", "reason": "x" }),
    )
    .await;
    assert_eq!(a, b);
}

// ---- uncertain outcomes -----------------------------------------------------

#[tokio::test]
async fn a_change_proposal_is_never_resolved_over_hcp_and_nothing_changes() {
    let h = harness().await;
    let (target, proposal, suggestion) = proposal_on(&h, "Pears are ripe", "Pears are ready").await;
    // Make the proposal stale too: if /hcp reached the engine, accepting would
    // mark it stale; if it flushed a session it would write.
    edit_body(&h.db, &web(), &target, "Pears are ripe", "Pears are green").await;
    let events = |ids: Vec<String>| {
        let db = h.db.clone();
        async move {
            let mut total = 0i64;
            for id in ids {
                total += sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM content_events WHERE record_id = ?",
                )
                .bind(id)
                .fetch_one(db.pool())
                .await
                .unwrap();
            }
            total
        }
    };
    let ids = vec![target.clone(), suggestion.clone()];
    let before = events(ids.clone()).await;
    let records = count(&h.db).await;
    for (who, action, expected) in [
        (alice(), "accept", Some(digest("Pears are ripe"))),
        (alice(), "accept", Some(digest("Pears are green"))),
        (alice(), "accept", None),
        (alice(), "reject", None),
        (web(), "accept", Some(digest("Pears are ripe"))),
        (web(), "reject", Some(digest("Pears are ripe"))),
    ] {
        let mut args = json!({ "ref": proposal, "action": action, "reason": "try" });
        if let Some(expected) = expected {
            args["expectedRevision"] = json!(expected);
        }
        let reply = resolve(&h, &who, args.clone()).await;
        assert_eq!(reply["success"], false, "{args} => {reply}");
        assert_eq!(reply["outcome"], "refused", "{args} => {reply}");
        assert_eq!(reply["code"], "RESOLVE_IN_NATIVE", "{args} => {reply}");
        assert_eq!(reply["changed"], false, "{args} => {reply}");
        // Tells the caller where: the target record's url, in the message too.
        let url = reply["target"]["url"].as_str().unwrap();
        assert!(url.starts_with('/'), "{reply}");
        assert!(reply["error"].as_str().unwrap().contains(url), "{reply}");
        assert!(
            reply["error"].as_str().unwrap().contains("Native"),
            "{reply}"
        );
    }
    // Not one event was appended to either record (so no stale-marking, no body
    // flush), and nothing was created.
    assert_eq!(events(ids).await, before);
    assert_eq!(count(&h.db).await, records);
    assert_eq!(body_of(&h.db, &target).await, "Pears are green");
    assert_eq!(
        lifecycle_of(&h.db, &suggestion).await.as_deref(),
        Some("open"),
        "not marked stale"
    );
    // Superseding a proposal is not something either.
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": proposal, "action": "supersede", "reason": "x",
                "expectedRevision": digest("Pears are ripe"),
                "replacement": { "ref": target } }),
    )
    .await;
    assert_eq!(reply["outcome"], "refused", "{reply}");
    assert_eq!(
        events(vec![target.clone(), suggestion.clone()]).await,
        before
    );
}

#[tokio::test]
async fn the_owner_accepting_a_proposal_in_native_is_endorsed_and_an_agent_is_not() {
    let h = harness().await;
    // The person accepts in Native (the workbench); slice 3's provenance gives
    // `endorsed`, and the proposal's author (an /hcp agent) is not who is named.
    let (target, _, suggestion) = proposal_on(&h, "Pears are ripe", "Pears are ready").await;
    let accepted = native(
        &h.db,
        &web(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let traced = trace(&h, &target).await;
    assert_eq!(
        traced["item"]["assertedBy"]["basis"], "endorsed",
        "{traced}"
    );
    assert_eq!(traced["item"]["acceptedBy"]["kind"], "person", "{traced}");

    // An agent accepting through plain /mcp claims nothing about the person.
    let (target, _, suggestion) = proposal_on(&h, "Plums are ripe", "Plums are ready").await;
    let accepted = native(
        &h.db,
        &alice(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let traced = trace(&h, &target).await;
    assert_eq!(traced["item"]["assertedBy"], Value::Null, "{traced}");
    assert_eq!(traced["item"]["acceptedBy"]["kind"], "agent", "{traced}");
}

#[tokio::test]
async fn a_viewer_may_suggest_as_native_allows_but_resolves_nothing_here() {
    let h = harness().await;
    let shared = view_only_for_bob(&h, "Shared plan").await;
    // Native lets anyone who can read a record suggest a change to it: a
    // suggestion is not an edit. The tool adds no rule of its own.
    let proposed = propose(
        &h,
        &bob(),
        json!({ "statement": "Bob's plan",
                "target": { "ref": shared, "expectedRevision": digest("Shared plan") } }),
    )
    .await;
    assert_eq!(proposed["success"], true, "{proposed}");
    assert_eq!(body_of(&h.db, &shared).await, "Shared plan");
    let proposal = proposed["proposal"]["ref"].as_str().unwrap().to_string();
    let reply = resolve(
        &h,
        &bob(),
        json!({ "ref": proposal, "action": "accept",
                "expectedRevision": digest("Shared plan"), "reason": "mine" }),
    )
    .await;
    assert_eq!(reply["code"], "RESOLVE_IN_NATIVE", "{reply}");
    assert_eq!(reply["changed"], false, "{reply}");
    let suggestion = id_of(&h, &proposal).await;
    assert_eq!(
        lifecycle_of(&h.db, &suggestion).await.as_deref(),
        Some("open")
    );

    // A caller who cannot even read the target is refused with no side effect.
    onboard(&h.db, "acct:carol").await;
    let carol = caller("acct:carol", Some("client_carol_app"));
    let before = count(&h.db).await;
    let hidden = propose(
        &h,
        &carol,
        json!({ "statement": "Carol's plan",
                "target": { "ref": shared, "expectedRevision": digest("Shared plan") } }),
    )
    .await;
    assert_eq!(hidden["code"], "NOT_FOUND", "{hidden}");
    assert_eq!(count(&h.db).await, before);
}

#[tokio::test]
async fn a_viewer_cannot_accept_or_supersede_and_nothing_changes() {
    let h = harness().await;
    let shared = view_only_for_bob(&h, "Shared plan").await;
    // A proposed item and an accepted one that bob can read but not edit.
    let (item_ref, item) = proposed_item(&h, "Plan B", "Alternative").await;
    let (other_ref, other) = proposed_item(&h, "Plan C", "Another").await;
    for id in [&item, &other] {
        crate::authorization::replace_explicit_policy(
            &h.db,
            "test:view-only",
            id,
            vec![
                crate::authorization::AllowEntry::account(
                    "acct:alice",
                    crate::authorization::Capability::Manage,
                ),
                crate::authorization::AllowEntry::account(
                    "acct:bob",
                    crate::authorization::Capability::View,
                ),
            ],
        )
        .await
        .unwrap();
    }
    let before = count(&h.db).await;
    let denied = resolve(
        &h,
        &bob(),
        json!({ "ref": item_ref, "action": "accept",
                "expectedRevision": digest(&statement_of("Plan B", "Alternative")),
                "reason": "mine" }),
    )
    .await;
    assert_eq!(denied["outcome"], "refused", "{denied}");
    assert_eq!(denied["code"], "MCP_PERMISSION_DENIED", "{denied}");
    assert_eq!(denied["changed"], false, "{denied}");
    assert_eq!(maturity_of(&h.db, &item).await.as_deref(), Some("proposed"));

    // Superseding what bob cannot edit is refused too, and nothing is linked.
    let denied = resolve(
        &h,
        &bob(),
        json!({ "ref": shared, "action": "supersede", "reason": "mine",
                "expectedRevision": digest("Shared plan"),
                "replacement": { "ref": other_ref } }),
    )
    .await;
    assert_eq!(denied["code"], "MCP_PERMISSION_DENIED", "{denied}");
    assert_eq!(denied["changed"], false, "{denied}");
    assert_eq!(maturity_of(&h.db, &shared).await, None);
    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE relationship = 'supersedes'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(links, 0);
    assert_eq!(count(&h.db).await, before);
}

#[tokio::test]
async fn a_replacement_that_cannot_be_linked_atomically_is_refused_before_any_write() {
    let h = harness().await;
    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let (replacement, _) = proposed_item(&h, "kiln supplier v2", "Buy from Baker").await;
    let (proposal_target, proposal_ref, _) =
        proposal_on(&h, "Pears are ripe", "Pears are ready").await;
    let revision = digest("Buy from Acme");
    for (replacement, code) in [
        // A revision on the replacement cannot be guarded in the same batch.
        (
            json!({ "ref": replacement, "expectedRevision": digest("x") }),
            "UNSUPPORTED_EXPECTED_REVISION",
        ),
        (json!({ "ref": old }), "INVALID_REPLACEMENT"),
        // A proposal's text is not a context item to replace with.
        (json!({ "ref": proposal_ref }), "INVALID_REPLACEMENT"),
        (json!({}), "INVALID_CONTEXT_INPUT"),
    ] {
        let reply = resolve(
            &h,
            &alice(),
            json!({ "ref": old, "action": "supersede", "expectedRevision": revision,
                    "replacement": replacement, "reason": "x" }),
        )
        .await;
        assert_eq!(reply["outcome"], "refused", "{replacement} => {reply}");
        assert_eq!(reply["code"], code, "{replacement} => {reply}");
        assert_eq!(reply["changed"], false, "{reply}");
    }
    let _ = proposal_target;
    assert_eq!(maturity_of(&h.db, &old).await, None);
    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE relationship = 'supersedes'")
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(links, 0);
}

#[tokio::test]
async fn superseding_with_a_still_proposed_replacement_is_allowed_and_visible_as_such() {
    let h = harness().await;
    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let (replacement, new_id) = proposed_item(&h, "kiln supplier v2", "Buy from Baker").await;
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede", "expectedRevision": digest("Buy from Acme"),
                "replacement": { "ref": replacement }, "reason": "Acme closed" }),
    )
    .await;
    assert_eq!(reply["outcome"], "superseded", "{reply}");
    // The old item is retired and the replacement is reported as it is: still
    // proposed, and unchanged.
    assert_eq!(reply["item"]["status"], "proposed", "{reply}");
    assert_eq!(
        maturity_of(&h.db, &new_id).await.as_deref(),
        Some("proposed")
    );
    assert_eq!(
        maturity_of(&h.db, &old).await.as_deref(),
        Some("superseded")
    );
    let traced = trace(&h, &old).await;
    assert_eq!(traced["item"]["status"], "superseded", "{traced}");
    assert_eq!(
        traced["supersession"]["supersededBy"]["status"], "proposed",
        "{traced}"
    );
}

// ---- no error after a write is read as "nothing changed" -------------------------

#[tokio::test]
async fn an_error_inside_a_native_call_after_it_committed_is_unconfirmed_never_unchanged() {
    use crate::mcp::record_ref::fail_next_display_reference_lookup;
    let h = harness().await;

    // proposeContextItem: create_record commits, then its compact receipt's
    // display-reference lookup fails inside the Native call (an `Engine` error).
    let before = count(&h.db).await;
    fail_next_display_reference_lookup();
    let reply = propose(
        &h,
        &alice(),
        json!({ "kind": "decision", "statement": "Fault one" }),
    )
    .await;
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(reply["changed"], Value::Null, "{reply}");
    assert_eq!(count(&h.db).await, before + 1, "the write did land");

    // The same for a change proposal.
    let target = decision(&h, "frame wood", "Frames use oak").await;
    let before = count(&h.db).await;
    fail_next_display_reference_lookup();
    let reply = propose(
        &h,
        &alice(),
        json!({ "statement": "Frames use ash",
                "target": { "ref": target, "expectedRevision": digest("Frames use oak") } }),
    )
    .await;
    assert_eq!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(reply["changed"], Value::Null, "{reply}");
    assert_eq!(count(&h.db).await, before + 1);

    // resolveContextItem accept: update_record commits, then its receipt fails.
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    fail_next_display_reference_lookup();
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "reason": "ok",
                "expectedRevision": digest(&statement_of("Ship the kiln", "Order it in March")) }),
    )
    .await;
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["outcome"], "unconfirmed", "{reply}");
    assert_eq!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(reply["changed"], Value::Null, "{reply}");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("decided"));
}

#[tokio::test]
async fn an_error_after_a_committed_write_returns_is_unconfirmed_never_unchanged() {
    let h = harness().await;
    arm_fault(FAULT_AFTER_WRITE);
    let before = count(&h.db).await;
    let reply = propose(
        &h,
        &alice(),
        json!({ "kind": "decision", "statement": "Fault two" }),
    )
    .await;
    assert_eq!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(reply["changed"], Value::Null, "{reply}");
    assert_eq!(count(&h.db).await, before + 1);

    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    arm_fault(FAULT_AFTER_WRITE);
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "reason": "ok",
                "expectedRevision": digest(&statement_of("Ship the kiln", "Order it in March")) }),
    )
    .await;
    assert_eq!(reply["outcome"], "unconfirmed", "{reply}");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("decided"));

    let old = decision(&h, "kiln supplier", "Buy from Acme").await;
    let (replacement, _) = proposed_item(&h, "kiln supplier v2", "Buy from Baker").await;
    arm_fault(FAULT_AFTER_WRITE);
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": old, "action": "supersede", "expectedRevision": digest("Buy from Acme"),
                "replacement": { "ref": replacement }, "reason": "x" }),
    )
    .await;
    assert_eq!(reply["outcome"], "unconfirmed", "{reply}");
    assert_eq!(reply["changed"], Value::Null, "{reply}");
    assert_eq!(
        maturity_of(&h.db, &old).await.as_deref(),
        Some("superseded"),
        "the write did land"
    );
}

#[tokio::test]
async fn a_guard_conflict_is_still_a_certain_refusal_not_an_uncertain_one() {
    // A `Conflict` is raised by Native before it writes, so it stays a conflict.
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let (db, renamed) = (h.db.clone(), id.clone());
    arm_pause(PAUSE_BEFORE_RESOLVE_WRITE, async move {
        native(
            &db,
            &web(),
            "update_record",
            json!({ "id": renamed, "name": "Ship two kilns", "reason": "rename" }),
        )
        .await;
    });
    let reply = resolve(
        &h,
        &alice(),
        json!({ "ref": reference, "action": "accept", "reason": "ok",
                "expectedRevision": digest(&statement_of("Ship the kiln", "Order it in March")) }),
    )
    .await;
    assert_eq!(reply["outcome"], "conflict", "{reply}");
    assert_ne!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(maturity_of(&h.db, &id).await.as_deref(), Some("proposed"));
}

#[tokio::test]
async fn a_decision_made_on_an_older_body_never_endorses_a_newer_one() {
    let h = harness().await;
    let (reference, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let original = statement_of("Ship the kiln", "Order it in March");
    let reply = resolve(
        &h,
        &web(),
        json!({ "ref": reference, "action": "accept", "reason": "yes",
                "expectedRevision": digest(&original) }),
    )
    .await;
    assert_eq!(reply["item"]["assertedBy"]["basis"], "endorsed", "{reply}");
    // The agent then rewrites the body: the person decided on the old one.
    edit_body(
        &h.db,
        &alice(),
        &id,
        &original,
        "Ship the kiln\nOrder it in May",
    )
    .await;
    let traced = trace(&h, &id).await;
    assert_eq!(traced["item"]["assertedBy"], Value::Null, "{traced}");
    assert_eq!(traced["item"]["acceptedBy"], Value::Null, "{traced}");
}

// ---- setup gate --------------------------------------------------------------

#[tokio::test]
async fn both_writes_wait_for_the_workspace_to_opt_in() {
    let h = unconfigured_harness().await;
    let before = count(&h.db).await;
    for (tool, args) in [
        (
            PROPOSE_CONTEXT_ITEM,
            json!({ "kind": "decision", "statement": "x" }),
        ),
        (
            RESOLVE_CONTEXT_ITEM,
            json!({ "ref": "abc1234", "action": "reject", "reason": "x" }),
        ),
    ] {
        let reply = h.call(&alice(), tool, args).await;
        assert_eq!(reply["code"], "HCP_NOT_CONFIGURED", "{tool}: {reply}");
    }
    assert_eq!(count(&h.db).await, before);
}

// ---- a decision endorses only the body it was made on -----------------------

#[tokio::test]
async fn a_decision_made_after_the_provenance_was_read_never_endorses_the_older_body() {
    let h = harness().await;
    let (_, id) = proposed_item(&h, "Ship the kiln", "Order it in March").await;
    let original = statement_of("Ship the kiln", "Order it in March");
    // The agent's body A is what trace reads from the record. Before the history
    // is read for its provenance, the owner rewrites the body (B) and decides.
    let (db, edited) = (h.db.clone(), id.clone());
    let from = original.clone();
    arm_pause("origin_after_history_read", async move {
        edit_body(
            &db,
            &web(),
            &edited,
            &from,
            "Ship the kiln\nOrder it in May",
        )
        .await;
        native(
            &db,
            &web(),
            "update_record",
            json!({ "id": edited, "maturity": "decided", "reason": "decided", "sources": [] }),
        )
        .await;
    });
    let traced = trace(&h, &id).await;
    assert_eq!(traced["success"], true, "{traced}");
    let item = &traced["item"];
    // Whatever it describes, it must not call the person's endorsement of B an
    // endorsement of A.
    assert_ne!(item["assertedBy"]["basis"], "endorsed", "{traced}");
    assert_eq!(item["acceptedBy"], Value::Null, "{traced}");
}
