//! A body produced by accepting suggestions says whose statement it is only if
//! Native's immutable record of that one action shows it resolved exactly one
//! suggestion. These use the tool surface only.

use serde_json::{json, Value};

use super::provenance_tests::{active, get_record, mcp, native, web};
use super::tests::{alice, harness, Harness};
use crate::db::Db;
use crate::mcp::registry::Caller;

const SLUG: &str = "notes.list";

/// A stored `[1,2]`.
async fn list() -> (Harness, String) {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "ARRAY", json!({})).await;
    let set = h.set(&a, SLUG, json!([1, 2])).await;
    assert_eq!(set["success"], true, "{set}");
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    (h, id)
}

/// An exact-span suggestion: replace `old` with `new` in the target's body.
async fn span(db: &Db, who: &Caller, target: &str, old: &str, new: &str) -> String {
    let created = native(
        db,
        who,
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": new,
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "facets": { "proposal.precondition": "span", "anchor.old": old },
            "reason": "a proposal",
            "sources": [],
        }),
    )
    .await;
    created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string()
}

async fn accept(db: &Db, who: &Caller, suggestions: &[&str]) {
    let accepted = native(
        db,
        who,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": suggestions, "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
}

#[tokio::test]
async fn two_proposals_accepted_by_an_agent_in_one_action_then_one_deleted_is_not_direct() {
    let (h, id) = list().await;
    // The person proposes 1 -> 3; the agent proposes 2 -> 999.
    let persons = span(&h.db, &web(), &id, "1", "3").await;
    let agents = span(&h.db, &mcp(), &id, "2", "999").await;
    // The agent accepts both in one action, then deletes its own proposal, so
    // the live records show a single accepted suggestion, the person's.
    accept(&h.db, &mcp(), &[&persons, &agents]).await;
    let deleted = native(
        &h.db,
        &mcp(),
        "delete_record",
        json!({ "id": agents, "reason": "tidy up" }),
    )
    .await;
    assert!(deleted.get("error").is_none(), "{deleted}");

    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 999]), "{pref}");
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
    // The accepting agent recorded it, even though who it speaks for is unclear.
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "agent", "name": "MCP client" })
    );
    assert_eq!(pref["confidence"], Value::Null);
}

#[tokio::test]
async fn an_ambiguous_web_acceptance_is_not_a_statement_of_the_person() {
    let (h, id) = list().await;
    let first = span(&h.db, &web(), &id, "1", "3").await;
    let second = span(&h.db, &mcp(), &id, "2", "999").await;
    // The person accepts two proposals in one action: which one they meant to
    // endorse cannot be told from the record.
    accept(&h.db, &web(), &[&first, &second]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 999]));
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
}

#[tokio::test]
async fn a_single_span_acceptance_still_derives_its_basis() {
    let (h, id) = list().await;
    // An agent's proposal accepted alone by the person: endorsed.
    let agents = span(&h.db, &mcp(), &id, "1", "3").await;
    accept(&h.db, &web(), &[&agents]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 2]));
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed", "{pref}");
    assert_eq!(pref["sourceType"], "USER");

    // The person's own proposal accepted alone by the person: still endorsed,
    // never `direct`: `direct` is only ever a body write.
    let persons = span(&h.db, &web(), &id, "2", "7").await;
    accept(&h.db, &web(), &[&persons]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 7]));
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed", "{pref}");

    // The accepted body is the record's current one.
    let record = get_record(&h.db, &id).await;
    assert_eq!(pref["native"]["revision"], record["body_digest"]);
}

/// The target is changed behind the proposal's back (the span still matches).
async fn rewrite_target(db: &Db, who: &Caller, target: &str, body: &str) {
    let record = get_record(db, target).await;
    let edited = native(
        db,
        who,
        "update_record",
        json!({
            "id": target,
            "body_set": body,
            "if_body_digest": record["body_digest"],
            "reason": "an edit",
            "sources": [],
        }),
    )
    .await;
    assert!(edited.get("error").is_none(), "{edited}");
}

#[tokio::test]
async fn a_persons_span_accepted_by_an_agent_over_agent_content_is_not_direct() {
    let (h, id) = list().await;
    // The person proposes 1 -> 3 in [1,2].
    let persons = span(&h.db, &web(), &id, "1", "3").await;
    // An agent edits the target to [1,999], then accepts only the person's span
    // through /mcp. The span still applies, and the result is [3,999].
    rewrite_target(&h.db, &mcp(), &id, "[1,999]").await;
    accept(&h.db, &mcp(), &[&persons]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 999]));
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
    // Recorded by whoever accepted, the agent: not the person who proposed
    // the span, whose proposal is only part of what the body now holds.
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "agent", "name": "MCP client" }),
        "{pref}"
    );
}

#[tokio::test]
async fn the_same_result_accepted_by_the_owner_on_the_web_is_endorsed() {
    let (h, id) = list().await;
    let persons = span(&h.db, &web(), &id, "1", "3").await;
    rewrite_target(&h.db, &mcp(), &id, "[1,999]").await;
    // The owner accepts the whole result: they endorse [3,999], whoever wrote
    // which part of it. Never `direct`.
    accept(&h.db, &web(), &[&persons]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 999]));
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed", "{pref}");
    assert_eq!(pref["sourceType"], "USER");
    // The owner accepted, so the owner recorded it, though an agent proposed
    // nothing here and the person proposed only the span.
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "person", "name": "acct:alice" }),
        "{pref}"
    );
}

#[tokio::test]
async fn an_agent_proposal_the_owner_accepts_is_recorded_by_the_owner() {
    let (h, id) = list().await;
    let agents = span(&h.db, &mcp(), &id, "1", "3").await;
    accept(&h.db, &web(), &[&agents]).await;
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed", "{pref}");
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "person", "name": "acct:alice" }),
        "the accepter, not the proposal's author"
    );
}

#[tokio::test]
async fn a_person_authored_proposal_accepted_by_an_agent_is_not_the_persons() {
    let (h, id) = list().await;
    let persons = span(&h.db, &web(), &id, "1", "3").await;
    accept(&h.db, &mcp(), &[&persons]).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], json!([3, 2]));
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
}
