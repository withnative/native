//! Slice 3 checks: the `native` block, the basis and `sourceType` derived for
//! it, confidence provenance, and `expectedRevision`.
//!
//! Every Native-side action here (a hand edit in the web workbench, accepting a
//! suggestion, creating an attribution) goes through the full tool registry as
//! a caller on the channel under test, so it is attested exactly as in
//! production. Nothing is asserted from text: each case differs only in a
//! recorded fact (channel, operation, relation, acceptance).

use serde_json::{json, Value};

use super::tests::{alice, harness, Harness};
use crate::db::Db;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::provenance::Channel;

const SLUG: &str = "writing.length";

/// The person in the web workbench: the first-party channel.
pub(super) fn web() -> Caller {
    Caller::authenticated("acct:alice").with_channel(Channel::Web)
}

/// The same person driving a plain MCP client (`/mcp`).
pub(super) fn mcp() -> Caller {
    Caller::authenticated("acct:alice").with_channel(Channel::Mcp)
}

pub(super) async fn native(db: &Db, who: &Caller, tool: &str, arguments: Value) -> Value {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(db.clone(), who.clone(), tool, arguments))
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

pub(super) async fn get_record(db: &Db, id: &str) -> Value {
    Box::pin(crate::mcp::tools::lifecycle::get_record(
        db.clone(),
        Caller::authenticated("acct:alice"),
        json!({ "ids": [id] }),
    ))
    .await
    .unwrap()["records"][0]
        .clone()
}

/// A workspace with one STRING definition and an HCP-set value.
pub(super) async fn set_up(value: &str) -> (Harness, String) {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "STRING", json!({})).await;
    let set = h.set(&a, SLUG, json!(value)).await;
    assert_eq!(set["success"], true, "{set}");
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    (h, id)
}

pub(super) async fn active(h: &Harness) -> Value {
    h.search(&alice(), json!({})).await["active"]["preferences"][0].clone()
}

/// A hand edit by `who`, guarded by the body digest, copying `reason`.
pub(super) async fn hand_edit(h: &Harness, who: &Caller, id: &str, value: &str, reason: &str) {
    hand_edit_db(&h.db, who, id, value, reason).await;
}

pub(super) async fn hand_edit_db(db: &Db, who: &Caller, id: &str, value: &str, reason: &str) {
    let record = get_record(db, id).await;
    let edited = native(
        db,
        who,
        "update_record",
        json!({
            "id": id,
            "body_set": json!(value).to_string(),
            "if_body_digest": record["body_digest"],
            "reason": reason,
            "sources": [],
        }),
    )
    .await;
    assert!(edited.get("error").is_none(), "{edited}");
}

/// Create an attribution of the current revision of `id` to the account
/// holder, as `who`.
pub(super) async fn attribute(
    h: &Harness,
    who: &Caller,
    id: &str,
    relation: &str,
    polarity: &str,
) -> String {
    let record = get_record(&h.db, id).await;
    let created = native(
        &h.db,
        who,
        "create_attribution",
        json!({
            "idempotency_key": format!("attr-{relation}-{polarity}-{}", uuid::Uuid::new_v4()),
            "bearer_id": id,
            "target": {
                "source_event_id": record["contribution"]["revision"]["event_id"],
                "source_body_sha256": record["body_digest"],
                "scope": "whole_revision",
            },
            "subject": { "kind": "self_person" },
            "relation": relation,
            "polarity": polarity,
            "confidence": "plausible",
            "transformation": "none",
            "rationale": "that is how I like it",
        }),
    )
    .await;
    created["annotation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no attribution created: {created}"))
        .to_string()
}

// ---- the block itself -------------------------------------------------------

#[tokio::test]
async fn an_agent_write_carries_a_block_with_no_asserter() {
    let (h, id) = set_up("concise").await;
    let pref = active(&h).await;
    let record = get_record(&h.db, &id).await;

    assert_eq!(pref["sourceType"], "INFERRED");
    let block = &pref["native"];
    assert_eq!(block["recordRef"], record["display_reference"]);
    assert_eq!(block["url"], record["record_path"]);
    // The revision is the body digest Native guards `update_record` with.
    assert_eq!(block["revision"], record["body_digest"]);
    assert_eq!(block["assertedBy"], Value::Null);
    assert_eq!(
        block["recordedBy"],
        json!({ "kind": "agent", "name": "client_alice_app", "client": "client_alice_app" })
    );
    assert_eq!(block["evidence"], json!([]));
}

#[tokio::test]
async fn the_block_is_on_every_preference_every_tool_returns() {
    let h = harness().await;
    let a = alice();
    let created = h.define(&a, SLUG, "STRING", json!({})).await;
    // A definition result has a block that names the catalog record.
    assert_eq!(created["definition"]["native"]["assertedBy"], Value::Null);
    assert_eq!(
        created["definition"]["native"]["recordedBy"]["client"],
        "client_alice_app"
    );
    assert!(created["definition"]["native"]["revision"].is_string());

    // SET result, active search, and smart search lists.
    let set = h.set(&a, SLUG, json!("concise")).await;
    assert!(set["preference"]["native"]["revision"].is_string(), "{set}");
    assert!(active(&h).await["native"]["recordRef"].is_string());

    // SUGGEST result and the suggested list: a suggestion has its own block.
    h.define(&a, "writing.tone", "STRING", json!({})).await;
    let suggested = h.suggest(&a, "writing.tone", json!("warm"), 0.5).await;
    let block = &suggested["preference"]["native"];
    assert_eq!(suggested["preference"]["status"], "SUGGESTED");
    assert_eq!(block["assertedBy"], Value::Null);
    assert_eq!(block["recordedBy"]["client"], "client_alice_app");
    let listed = h
        .search(&a, json!({ "query": "tone", "includeSuggestions": true }))
        .await;
    assert_eq!(
        listed["suggested"]["preferences"][0]["native"]["revision"],
        block["revision"]
    );

    // DELETE result describes what was removed.
    let id = set["preference"]["id"].as_str().unwrap();
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(
        deleted["preference"]["native"]["revision"],
        set["preference"]["native"]["revision"]
    );
}

/// ContextRouter's `Pref`, strict: any field the contract does not name fails
/// to parse. `native` is the one addition the contract allows clients to
/// ignore, so removing it must leave exactly this shape.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ContextRouterPref {
    id: String,
    slug: String,
    value: Value,
    status: String,
    #[serde(rename = "sourceType")]
    source_type: String,
    confidence: Option<f64>,
    #[serde(rename = "locationId")]
    location_id: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    category: String,
    description: String,
}

#[tokio::test]
async fn a_contextrouter_client_that_ignores_native_sees_its_own_shape() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    h.define(&a, "writing.tone", "STRING", json!({})).await;
    h.suggest(&a, "writing.tone", json!("warm"), 0.5).await;
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    for list in ["active", "suggested"] {
        let preferences = found[list]["preferences"].as_array().unwrap();
        assert_eq!(preferences.len(), 1, "{list}");
        for preference in preferences {
            let mut stripped = preference.clone();
            assert!(stripped.as_object_mut().unwrap().remove("native").is_some());
            serde_json::from_value::<ContextRouterPref>(stripped)
                .unwrap_or_else(|error| panic!("{list}: {error}"));
        }
    }
    // A mutate envelope without the optional additions is unchanged.
    let set = h.set(&a, SLUG, json!("brief")).await;
    for key in [
        "success",
        "changed",
        "operation",
        "requiredPermission",
        "target",
        "audit",
    ] {
        assert!(set.get(key).is_some(), "{key}");
    }
    assert!(set.get("current").is_none());
    assert!(set.get("code").is_none());
}

// ---- basis ------------------------------------------------------------------

#[tokio::test]
async fn direct_when_the_person_edits_in_the_web_workbench() {
    let (h, id) = set_up("concise").await;
    hand_edit(&h, &web(), &id, "brief", "tidying").await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["sourceType"], "USER");
    assert_eq!(pref["confidence"], Value::Null);
    assert_eq!(
        pref["native"]["assertedBy"],
        json!({ "kind": "person", "name": "acct:alice", "basis": "direct" })
    );
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "person", "name": "acct:alice" })
    );
}

#[tokio::test]
async fn a_plain_mcp_edit_is_not_direct() {
    let (h, id) = set_up("concise").await;
    hand_edit(&h, &mcp(), &id, "brief", "an agent tidying").await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["sourceType"], "INFERRED");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    // A /mcp write is attested but not an HCP write: no client to name.
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "agent", "name": "MCP client" })
    );
}

#[tokio::test]
async fn endorsed_when_the_person_accepts_an_agent_suggestion_in_the_web() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    let suggested = h.suggest(&a, SLUG, json!("brief"), 0.6).await;
    let suggestion = suggested["preference"]["id"].as_str().unwrap();
    let accepted = native(
        &h.db,
        &web(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["sourceType"], "USER");
    // The suggestion's own confidence, not the earlier value's.
    assert_eq!(pref["confidence"], 0.6);
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed");
    // Whoever accepted it recorded it, not the agent that proposed it; the
    // proposal's own confidence is still the proposal's.
    assert_eq!(
        pref["native"]["recordedBy"],
        json!({ "kind": "person", "name": "acct:alice" })
    );
}

#[tokio::test]
async fn an_agent_accepting_a_suggestion_is_not_an_endorsement() {
    let (h, _) = set_up("concise").await;
    let suggested = h.suggest(&alice(), SLUG, json!("brief"), 0.6).await;
    let suggestion = suggested["preference"]["id"].as_str().unwrap();
    let accepted = native(
        &h.db,
        &mcp(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "agent" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["sourceType"], "INFERRED");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
}

#[tokio::test]
async fn endorsed_when_the_person_attributes_the_value_to_themselves_in_the_web() {
    let (h, id) = set_up("concise").await;
    assert_eq!(active(&h).await["native"]["assertedBy"], Value::Null);
    attribute(&h, &web(), &id, "endorses", "affirmed").await;
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed");
    assert_eq!(pref["sourceType"], "USER");
    // The attribution's rationale is evidence for the basis.
    assert_eq!(
        pref["native"]["evidence"],
        json!([{ "text": "that is how I like it", "role": "basis" }])
    );
    // The value is still recorded by the agent.
    assert_eq!(pref["native"]["recordedBy"]["kind"], "agent");
}

#[tokio::test]
async fn reported_when_an_agent_declares_the_value_the_persons_view() {
    let (h, id) = set_up("concise").await;
    attribute(&h, &mcp(), &id, "expresses_view", "affirmed").await;
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"]["basis"], "reported");
    assert_eq!(pref["native"]["assertedBy"]["kind"], "person");
    // Reported is the agent's say-so, not the person's act.
    assert_eq!(pref["sourceType"], "INFERRED");
}

#[tokio::test]
async fn a_denial_is_counterevidence_and_never_a_basis() {
    let (h, id) = set_up("concise").await;
    attribute(&h, &web(), &id, "expresses_view", "denied").await;
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    assert_eq!(pref["sourceType"], "INFERRED");
    assert_eq!(
        pref["native"]["evidence"],
        json!([{ "text": "that is how I like it", "role": "counterevidence" }])
    );
}

#[tokio::test]
async fn an_attribution_speaks_only_for_the_revision_it_was_made_about() {
    let (h, id) = set_up("concise").await;
    attribute(&h, &web(), &id, "endorses", "affirmed").await;
    assert_eq!(
        active(&h).await["native"]["assertedBy"]["basis"],
        "endorsed"
    );
    // The agent revises the value: the person endorsed the old one.
    let revised = h.set(&alice(), SLUG, json!("brief")).await;
    assert_eq!(revised["success"], true, "{revised}");
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    assert_eq!(pref["sourceType"], "INFERRED");
}

#[tokio::test]
async fn a_retracted_attribution_no_longer_counts() {
    let (h, id) = set_up("concise").await;
    let annotation = attribute(&h, &web(), &id, "endorses", "affirmed").await;
    native(
        &h.db,
        &web(),
        "manage_attributions",
        json!({ "action": "retract", "annotation_id": annotation, "reason": "changed my mind" }),
    )
    .await;
    assert_eq!(active(&h).await["native"]["assertedBy"], Value::Null);
}

#[tokio::test]
async fn reported_when_the_hcp_evidence_is_structured_as_the_persons_instruction() {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "STRING", json!({})).await;
    let set = |evidence: Value| {
        h.mutate(
            &a,
            json!({
                "operation": "SET_PREFERENCE",
                "preference": { "slug": SLUG, "value": "\"concise\"", "evidence": evidence },
            }),
        )
    };
    let said = set(json!({ "speaker": "user", "quote": "keep it concise from now on" })).await;
    assert_eq!(said["success"], true, "{said}");
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"]["basis"], "reported");
    assert_eq!(pref["sourceType"], "INFERRED");
    assert_eq!(
        pref["native"]["evidence"],
        json!([{ "text": "keep it concise from now on", "role": "basis" }])
    );

    // The words alone prove nothing: no text is read for meaning.
    set(json!({ "quote": "the user said keep it concise from now on" })).await;
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    assert_eq!(pref["native"]["evidence"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn person_instruction_evidence_does_not_outlive_the_write_that_carried_it() {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "STRING", json!({})).await;
    h.mutate(
        &a,
        json!({
            "operation": "SET_PREFERENCE",
            "preference": {
                "slug": SLUG, "value": "\"concise\"", "evidence": { "speaker": "user" },
            },
        }),
    )
    .await;
    let id = active(&h).await["id"].as_str().unwrap().to_string();
    // Someone else's /mcp edit leaves the old `hcp.evidence` facet behind.
    hand_edit(&h, &mcp(), &id, "brief", "edit").await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    assert_eq!(pref["native"]["evidence"], json!([]));
}

#[tokio::test]
async fn a_person_authored_suggestion_the_person_accepts_is_endorsed_not_direct() {
    let (h, _) = set_up("concise").await;
    // The person proposes a change in the workbench: a plain suggestion record.
    let id = active(&h).await["id"].as_str().unwrap().to_string();
    let record = get_record(&h.db, &id).await;
    let suggestion = native(
        &h.db,
        &web(),
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": "\"brief\"",
            "links": [{ "target_id": record["id"], "relationship": "part_of" }],
            "facets": {
                "proposal.precondition": "digest",
                "anchor.base_digest": record["body_digest"],
            },
            "reason": "my own proposal",
            "sources": [],
        }),
    )
    .await;
    let suggestion = suggestion["id"].as_str().unwrap().to_string();
    let accepted = native(
        &h.db,
        &web(),
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed");
    assert_eq!(pref["native"]["recordedBy"]["kind"], "person");
}

#[tokio::test]
async fn a_suggestion_the_person_wrote_has_a_direct_basis_before_it_is_accepted() {
    let (h, _) = set_up("concise").await;
    let id = active(&h).await["id"].as_str().unwrap().to_string();
    let record = get_record(&h.db, &id).await;
    native(
        &h.db,
        &web(),
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": "\"brief\"",
            "links": [{ "target_id": record["id"], "relationship": "part_of" }],
            "facets": {
                "proposal.precondition": "digest",
                "anchor.base_digest": record["body_digest"],
            },
            "reason": "my own proposal",
            "sources": [],
        }),
    )
    .await;
    let found = h
        .search(&alice(), json!({ "includeSuggestions": true }))
        .await;
    let person = &found["suggested"]["preferences"][0];
    assert_eq!(person["value"], "brief");
    assert_eq!(person["native"]["assertedBy"]["basis"], "direct");
    assert_eq!(person["native"]["recordedBy"]["kind"], "person");
    assert_eq!(person["sourceType"], "USER");

    // An agent's suggestion on another slug, for comparison, has no asserter.
    h.define(&alice(), "writing.tone", "STRING", json!({}))
        .await;
    h.suggest(&alice(), "writing.tone", json!("warm"), 0.4)
        .await;
    let found = h
        .search(
            &alice(),
            json!({ "query": "tone", "includeSuggestions": true }),
        )
        .await;
    let agent = &found["suggested"]["preferences"][0];
    assert_eq!(agent["native"]["assertedBy"], Value::Null);
    assert_eq!(agent["sourceType"], "INFERRED");
}

// ---- sourceType --------------------------------------------------------------

#[tokio::test]
async fn trusted_local_and_delegated_service_writes_map_to_system_and_imported() {
    let (h, id) = set_up("concise").await;
    hand_edit(&h, &Caller::local(), &id, "from-system", "seeding").await;
    let pref = active(&h).await;
    assert_eq!(pref["sourceType"], "SYSTEM");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);

    // SAFETY: a test caller; the unsafe marks the trusted ingress seam.
    let service = unsafe {
        Caller::authenticated("acct:alice")
            .with_verified_delegated_service("endpoint-1", "credential-1")
            .unwrap()
    };
    hand_edit(&h, &service, &id, "from-webhook", "import").await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "from-webhook");
    assert_eq!(pref["sourceType"], "IMPORTED");
    assert_eq!(pref["native"]["assertedBy"], Value::Null);
    assert_eq!(pref["native"]["recordedBy"]["name"], "external service");

    // The person endorsing it makes it theirs.
    attribute(&h, &web(), &id, "endorses", "affirmed").await;
    assert_eq!(active(&h).await["sourceType"], "USER");
}

// ---- confidence provenance (the logged follow-up) ------------------------------

/// The reason HCP wrote for its own change, copied onto a hand edit.
fn copied_reason(set: &Value) -> String {
    format!(
        "HCP set {SLUG} via client client_alice_app (correlation {})",
        set["audit"]["correlationId"].as_str().unwrap()
    )
}

#[tokio::test]
async fn a_hand_edit_that_copies_the_reason_text_gets_no_hcp_confidence() {
    for editor in [web(), mcp()] {
        let h = harness().await;
        let a = alice();
        h.define(&a, SLUG, "STRING", json!({})).await;
        let set = h
            .mutate(
                &a,
                json!({
                    "operation": "SET_PREFERENCE",
                    "preference": { "slug": SLUG, "value": "\"concise\"", "confidence": 0.9 },
                }),
            )
            .await;
        assert_eq!(active(&h).await["confidence"], 0.9);
        let id = set["preference"]["id"].as_str().unwrap();
        // The hand edit does not touch the `hcp.*` facets, and its reason
        // repeats HCP's, correlation id included.
        hand_edit(&h, &editor, id, "brief", &copied_reason(&set)).await;
        let pref = active(&h).await;
        assert_eq!(pref["value"], "brief");
        assert_eq!(pref["confidence"], Value::Null, "{pref}");
    }
}

#[tokio::test]
async fn the_hcp_write_that_produced_the_body_keeps_its_confidence() {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "STRING", json!({})).await;
    h.mutate(
        &a,
        json!({
            "operation": "SET_PREFERENCE",
            "preference": { "slug": SLUG, "value": "\"concise\"", "confidence": 0.9 },
        }),
    )
    .await;
    assert_eq!(active(&h).await["confidence"], 0.9);
    h.mutate(
        &a,
        json!({
            "operation": "SET_PREFERENCE",
            "preference": { "slug": SLUG, "value": "\"brief\"", "confidence": 0.3 },
        }),
    )
    .await;
    assert_eq!(active(&h).await["confidence"], 0.3);
}

// ---- expectedRevision ----------------------------------------------------------

fn set_with(revision: Option<&str>, value: &str) -> Value {
    let mut preference = json!({ "slug": SLUG, "value": json!(value).to_string() });
    if let Some(revision) = revision {
        preference["expectedRevision"] = json!(revision);
    }
    json!({ "operation": "SET_PREFERENCE", "preference": preference })
}

#[tokio::test]
async fn set_with_the_current_revision_succeeds_and_the_new_revision_works_next() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    let revision = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let set = h.mutate(&a, set_with(Some(&revision), "brief")).await;
    assert_eq!(set["success"], true, "{set}");
    assert_eq!(set["changed"], true);
    let next = set["preference"]["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(next, revision);
    let again = h.mutate(&a, set_with(Some(&next), "terse")).await;
    assert_eq!(again["success"], true, "{again}");
}

#[tokio::test]
async fn set_with_a_stale_revision_is_refused_and_changes_nothing() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    let stale = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    // A hand edit moves the value on.
    hand_edit(&h, &web(), &id, "brief", "edit").await;
    let current = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(stale, current);

    let refused = h.mutate(&a, set_with(Some(&stale), "terse")).await;
    assert_eq!(refused["success"], false);
    assert_eq!(refused["changed"], false);
    assert_eq!(refused["code"], "STALE_REVISION");
    assert_eq!(refused["current"], json!({ "revision": current }));
    assert_eq!(refused["target"], SLUG);
    let frame = h
        .frame(&a, "mutatePreferences", set_with(Some(&stale), "terse"))
        .await;
    assert_eq!(frame["isError"], true);

    // Nothing was written: value and revision are what the hand edit left.
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["native"]["revision"], json!(current));
    assert_eq!(pref["native"]["assertedBy"]["basis"], "direct");
}

#[tokio::test]
async fn set_without_a_revision_is_unchanged() {
    let (h, id) = set_up("concise").await;
    hand_edit(&h, &web(), &id, "brief", "edit").await;
    let set = h.mutate(&alice(), set_with(None, "terse")).await;
    assert_eq!(set["success"], true, "{set}");
    assert_eq!(set["changed"], true);
    assert!(set.get("current").is_none());
    assert_eq!(active(&h).await["value"], "terse");
}

#[tokio::test]
async fn a_first_set_cannot_carry_a_revision_but_an_existing_empty_shell_can() {
    let h = harness().await;
    let a = alice();
    h.define(&a, SLUG, "STRING", json!({})).await;
    let empty = super::store::sha256_hex("");
    let count_records = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM records WHERE type = 'Resolution' AND kind = 'preference'",
        )
        .fetch_one(h.db.pool())
        .await
        .unwrap()
    };
    // No record exists: creating one has no digest guard, so even the digest of
    // the empty body is refused, and nothing is created.
    for revision in ["not-the-empty-revision", empty.as_str()] {
        let refused = h.mutate(&a, set_with(Some(revision), "x")).await;
        assert_eq!(refused["success"], false, "{refused}");
        assert_eq!(refused["changed"], false);
        assert_eq!(
            refused["code"], "UNSUPPORTED_EXPECTED_REVISION",
            "{refused}"
        );
    }
    assert_eq!(count_records().await, 0, "nothing was created");
    // A suggestion leaves an empty shell, which has a guarded update.
    h.suggest(&a, SLUG, json!("y"), 0.5).await;
    assert_eq!(count_records().await, 1);
    let stale = h
        .mutate(&a, set_with(Some("not-the-empty-revision"), "x"))
        .await;
    assert_eq!(stale["code"], "STALE_REVISION", "{stale}");
    assert_eq!(stale["current"]["revision"], json!(empty));
    let ok = h.mutate(&a, set_with(Some(&empty), "x")).await;
    assert_eq!(ok["success"], true, "{ok}");
    assert_eq!(count_records().await, 1);
}

#[tokio::test]
async fn delete_checks_the_revision_of_what_it_removes() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    let stale = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    hand_edit(&h, &web(), &id, "brief", "edit").await;
    let delete = |revision: &str| {
        h.mutate(
            &a,
            json!({
                "operation": "DELETE_PREFERENCE",
                "preference": { "id": id, "expectedRevision": revision },
            }),
        )
    };
    let refused = delete(&stale).await;
    assert_eq!(refused["code"], "STALE_REVISION", "{refused}");
    assert_eq!(active(&h).await["value"], "brief");
    let current = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(delete(&current).await["success"], true);
    assert_eq!(h.search(&a, json!({})).await["active"]["count"], 0);
}

#[tokio::test]
async fn definitions_take_a_revision_too() {
    let h = harness().await;
    let a = alice();
    let created = h.define(&a, SLUG, "STRING", json!({})).await;
    let first = created["definition"]["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let update = |revision: &str, description: &str| {
        h.mutate(
            &a,
            json!({
                "operation": "UPDATE_DEFINITION",
                "definition": {
                    "slug": SLUG, "description": description, "expectedRevision": revision,
                },
            }),
        )
    };
    let updated = update(&first, "second").await;
    assert_eq!(updated["success"], true, "{updated}");
    let second = updated["definition"]["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(first, second);

    let refused = update(&first, "third").await;
    assert_eq!(refused["code"], "STALE_REVISION", "{refused}");
    assert_eq!(refused["current"], json!({ "revision": second }));
    assert_eq!(refused["changed"], false);

    // Another definition's change does not make this one stale.
    h.define(&a, "writing.tone", "STRING", json!({})).await;
    let archive = |revision: &str| {
        h.mutate(
            &a,
            json!({
                "operation": "ARCHIVE_DEFINITION",
                "definition": { "slug": SLUG, "expectedRevision": revision },
            }),
        )
    };
    assert_eq!(archive(&first).await["code"], "STALE_REVISION");
    assert_eq!(archive(&second).await["success"], true);
}

#[tokio::test]
async fn a_malformed_or_misplaced_revision_is_an_input_error() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    for bad in [json!(7), json!(""), json!(["x"])] {
        let refused = h
            .mutate(
                &a,
                json!({
                    "operation": "SET_PREFERENCE",
                    "preference": { "slug": SLUG, "value": "\"x\"", "expectedRevision": bad },
                }),
            )
            .await;
        assert_eq!(refused["code"], "INVALID_MUTATION_INPUT", "{refused}");
    }
    let create = h
        .mutate(
            &a,
            json!({
                "operation": "CREATE_DEFINITION",
                "definition": {
                    "slug": "a.b", "description": "d", "valueType": "STRING",
                    "scope": "GLOBAL", "expectedRevision": "x",
                },
            }),
        )
        .await;
    assert_eq!(create["code"], "INVALID_MUTATION_INPUT", "{create}");
    assert_eq!(h.slugs(&a).await, [SLUG]);
}

// ---- smart search ----------------------------------------------------------------

#[tokio::test]
async fn smart_search_returns_the_block_on_active_and_suggested_preferences() {
    use super::claude::{mock, TestModel};
    use super::SMART_SEARCH_PREFERENCES;

    let (h, id) = set_up("concise").await;
    let a = alice();
    h.define(&a, "writing.tone", "STRING", json!({})).await;
    h.set(&a, "writing.tone", json!("warm")).await;
    h.suggest(&a, SLUG, json!("brief"), 0.7).await;
    hand_edit(&h, &web(), &id, "terse", "edit").await;
    // The agent's suggestion was anchored to the old body; it stays listed as
    // an open suggestion regardless.
    let server = mock::MockServer::start(
        vec![(
            200u16,
            mock::relevance_response(&[SLUG, "writing.tone"], "style"),
        )],
        None,
    )
    .await;
    let _model = TestModel::point_at(
        "test-key",
        &server.base_url,
        std::time::Duration::from_secs(10),
    );
    let body = h
        .call(
            &a,
            SMART_SEARCH_PREFERENCES,
            json!({ "query": "style", "includeSuggestions": true }),
        )
        .await;
    assert_eq!(body["success"], true, "{body}");
    let active = body["matchedActivePreferences"].as_array().unwrap();
    assert_eq!(active.len(), 2);
    // Relevance order: the web-edited value first, then the agent's.
    assert_eq!(active[0]["native"]["assertedBy"]["basis"], "direct");
    assert_eq!(active[0]["sourceType"], "USER");
    assert_eq!(active[1]["native"]["assertedBy"], Value::Null);
    assert_eq!(active[1]["sourceType"], "INFERRED");
    let suggested = &body["matchedSuggestedPreferences"][0];
    assert_eq!(suggested["status"], "SUGGESTED");
    assert_eq!(
        suggested["native"]["recordedBy"]["client"],
        "client_alice_app"
    );
    assert!(suggested["native"]["revision"].is_string());
}

// ---- links -------------------------------------------------------------------------

#[tokio::test]
async fn the_url_uses_the_deployments_short_link_origin_else_its_public_origin() {
    let (mut h, _) = set_up("concise").await;
    let reference = active(&h).await["native"]["recordRef"]
        .as_str()
        .unwrap()
        .to_string();
    // No origin configured: the relative path, as on stdio.
    assert_eq!(active(&h).await["native"]["url"], format!("/{reference}"));

    h.registry
        .set_public_origin(Some("https://app.example".into()));
    assert_eq!(
        active(&h).await["native"]["url"],
        format!("https://app.example/{reference}")
    );
    h.registry
        .set_share_origin(Some("https://n8v.example".into()));
    assert_eq!(
        active(&h).await["native"]["url"],
        format!("https://n8v.example/{reference}")
    );
    // Definitions and write results get the same treatment.
    let set = h.set(&alice(), SLUG, json!("brief")).await;
    assert_eq!(
        set["preference"]["native"]["url"],
        format!("https://n8v.example/{reference}")
    );
}
