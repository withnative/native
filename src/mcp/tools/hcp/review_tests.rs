//! Findings from the independent review of #2593. Each test reproduces the
//! reviewer's scenario and failed on the reviewed head (`11fde212d`) before its
//! fix. `basis` must never overclaim, and `expectedRevision` must hold against a
//! Native edit that lands between the check and the write.

use serde_json::{json, Value};

use super::provenance_tests::{
    active, attribute, get_record, hand_edit, hand_edit_db, mcp, native, set_up, web,
};
use super::store::Store;
use super::tests::{alice, harness, onboard, Harness};
use super::{arm_fault, arm_pause, MUTATE_PREFERENCES, SEARCH_PREFERENCES};
use crate::db::Db;
use crate::mcp::registry::Caller;
use crate::provenance::Channel;

const SLUG: &str = "writing.length";

fn bob() -> Caller {
    Caller::authenticated("acct:bob").with_channel(Channel::Web)
}

/// A suggestion record written through `who`, anchored to `target`'s body.
async fn suggestion(db: &Db, who: &Caller, target: &str, value: &str) -> String {
    let record = get_record(db, target).await;
    let created = native(
        db,
        who,
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": json!(value).to_string(),
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "facets": {
                "proposal.precondition": "digest",
                "anchor.base_digest": record["body_digest"],
            },
            "reason": "a proposal",
            "sources": [],
        }),
    )
    .await;
    created["id"].as_str().unwrap().to_string()
}

async fn accept(db: &Db, who: &Caller, suggestion: &str) {
    let accepted = native(
        db,
        who,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [suggestion], "reason": "yes" }),
    )
    .await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
}

/// Alice's pref, shared for editing with Bob (a second member).
async fn shared_with_bob(value: &str) -> (Harness, String) {
    let (h, id) = set_up(value).await;
    onboard(&h.db, "acct:bob").await;
    let granted = native(
        &h.db,
        &web(),
        "manage_record_policy",
        json!({
            "action": "grant",
            "record_id": id,
            "subject": { "kind": "account", "account_id": "acct:bob" },
            "capability": "edit",
            "reason": "share",
        }),
    )
    .await;
    assert!(granted.get("error").is_none(), "{granted}");
    (h, id)
}

// ---- 1: an old acceptance cannot manufacture `direct` ------------------------

#[tokio::test]
async fn an_old_accepted_suggestion_cannot_make_an_agent_write_direct() {
    let (h, id) = set_up("concise").await;
    let proposal = suggestion(&h.db, &web(), &id, "brief").await;
    accept(&h.db, &web(), &proposal).await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "brief");
    assert_eq!(pref["native"]["assertedBy"]["basis"], "endorsed");

    // An unrelated value arrives through /mcp ...
    hand_edit(&h, &mcp(), &id, "unrelated", "an agent writes").await;
    // ... and the agent re-issues the identical `accepted` lifecycle update on
    // the old suggestion, which appends an event after the body write.
    let reissued = native(
        &h.db,
        &mcp(),
        "update_record",
        json!({ "id": proposal, "lifecycle": "accepted", "reason": "again", "sources": [] }),
    )
    .await;
    assert!(reissued.get("error").is_none(), "{reissued}");

    let pref = active(&h).await;
    assert_eq!(pref["value"], "unrelated");
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
}

// ---- 2: person-channel activity is bound to the owner --------------------------

#[tokio::test]
async fn a_collaborators_web_edit_is_not_the_owners_direct_statement() {
    let (h, id) = shared_with_bob("concise").await;
    hand_edit(&h, &bob(), &id, "bobs value", "bob edits").await;
    let pref = active(&h).await;
    assert_eq!(pref["value"], "bobs value");
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
    // The writer is not named as Alice: Bob if Native shows Alice who Bob is,
    // otherwise nobody.
    let recorded = &pref["native"]["recordedBy"];
    assert!(
        recorded.is_null() || recorded["name"] != "acct:alice",
        "{recorded}"
    );
}

#[tokio::test]
async fn a_collaborators_attribution_does_not_make_the_owners_value_endorsed() {
    let (h, id) = shared_with_bob("concise").await;
    let alice_person = get_record(&h.db, &id).await["contribution"]["principal"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let record = get_record(&h.db, &id).await;
    let created = native(
        &h.db,
        &bob(),
        "create_attribution",
        json!({
            "idempotency_key": "bob-says-alice-endorses",
            "bearer_id": id,
            "target": {
                "source_event_id": record["contribution"]["revision"]["event_id"],
                "source_body_sha256": record["body_digest"],
                "scope": "whole_revision",
            },
            "subject": { "kind": "person_record", "record_id": alice_person },
            "relation": "endorses",
            "polarity": "affirmed",
            "confidence": "plausible",
            "transformation": "none",
            "rationale": "bob thinks so",
        }),
    )
    .await;
    assert!(created["annotation_id"].is_string(), "{created}");
    let pref = active(&h).await;
    assert_eq!(pref["native"]["assertedBy"], Value::Null, "{pref}");
    assert_eq!(pref["sourceType"], "INFERRED");
    // Alice's own attribution still counts.
    attribute(&h, &web(), &id, "endorses", "affirmed").await;
    assert_eq!(
        active(&h).await["native"]["assertedBy"]["basis"],
        "endorsed"
    );
}

// ---- 3: expectedRevision where it rides an atomic guarded write ----------------

fn set_expecting(revision: &str, value: &str) -> Value {
    json!({
        "operation": "SET_PREFERENCE",
        "preference": {
            "slug": SLUG, "value": json!(value).to_string(), "expectedRevision": revision,
        },
    })
}

#[tokio::test]
async fn set_with_a_revision_is_stale_when_a_native_edit_lands_between_check_and_write() {
    let (h, id) = set_up("concise").await;
    let revision = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let db = h.db.clone();
    let edited = id.clone();
    arm_pause("set_checked", async move {
        hand_edit_db(&db, &web(), &edited, "native edit", "concurrent edit").await;
    });
    let refused = h.mutate(&alice(), set_expecting(&revision, "terse")).await;
    assert_eq!(refused["code"], "STALE_REVISION", "{refused}");
    assert_eq!(refused["changed"], false);
    // The digest-guarded write never landed over the edit.
    assert_eq!(active(&h).await["value"], "native edit");
    assert_eq!(
        refused["current"]["revision"],
        active(&h).await["native"]["revision"]
    );
}

#[tokio::test]
async fn delete_with_a_revision_is_stale_when_a_native_edit_lands_between_check_and_write() {
    let (h, id) = set_up("concise").await;
    let revision = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let db = h.db.clone();
    let edited = id.clone();
    arm_pause("delete_checked", async move {
        hand_edit_db(&db, &web(), &edited, "native edit", "concurrent edit").await;
    });
    let refused = h
        .mutate(
            &alice(),
            json!({
                "operation": "DELETE_PREFERENCE",
                "preference": { "id": id, "expectedRevision": revision },
            }),
        )
        .await;
    assert_eq!(refused["code"], "STALE_REVISION", "{refused}");
    assert_eq!(refused["changed"], false);
    assert_eq!(
        active(&h).await["value"],
        "native edit",
        "the value was not cleared"
    );
}

#[tokio::test]
async fn suggest_with_a_revision_is_refused_up_front_and_without_one_is_unchanged() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    let revision = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let suggest = |extra: Value| {
        let mut preference = json!({ "slug": SLUG, "value": "\"terse\"", "confidence": 0.5 });
        if let Some(extra) = extra.as_object() {
            preference.as_object_mut().unwrap().extend(extra.clone());
        }
        h.mutate(
            &a,
            json!({ "operation": "SUGGEST_PREFERENCE", "preference": preference }),
        )
    };
    // Even the current revision is refused: nothing can enforce it atomically.
    let refused = suggest(json!({ "expectedRevision": revision })).await;
    assert_eq!(refused["success"], false, "{refused}");
    assert_eq!(refused["changed"], false);
    assert_eq!(refused["code"], "UNSUPPORTED_EXPECTED_REVISION");
    assert!(refused["error"]
        .as_str()
        .unwrap()
        .contains("SUGGEST_PREFERENCE"));
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["suggested"]["count"], 0, "nothing was attempted");
    // Without it, a suggestion is made as before.
    let made = suggest(json!({})).await;
    assert_eq!(made["success"], true, "{made}");
    assert_eq!(made["preference"]["status"], "SUGGESTED");
}

#[tokio::test]
async fn deleting_a_suggestion_with_a_revision_is_refused_up_front_and_without_one_is_unchanged() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    let suggested = h.suggest(&a, SLUG, json!("brief"), 0.6).await;
    let proposal = suggested["preference"]["id"].as_str().unwrap().to_string();
    let revision = suggested["preference"]["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let delete = |extra: Value| {
        let mut preference = json!({ "id": proposal });
        if let Some(extra) = extra.as_object() {
            preference.as_object_mut().unwrap().extend(extra.clone());
        }
        h.mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": preference }),
        )
    };
    let refused = delete(json!({ "expectedRevision": revision })).await;
    assert_eq!(refused["success"], false, "{refused}");
    assert_eq!(refused["changed"], false);
    assert_eq!(refused["code"], "UNSUPPORTED_EXPECTED_REVISION");
    let archived: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
        .bind(&proposal)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(archived, 0, "nothing was attempted");
    // Without it, the suggestion is withdrawn as before.
    let withdrawn = delete(json!({})).await;
    assert_eq!(withdrawn["success"], true, "{withdrawn}");
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["suggested"]["count"], 0);
}

#[tokio::test]
async fn set_with_a_revision_on_an_archived_record_is_stale_and_does_not_restore_it() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    let revision = active(&h).await["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    native(
        &h.db,
        &web(),
        "archive_record",
        json!({ "id": id, "archived": true, "reason": "tidy" }),
    )
    .await;
    let archived = || async {
        sqlx::query_scalar::<_, i64>("SELECT archived FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(h.db.pool())
            .await
            .unwrap()
    };
    // Even the value's own revision does not match an archived record.
    let refused = h.mutate(&a, set_expecting(&revision, "terse")).await;
    assert_eq!(refused["success"], false, "{refused}");
    assert_eq!(refused["code"], "STALE_REVISION");
    assert_eq!(refused["changed"], false);
    assert!(refused.get("current").is_none(), "no revision to offer");
    assert_eq!(archived().await, 1, "it was not restored");
    // Without a revision, a SET restores it as before.
    let restored = h.set(&a, SLUG, json!("terse")).await;
    assert_eq!(restored["success"], true, "{restored}");
    assert_eq!(archived().await, 0);
}

#[tokio::test]
async fn a_suppressed_suggestion_changes_nothing_not_even_the_archive_state() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    native(
        &h.db,
        &web(),
        "archive_record",
        json!({ "id": id, "archived": true, "reason": "tidy" }),
    )
    .await;
    let archived = || async {
        sqlx::query_scalar::<_, i64>("SELECT archived FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(h.db.pool())
            .await
            .unwrap()
    };
    let events = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(h.db.pool())
            .await
            .unwrap()
    };
    // The archived preference holds "concise": suggesting it is suppressed, and
    // nothing at all is written (the record stays archived).
    let before = events().await;
    let suppressed = h.suggest(&a, SLUG, json!("concise"), 0.5).await;
    assert_eq!(suppressed["success"], true, "{suppressed}");
    assert_eq!(suppressed["changed"], false);
    assert_eq!(suppressed["code"], "SUGGESTION_SUPPRESSED");
    assert_eq!(archived().await, 1, "it was not restored");
    assert_eq!(events().await, before, "no event was written");
    // Something different is still a real suggestion, which does restore the
    // record it attaches to.
    let made = h.suggest(&a, SLUG, json!("brief"), 0.5).await;
    assert_eq!(made["changed"], true, "{made}");
    assert_eq!(archived().await, 0);
}

#[tokio::test]
async fn a_suggestion_already_pending_on_an_archived_record_is_suppressed_without_restoring_it() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    let first = h.suggest(&a, SLUG, json!("brief"), 0.5).await;
    assert_eq!(first["changed"], true, "{first}");
    native(
        &h.db,
        &web(),
        "archive_record",
        json!({ "id": id, "archived": true, "reason": "tidy" }),
    )
    .await;
    let again = h.suggest(&a, SLUG, json!("brief"), 0.5).await;
    assert_eq!(again["changed"], false, "{again}");
    assert_eq!(again["code"], "SUGGESTION_SUPPRESSED");
    let archived: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
        .bind(&id)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(archived, 1, "it was not restored");
}

#[tokio::test]
async fn a_suggestion_suppressed_after_a_restore_does_not_claim_nothing_changed() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    native(
        &h.db,
        &web(),
        "archive_record",
        json!({ "id": id, "archived": true, "reason": "tidy" }),
    )
    .await;
    // The preliminary read sees the archived value "concise", so SUGGEST "brief"
    // looks worth making. Then a Native edit makes the archived body "brief"
    // before the record is restored, and the check inside the write finds
    // nothing to propose.
    let db = h.db.clone();
    let edited = id.clone();
    arm_pause("suggest_prechecked", async move {
        hand_edit_db(&db, &web(), &edited, "brief", "concurrent edit").await;
    });
    let reply = h.suggest(&a, SLUG, json!("brief"), 0.5).await;
    let archived: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
        .bind(&id)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    // The restore did commit, so the answer must not say nothing changed. It
    // is a success that names the reason no suggestion was made.
    assert_eq!(archived, 0, "the record was restored: {reply}");
    assert_ne!(reply["changed"], false, "{reply}");
    assert_eq!(reply["changed"], true, "{reply}");
    assert_eq!(reply["code"], "SUGGESTION_SUPPRESSED", "{reply}");
    assert_eq!(reply["success"], true);
    assert!(reply.get("preference").is_none(), "no suggestion was made");
}

// ---- an error after a write is never reported as "nothing changed" -------------

#[tokio::test]
async fn an_error_after_a_committed_write_is_reported_as_uncertain_not_unchanged() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    arm_fault("set_written");
    let reply = h.mutate(&a, set_expecting_none("terse")).await;
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["code"], "OUTCOME_UNCERTAIN", "{reply}");
    assert_eq!(
        reply["changed"],
        Value::Null,
        "must not claim no change: {reply}"
    );
    assert!(reply["error"].as_str().unwrap().contains("may or may not"));
    // The write did land, which is why `false` would have been a lie.
    assert_eq!(active(&h).await["value"], "terse");
}

#[tokio::test]
async fn an_error_before_any_write_is_still_reported_as_unchanged() {
    let (h, _) = set_up("concise").await;
    let a = alice();
    arm_fault("set_before_write");
    let reply = h.mutate(&a, set_expecting_none("terse")).await;
    assert_eq!(reply["success"], false, "{reply}");
    assert_eq!(reply["code"], "INTERNAL_ERROR");
    assert_eq!(reply["changed"], false);
    assert_eq!(active(&h).await["value"], "concise");
}

fn set_expecting_none(value: &str) -> Value {
    json!({
        "operation": "SET_PREFERENCE",
        "preference": { "slug": SLUG, "value": json!(value).to_string() },
    })
}

#[test]
fn a_failure_that_escapes_a_mutation_does_not_claim_no_change() {
    use crate::error::{DeploymentReadOnlyOperation, Error};
    let frame = |error: Error| {
        super::failure_frame(MUTATE_PREFERENCES, &error)["structuredContent"].clone()
    };
    // Refused by the read-only fence before anything changed.
    assert_eq!(
        frame(Error::DeploymentReadOnly(
            DeploymentReadOnlyOperation::server("x")
        ))["changed"],
        false
    );
    // Its own message says the outcome is unknown; anything else may have
    // followed a write.
    assert_eq!(
        frame(Error::DeploymentDraining(
            DeploymentReadOnlyOperation::server("x")
        ))["changed"],
        Value::Null
    );
    assert_eq!(frame(Error::engine("boom"))["changed"], Value::Null);
    // A read tool has no `changed`.
    assert!(
        super::failure_frame(SEARCH_PREFERENCES, &Error::engine("boom"))["structuredContent"]
            .get("changed")
            .is_none()
    );
}

// ---- 4: a definition's revision belongs to the definition it describes ---------

#[tokio::test]
async fn a_definition_response_does_not_pair_old_content_with_a_newer_revision() {
    let h = harness().await;
    let a = alice();
    let created = h.define(&a, SLUG, "STRING", json!({})).await;
    let first = created["definition"]["native"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let catalog: String = sqlx::query_scalar(
        "SELECT id FROM records WHERE type = 'Document' AND kind = 'note' AND name = 'HCP preference catalog'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    // A Native edit of the catalog lands right after HCP wrote the update.
    let db = h.db.clone();
    arm_pause("definition_written", async move {
        let record = get_record(&db, &catalog).await;
        let mut body: Value = serde_json::from_str(record["body"].as_str().unwrap()).unwrap();
        body["definitions"][0]["description"] = json!("edited in Native");
        native(
            &db,
            &web(),
            "update_record",
            json!({
                "id": catalog,
                "body_set": body.to_string(),
                "if_body_digest": record["body_digest"],
                "reason": "concurrent edit",
                "sources": [],
            }),
        )
        .await;
    });
    let updated = h
        .mutate(
            &a,
            json!({
                "operation": "UPDATE_DEFINITION",
                "definition": { "slug": SLUG, "description": "written by HCP", "expectedRevision": first },
            }),
        )
        .await;
    assert_eq!(updated["success"], true, "{updated}");
    assert_eq!(updated["definition"]["description"], "written by HCP");
    // The revision describes what HCP wrote, which Native has since changed:
    // using it must be stale.
    let returned = updated["definition"]["native"]["revision"]
        .as_str()
        .unwrap();
    let next = h
        .mutate(
            &a,
            json!({
                "operation": "UPDATE_DEFINITION",
                "definition": { "slug": SLUG, "description": "again", "expectedRevision": returned },
            }),
        )
        .await;
    assert_eq!(next["code"], "STALE_REVISION", "{next}");
}

// ---- 5: only provenance fields are rewritten, never a value ---------------------

#[tokio::test]
async fn a_value_that_looks_like_a_native_block_is_never_rewritten() {
    let mut h = harness().await;
    let a = alice();
    h.define(&a, "notes.raw", "ARRAY", json!({})).await;
    h.registry
        .set_share_origin(Some("https://n8v.example".into()));
    let value = json!([{ "native": { "url": "/example" } }]);
    let set = h.set(&a, "notes.raw", value.clone()).await;
    assert_eq!(set["success"], true, "{set}");
    assert_eq!(set["preference"]["value"], value);
    let found = h.call(&a, SEARCH_PREFERENCES, json!({})).await;
    assert_eq!(found["active"]["preferences"][0]["value"], value);
    // The real block still gets its origin.
    let url = found["active"]["preferences"][0]["native"]["url"]
        .as_str()
        .unwrap();
    assert!(url.starts_with("https://n8v.example/"), "{url}");
    let _ = MUTATE_PREFERENCES;
}

// ---- 6: provenance describes the body that is returned --------------------------

#[tokio::test]
async fn provenance_never_describes_a_different_body_from_the_one_returned() {
    let (h, id) = set_up("concise").await;
    let a = alice();
    let store = Store::new(&h.db, &a);
    // The body is loaded, then a web edit lands before provenance is looked up.
    let loaded = store.load_preferences().await.unwrap();
    hand_edit(&h, &web(), &id, "edited", "edit between load and lookup").await;
    let described = store.describe_active(&loaded).await.unwrap();
    let current = get_record(&h.db, &id).await["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let native = &described[0].native;
    // Either the revision is the current body's and the basis is the web
    // edit's, or no asserter is claimed. Never value A with B's basis.
    assert!(
        native["assertedBy"].is_null() || native["revision"] == json!(current),
        "{native}"
    );
    // The description is of the record as it is now, and says so: the caller
    // must return this value, not the stale one it loaded.
    let fresh = described[0].refreshed.as_ref().expect("the record moved");
    assert_eq!(fresh.value(), Some(json!("edited")));
    assert_eq!(native["assertedBy"]["basis"], "direct");
}
