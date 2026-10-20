//! Atomic account-only creation for private Foci state (task 5b5bfa5).
//!
//! `create_record` accepts one optional literal, `access_policy:
//! "account_only"`, which installs an explicit caller-account-only Manage
//! policy in the same transaction as creation. Absent retains inherited-home
//! behavior. These tests prove the privacy boundary against two canonical
//! principals from the first committed value — no payload identity, no
//! inheritance trust, no mock — plus replay and facet-CAS behavior.
//!
//! Explicit non-goal: cross-intent singleton. A constant idempotency key
//! reused under a different resolved intent is refused as an idempotency
//! conflict by the generic seam (see the keyed-replay contract); the host
//! singleton strategy is a later slice.

use native_ce::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::Db;
use serde_json::{json, Value};

// Pinned v4 UUID fixtures. Hardcoded, never generated.
const HOME: &str = "90220000-0000-4000-8000-000000000006";
const PREFS: &str = "90220000-0000-4000-8000-000000000007";
const NOTE: &str = "90220000-0000-4000-8000-000000000008";

/// Two canonically onboarded principals and a shared home. Identity comes
/// through the real engine onboarding API — canonical `acct_<32hex>` tokens
/// with person records and bindings — never a raw bindings INSERT.
struct Fixture {
    db: Db,
    acct_a: String,
    acct_b: String,
}

fn auth(account: &str) -> Caller {
    Caller::authenticated(account)
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn onboard(db: &Db, email: &str, catalog: &str, role: HostedMembershipRole) -> String {
    let arrival = HostedMembershipArrival::new(
        role,
        HostedMembershipSource::Direct,
        "2026-10-09T00:00:00Z".into(),
    )
    .unwrap();
    reconcile_hosted_identity(db, email, catalog, &arrival, None)
        .await
        .unwrap()
}

/// Two canonically onboarded principals plus a shared home folder B can file
/// into. The legacy-local caller is the fixture author and holds setup
/// authority only.
async fn fixture(registry: &ToolRegistry) -> Fixture {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let acct_a = onboard(
        &db,
        "foci-a@example.test",
        "foci-a-catalog",
        HostedMembershipRole::Owner,
    )
    .await;
    let acct_b = onboard(
        &db,
        "foci-b@example.test",
        "foci-b-catalog",
        HostedMembershipRole::Member,
    )
    .await;
    // Canonical portable tokens, never readable aliases.
    assert!(
        acct_a.starts_with("acct_") && acct_a != acct_b,
        "{acct_a} vs {acct_b}"
    );
    let local = Caller::local();
    call(
        registry,
        &db,
        local.clone(),
        "create_record",
        json!({"id":HOME,"type":"Collection","kind":"folder","name":"Shared home"}),
    )
    .await
    .unwrap();
    // B may file into the home, so the home check passes for B and only the
    // record's own explicit policy can refuse.
    call(
        registry,
        &db,
        local,
        "manage_record_policy",
        json!({"action":"grant","record_id":HOME,
            "subject":{"kind":"account","account_id":acct_b},
            "capability":"edit","reason":"Shared-home fixture."}),
    )
    .await
    .unwrap();
    Fixture { db, acct_a, acct_b }
}

#[test]
fn create_schema_advertises_only_the_account_only_literal() {
    let registry = registry();
    let schema = &registry.get("create_record").unwrap().input_schema;
    assert_eq!(
        schema["properties"]["access_policy"],
        json!({"type":"string","enum":["account_only"],
            "description":"Optional privacy boundary: the single literal account_only installs an explicit caller-account-only Manage policy atomically with creation. Absent inherits the home policy as today."}),
    );
    assert!(!schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("access_policy")));
}

#[tokio::test]
async fn private_record_is_invisible_to_b_from_first_commit() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    let created = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":PREFS,"type":"Configuration","kind":"focus_preferences",
            "name":"A prefs","home_id":HOME,
            "facets":{"focus.preferences":{"version":1,"foci":[]}},
            "access_policy":"account_only"}),
    )
    .await
    .unwrap();
    assert_eq!(created["id"].as_str().unwrap(), PREFS);

    // The explicit policy names exactly the creating account with Manage.
    let policy = call(
        &registry,
        &db,
        auth(&acct_a),
        "manage_record_policy",
        json!({"action":"list","record_id":PREFS}),
    )
    .await
    .unwrap();
    let entries = policy["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{policy}");
    assert_eq!(entries[0]["subject"]["kind"], "account");
    assert_eq!(entries[0]["subject"]["account_id"], acct_a);
    assert_eq!(entries[0]["capability"], "manage");

    // B can file into the home yet sees nothing of the record — from the
    // first committed value, with no later policy call involved. Reads
    // report the record exactly as a nonexistent one; writes refuse.
    let view_b = call(
        &registry,
        &db,
        auth(&acct_b),
        "get_record",
        json!({"ids":[PREFS]}),
    )
    .await
    .unwrap();
    assert_eq!(view_b["records"][0]["status"], "not_found", "{view_b}");
    assert_eq!(view_b["records"][0].get("name"), None, "{view_b}");
    for (tool, args) in [
        ("update_record", json!({"id":PREFS,"name":"B overwrite"})),
        (
            "manage_record_policy",
            json!({"action":"list","record_id":PREFS}),
        ),
    ] {
        let error = call(&registry, &db, auth(&acct_b), tool, args)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not exist") || error.contains("unavailable"),
            "{tool}: unexpected refusal: {error}"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn access_policy_rejects_values_routes_and_unportable_callers() {
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    // Any literal besides account_only is refused.
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"type":"Document","kind":"note","name":"x","home_id":HOME,
            "access_policy":"owner_only"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("single literal"), "{error}");
    // Message creation keeps audience policy; the field must not blend.
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"type":"Message","kind":"note","name":"m","home_id":HOME,
            "addressed_to":[],"access_policy":"account_only",
            "facets":{"expectation":"informational"}}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Message"), "{error}");
    // Legacy-local callers name no portable account; refuse, never mint a
    // policy over an unauthenticated subject.
    let error = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"x","home_id":HOME,
            "access_policy":"account_only"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("portable account"), "{error}");
    // create_many never offers the field: refuse rather than ignore.
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_many",
        json!({"reason":"Probe.","records":[{"type":"Document","kind":"note",
            "name":"x","access_policy":"account_only"}]}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("access_policy"), "{error}");
    db.close().await;
}

fn prefs_args(key: &str) -> Value {
    json!({"id":PREFS,"type":"Configuration","kind":"focus_preferences",
        "name":"A prefs","home_id":HOME,
        "facets":{"focus.preferences":{"version":1,"foci":[]}},
        "access_policy":"account_only","idempotency_key":key})
}

async fn read_record(registry: &ToolRegistry, db: &Db, caller: Caller, id: &str) -> Value {
    call(registry, db, caller, "get_record", json!({"ids":[id]}))
        .await
        .unwrap()["records"][0]
        .clone()
}

async fn read_prefs_facet(registry: &ToolRegistry, db: &Db, caller: Caller, id: &str) -> Value {
    // get_record renders facets as an array of {key, value} entries, with
    // object values serialized to JSON strings.
    let record = read_record(registry, db, caller, id).await;
    let raw = record["facets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == "focus.preferences")
        .unwrap_or_else(|| panic!("focus.preferences absent in {record}"))["value"]
        .clone();
    match raw {
        Value::String(text) => serde_json::from_str(&text).unwrap(),
        value => value,
    }
}

#[tokio::test]
async fn second_principal_read_surface_sweep_sees_nothing() {
    // Every read surface reports the private record exactly as absent for
    // the second principal: listings omit it, history/events hide it, and
    // raw query_sql over records/links/facet_values returns no rows.
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("foci-sweep-1"),
    )
    .await
    .unwrap();
    let flat = |label: &str, value: &Value| {
        let text = value.to_string();
        assert!(
            !text.contains(PREFS),
            "{label} leaks the private id: {text}"
        );
    };
    flat(
        "query_record",
        &call(
            &registry,
            &db,
            auth(&acct_b),
            "query_record",
            json!({"steps":[{"step":"filter","types":["Configuration"],"home_id":HOME}]}),
        )
        .await
        .unwrap(),
    );
    flat(
        "search",
        &call(
            &registry,
            &db,
            auth(&acct_b),
            "search",
            json!({"query":"A prefs"}),
        )
        .await
        .unwrap(),
    );
    for (label, sql) in [
        (
            "records",
            "SELECT id FROM records WHERE id = ?1 ORDER BY id",
        ),
        (
            "links",
            "SELECT source_id FROM links WHERE source_id = ?1 OR target_id = ?1 ORDER BY source_id",
        ),
        (
            "facet_values",
            "SELECT record_id FROM facet_values WHERE record_id = ?1 ORDER BY record_id",
        ),
    ] {
        let out = call(
            &registry,
            &db,
            auth(&acct_b),
            "query_sql",
            json!({"sql":sql,"parameters":[{"type":"text","value":PREFS}]}),
        )
        .await
        .unwrap();
        assert_eq!(out["rows"].as_array().unwrap().len(), 0, "{label}: {out}");
    }
    flat(
        "get_structure",
        &call(
            &registry,
            &db,
            auth(&acct_b),
            "get_structure",
            json!({"root_id":HOME}),
        )
        .await
        .unwrap(),
    );
    flat(
        "whats_changed",
        &call(&registry, &db, auth(&acct_b), "whats_changed", json!({}))
            .await
            .unwrap(),
    );
    // History of an invisible record is refused, never disclosed.
    let history = call(
        &registry,
        &db,
        auth(&acct_b),
        "get_history",
        json!({"record_id":PREFS,"detail":"metadata","order":"newest_first","limit":10}),
    )
    .await;
    match history {
        Err(error) => assert!(!error.to_string().is_empty()),
        Ok(value) => flat("get_history", &value),
    }
    db.close().await;
}

#[tokio::test]
async fn body_text_naming_b_creates_no_awareness_pointer() {
    // Literal body text has no mention semantics, and structured principal
    // mentions are Message-only (already refused with account_only): naming
    // the second principal in a private body must leave no pointer behind.
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"About B",
            "body":"Assigned to Foci B for review.","home_id":HOME,
            "access_policy":"account_only"}),
    )
    .await
    .unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM message_mentions WHERE message_id = ?")
            .bind(NOTE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    let candidates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_candidate_events WHERE message_id = ?",
    )
    .bind(NOTE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(candidates, 0);
    db.close().await;
}

#[tokio::test]
async fn keyed_private_create_replays_without_resetting_edits() {
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    let args = prefs_args("foci-prefs-constant-1");
    let first = call(&registry, &db, auth(&acct_a), "create_record", args.clone())
        .await
        .unwrap();
    assert_eq!(first["id"].as_str().unwrap(), PREFS);

    // The owner edits preferences through the ordinary guarded path, changing
    // the value so the write token strictly advances.
    let live = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    let stamp = live["updated_at"].as_str().unwrap().to_string();
    let edited_value = json!({"version":1,"foci":[
        {"focus_id":NOTE,"tier":"now","hidden":false}]});
    call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":PREFS,
            "facets":{"focus.preferences":edited_value},
            "if_unmodified_since":stamp}),
    )
    .await
    .unwrap();
    let edited = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    assert_ne!(edited["updated_at"].as_str().unwrap(), stamp);
    let events_after_edit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    // Replaying the constant creation key returns the original receipt and
    // appends nothing: edited preferences are not reset to the initial
    // empty payload.
    let replay = call(&registry, &db, auth(&acct_a), "create_record", args)
        .await
        .unwrap();
    assert_eq!(replay["id"].as_str().unwrap(), PREFS);
    let prefs_again = read_prefs_facet(&registry, &db, auth(&acct_a), PREFS).await;
    assert_eq!(prefs_again, edited_value);
    let events_after_replay: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        events_after_edit, events_after_replay,
        "replay appended events"
    );
    db.close().await;
}

#[tokio::test]
async fn same_key_with_different_request_conflicts_and_writes_nothing() {
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("foci-prefs-constant-2"),
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    // Dropping access_policy changes the normalized command: same key must
    // conflict rather than return the private record under public semantics.
    for conflicting in [
        json!({"id":NOTE,"type":"Document","kind":"note","name":"renamed",
            "home_id":HOME,"idempotency_key":"foci-prefs-constant-2"}),
        json!({"id":NOTE,"type":"Configuration","kind":"focus_preferences",
            "name":"A prefs","home_id":HOME,
            "facets":{"focus.preferences":{"version":1,"foci":[]}},
            "idempotency_key":"foci-prefs-constant-2"}),
    ] {
        let error = call(&registry, &db, auth(&acct_a), "create_record", conflicting)
            .await
            .unwrap_err();
        assert!(
            error.is_idempotency_conflict(),
            "expected idempotency_conflict, got {error}"
        );
    }
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "refused reuse wrote events");
    db.close().await;
}

#[tokio::test]
async fn concurrent_private_creates_write_once() {
    use crate::keyed_replay::{assert_concurrent_calls_write_once, KeyedCase};
    use std::sync::Arc;
    let registry = Arc::new(registry());
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    let case = KeyedCase {
        tool: "create_record",
        args: json!({"id":NOTE,"type":"Configuration","kind":"focus_preferences",
            "name":"A prefs","home_id":HOME,
            "facets":{"focus.preferences":{"version":1,"foci":[]}},
            "access_policy":"account_only","idempotency_key":"foci-prefs-race-1",
            "response_mode":"summary"}),
        conflicting: json!({}),
    };
    // This is the eight-call write-once proof. Ask for the pinned summary
    // explicitly so unrelated tests cannot exhaust the bounded full-view
    // replay pool and change the receipt shape. Verbose replay is covered by
    // keyed_private_create_replays_without_resetting_edits and the capacity
    // fallback tests; the shared harness still requires byte-identical replies.
    let receipt = assert_concurrent_calls_write_once(registry, &db, auth(&acct_a), &case, 8).await;
    assert_eq!(receipt["id"].as_str().unwrap(), NOTE);
    // Exactly one record row exists for the raced id.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id=?")
        .bind(NOTE)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    let created: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(NOTE)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(created, 1, "the racers append exactly one create event");
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events WHERE record_id=?")
        .bind(NOTE)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(policies, 1, "the racers install the private policy once");
    db.close().await;
}

#[tokio::test]
async fn derived_citation_refuses_account_only() {
    // Derived records resolve authorization to their bearer; an explicit
    // policy on the derived row would detach it. manage_record_policy
    // refuses such targets, and atomic create must too.
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    let local = Caller::local();
    let source: String = call(
        &registry,
        &db,
        local.clone(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"Source","body":"alpha beta"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bearer: String = call(
        &registry,
        &db,
        local,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Bearer"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"type":"Annotation","kind":"citation","name":"Evidence",
            "home_id":bearer,
            "links":[{"target_id":bearer,"relationship":"part_of"}],
            "target":{"target_record_id":source,"source_slot":"body",
                "purpose":"extracted_from",
                "selectors":[{"type":"text_quote","exact":"alpha"}]},
            "access_policy":"account_only"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("derived"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn existing_id_refusal_preserves_content_and_policy() {
    // Re-creating an existing shared id fails and leaves that record's
    // content and policy exactly as they were: no overwrite, no narrowing.
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    let shared: String = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"Shared",
            "body":"v1","home_id":HOME}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(shared, NOTE);
    // B reads the shared record before the attempt (sanity).
    let before = read_record(&registry, &db, auth(&acct_b), NOTE).await;
    assert_eq!(before["name"], "Shared");
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"Squatter",
            "home_id":HOME,"access_policy":"account_only"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!error.is_empty(), "duplicate id must refuse");
    let after = read_record(&registry, &db, auth(&acct_b), NOTE).await;
    assert_eq!(after["name"], "Shared", "{after}");
    assert_eq!(after["status"], "found", "{after}");
    db.close().await;
}

/// A fresh authenticated run carrying `intent`: bootstrap, declare the
/// intent, and return the run key for tool args (keyed_replay.rs precedent).
async fn run_with_intent(registry: &ToolRegistry, db: &Db, account: &str, intent: &str) -> String {
    let boot = call(registry, db, auth(account), "bootstrap", json!({}))
        .await
        .unwrap();
    let key = boot["run"]["run_key"].as_str().unwrap().to_string();
    call(
        registry,
        db,
        auth(account),
        "set_intent",
        json!({"run_key": key, "intent": intent}),
    )
    .await
    .unwrap();
    key
}

#[tokio::test]
async fn same_account_second_session_reads_edits_and_replay_survives_widening() {
    // A second authenticated run of the SAME account, under a distinct
    // resolved intent, reads and edits positively. When the owner then
    // widens the policy, replaying the original keyed create under the
    // ORIGINAL intent returns the same receipt and leaves the widened
    // policy and edited content in place — replay never narrows or resets.
    // The same key under the second intent conflicts: intent-bound replay
    // semantics are unchanged, so a constant key is not a cross-session
    // singleton (host singleton is a later slice).
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    let run1 = run_with_intent(&registry, &db, &acct_a, "Foci prefs session one").await;
    let run2 = run_with_intent(&registry, &db, &acct_a, "Foci prefs session two").await;
    let mut args = prefs_args("foci-session-1");
    args["run_key"] = json!(run1);
    call(&registry, &db, auth(&acct_a), "create_record", args.clone())
        .await
        .unwrap();
    let live = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    assert_eq!(live["status"], "found");
    let stamp = live["updated_at"].as_str().unwrap().to_string();
    let edited_value = json!({"version":1,"foci":[
        {"focus_id":NOTE,"tier":"background","hidden":true}]});
    call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":PREFS,"run_key":run2,
            "facets":{"focus.preferences":edited_value},
            "if_unmodified_since":stamp}),
    )
    .await
    .unwrap();
    // Owner widens: B gains View through the ordinary policy lane.
    call(
        &registry,
        &db,
        auth(&acct_a),
        "manage_record_policy",
        json!({"action":"grant","record_id":PREFS,
            "subject":{"kind":"account","account_id":acct_b},
            "capability":"view","reason":"Widen fixture."}),
    )
    .await
    .unwrap();
    let widened = read_record(&registry, &db, auth(&acct_b), PREFS).await;
    assert_eq!(widened["status"], "found", "{widened}");
    // Same key under the second intent: conflict, nothing written.
    let mut moved = args.clone();
    moved["run_key"] = json!(run2);
    let error = call(&registry, &db, auth(&acct_a), "create_record", moved)
        .await
        .unwrap_err();
    assert!(error.is_idempotency_conflict(), "{error}");
    // Original keyed replay under the original intent: same receipt,
    // policy stays widened, content stays edited.
    let replay = call(&registry, &db, auth(&acct_a), "create_record", args)
        .await
        .unwrap();
    assert_eq!(replay["id"].as_str().unwrap(), PREFS);
    let policy = call(
        &registry,
        &db,
        auth(&acct_a),
        "manage_record_policy",
        json!({"action":"list","record_id":PREFS}),
    )
    .await
    .unwrap();
    assert_eq!(policy["entries"].as_array().unwrap().len(), 2, "{policy}");
    assert_eq!(
        read_prefs_facet(&registry, &db, auth(&acct_a), PREFS).await,
        edited_value
    );
    db.close().await;
}

#[tokio::test]
async fn facet_edits_advance_the_timestamp_guard() {
    let registry = registry();
    let Fixture {
        db,
        acct_a,
        acct_b: _,
    } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"CAS note",
            "home_id":HOME,"facets":{"triage":"untriaged"}}),
    )
    .await
    .unwrap();
    let first = read_record(&registry, &db, auth(&acct_a), NOTE).await;
    let stale = first["updated_at"].as_str().unwrap().to_string();

    // A rival facet edit advances updated_at even though the body never moves.
    call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":NOTE,"facets":{"triage":"triaged"},
            "if_unmodified_since":stale}),
    )
    .await
    .unwrap();
    let moved = read_record(&registry, &db, auth(&acct_a), NOTE).await;
    assert_ne!(moved["updated_at"].as_str().unwrap(), stale);

    // The stale token now refuses: conflicts surface, never overwrite.
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":NOTE,"facets":{"triage":"untriaged"},
            "if_unmodified_since":stale}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.to_lowercase().contains("conflict") || error.contains("no longer"),
        "{error}"
    );
    db.close().await;
}

async fn policy_revision(registry: &ToolRegistry, db: &Db, account: &str) -> Value {
    call(
        registry,
        db,
        auth(account),
        "manage_record_policy",
        json!({"action":"list","record_id":PREFS}),
    )
    .await
    .unwrap()["policy_revision"]
        .clone()
}

async fn widen_policy(registry: &ToolRegistry, db: &Db, owner: &str, other: &str) {
    call(
        registry,
        db,
        auth(owner),
        "manage_record_policy",
        json!({"action":"grant","record_id":PREFS,
            "subject":{"kind":"account","account_id":other},"capability":"view","reason":"Exercise audience precondition."}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn write_policy_guard_refuses_policy_race_even_with_current_content_stamp() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("policy-race"),
    )
    .await
    .unwrap();
    let before = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    let old_policy = policy_revision(&registry, &db, &acct_a).await;
    widen_policy(&registry, &db, &acct_a, &acct_b).await;
    let current_policy = policy_revision(&registry, &db, &acct_a).await;
    assert_ne!(current_policy, old_policy);
    let after_policy = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    assert_eq!(before["updated_at"], after_policy["updated_at"]);
    let events = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    // Even an unchanged name must not bypass the audience precondition.
    for name in [json!("raced edit"), before["name"].clone()] {
        let error = call(
            &registry,
            &db,
            auth(&acct_a),
            "update_record",
            json!({"id":PREFS,"name":name,"if_unmodified_since":before["updated_at"],
                "if_policy_revision":old_policy}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("policy revision conflict"), "{error}");
    }
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events
    );
    call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":PREFS,"name":"fresh edit","if_unmodified_since":before["updated_at"],
            "if_policy_revision":current_policy}),
    )
    .await
    .unwrap();
    let changed = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    assert_eq!(changed["name"], "fresh edit");
    // The content guard remains independently enforced under a fresh policy.
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":PREFS,"name":"stale content","if_unmodified_since":before["updated_at"],
            "if_policy_revision":current_policy}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!error.contains("policy revision conflict"), "{error}");
    assert_eq!(
        read_record(&registry, &db, auth(&acct_a), PREFS).await["name"],
        "fresh edit"
    );
    db.close().await;
}

#[tokio::test]
async fn write_policy_guard_batch_rolls_back_prior_items_and_admits_guard_only_archive() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("batch-policy-race"),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"unchanged","home_id":HOME,
            "access_policy":"account_only"}),
    )
    .await
    .unwrap();
    let basis = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    let old_policy = policy_revision(&registry, &db, &acct_a).await;
    widen_policy(&registry, &db, &acct_a, &acct_b).await;
    let current_policy = policy_revision(&registry, &db, &acct_a).await;
    let events = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let error = call(&registry, &db, auth(&acct_a), "batch_write", json!({"reason":"Exercise atomic audience guard.","items":[
        {"op":"update","id":NOTE,"name":"must roll back"},
        {"op":"update","id":PREFS,"if_unmodified_since":basis["updated_at"],"if_policy_revision":old_policy},
        {"op":"archive","id":PREFS,"archived":true}
    ]})).await.unwrap_err().to_string();
    assert!(error.contains("policy revision conflict"), "{error}");
    assert_eq!(
        read_record(&registry, &db, auth(&acct_a), NOTE).await["name"],
        "unchanged"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events
    );
    assert_eq!(
        read_record(&registry, &db, auth(&acct_a), PREFS).await["updated_at"],
        basis["updated_at"]
    );
    let guarded_archive = json!({"reason":"Exercise atomic audience guard.","idempotency_key":"guarded-archive-replay","items":[
        {"op":"update","id":PREFS,"if_unmodified_since":basis["updated_at"],"if_policy_revision":current_policy},
        {"op":"archive","id":PREFS,"archived":true}
    ]});
    let receipt = call(
        &registry,
        &db,
        auth(&acct_a),
        "batch_write",
        guarded_archive.clone(),
    )
    .await
    .unwrap();
    assert_eq!(receipt["changed"], 1);
    let archived: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM facet_values WHERE record_id=? AND key='archived'",
    )
    .bind(PREFS)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(archived, 1);
    let committed_events =
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    // A keyed retry returns the committed receipt despite the now-old guard.
    let replay = call(
        &registry,
        &db,
        auth(&acct_a),
        "batch_write",
        guarded_archive,
    )
    .await
    .unwrap();
    assert_eq!(
        replay, receipt,
        "guarded archive retry reproduces the whole receipt"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        committed_events
    );
    for invalid_items in [
        json!([{"op":"update","id":PREFS,"name":"mutates"},{"op":"archive","id":PREFS}]),
        json!([{"op":"archive","id":PREFS},{"op":"update","id":PREFS,"if_policy_revision":current_policy}]),
        json!([{"op":"update","id":PREFS,"if_policy_revision":current_policy},{"op":"archive","id":PREFS},{"op":"archive","id":PREFS}]),
    ] {
        let error = call(
            &registry,
            &db,
            auth(&acct_a),
            "batch_write",
            json!({"reason":"Refuse repeated mutations.","items":invalid_items}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicates"), "{error}");
        assert_eq!(
            crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
            committed_events
        );
    }
    // Empty, unguarded updates continue to be refused.
    assert!(call(
        &registry,
        &db,
        auth(&acct_a),
        "batch_write",
        json!({"reason":"Exercise atomic audience guard.","items":[{"op":"update","id":NOTE}]})
    )
    .await
    .is_err());
    db.close().await;
}

#[tokio::test]
async fn write_policy_guard_tracks_every_policy_mutation_and_inherited_anchor() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(&registry, &db, Caller::local(), "manage_record_policy",
        json!({"action":"grant","record_id":HOME,"subject":{"kind":"account","account_id":acct_a},
            "capability":"manage","reason":"Authorize the account to edit the fixture parent policy."})).await.unwrap();
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("policy-transitions"),
    )
    .await
    .unwrap();
    let basis = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    let mutations = [
        json!({"action":"grant","subject":{"kind":"account","account_id":acct_b},"capability":"view"}),
        json!({"action":"revoke","subject":{"kind":"account","account_id":acct_b}}),
        json!({"action":"set_members_baseline","capability":"view"}),
        json!({"action":"replace","entries":[{"subject":{"kind":"account","account_id":acct_a},"capability":"manage"}]}),
        json!({"action":"restore_inheritance"}),
    ];
    for mut mutation in mutations {
        let old = policy_revision(&registry, &db, &acct_a).await;
        mutation["reason"] = json!("Exercise each audience transition.");
        mutation["record_id"] = json!(PREFS);
        mutation["if_policy_revision"] = old.clone();
        call(
            &registry,
            &db,
            auth(&acct_a),
            "manage_record_policy",
            mutation,
        )
        .await
        .unwrap();
        assert_ne!(policy_revision(&registry, &db, &acct_a).await, old);
        let error = call(
            &registry,
            &db,
            auth(&acct_a),
            "update_record",
            json!({"id":PREFS,"name":basis["name"],"if_policy_revision":old}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("policy revision conflict"), "{error}");
        assert_eq!(
            read_record(&registry, &db, auth(&acct_a), PREFS).await["updated_at"],
            basis["updated_at"]
        );
    }
    // A child that inherits policy must detect an edit to its policy anchor.
    let inherited = policy_revision(&registry, &db, &acct_a).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "manage_record_policy",
        json!({"action":"set_members_baseline","record_id":HOME,"capability":"view","reason":"Change inherited audience."}),
    )
    .await
    .unwrap();
    assert_ne!(policy_revision(&registry, &db, &acct_a).await, inherited);
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "batch_write",
        json!({"reason":"Exercise atomic audience guard.","items":[{"op":"update","id":PREFS,"if_policy_revision":inherited}]}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("policy revision conflict"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn write_policy_guard_keyed_singular_replays_before_current_policy_and_ids_refuse() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        prefs_args("singular-policy-replay"),
    )
    .await
    .unwrap();
    let basis = read_record(&registry, &db, auth(&acct_a), PREFS).await;
    let old = policy_revision(&registry, &db, &acct_a).await;
    let args = json!({"id":PREFS,"name":"committed edit","if_unmodified_since":basis["updated_at"],
        "if_policy_revision":old,"idempotency_key":"singular-guarded-edit"});
    let first = call(&registry, &db, auth(&acct_a), "update_record", args.clone())
        .await
        .unwrap();
    widen_policy(&registry, &db, &acct_a, &acct_b).await;
    let events = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let replay = call(&registry, &db, auth(&acct_a), "update_record", args)
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events
    );
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"ids":[PREFS],"facets":{"focus.preferences":{"version":1,"foci":[]}},
            "if_policy_revision":policy_revision(&registry, &db, &acct_a).await}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("unknown field") && error.contains("if_policy_revision"),
        "{error}"
    );
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events
    );
    db.close().await;
}

#[tokio::test]
async fn write_policy_guard_on_derived_citation_follows_the_bearer() {
    let registry = registry();
    let Fixture { db, acct_a, acct_b } = fixture(&registry).await;
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":PREFS,"type":"Collection","kind":"folder","name":"Private bearer",
            "home_id":HOME,"access_policy":"account_only"}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"id":NOTE,"type":"Document","kind":"note","name":"Source","body":"alpha beta",
            "home_id":HOME,"access_policy":"account_only"}),
    )
    .await
    .unwrap();
    let citation = call(
        &registry,
        &db,
        auth(&acct_a),
        "create_record",
        json!({"type":"Annotation","kind":"citation","name":"Evidence","home_id":PREFS,
            "links":[{"target_id":PREFS,"relationship":"part_of"}],
            "target":{"target_record_id":NOTE,"source_slot":"body","purpose":"extracted_from",
                "selectors":[{"type":"text_quote","exact":"alpha"}]}}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let old = policy_revision(&registry, &db, &acct_a).await;
    let listed = call(
        &registry,
        &db,
        auth(&acct_a),
        "manage_record_policy",
        json!({"action":"list","record_id":citation}),
    )
    .await
    .unwrap();
    assert_eq!(listed["authorization_target_id"], PREFS);
    assert_eq!(listed["policy_revision"], old);
    call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":citation,"name":"Guarded evidence","if_policy_revision":old}),
    )
    .await
    .unwrap();
    widen_policy(&registry, &db, &acct_a, &acct_b).await;
    let events = crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let error = call(
        &registry,
        &db,
        auth(&acct_a),
        "update_record",
        json!({"id":citation,"name":"must not edit","if_policy_revision":old}),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, native_ce::Error::Conflict(_)), "{error}");
    assert!(error.to_string().contains("policy revision conflict"));
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events
    );
    db.close().await;
}
