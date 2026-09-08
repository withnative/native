//! `create_record` idempotency on the provenance command-attestation mechanism.
//!
//! The ordinary create path joins the generic idempotency mechanism that
//! `manage_relationships` uses: `command_identity_digest` (trimmed caller key)
//! for lookup, `action_digest` (normalised full request) for conflict
//! detection, lookup inside the `BEGIN IMMEDIATE` transaction after the
//! handler's own authorization checks, rollback-plus-byte-identical receipt on
//! replay. These tests lock that in, including the three gaps the precedent's
//! own test leaves: concurrency, cross-principal isolation, and replay after
//! authorization loss.

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

async fn create(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    args: Value,
) -> native_ce::Result<Value> {
    call(registry, db, caller, "create_record", args).await
}

async fn content_event_count(db: &Db) -> i64 {
    crate::common::count(db, "SELECT COUNT(*) AS n FROM content_events").await
}

async fn records_named(db: &Db, name: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE name = ?")
        .bind(name)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn keyed(name: &str, key: &str) -> Value {
    json!({
        "type": "Document",
        "kind": "note",
        "name": name,
        "body": "durable prose",
        "idempotency_key": key,
    })
}

#[tokio::test]
async fn keyed_replay_returns_the_original_receipt_and_appends_nothing() {
    let db = db().await;
    let registry = registry();
    let before = content_event_count(&db).await;

    let first = create(&registry, &db, Caller::local(), keyed("replay-me", "key-1"))
        .await
        .unwrap();
    let first_id = first["id"].as_str().unwrap().to_string();
    assert_eq!(first["action_attestation_ids"].as_array().unwrap().len(), 1);
    let after_first = content_event_count(&db).await;
    assert!(after_first > before);

    let retry = create(&registry, &db, Caller::local(), keyed("replay-me", "key-1"))
        .await
        .unwrap();
    assert_eq!(retry, first, "retry receipt must be byte-identical JSON");
    assert_eq!(retry["id"].as_str().unwrap(), first_id);
    assert_eq!(
        content_event_count(&db).await,
        after_first,
        "replay must append nothing"
    );
    assert_eq!(records_named(&db, "replay-me").await, 1);
}

#[tokio::test]
async fn reused_key_with_materially_different_request_conflicts() {
    let db = db().await;
    let registry = registry();

    let first = create(
        &registry,
        &db,
        Caller::local(),
        keyed("conflict-me", "key-2"),
    )
    .await
    .unwrap();
    let first_id = first["id"].as_str().unwrap().to_string();
    let events = content_event_count(&db).await;

    let mut different = keyed("conflict-me", "key-2");
    different["body"] = json!("changed prose");
    let conflict = create(&registry, &db, Caller::local(), different)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        conflict.contains("reused with conflicting action input"),
        "{conflict}"
    );
    // The failed retry appends nothing and mints no second record.
    assert_eq!(content_event_count(&db).await, events);
    assert_eq!(records_named(&db, "conflict-me").await, 1);

    // The original key still replays the original receipt afterwards.
    let retry = create(
        &registry,
        &db,
        Caller::local(),
        keyed("conflict-me", "key-2"),
    )
    .await
    .unwrap();
    assert_eq!(retry, first);
    assert_eq!(retry["id"].as_str().unwrap(), first_id);
}

#[tokio::test]
async fn cosmetic_differences_replay_rather_than_conflict() {
    let db = db().await;
    let registry = registry();

    let first = create(&registry, &db, Caller::local(), keyed("cosmetic", "key-3"))
        .await
        .unwrap();

    // Key whitespace is lookup-scoped trimmed on both digests.
    let retry = create(
        &registry,
        &db,
        Caller::local(),
        keyed("cosmetic", "  key-3\t"),
    )
    .await
    .unwrap();
    assert_eq!(retry, first);

    // Transport-only run context never enters the request digest: the same
    // logical call under a run key replays.
    let retry = create(
        &registry,
        &db,
        Caller::local().with_run_context(Some("run-cosmetic-1".into()), None),
        keyed("cosmetic", "key-3"),
    )
    .await
    .unwrap();
    assert_eq!(retry, first);

    // Explicit nulls parse to the same absent options as omitted fields.
    let mut nulled = keyed("cosmetic", "key-3");
    nulled["summary"] = Value::Null;
    nulled["home_id"] = Value::Null;
    let retry = create(&registry, &db, Caller::local(), nulled)
        .await
        .unwrap();
    assert_eq!(retry, first);

    assert_eq!(records_named(&db, "cosmetic").await, 1);
}

#[tokio::test]
async fn create_without_a_key_behaves_as_today() {
    let db = db().await;
    let registry = registry();

    let plain = || {
        json!({
            "type": "Document",
            "kind": "note",
            "name": "unkeyed",
            "body": "same prose twice",
        })
    };
    let first = create(&registry, &db, Caller::local(), plain())
        .await
        .unwrap();
    let second = create(&registry, &db, Caller::local(), plain())
        .await
        .unwrap();
    assert_ne!(
        first["id"].as_str().unwrap(),
        second["id"].as_str().unwrap(),
        "identical content still means distinct records without a key"
    );
    assert_eq!(records_named(&db, "unkeyed").await, 2);

    // A blank key is no key: whitespace-only keys take the legacy path too.
    let blanked = || {
        json!({
            "type": "Document",
            "kind": "note",
            "name": "blank-keyed",
            "body": "same prose twice",
            "idempotency_key": "   ",
        })
    };
    let first = create(&registry, &db, Caller::local(), blanked())
        .await
        .unwrap();
    let second = create(&registry, &db, Caller::local(), blanked())
        .await
        .unwrap();
    assert_ne!(
        first["id"].as_str().unwrap(),
        second["id"].as_str().unwrap(),
        "a blank key must behave exactly as no key"
    );
    assert_eq!(records_named(&db, "blank-keyed").await, 2);
}

#[tokio::test]
async fn replay_reflects_live_alternative_set_membership() {
    // `contribution.context` (alternative-set and selection) is deliberately
    // live by design — it answers what the viewer can see now, not what the
    // attested command saw — so a replay after a membership change differs
    // from the original receipt exactly there and nowhere else. This pins
    // that tier split so the next reader meets a documented decision.
    let db = db().await;
    let registry = registry();

    let collection = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Collection",
            "kind": "folder",
            "name": "Expedition",
            "facets": {"decision.selection_role": "alternative_set"},
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut args = keyed("option-candidate", "key-9");
    args["links"] = json!([{ "target_id": collection, "relationship": "member_of" }]);
    let first = create(&registry, &db, Caller::local(), args.clone())
        .await
        .unwrap();
    let first_members = first["contribution"]["context"]["alternative_set"]["visible_member_count"]
        .as_i64()
        .unwrap();
    assert_eq!(first_members, 1);

    // A second option joins the set after the attested command committed.
    create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "late option",
            "links": [{ "target_id": collection, "relationship": "member_of" }],
        }),
    )
    .await
    .unwrap();

    let retry = create(&registry, &db, Caller::local(), args).await.unwrap();
    assert_eq!(
        retry["body_digest"], first["body_digest"],
        "pinned content still replays attested"
    );
    assert_eq!(
        retry["contribution"]["context"]["alternative_set"]["visible_member_count"],
        first_members + 1,
        "alternative-set context follows live membership by design"
    );
    assert_eq!(records_named(&db, "option-candidate").await, 1);
}

#[tokio::test]
async fn overlong_idempotency_key_is_rejected() {
    let db = db().await;
    let registry = registry();

    let mut args = keyed("sized", "k");
    args["idempotency_key"] = json!("k".repeat(201));
    let error = create(&registry, &db, Caller::local(), args)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("idempotency_key must be 1..200 characters"),
        "{error}"
    );

    // The boundary itself is usable and replays.
    let mut args = keyed("sized", "k");
    args["idempotency_key"] = json!("k".repeat(200));
    let first = create(&registry, &db, Caller::local(), args.clone())
        .await
        .unwrap();
    let retry = create(&registry, &db, Caller::local(), args).await.unwrap();
    assert_eq!(retry, first);
}

#[tokio::test]
async fn keyed_create_with_caller_supplied_id_replays() {
    let db = db().await;
    let registry = registry();
    let id = "700c3000-0000-4000-8000-0000000000a1";

    let mut args = keyed("pinned-id", "key-4");
    args["id"] = json!(id);
    let first = create(&registry, &db, Caller::local(), args.clone())
        .await
        .unwrap();
    assert_eq!(first["id"].as_str().unwrap(), id);

    let retry = create(&registry, &db, Caller::local(), args).await.unwrap();
    assert_eq!(retry, first);
    assert_eq!(records_named(&db, "pinned-id").await, 1);
}

#[tokio::test]
async fn keyed_create_covering_a_relationship_link_replays() {
    // A keyed create whose links include a relationship-owned token reserves
    // exactly one action identity for the whole command (content and
    // relationship outputs share it); the retry must still replay.
    let db = db().await;
    let registry = registry();

    let target = create(
        &registry,
        &db,
        Caller::local(),
        json!({"type": "Outcome", "kind": "target", "name": "link-target"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut args = keyed("linked", "key-5");
    args["links"] = json!([{ "target_id": target, "relationship": "depends_on" }]);
    let first = create(&registry, &db, Caller::local(), args.clone())
        .await
        .unwrap();
    assert_eq!(first["action_attestation_ids"].as_array().unwrap().len(), 1);

    let retry = create(&registry, &db, Caller::local(), args).await.unwrap();
    assert_eq!(retry, first);
    assert_eq!(records_named(&db, "linked").await, 1);
}

// ---------------------------------------------------------------------------
// Hosted callers: cross-principal isolation and authorization loss.
// ---------------------------------------------------------------------------

async fn bind_account(db: &Db, person: &str, account: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

fn hosted(account: &str) -> Caller {
    Caller::authenticated(account).with_hosting_context(format!("host:{account}"), "db:test")
}

async fn hosted_person(registry: &ToolRegistry, db: &Db, name: &str, account: &str) {
    let person = create(
        registry,
        db,
        Caller::local(),
        json!({"type": "Entity", "kind": "person", "name": name}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    bind_account(db, &person, account).await;
}

#[tokio::test]
async fn same_key_string_in_two_principal_namespaces_creates_two_records() {
    let db = db().await;
    let registry = registry();
    hosted_person(&registry, &db, "Alice", "acct:alice").await;
    hosted_person(&registry, &db, "Bea", "acct:bea").await;

    let alice_first = create(
        &registry,
        &db,
        hosted("acct:alice"),
        keyed("shared-key-record", "shared-key"),
    )
    .await
    .unwrap();
    // The conflict path is principal-scoped: Bea's FIRST use of the same key
    // string with a different body is an independent write, not a conflict
    // against Alice's command.
    let mut bea_args = keyed("shared-key-record", "shared-key");
    bea_args["body"] = json!("bea's own prose");
    let bea_first = create(&registry, &db, hosted("acct:bea"), bea_args.clone())
        .await
        .unwrap();
    assert_ne!(
        alice_first["id"].as_str().unwrap(),
        bea_first["id"].as_str().unwrap(),
        "two principals never share a key namespace"
    );
    assert_eq!(records_named(&db, "shared-key-record").await, 2);

    // And each principal replays its own record under the shared key string.
    let alice_retry = create(
        &registry,
        &db,
        hosted("acct:alice"),
        keyed("shared-key-record", "shared-key"),
    )
    .await
    .unwrap();
    assert_eq!(alice_retry, alice_first);
    let bea_retry = create(&registry, &db, hosted("acct:bea"), bea_args)
        .await
        .unwrap();
    assert_eq!(bea_retry, bea_first);
    assert_eq!(records_named(&db, "shared-key-record").await, 2);

    // While a conflicting reuse inside one namespace still conflicts there:
    // Bea's key with yet another body is hers to collide with, and Alice's
    // divergent reuse collides with hers.
    let mut bea_divergent = keyed("shared-key-record", "shared-key");
    bea_divergent["body"] = json!("bea's divergent prose");
    let bea_conflict = create(&registry, &db, hosted("acct:bea"), bea_divergent)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        bea_conflict.contains("reused with conflicting action input"),
        "{bea_conflict}"
    );
    let mut alice_different = keyed("shared-key-record", "shared-key");
    alice_different["body"] = json!("alice's divergent prose");
    let conflict = create(&registry, &db, hosted("acct:alice"), alice_different)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        conflict.contains("reused with conflicting action input"),
        "{conflict}"
    );
}

#[tokio::test]
async fn replay_after_authorization_loss_gets_the_opaque_denial() {
    let db = db().await;
    let registry = registry();
    hosted_person(&registry, &db, "Alice", "acct:alice").await;

    let args = keyed("doomed", "key-6");
    let first = create(&registry, &db, hosted("acct:alice"), args.clone())
        .await
        .unwrap();
    let record_id = first["id"].as_str().unwrap().to_string();

    // Alice loses access to the record she created: a tombstone makes it
    // unreadable to her through the ordinary eligibility fold.
    call(
        &registry,
        &db,
        Caller::local(),
        "delete_record",
        json!({"id": record_id}),
    )
    .await
    .unwrap();
    let after_delete = content_event_count(&db).await;

    let denied = create(&registry, &db, hosted("acct:alice"), args.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        denied.contains("does not exist"),
        "replay after access loss must be the opaque denial, got: {denied}"
    );
    assert!(
        !denied.contains("durable prose"),
        "the denial must not disclose record content: {denied}"
    );
    assert_eq!(
        content_event_count(&db).await,
        after_delete,
        "the denied replay must append nothing"
    );

    // Indistinguishability: the denial is byte-equal to the error a FRESH key
    // gets when it names the same missing record as a link target. Replaying
    // a dead key discloses nothing beyond what any nonexistent id would.
    let events_before_probe = content_event_count(&db).await;
    let fresh = create(
        &registry,
        &db,
        hosted("acct:alice"),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "probe",
            "idempotency_key": "never-used-key",
            "links": [{"target_id": record_id, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        denied, fresh,
        "denied replay must be indistinguishable from a missing record"
    );
    assert_eq!(
        content_event_count(&db).await,
        events_before_probe,
        "the probe must append nothing"
    );

    // Across the principal boundary, guessing Alice's key discloses nothing
    // either: Bea's identical call is an ordinary first write in her own
    // namespace, succeeding with a different record rather than replaying or
    // conflicting.
    hosted_person(&registry, &db, "Bea", "acct:bea").await;
    let bea_guess = create(&registry, &db, hosted("acct:bea"), args)
        .await
        .unwrap();
    assert_ne!(
        bea_guess["id"].as_str().unwrap(),
        record_id,
        "a guessed key must not replay another principal's record"
    );
}

#[tokio::test]
async fn replay_after_intervening_update_returns_the_attested_receipt() {
    // The lost-update guard: a retry after another writer's commit must see
    // the ATTESTED body_digest, not the live one. A guarded write issued
    // against the stale digest then fails closed instead of clobbering.
    let db = db().await;
    let registry = registry();

    let first = create(
        &registry,
        &db,
        Caller::local(),
        keyed("stale-guard", "key-7"),
    )
    .await
    .unwrap();
    let record_id = first["id"].as_str().unwrap().to_string();
    let attested_digest = first["body_digest"].as_str().unwrap().to_string();

    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id": record_id,
            "body": "another agent's edit",
            "if_body_digest": attested_digest,
        }),
    )
    .await
    .unwrap();
    let live: Value = call(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({"ids": [record_id]}),
    )
    .await
    .unwrap();
    let live_digest = live["records"][0]["body_digest"].as_str().unwrap();
    assert_ne!(
        live_digest, attested_digest,
        "sanity: the intervening update really moved the digest"
    );
    let events = content_event_count(&db).await;

    let retry = create(
        &registry,
        &db,
        Caller::local(),
        keyed("stale-guard", "key-7"),
    )
    .await
    .unwrap();
    assert_eq!(
        retry, first,
        "replay must reconstruct the attested receipt, not re-read live state"
    );
    assert_eq!(retry["body_digest"].as_str().unwrap(), attested_digest);
    assert_eq!(
        content_event_count(&db).await,
        events,
        "replay must append nothing"
    );
}
