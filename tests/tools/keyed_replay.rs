//! The shared keyed-replay seam (task 8bef361, design 515067b, slice A0).
//!
//! The first half of this file is a reusable harness: a later slice wires a
//! tool to `mcp::tools::keyed_replay` and proves the contract by building a
//! [`KeyedCase`] and calling the `assert_*` functions below. The second half
//! is A0's proving tools, `update_record` and `manage_links.add/remove`.

use std::sync::Arc;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// One keyed write under test. `args` carries an `idempotency_key`;
/// `conflicting` reuses that key with different arguments.
pub(crate) struct KeyedCase {
    pub(crate) tool: &'static str,
    pub(crate) args: Value,
    pub(crate) conflicting: Value,
}

pub(crate) fn registry() -> Arc<ToolRegistry> {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    Arc::new(registry)
}

pub(crate) async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

pub(crate) async fn call(
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

/// Everything a write can append: both canonical event logs and the
/// attestations that key them.
pub(crate) async fn write_footprint(db: &Db) -> (i64, i64, i64) {
    (
        crate::common::count(db, "SELECT COUNT(*) AS n FROM content_events").await,
        crate::common::count(db, "SELECT COUNT(*) AS n FROM relationship_events").await,
        crate::common::count(
            db,
            "SELECT COUNT(*) AS n FROM provenance_action_attestations",
        )
        .await,
    )
}

/// Byte identity, not just JSON equality: key order is part of a receipt.
pub(crate) fn assert_same_receipt(replay: &Value, first: &Value, context: &str) {
    assert_eq!(replay, first, "{context}: replay receipt differs");
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "{context}: replay receipt is not byte-identical"
    );
}

/// Same key, same arguments: the first call writes, the retry returns the
/// same receipt and appends nothing. Returns the receipt.
pub(crate) async fn assert_replays_without_writing(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    case: &KeyedCase,
) -> Value {
    let before = write_footprint(db).await;
    let first = call(registry, db, caller.clone(), case.tool, case.args.clone())
        .await
        .unwrap();
    let after_first = write_footprint(db).await;
    assert_ne!(
        after_first, before,
        "{}: the first keyed call must write",
        case.tool
    );
    let replay = call(registry, db, caller, case.tool, case.args.clone())
        .await
        .unwrap();
    assert_same_receipt(&replay, &first, case.tool);
    assert_eq!(
        write_footprint(db).await,
        after_first,
        "{}: a replay must append nothing",
        case.tool
    );
    first
}

/// Same key, different arguments: refused as `idempotency_conflict`, with
/// nothing written.
pub(crate) async fn assert_reuse_with_other_args_conflicts(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    case: &KeyedCase,
) {
    let before = write_footprint(db).await;
    let error = call(registry, db, caller, case.tool, case.conflicting.clone())
        .await
        .unwrap_err();
    assert!(
        error.is_idempotency_conflict(),
        "{}: expected idempotency_conflict, got {error}",
        case.tool
    );
    assert!(
        !matches!(error, native_ce::Error::Conflict(_)),
        "{}: a reused key is not a stale write",
        case.tool
    );
    assert_eq!(
        write_footprint(db).await,
        before,
        "{}: refusal wrote",
        case.tool
    );
}

/// Several concurrent calls with one key write exactly once and all return
/// the same receipt. `writes_once` measures the effect the tool appends once.
pub(crate) async fn assert_concurrent_calls_write_once(
    registry: Arc<ToolRegistry>,
    db: &Db,
    caller: Caller,
    case: &KeyedCase,
    concurrency: usize,
) -> Value {
    let before = write_footprint(db).await;
    let calls = (0..concurrency).map(|_| {
        let registry = registry.clone();
        let db = db.clone();
        let caller = caller.clone();
        let tool = case.tool;
        let args = case.args.clone();
        tokio::spawn(async move { call(&registry, &db, caller, tool, args).await })
    });
    let receipts = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|joined| joined.unwrap().unwrap())
        .collect::<Vec<_>>();
    for receipt in &receipts[1..] {
        assert_same_receipt(receipt, &receipts[0], case.tool);
    }
    let after = write_footprint(db).await;
    assert_ne!(after, before, "{}: nobody wrote", case.tool);
    // One more serial call with the key must be a pure replay: if any racer
    // had written separately, its attestation or events would show here as
    // a different receipt or a changed footprint.
    let replay = call(&registry, db, caller, case.tool, case.args.clone())
        .await
        .unwrap();
    assert_same_receipt(&replay, &receipts[0], case.tool);
    assert_eq!(write_footprint(db).await, after);
    receipts[0].clone()
}

/// A keyed write that changed nothing replays as that no-op even after the
/// state moves so that the same arguments would now change something.
/// `disturb` makes that move without the key.
async fn assert_noop_replays_as_noop<F, Fut>(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    case: &KeyedCase,
    disturb: F,
) -> Value
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let before = write_footprint(db).await;
    let first = call(registry, db, caller.clone(), case.tool, case.args.clone())
        .await
        .unwrap();
    assert!(
        first.get("act").is_none(),
        "{}: not a no-op: {first}",
        case.tool
    );
    let (content, relationship, attestations) = write_footprint(db).await;
    assert_eq!(
        (content, relationship),
        (before.0, before.1),
        "{}: a no-op appended events",
        case.tool
    );
    assert_eq!(
        attestations,
        before.2 + 1,
        "{}: a keyed no-op leaves one anchor",
        case.tool
    );
    disturb().await;
    let disturbed = write_footprint(db).await;
    let replay = call(registry, db, caller, case.tool, case.args.clone())
        .await
        .unwrap();
    assert_same_receipt(&replay, &first, case.tool);
    assert_eq!(
        write_footprint(db).await,
        disturbed,
        "{}: the replay wrote",
        case.tool
    );
    first
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A fresh note's verbose create receipt (it carries the guard tokens).
async fn created_note(registry: &ToolRegistry, db: &Db, name: &str, body: &str) -> Value {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": name, "body": body }),
    )
    .await
    .unwrap()
}

pub(crate) async fn note(registry: &ToolRegistry, db: &Db, name: &str, body: &str) -> String {
    created_note(registry, db, name, body).await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub(crate) async fn note_named(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    note(registry, db, name, "").await
}

async fn body_of(db: &Db, id: &str) -> String {
    sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// update_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_record_summary_append_replays_and_conflicts() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "append", "start").await;
    let case = KeyedCase {
        tool: "update_record",
        args: json!({
            "id": id, "body_append": " plus", "response_mode": "summary",
            "idempotency_key": "append-1",
        }),
        conflicting: json!({
            "id": id, "body_append": " other", "response_mode": "summary",
            "idempotency_key": "append-1",
        }),
    };
    let receipt = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(receipt["body_receipt"]["operation"], "body_append");
    assert!(receipt["act"].is_i64(), "{receipt}");
    assert_eq!(
        receipt["action_attestation_ids"].as_array().unwrap().len(),
        1
    );
    assert_eq!(body_of(&db, &id).await, "start plus");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
    // Presentation is not identity: a verbose retry replays the same write.
    let mut verbose = case.args.clone();
    verbose["response_mode"] = json!("verbose");
    let reshaped = call(&registry, &db, Caller::local(), "update_record", verbose)
        .await
        .unwrap();
    assert_eq!(reshaped["body"], "start plus");
    assert_eq!(reshaped["act"], receipt["act"]);
    assert_eq!(body_of(&db, &id).await, "start plus");
}

#[tokio::test]
async fn update_record_verbose_set_with_facets_replays_byte_identically() {
    let registry = registry();
    let db = db().await;
    let created = created_note(&registry, &db, "verbose", "old body").await;
    let id = created["id"].as_str().unwrap().to_owned();
    let digest = created["body_digest"].clone();
    assert!(digest.is_string(), "{created}");
    let case = KeyedCase {
        tool: "update_record",
        args: json!({
            "id": id, "body_set": "new body", "if_body_digest": digest,
            "name": "renamed", "facets": { "colour": "blue", "assignee": "x" },
            "sources": [], "idempotency_key": "verbose-1",
        }),
        conflicting: json!({
            "id": id, "body_set": "new body", "if_body_digest": digest,
            "name": "renamed again", "idempotency_key": "verbose-1",
        }),
    };
    let receipt = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(receipt["body"], "new body");
    assert!(receipt["source_event_id"].is_string(), "{receipt}");
    assert_eq!(receipt["basis"]["status"], "declared_none");
    assert!(receipt.get("advisories").is_none());
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
}

/// The point of keying update_record: a guarded write whose response was
/// lost succeeded, so the retry's guard is stale. With a key the retry
/// replays instead of failing.
#[tokio::test]
async fn update_record_guarded_retry_replays_instead_of_reporting_stale() {
    let registry = registry();
    let db = db().await;
    let current = created_note(&registry, &db, "guarded", "v1").await;
    let id = current["id"].as_str().unwrap().to_owned();
    assert!(current["updated_at"].is_string(), "{current}");
    let guarded = |key: Option<&str>| {
        let mut args = json!({
            "id": id, "body_set": "v2",
            "if_unmodified_since": current["updated_at"],
        });
        if let Some(key) = key {
            args["idempotency_key"] = json!(key);
        }
        args
    };
    let first = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        guarded(Some("guard-1")),
    )
    .await
    .unwrap();
    let unkeyed = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        guarded(None),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(unkeyed, native_ce::Error::Conflict(_)),
        "{unkeyed}"
    );
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        guarded(Some("guard-1")),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &first, "guarded retry");
}

/// Once the record has been written again, a replay must not hand back the
/// later state (or its body digest) as this write's result.
#[tokio::test]
async fn update_record_replay_after_a_later_write_pins_the_original_record() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "pinned", "one").await;
    for mode in ["summary", "verbose"] {
        let args = json!({
            "id": id, "body_append": format!(" {mode}"), "response_mode": mode,
            "idempotency_key": format!("pinned-{mode}"),
        });
        let first = call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            args.clone(),
        )
        .await
        .unwrap();
        call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            json!({ "id": id, "body_append": " later", "name": "later name" }),
        )
        .await
        .unwrap();
        let before = write_footprint(&db).await;
        let replay = call(&registry, &db, Caller::local(), "update_record", args)
            .await
            .unwrap();
        assert_eq!(replay["body_digest"], first["body_digest"], "{mode}");
        assert_eq!(replay["name"], first["name"], "{mode}");
        assert_eq!(replay["previous_seq"], first["previous_seq"], "{mode}");
        assert_eq!(replay["body_receipt"], first["body_receipt"], "{mode}");
        assert_same_receipt(&replay, &first, mode);
        assert_eq!(write_footprint(&db).await, before, "{mode}: replay wrote");
    }
}

#[tokio::test]
async fn update_record_concurrent_same_key_writes_once() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "race", "start").await;
    let case = KeyedCase {
        tool: "update_record",
        args: json!({ "id": id, "body_append": "!", "idempotency_key": "race-1" }),
        conflicting: Value::Null,
    };
    assert_concurrent_calls_write_once(registry, &db, Caller::local(), &case, 6).await;
    assert_eq!(body_of(&db, &id).await, "start!");
}

#[tokio::test]
async fn update_record_multi_noop_replays_as_noop() {
    let registry = registry();
    let db = db().await;
    let first = note(&registry, &db, "a", "").await;
    let second = note(&registry, &db, "b", "").await;
    for id in [&first, &second] {
        call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            json!({ "id": id, "facets": { "colour": "blue" } }),
        )
        .await
        .unwrap();
    }
    let case = KeyedCase {
        tool: "update_record",
        args: json!({
            "ids": [first, second], "facets": { "colour": "blue" },
            "idempotency_key": "noop-1",
        }),
        conflicting: json!({
            "ids": [first, second], "facets": { "colour": "green" },
            "idempotency_key": "noop-1",
        }),
    };
    let registry_for_disturb = registry.clone();
    let db_for_disturb = db.clone();
    let disturbed = first.clone();
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &case, || async move {
            call(
                &registry_for_disturb,
                &db_for_disturb,
                Caller::local(),
                "update_record",
                json!({ "id": disturbed, "facets": { "colour": "red" } }),
            )
            .await
            .unwrap();
        })
        .await;
    assert_eq!(receipt["changed"], 0, "{receipt}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
}

#[tokio::test]
async fn update_record_multi_change_replays_and_conflicts() {
    let registry = registry();
    let db = db().await;
    let first = note(&registry, &db, "a", "").await;
    let second = note(&registry, &db, "b", "").await;
    let case = KeyedCase {
        tool: "update_record",
        args: json!({
            "ids": [first, second], "facets": { "colour": "blue" }, "if_facets": { "colour": null },
            "idempotency_key": "multi-1",
        }),
        conflicting: json!({
            "ids": [first], "facets": { "colour": "blue" }, "idempotency_key": "multi-1",
        }),
    };
    let receipt = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(receipt["changed"], 2, "{receipt}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
}

// ---------------------------------------------------------------------------
// manage_links
// ---------------------------------------------------------------------------

/// The design's claim, re-checked: without a key a retried add appends
/// again. A generic token now goes through the relationship path, so the
/// duplicate is a second support assertion rather than a second
/// `link.added` content event; a closed-list token still appends content.
#[tokio::test]
async fn unkeyed_link_add_retries_append_again() {
    let registry = registry();
    let db = db().await;
    let source = note(&registry, &db, "source", "").await;
    let target = note(&registry, &db, "target", "").await;
    for relationship in ["relates_to", "derived_from"] {
        let args = json!({
            "action": "add", "source_id": source, "target_id": target,
            "relationship": relationship,
        });
        call(
            &registry,
            &db,
            Caller::local(),
            "manage_links",
            args.clone(),
        )
        .await
        .unwrap();
        let before = write_footprint(&db).await;
        call(&registry, &db, Caller::local(), "manage_links", args)
            .await
            .unwrap();
        assert_ne!(write_footprint(&db).await, before, "{relationship}");
    }
}

#[tokio::test]
async fn manage_links_add_and_remove_replay_on_both_write_paths() {
    let registry = registry();
    let db = db().await;
    let source = note(&registry, &db, "source", "").await;
    let target = note(&registry, &db, "target", "").await;
    // `relates_to` is relationship-owned; `derived_from` keeps content events.
    for (relationship, domain) in [
        ("relates_to", "relationship_assertion"),
        ("derived_from", "content_event"),
    ] {
        let add = KeyedCase {
            tool: "manage_links",
            args: json!({
                "action": "add", "source_id": source, "target_id": target,
                "relationship": relationship, "note": "why",
                "idempotency_key": format!("add-{relationship}"),
            }),
            conflicting: json!({
                "action": "add", "source_id": source, "target_id": target,
                "relationship": relationship, "note": "another reason",
                "idempotency_key": format!("add-{relationship}"),
            }),
        };
        let added = assert_replays_without_writing(&registry, &db, Caller::local(), &add).await;
        assert_eq!(added["write_receipt"]["kind"], domain, "{added}");
        assert!(added["act"].is_i64());
        assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &add).await;
        // Keys compare trimmed, as the lookup does.
        let mut padded = add.args.clone();
        padded["idempotency_key"] = json!(format!("  add-{relationship}  "));
        let trimmed = call(&registry, &db, Caller::local(), "manage_links", padded)
            .await
            .unwrap();
        assert_same_receipt(&trimmed, &added, "trimmed key");

        // A retried remove would fail without a key: the link is gone.
        let remove = KeyedCase {
            tool: "manage_links",
            args: json!({
                "action": "remove", "source_id": source, "target_id": target,
                "relationship": relationship,
                "idempotency_key": format!("remove-{relationship}"),
            }),
            conflicting: json!({
                "action": "add", "source_id": source, "target_id": target,
                "relationship": relationship,
                "idempotency_key": format!("remove-{relationship}"),
            }),
        };
        let removed =
            assert_replays_without_writing(&registry, &db, Caller::local(), &remove).await;
        assert_eq!(removed["status"], "removed");
        let mut unkeyed = remove.args.clone();
        unkeyed.as_object_mut().unwrap().remove("idempotency_key");
        assert!(
            call(&registry, &db, Caller::local(), "manage_links", unkeyed)
                .await
                .is_err()
        );
        assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &remove).await;
    }
}

#[tokio::test]
async fn manage_links_concurrent_same_key_writes_once() {
    let registry = registry();
    let db = db().await;
    let source = note(&registry, &db, "source", "").await;
    let target = note(&registry, &db, "target", "").await;
    let case = KeyedCase {
        tool: "manage_links",
        args: json!({
            "action": "add", "source_id": source, "target_id": target,
            "relationship": "relates_to", "idempotency_key": "link-race",
        }),
        conflicting: Value::Null,
    };
    let receipt =
        assert_concurrent_calls_write_once(registry, &db, Caller::local(), &case, 6).await;
    let assertions = crate::common::count(
        &db,
        "SELECT COUNT(*) AS n FROM relationship_events WHERE stream_kind = 'assertion'",
    )
    .await;
    assert_eq!(assertions, 1, "{receipt}");
}

#[tokio::test]
async fn manage_links_list_refuses_a_key() {
    let registry = registry();
    let db = db().await;
    let source = note(&registry, &db, "source", "").await;
    let error = call(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({ "action": "list", "record_id": source, "idempotency_key": "k" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("idempotency_key"), "{error}");
}

// ---------------------------------------------------------------------------
// Principals, access loss and intent (review S2)
// ---------------------------------------------------------------------------

pub(crate) fn hosted(account: &str) -> Caller {
    Caller::authenticated(account).with_hosting_context(format!("host:{account}"), "db:test")
}

/// An Entity/person bound to `account`, so a hosted caller owns what it creates.
pub(crate) async fn hosted_person(registry: &ToolRegistry, db: &Db, account: &str) {
    let person = call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Entity", "kind": "person", "name": account}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(&person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn owned_note(registry: &ToolRegistry, db: &Db, account: &str, name: &str) -> String {
    call(
        registry,
        db,
        hosted(account),
        "create_record",
        json!({"type": "Document", "kind": "note", "name": name, "body": "start"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The key namespace is the principal's own. Workspace members can edit
/// each other's records here, so another principal sending the very same key
/// and arguments is the sharpest probe: it must get an independent first
/// write — never the first principal's receipt — and its own later reuse
/// conflicts only within its own namespace.
#[tokio::test]
async fn a_second_principal_reusing_the_key_string_is_independent() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    hosted_person(&registry, &db, "acct:bea").await;
    let note = owned_note(&registry, &db, "acct:alice", "shared note").await;
    let args = json!({"id": note, "body_append": " once", "idempotency_key": "shared"});

    let alice = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "update_record",
        args.clone(),
    )
    .await
    .unwrap();
    let bea = call(
        &registry,
        &db,
        hosted("acct:bea"),
        "update_record",
        args.clone(),
    )
    .await
    .unwrap();
    // Hosted members are non-owners, so neither receipt carries the act; the
    // stored acts of the two writes are what must differ.
    let acts: Vec<Option<i64>> = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 2",
    )
    .bind(&note)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(acts.len(), 2);
    assert!(acts.iter().all(Option::is_some));
    assert_ne!(acts[0], acts[1], "Bea must not receive Alice's receipt");
    assert_ne!(
        bea["action_attestation_ids"],
        alice["action_attestation_ids"]
    );
    assert_eq!(body_of(&db, &note).await, "start once once");

    // Each principal replays only its own command.
    let before = write_footprint(&db).await;
    let alice_again = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "update_record",
        args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&alice_again, &alice, "alice replay");
    let bea_again = call(
        &registry,
        &db,
        hosted("acct:bea"),
        "update_record",
        args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&bea_again, &bea, "bea replay");
    assert_eq!(write_footprint(&db).await, before);

    // A divergent reuse conflicts inside the reusing principal's namespace.
    let mut divergent = args;
    divergent["body_append"] = json!(" twice");
    let conflict = call(
        &registry,
        &db,
        hosted("acct:bea"),
        "update_record",
        divergent,
    )
    .await
    .unwrap_err();
    assert!(conflict.is_idempotency_conflict(), "{conflict}");
    assert_eq!(write_footprint(&db).await, before);
}

/// Replay runs after the handler's own authorization: a caller who has lost
/// access since the original call, with the record still alive, gets the
/// ordinary denial — the same one a fresh key gets, so the key's existence is
/// not disclosed — and nothing is written. Three losses are covered: Edit on
/// the source of an update, Edit on the source of a link, and View on a link's
/// target alone. Mirrors create_record's opaque-denial semantics.
#[tokio::test]
async fn a_caller_who_lost_access_gets_the_fresh_key_denial() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    // Created by the local owner, so Alice is an ordinary member whose access
    // comes from the members baseline.
    let note = note(&registry, &db, "revoked source", "start").await;
    let target = note_named(&registry, &db, "revoked target").await;
    let other_source = note_named(&registry, &db, "still editable").await;
    let update = json!({"id": note, "body_append": " once", "idempotency_key": "lost-update"});
    let link = json!({"action": "add", "source_id": note, "target_id": target,
                      "relationship": "relates_to", "idempotency_key": "lost-link"});
    let target_link = json!({"action": "add", "source_id": other_source, "target_id": target,
                             "relationship": "relates_to", "idempotency_key": "lost-target"});
    for (tool, args) in [
        ("update_record", &update),
        ("manage_links", &link),
        ("manage_links", &target_link),
    ] {
        call(&registry, &db, hosted("acct:alice"), tool, args.clone())
            .await
            .unwrap();
    }

    // Remove the members baseline (capability null): Alice keeps nothing on
    // these records, and the records stay alive.
    for record in [&note, &target] {
        call(
            &registry,
            &db,
            Caller::local(),
            "manage_record_policy",
            json!({"action": "set_members_baseline", "record_id": record,
                   "reason": "Revoke the members baseline for the replay test."}),
        )
        .await
        .unwrap();
    }
    assert_eq!(body_of(&db, &note).await, "start once");
    let before = write_footprint(&db).await;
    for (tool, args) in [
        ("update_record", update),
        ("manage_links", link),
        ("manage_links", target_link),
    ] {
        let denied = call(&registry, &db, hosted("acct:alice"), tool, args.clone())
            .await
            .unwrap_err()
            .to_string();
        let mut fresh_args = args;
        fresh_args["idempotency_key"] = json!("never-used");
        let fresh = call(&registry, &db, hosted("acct:alice"), tool, fresh_args)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            denied, fresh,
            "{tool}: replay denial must match a fresh key's"
        );
        assert!(
            !denied.contains("once"),
            "{tool}: denial disclosed content: {denied}"
        );
    }
    assert_eq!(write_footprint(&db).await, before, "a denied replay wrote");
}

/// The resolved run intent is part of the command identity: the same key and
/// arguments under a different intent are refused as `idempotency_conflict`,
/// and under the same intent from a fresh run they replay.
#[tokio::test]
async fn a_changed_run_intent_conflicts_and_the_same_intent_replays() {
    let registry = registry();
    let db = db().await;
    async fn run(registry: &ToolRegistry, db: &Db, intent: &str) -> String {
        let boot = call(registry, db, Caller::local(), "bootstrap", json!({}))
            .await
            .unwrap();
        let key = boot["run"]["run_key"].as_str().unwrap().to_owned();
        call(
            registry,
            db,
            Caller::local(),
            "set_intent",
            json!({"run_key": key, "intent": intent}),
        )
        .await
        .unwrap();
        key
    }
    let id = note(&registry, &db, "intent", "start").await;
    let args = |run_key: String| {
        json!({"id": id, "body_append": " once", "response_mode": "summary",
               "idempotency_key": "intent-key", "run_key": run_key})
    };
    let first = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        args(run(&registry, &db, "Append once").await),
    )
    .await
    .unwrap();
    let before = write_footprint(&db).await;
    let conflict = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        args(run(&registry, &db, "Something else").await),
    )
    .await
    .unwrap_err();
    assert!(conflict.is_idempotency_conflict(), "{conflict}");
    assert!(
        conflict.to_string().contains("different resolved intent"),
        "{conflict}"
    );
    assert_eq!(write_footprint(&db).await, before);
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        args(run(&registry, &db, "Append once").await),
    )
    .await
    .unwrap();
    assert_eq!(replay["act"], first["act"]);
    assert_eq!(replay["body_digest"], first["body_digest"]);
    assert_eq!(write_footprint(&db).await, before);
    assert_eq!(body_of(&db, &id).await, "start once");
}

// ---------------------------------------------------------------------------
// previous_seq and act-less events (review N2)
// ---------------------------------------------------------------------------

/// Append an event with no act, as a pre-act bundle import would.
async fn insert_actless_event(db: &Db, record_id: &str, id: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'record.updated', '{\"reason\":\"imported\"}', 'importer',
                 '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')
         RETURNING seq",
    )
    .bind(id)
    .bind(record_id)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

/// `previous_seq` pins the record's position just before the command. An
/// act-less event written before it is part of that position; one imported
/// after it must not inflate the replayed value.
#[tokio::test]
async fn update_record_replay_previous_seq_ignores_actless_events_imported_later() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "actless", "one").await;
    let earlier = insert_actless_event(&db, &id, "actless-before").await;
    let args = json!({
        "id": id, "body_append": " two", "response_mode": "summary",
        "idempotency_key": "actless-1",
    });
    let first = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["previous_seq"], earlier, "{first}");

    let later = insert_actless_event(&db, &id, "actless-after").await;
    assert!(later > earlier);
    let before = write_footprint(&db).await;
    let replay = call(&registry, &db, Caller::local(), "update_record", args)
        .await
        .unwrap();
    assert_eq!(
        replay["previous_seq"], first["previous_seq"],
        "a later act-less import inflated previous_seq: {replay}"
    );
    assert_eq!(write_footprint(&db).await, before);
}

// ---------------------------------------------------------------------------
// Slice A1: record-scoped writes on the seam
// ---------------------------------------------------------------------------

/// A later unkeyed write on the same record, then the keyed call again: the
/// replay still returns the first receipt byte for byte.
async fn assert_replay_is_pinned_after_later_write(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    case: &KeyedCase,
    first: &Value,
    later: (&str, Value),
) {
    call(registry, db, Caller::local(), later.0, later.1)
        .await
        .unwrap();
    let before = write_footprint(db).await;
    let replay = call(registry, db, caller, case.tool, case.args.clone())
        .await
        .unwrap();
    assert_same_receipt(&replay, first, case.tool);
    assert_eq!(
        write_footprint(db).await,
        before,
        "{}: replay wrote",
        case.tool
    );
}

#[tokio::test]
async fn facet_observations_set_and_unset_replay_conflict_and_stay_pinned() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "observed", "").await;
    let observation = |action: &str, value: &str, key: &str| {
        let mut args = json!({
            "action": action, "record_id": id, "key": "current",
            "as_of": "2026-08-01T00:00:00Z", "reason": "Measured at this valid time.",
            "idempotency_key": key,
        });
        if action == "set" {
            args["value"] = json!(value);
        }
        args
    };
    let set = KeyedCase {
        tool: "manage_facet_observations",
        args: observation("set", "11", "obs-set"),
        conflicting: observation("set", "12", "obs-set"),
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &set).await;
    assert_eq!(first["status"], "set", "{first}");
    assert!(first["act"].is_i64(), "{first}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &set).await;
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        Caller::local(),
        &set,
        &first,
        ("update_record", json!({"id": id, "body_append": "moved"})),
    )
    .await;

    let unset = KeyedCase {
        tool: "manage_facet_observations",
        args: observation("unset", "", "obs-unset"),
        conflicting: json!({
            "action": "unset", "record_id": id, "key": "other",
            "as_of": "2026-08-01T00:00:00Z", "reason": "Measured at this valid time.",
            "idempotency_key": "obs-unset",
        }),
    };
    let removed = assert_replays_without_writing(&registry, &db, Caller::local(), &unset).await;
    assert_eq!(removed["status"], "unset", "{removed}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &unset).await;
}

/// The new record-scoped writes replay after authorization too: a member who
/// lost Edit gets the fresh-key denial, not the original receipt.
#[tokio::test]
async fn a_revoked_member_replaying_an_observation_gets_the_fresh_key_denial() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let id = note(&registry, &db, "observed by a member", "").await;
    let args = json!({
        "action": "set", "record_id": id, "key": "current", "value": "11",
        "as_of": "2026-08-01T00:00:00Z", "reason": "Measured.", "idempotency_key": "member-obs",
    });
    call(
        &registry,
        &db,
        hosted("acct:alice"),
        "manage_facet_observations",
        args.clone(),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "set_members_baseline", "record_id": id,
               "reason": "Revoke the members baseline for the replay test."}),
    )
    .await
    .unwrap();
    let before = write_footprint(&db).await;
    let denied = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "manage_facet_observations",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    let mut fresh = args;
    fresh["idempotency_key"] = json!("never-used");
    let fresh = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "manage_facet_observations",
        fresh,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(denied, fresh);
    assert_eq!(write_footprint(&db).await, before);
}

#[tokio::test]
async fn archive_record_replays_conflicts_and_replays_a_noop_as_a_noop() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "archivable", "").await;
    let archive = KeyedCase {
        tool: "archive_record",
        args: json!({"id": id, "reason": "Done", "idempotency_key": "archive-1"}),
        conflicting: json!({"id": id, "archived": false, "reason": "Done",
                            "idempotency_key": "archive-1"}),
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &archive).await;
    assert_eq!(first["changed"], true, "{first}");
    assert!(
        first["previous_seq"].is_i64() && first["act"].is_i64(),
        "{first}"
    );
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &archive).await;
    // Restoring and writing again leaves the keyed archive's receipt alone.
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        Caller::local(),
        &archive,
        &first,
        (
            "archive_record",
            json!({"id": id, "archived": false, "reason": "Back again"}),
        ),
    )
    .await;

    // A keyed archive of an already archived record is a no-op that leaves an
    // anchor, and a retry replays the no-op even after a restore would make
    // the same arguments change something.
    call(
        &registry,
        &db,
        Caller::local(),
        "archive_record",
        json!({"id": id, "reason": "Archive for the no-op case"}),
    )
    .await
    .unwrap();
    let noop = KeyedCase {
        tool: "archive_record",
        args: json!({"id": id, "reason": "Already archived", "idempotency_key": "archive-noop"}),
        conflicting: json!({"id": id, "archived": false, "reason": "Already archived",
                            "idempotency_key": "archive-noop"}),
    };
    let registry_for_disturb = registry.clone();
    let db_for_disturb = db.clone();
    let disturbed = id.clone();
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &noop, || async move {
            call(
                &registry_for_disturb,
                &db_for_disturb,
                Caller::local(),
                "archive_record",
                json!({"id": disturbed, "archived": false, "reason": "Restore"}),
            )
            .await
            .unwrap();
        })
        .await;
    assert_eq!(receipt["changed"], false, "{receipt}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &noop).await;
}

#[tokio::test]
async fn claim_unowned_record_replays_the_claim_and_conflicts() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let claimable = note(&registry, &db, "ownerless", "").await;
    let owner = hosted("acct:alice").with_hosting_owner(true);
    let case = KeyedCase {
        tool: "claim_unowned_record",
        args: json!({"record_id": claimable, "reason": "Recover abandoned work",
                     "idempotency_key": "claim-1"}),
        conflicting: json!({"record_id": claimable, "reason": "A different reason",
                            "idempotency_key": "claim-1"}),
    };
    let first = assert_replays_without_writing(&registry, &db, owner.clone(), &case).await;
    assert!(
        first["owner_id"].is_string() && first["event_seq"].is_i64(),
        "{first}"
    );
    assert_reuse_with_other_args_conflicts(&registry, &db, owner.clone(), &case).await;
    // Without the key the retry is refused: the record now has an owner.
    let mut unkeyed = case.args.clone();
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    call(
        &registry,
        &db,
        owner.clone(),
        "claim_unowned_record",
        unkeyed,
    )
    .await
    .unwrap_err();
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        owner,
        &case,
        &first,
        (
            "update_record",
            json!({"id": claimable, "body_append": "moved"}),
        ),
    )
    .await;
}

#[tokio::test]
async fn citation_reanchor_replays_conflicts_and_survives_a_changed_source() {
    let registry = registry();
    let db = db().await;
    let source = note(&registry, &db, "source", "alpha beta").await;
    let bearer = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type": "WorkItem", "kind": "task", "name": "Bearer"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let citation = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type": "Annotation", "kind": "citation", "name": "Evidence",
            "body": "Why this matters",
            "links": [{"target_id": bearer, "relationship": "part_of"}],
            "target": {"target_record_id": source, "source_slot": "body",
                       "selectors": [{"type": "text_quote", "exact": "alpha"}]},
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reanchor = |exact: &str| {
        json!({
            "action": "reanchor", "citation_id": citation,
            "target": {"target_record_id": source, "source_slot": "body",
                       "selectors": [{"type": "text_quote", "exact": exact}]},
            "reason": "The evidence is the second word", "idempotency_key": "cite-1",
        })
    };
    let case = KeyedCase {
        tool: "manage_citations",
        args: reanchor("beta"),
        conflicting: reanchor("alpha"),
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(first["action"], "reanchored", "{first}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
    // The quoted text is gone from the source now, so an unkeyed retry could
    // not capture it; the key replays the original receipt instead.
    let digest = call(
        &registry,
        &db,
        Caller::local(),
        "get_record",
        json!({"ids": [source]}),
    )
    .await
    .unwrap()["records"][0]["body_digest"]
        .clone();
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        Caller::local(),
        &case,
        &first,
        (
            "update_record",
            json!({"id": source, "body_set": "gamma", "if_body_digest": digest}),
        ),
    )
    .await;
    // `remove` is not a keyed action.
    let refused = call(
        &registry,
        &db,
        Caller::local(),
        "manage_citations",
        json!({"action": "remove", "citation_id": citation, "reason": "x",
               "idempotency_key": "cite-remove"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("idempotency_key"), "{refused}");
}

fn agent_caller(
    issuer: &native_ce::awareness::HumanInteractionTokenIssuer,
    bearer: &str,
) -> Caller {
    let ids = vec![bearer.to_string()];
    let token = issuer
        .issue(
            "local",
            "agent-executor:test-agent:test-delegation",
            &ids,
            60,
        )
        .unwrap();
    Caller::local()
        .with_agent_executor_token(issuer, &token, "test-agent", "test-delegation", &ids)
        .unwrap()
}

/// An assessment attribution over `bearer`'s current body, made by an agent.
async fn assessment(registry: &ToolRegistry, db: &Db, bearer: &str) -> Value {
    use sha2::{Digest, Sha256};
    let (event_id, body): (String, String) = sqlx::query_as(
        "SELECT e.id, r.body FROM records r JOIN content_events e ON e.record_id = r.id
          WHERE r.id = ? AND e.type = 'record.created'",
    )
    .bind(bearer)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("agent");
    call(
        registry,
        db,
        agent_caller(&issuer, bearer),
        "create_attribution",
        json!({
            "idempotency_key": format!("assess-{}", uuid::Uuid::new_v4()),
            "bearer_id": bearer,
            "target": {"source_event_id": event_id,
                       "source_body_sha256": hex::encode(Sha256::digest(body.as_bytes())),
                       "scope": "whole_revision", "selectors": []},
            "subject": {"kind": "self_agent_execution"},
            "relation": "expresses_view", "polarity": "affirmed", "confidence": "likely",
            "transformation": "summary",
            "rationale": "The agent assesses that the exact revision is its own view.",
        }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn attribution_retract_and_add_evidence_replay_and_conflict() {
    let registry = registry();
    let db = db().await;
    let bearer = note(&registry, &db, "claim bearer", "A considered view.").await;
    let evidence = assessment(&registry, &db, &bearer).await;
    let annotation = evidence["annotation_id"].as_str().unwrap().to_owned();
    let attestation = evidence["action_attestation_id"].clone();

    let add = KeyedCase {
        tool: "manage_attributions",
        args: json!({"action": "add_evidence", "annotation_id": annotation,
                     "evidence": {"role": "basis", "action_attestation_id": attestation},
                     "idempotency_key": "attr-evidence"}),
        conflicting: json!({"action": "add_evidence", "annotation_id": annotation,
                            "evidence": {"role": "counterevidence",
                                         "action_attestation_id": attestation},
                            "idempotency_key": "attr-evidence"}),
    };
    let added = assert_replays_without_writing(&registry, &db, Caller::local(), &add).await;
    assert_eq!(added["action"], "evidence_added", "{added}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &add).await;

    let retract = KeyedCase {
        tool: "manage_attributions",
        args: json!({"action": "retract", "annotation_id": annotation,
                     "reason": "The subject was resolved incorrectly.",
                     "idempotency_key": "attr-retract"}),
        conflicting: json!({"action": "retract", "annotation_id": annotation,
                            "reason": "A different reason.", "idempotency_key": "attr-retract"}),
    };
    let retracted = assert_replays_without_writing(&registry, &db, Caller::local(), &retract).await;
    assert_eq!(retracted["action"], "retracted", "{retracted}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &retract).await;
    // Unkeyed, the second retraction is refused; keyed, it replays.
    let mut unkeyed = retract.args.clone();
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_attributions",
        unkeyed,
    )
    .await
    .unwrap_err();
}

#[tokio::test]
async fn suggestion_reject_replays_and_accept_refuses_a_key() {
    let registry = registry();
    let db = db().await;
    let target = note(&registry, &db, "suggested", "alpha beta").await;
    let suggestion = |name: &str| {
        let target = target.clone();
        let registry = &registry;
        let db = &db;
        let name = name.to_owned();
        async move {
            call(
                registry,
                db,
                Caller::local(),
                "create_record",
                json!({
                    "type": "Annotation", "kind": "suggestion", "name": name,
                    "lifecycle": "open", "body": "gamma",
                    "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
                    "links": [{"target_id": target, "relationship": "part_of"}],
                }),
            )
            .await
            .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let rejected = suggestion("to reject").await;
    let case = KeyedCase {
        tool: "resolve_suggestions",
        args: json!({"action": "reject", "suggestion_ids": [rejected],
                     "reason": "Not needed", "idempotency_key": "suggest-1"}),
        conflicting: json!({"action": "reject", "suggestion_ids": [rejected],
                            "reason": "A different reason", "idempotency_key": "suggest-1"}),
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(first["status"], "rejected", "{first}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
    // Unkeyed, the retry is a lifecycle conflict; the key replays the rejection.
    let mut unkeyed = case.args.clone();
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    let unkeyed = call(
        &registry,
        &db,
        Caller::local(),
        "resolve_suggestions",
        unkeyed,
    )
    .await
    .unwrap();
    assert_eq!(unkeyed["status"], "conflict", "{unkeyed}");

    // Accept is not keyed, and says so by name.
    let open = suggestion("to accept").await;
    let refused = call(
        &registry,
        &db,
        Caller::local(),
        "resolve_suggestions",
        json!({"action": "accept", "suggestion_ids": [open], "reason": "Yes",
               "idempotency_key": "suggest-accept"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("accept does not accept idempotency_key"),
        "{refused}"
    );
    assert_eq!(body_of(&db, &target).await, "alpha beta");
}

/// A person who owns personas: an account and a native-principal binding.
async fn participant_owner(registry: &ToolRegistry, db: &Db, account: &str) {
    hosted_person(registry, db, account).await;
    let person: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system = 'account' AND identifier = ?",
    )
    .bind(account)
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'native-principal', ?, 1)",
    )
    .bind(person)
    .bind(format!("native/{}", account.trim_start_matches("acct:")))
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn participants_register_and_retire_replay_and_conflict() {
    let registry = registry();
    let db = db().await;
    participant_owner(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let register = KeyedCase {
        tool: "manage_participants",
        args: json!({"action": "register_persona", "name": "Chief", "reason": "A named persona.",
                     "idempotency_key": "persona-1"}),
        conflicting: json!({"action": "register_persona", "name": "Deputy",
                            "reason": "A named persona.", "idempotency_key": "persona-1"}),
    };
    let registered = assert_replays_without_writing(&registry, &db, alice.clone(), &register).await;
    assert_eq!(registered["state"], "active", "{registered}");
    let persona = registered["persona_id"].as_str().unwrap().to_owned();
    assert_reuse_with_other_args_conflicts(&registry, &db, alice.clone(), &register).await;
    // One persona, not one per attempt.
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM personas").await,
        1
    );

    let retire = KeyedCase {
        tool: "manage_participants",
        args: json!({"action": "retire_persona", "persona_id": persona,
                     "reason": "No longer needed.", "idempotency_key": "persona-retire"}),
        conflicting: json!({"action": "retire_persona", "persona_id": persona,
                            "reason": "A different reason.", "idempotency_key": "persona-retire"}),
    };
    let retired = assert_replays_without_writing(&registry, &db, alice.clone(), &retire).await;
    assert_eq!(retired["state"], "retired", "{retired}");
    assert_reuse_with_other_args_conflicts(&registry, &db, alice.clone(), &retire).await;
    // Unkeyed, the second retirement fails: the persona is no longer active.
    let mut unkeyed = retire.args.clone();
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    call(&registry, &db, alice, "manage_participants", unkeyed)
        .await
        .unwrap_err();
}

// ---------------------------------------------------------------------------
// Lost access, table-driven (A1 review S1)
// ---------------------------------------------------------------------------

/// One keyed call by `caller` that `revoke` then takes away the access for.
struct LostAccess {
    label: &'static str,
    tool: &'static str,
    caller: Caller,
    args: Value,
    /// Records whose explicit policy stops naming the caller after the keyed
    /// call.
    revoke: Vec<String>,
    /// Withdraws the caller's host ownership instead of a record grant.
    drop_host_owner: bool,
}

/// Make `account` hold exactly `capability` on `record`.
async fn grant(
    db: &Db,
    record: &str,
    account: &str,
    capability: native_ce::authorization::Capability,
) {
    native_ce::authorization::replace_explicit_policy(
        db,
        "local",
        record,
        vec![native_ce::authorization::AllowEntry::account(
            account, capability,
        )],
    )
    .await
    .unwrap();
}

/// A caller who loses the access after a committed keyed call must get
/// exactly the refusal a fresh key gets (replay runs after authorization, so
/// the key's existence is not an oracle), and nothing is written.
async fn assert_lost_access_gets_the_fresh_key_denial(
    registry: &ToolRegistry,
    db: &Db,
    case: LostAccess,
) {
    let first = call(
        registry,
        db,
        case.caller.clone(),
        case.tool,
        case.args.clone(),
    )
    .await
    .unwrap_or_else(|error| panic!("{}: the keyed call must succeed first: {error}", case.label));
    // Still replays while the access is intact.
    let replay = call(
        registry,
        db,
        case.caller.clone(),
        case.tool,
        case.args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &first, case.label);
    for record in &case.revoke {
        grant(
            db,
            record,
            "acct:nobody",
            native_ce::authorization::Capability::Manage,
        )
        .await;
    }
    let caller = if case.drop_host_owner {
        case.caller.clone().with_hosting_owner(false)
    } else {
        case.caller.clone()
    };
    let before = write_footprint(db).await;
    let denied = call(registry, db, caller.clone(), case.tool, case.args.clone())
        .await
        .expect_err(&format!(
            "{}: a replay after losing access must be refused",
            case.label
        ))
        .to_string();
    let mut fresh_args = case.args.clone();
    fresh_args["idempotency_key"] = json!("never-used");
    let fresh = call(registry, db, caller, case.tool, fresh_args)
        .await
        .expect_err(&format!("{}: a fresh key must be refused too", case.label))
        .to_string();
    assert_eq!(
        denied, fresh,
        "{}: the replay denial must match a fresh key's",
        case.label
    );
    assert_eq!(
        write_footprint(db).await,
        before,
        "{}: a denied replay wrote",
        case.label
    );
}

#[tokio::test]
async fn every_a1_tool_refuses_a_caller_who_lost_access_like_a_fresh_key() {
    use native_ce::authorization::Capability;
    let registry = registry();
    let db = db().await;
    participant_owner(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let mut cases = Vec::new();

    // archive_record: Manage on the record.
    let archivable = note(&registry, &db, "archive me", "").await;
    grant(&db, &archivable, "acct:alice", Capability::Manage).await;
    cases.push(LostAccess {
        label: "archive_record",
        tool: "archive_record",
        caller: alice.clone(),
        args: json!({"id": archivable, "reason": "Done", "idempotency_key": "lost-archive"}),
        revoke: vec![archivable.clone()],
        drop_host_owner: false,
    });

    // claim_unowned_record: host-owner status. (View cannot be lost here: the
    // claim makes the caller the record's owner.)
    let claimable = note(&registry, &db, "claim me", "").await;
    cases.push(LostAccess {
        label: "claim_unowned_record (host owner)",
        tool: "claim_unowned_record",
        caller: alice.clone().with_hosting_owner(true),
        args: json!({"record_id": claimable, "reason": "Recover abandoned work",
                     "idempotency_key": "lost-claim"}),
        revoke: vec![],
        drop_host_owner: true,
    });

    // manage_citations.reanchor: Edit on the bearer, and View on the target.
    for (label, revoke_bearer) in [
        ("reanchor (bearer Edit)", true),
        ("reanchor (target View)", false),
    ] {
        let source = note(&registry, &db, &format!("{label} source"), "alpha beta").await;
        let bearer = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({"type": "WorkItem", "kind": "task", "name": format!("{label} bearer")}),
        )
        .await
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let citation = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({
                "type": "Annotation", "kind": "citation", "name": "Evidence",
                "body": "Why this matters",
                "links": [{"target_id": bearer, "relationship": "part_of"}],
                "target": {"target_record_id": source, "source_slot": "body",
                           "selectors": [{"type": "text_quote", "exact": "alpha"}]},
            }),
        )
        .await
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        cases.push(LostAccess {
            label,
            tool: "manage_citations",
            caller: alice.clone(),
            args: json!({
                "action": "reanchor", "citation_id": citation,
                "target": {"target_record_id": source, "source_slot": "body",
                           "selectors": [{"type": "text_quote", "exact": "beta"}]},
                "reason": "The evidence is the second word",
                "idempotency_key": format!("lost-{label}"),
            }),
            revoke: vec![if revoke_bearer { bearer } else { source }],
            drop_host_owner: false,
        });
    }

    // manage_attributions retract / add_evidence: Edit on the bearer.
    for action in ["retract", "add_evidence"] {
        let bearer = note(
            &registry,
            &db,
            &format!("{action} bearer"),
            "A considered view.",
        )
        .await;
        let evidence = assessment(&registry, &db, &bearer).await;
        let annotation = evidence["annotation_id"].clone();
        let args = if action == "retract" {
            json!({"action": "retract", "annotation_id": annotation,
                   "reason": "The subject was resolved incorrectly.",
                   "idempotency_key": "lost-retract"})
        } else {
            json!({"action": "add_evidence", "annotation_id": annotation,
                   "evidence": {"role": "basis",
                                "action_attestation_id": evidence["action_attestation_id"]},
                   "idempotency_key": "lost-add-evidence"})
        };
        cases.push(LostAccess {
            label: action,
            tool: "manage_attributions",
            caller: alice.clone(),
            args,
            revoke: vec![bearer],
            drop_host_owner: false,
        });
    }

    // manage_participants: Edit on the new persona's home.
    let home = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type": "Collection", "kind": "folder", "name": "persona home"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    grant(&db, &home, "acct:alice", Capability::Edit).await;
    cases.push(LostAccess {
        label: "register_persona (home Edit)",
        tool: "manage_participants",
        caller: alice.clone(),
        args: json!({"action": "register_persona", "name": "Chief", "home_id": home,
                     "reason": "A named persona.", "idempotency_key": "lost-register"}),
        revoke: vec![home],
        drop_host_owner: false,
    });
    // retire_persona (Manage) has no lost-access case: a registered persona's
    // policy is owner-locked, so its owner cannot lose Manage on it.

    // resolve_suggestions.reject: Edit on the target.
    let target = note(&registry, &db, "suggested", "alpha beta").await;
    let suggestion = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type": "Annotation", "kind": "suggestion", "name": "to reject",
            "lifecycle": "open", "body": "gamma",
            "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
            "links": [{"target_id": target, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cases.push(LostAccess {
        label: "resolve_suggestions.reject",
        tool: "resolve_suggestions",
        caller: alice.clone(),
        args: json!({"action": "reject", "suggestion_ids": [suggestion],
                     "reason": "Not needed", "idempotency_key": "lost-reject"}),
        revoke: vec![target],
        drop_host_owner: false,
    });

    for case in cases {
        assert_lost_access_gets_the_fresh_key_denial(&registry, &db, case).await;
    }
}

// ---------------------------------------------------------------------------
// update_record: a committed large body still replays (A1 review N2)
// ---------------------------------------------------------------------------

/// A body of about 250 KB used to put the latest body event over the 1 MiB
/// per-event replay cap (a 6x charge), so a retry after any later write was
/// refused as "historical replay budget exceeded" for a write that had
/// committed. Replaying must never be refused for the size of what it wrote.
#[tokio::test]
async fn update_record_replay_of_a_large_body_survives_a_later_write() {
    let registry = registry();
    let db = db().await;
    let id = note(&registry, &db, "large body", "start").await;
    let large = "x".repeat(250 * 1024);
    for (mode, key) in [("summary", "large-summary"), ("verbose", "large-verbose")] {
        let args = json!({
            "id": id, "body_append": large, "response_mode": mode, "idempotency_key": key,
        });
        let first = call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            args.clone(),
        )
        .await
        .unwrap();
        call(
            &registry,
            &db,
            Caller::local(),
            "update_record",
            json!({"id": id, "body_append": " later", "name": format!("later {mode}")}),
        )
        .await
        .unwrap();
        let before = write_footprint(&db).await;
        let replay = call(&registry, &db, Caller::local(), "update_record", args)
            .await
            .unwrap_or_else(|error| panic!("{mode}: a committed write must replay: {error}"));
        assert_eq!(replay["body_digest"], first["body_digest"], "{mode}");
        assert_same_receipt(&replay, &first, mode);
        assert_eq!(write_footprint(&db).await, before, "{mode}: replay wrote");
    }
}

// ---------------------------------------------------------------------------
// register_persona: replay before the schema check, and the adopt branch
// (A1 review N3, N6)
// ---------------------------------------------------------------------------

/// A vocabulary-governed facet value that was valid when the persona was
/// registered and has been withdrawn since must not turn the retry into a
/// validation failure; a fresh key still gets the current schema's refusal.
#[tokio::test]
async fn register_persona_replays_before_revalidating_facets_against_the_schema() {
    let registry = registry();
    let db = db().await;
    participant_owner(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let schema = |values: Value| {
        json!({"action": "write", "data": {"shapes": {
            "Entity:persona": {"facets": {"stage": {"values": values}}}
        }}})
    };
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_schema_config",
        schema(json!(["draft", "live"])),
    )
    .await
    .unwrap();
    let args = json!({"action": "register_persona", "name": "Chief", "reason": "A named persona.",
                      "facets": {"stage": "draft"}, "idempotency_key": "persona-schema"});
    let first = call(
        &registry,
        &db,
        alice.clone(),
        "manage_participants",
        args.clone(),
    )
    .await
    .unwrap();
    // "draft" is withdrawn after the persona was registered.
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_schema_config",
        schema(json!(["live"])),
    )
    .await
    .unwrap();
    let before = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        alice.clone(),
        "manage_participants",
        args.clone(),
    )
    .await
    .unwrap_or_else(|error| panic!("the retry must replay, not revalidate: {error}"));
    assert_same_receipt(&replay, &first, "register_persona");
    assert_eq!(write_footprint(&db).await, before);
    let mut fresh = args;
    fresh["idempotency_key"] = json!("persona-schema-fresh");
    let refused = call(&registry, &db, alice, "manage_participants", fresh)
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("declared values"), "{refused}");
}

/// Registering an existing owner-only persona profile by `record_id` is the
/// other register branch: it replays too, and registers once.
#[tokio::test]
async fn register_persona_adopting_an_existing_profile_replays() {
    let registry = registry();
    let db = db().await;
    participant_owner(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let profile = call(
        &registry,
        &db,
        alice.clone(),
        "create_record",
        json!({"type": "Entity", "kind": "persona", "name": "Existing Chief"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The adopt branch requires an owner-only profile.
    native_ce::authorization::replace_explicit_policy(
        &db,
        "acct:alice",
        &profile,
        vec![native_ce::authorization::AllowEntry::account(
            "acct:alice",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    let case = KeyedCase {
        tool: "manage_participants",
        args: json!({"action": "register_persona", "record_id": profile,
                     "reason": "Adopt the profile.", "idempotency_key": "persona-adopt"}),
        conflicting: json!({"action": "register_persona", "record_id": profile,
                            "reason": "A different reason.", "idempotency_key": "persona-adopt"}),
    };
    let registered = assert_replays_without_writing(&registry, &db, alice.clone(), &case).await;
    assert_eq!(registered["persona_id"], json!(profile), "{registered}");
    assert_eq!(registered["state"], "active");
    assert_reuse_with_other_args_conflicts(&registry, &db, alice.clone(), &case).await;
    // The profile is registered now, so unkeyed it would be refused; the key
    // replays it, and no second persona appears.
    let mut unkeyed = case.args.clone();
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    call(&registry, &db, alice, "manage_participants", unkeyed)
        .await
        .unwrap_err();
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM personas").await,
        1
    );
}

// ---------------------------------------------------------------------------
// resolve_suggestions.reject: the unanchored conflict (A1 review N6)
// ---------------------------------------------------------------------------

/// A keyed reject that finds the suggestion no longer open returns the
/// `conflict` outcome and leaves NO anchor, because that outcome embeds the
/// suggestion's live lifecycle. The key is therefore still free to be used
/// for a first call.
#[tokio::test]
async fn an_unanchored_reject_conflict_leaves_the_key_free() {
    let registry = registry();
    let db = db().await;
    let target = note(&registry, &db, "suggested", "alpha beta").await;
    let suggestion = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type": "Annotation", "kind": "suggestion", "name": "to reject",
            "lifecycle": "open", "body": "gamma",
            "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
            "links": [{"target_id": target, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reject = |key: &str| {
        json!({"action": "reject", "suggestion_ids": [suggestion],
               "reason": "Not needed", "idempotency_key": key})
    };
    // Reject it without a key, so the keyed call finds it already resolved.
    let mut unkeyed = reject("unused");
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    let rejected = call(
        &registry,
        &db,
        Caller::local(),
        "resolve_suggestions",
        unkeyed,
    )
    .await
    .unwrap();
    assert_eq!(rejected["status"], "rejected", "{rejected}");

    let before = write_footprint(&db).await;
    let conflict = call(
        &registry,
        &db,
        Caller::local(),
        "resolve_suggestions",
        reject("reopened-later"),
    )
    .await
    .unwrap();
    assert_eq!(conflict["status"], "conflict", "{conflict}");
    assert_eq!(
        write_footprint(&db).await,
        before,
        "the unanchored conflict must write nothing, not even an anchor"
    );

    // The key is still free: had the conflict left an anchor, reusing it for
    // another suggestion (different arguments) would be refused as a conflict.
    let other = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type": "Annotation", "kind": "suggestion", "name": "another",
            "lifecycle": "open", "body": "gamma",
            "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
            "links": [{"target_id": target, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let case = KeyedCase {
        tool: "resolve_suggestions",
        args: json!({"action": "reject", "suggestion_ids": [other],
                     "reason": "Not needed", "idempotency_key": "reopened-later"}),
        conflicting: json!({"action": "reject", "suggestion_ids": [other],
                            "reason": "A different reason", "idempotency_key": "reopened-later"}),
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(first["status"], "rejected", "{first}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
}

// ---------------------------------------------------------------------------
// Slice A1b: manage_messages classify / unclassify / move
// ---------------------------------------------------------------------------

/// Two people bound to a principal and an account, so a Message can be sent
/// between them.
async fn message_people(db: &Db) -> (String, String) {
    let mut ids = Vec::new();
    for (principal, account) in [
        ("native/msg-sender", "acct_msg_sender"),
        ("native/msg-recipient", "acct_msg_recipient"),
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        native_ce::store::create_record(
            db,
            json!({"id": id, "type": "Entity", "kind": "person", "name": account}),
        )
        .await
        .unwrap();
        for (system, identifier) in [("native-principal", principal), ("account", account)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,?,?,1)",
            )
            .bind(&id)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(db).await)
            .await
            .unwrap();
        }
        ids.push(id);
    }
    (ids[0].clone(), ids[1].clone())
}

async fn sent_message(registry: &ToolRegistry, db: &Db, people: &(String, String)) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "manage_messages",
        json!({
            "action": "send", "body": "classify me", "owner_id": people.0,
            "origin": {"type": "direct", "participant_ids": [people.0, people.1]},
            "addressed_to": [people.1], "expectation": "none",
            "idempotency_key": format!("send-{}", uuid::Uuid::new_v4()),
            "reason": "Create the addressed Message fixture."
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn conversation(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Conversation", "kind": "discussion", "name": name}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// An unkeyed call by the local owner: the state change a keyed call's retry
/// must survive.
async fn unkeyed(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    call(registry, db, Caller::local(), tool, args)
        .await
        .unwrap()
}

#[tokio::test]
async fn message_classify_unclassify_and_move_replay_conflict_and_replay_noops() {
    let registry = registry();
    let db = db().await;
    let people = message_people(&db).await;
    let message = sent_message(&registry, &db, &people).await;
    let first_room = conversation(&registry, &db, "First").await;
    let second_room = conversation(&registry, &db, "Second").await;
    let third_room = conversation(&registry, &db, "Third").await;
    let classify = |room: &str, key: &str| {
        json!({"action": "classify", "message_id": message, "conversation_id": room,
               "idempotency_key": key})
    };
    let unclassify = |room: &str, key: Option<&str>| {
        let mut args = json!({"action": "unclassify", "message_id": message,
                              "conversation_id": room});
        if let Some(key) = key {
            args["idempotency_key"] = json!(key);
        }
        args
    };

    // classify: changes, replays, conflicts, stays pinned after a later write.
    let classify_case = KeyedCase {
        tool: "manage_messages",
        args: classify(&first_room, "classify-1"),
        conflicting: classify(&second_room, "classify-1"),
    };
    let first =
        assert_replays_without_writing(&registry, &db, Caller::local(), &classify_case).await;
    assert_eq!(first["status"], "classified", "{first}");
    assert_eq!(first["changed"], true);
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &classify_case).await;
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        Caller::local(),
        &classify_case,
        &first,
        ("manage_messages", unclassify(&first_room, None)),
    )
    .await;

    // classify of an already classified pair is a keyed no-op that replays as
    // one even after the pair is unclassified.
    unkeyed(
        &registry,
        &db,
        "manage_messages",
        json!({"action": "classify", "message_id": message, "conversation_id": second_room}),
    )
    .await;
    let noop = KeyedCase {
        tool: "manage_messages",
        args: classify(&second_room, "classify-noop"),
        conflicting: classify(&third_room, "classify-noop"),
    };
    let (registry_for_disturb, db_for_disturb) = (registry.clone(), db.clone());
    let (message_for_disturb, room) = (message.clone(), second_room.clone());
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &noop, || async move {
            unkeyed(
                &registry_for_disturb,
                &db_for_disturb,
                "manage_messages",
                json!({"action": "unclassify", "message_id": message_for_disturb,
                       "conversation_id": room}),
            )
            .await;
        })
        .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");
    assert_eq!(receipt["changed"], false);
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &noop).await;

    // unclassify of a pair that is not classified: a keyed no-op, replayed.
    let unclassify_noop = KeyedCase {
        tool: "manage_messages",
        args: unclassify(&second_room, Some("unclassify-noop")),
        conflicting: unclassify(&third_room, Some("unclassify-noop")),
    };
    let (registry_for_disturb, db_for_disturb) = (registry.clone(), db.clone());
    let (message_for_disturb, room) = (message.clone(), second_room.clone());
    let receipt = assert_noop_replays_as_noop(
        &registry,
        &db,
        Caller::local(),
        &unclassify_noop,
        || async move {
            unkeyed(
                &registry_for_disturb,
                &db_for_disturb,
                "manage_messages",
                json!({"action": "classify", "message_id": message_for_disturb,
                       "conversation_id": room}),
            )
            .await;
        },
    )
    .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");

    // unclassify that changes (the disturb above classified the pair again).
    let unclassify_case = KeyedCase {
        tool: "manage_messages",
        args: unclassify(&second_room, Some("unclassify-1")),
        conflicting: unclassify(&third_room, Some("unclassify-1")),
    };
    let removed =
        assert_replays_without_writing(&registry, &db, Caller::local(), &unclassify_case).await;
    assert_eq!(removed["status"], "unclassified", "{removed}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &unclassify_case).await;

    // move: replays after the move source was consumed.
    unkeyed(
        &registry,
        &db,
        "manage_messages",
        json!({"action": "classify", "message_id": message, "conversation_id": first_room}),
    )
    .await;
    let move_args = |to: &str| {
        json!({"action": "move", "message_id": message, "from_conversation_id": first_room,
               "to_conversation_id": to, "idempotency_key": "move-1"})
    };
    let move_case = KeyedCase {
        tool: "manage_messages",
        args: move_args(&second_room),
        conflicting: move_args(&third_room),
    };
    let moved = assert_replays_without_writing(&registry, &db, Caller::local(), &move_case).await;
    assert_eq!(moved["status"], "moved", "{moved}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &move_case).await;
    // Unkeyed, the same move now fails: its source classification is gone.
    let mut without_key = move_case.args.clone();
    without_key
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        without_key,
    )
    .await
    .unwrap_err();
}

/// A blank key is no key for the wired actions, and a real one is refused by
/// name where an action is not wired.
#[tokio::test]
async fn share_history_refuses_a_key_by_name_and_a_blank_key_is_no_key() {
    let registry = registry();
    let db = db().await;
    let people = message_people(&db).await;
    let message = sent_message(&registry, &db, &people).await;
    let room = conversation(&registry, &db, "Room").await;
    let share = |key: Value| {
        json!({"action": "share_history", "recipient_id": people.1, "message_ids": [message],
               "reason": "Share the thread.", "idempotency_key": key})
    };
    let before = write_footprint(&db).await;
    let refused = call(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        share(json!("k")),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("share_history does not accept idempotency_key")
            && refused.contains("retry without a key"),
        "{refused}"
    );
    assert_eq!(write_footprint(&db).await, before);
    for blank in [json!(null), json!(""), json!("  ")] {
        let outcome = call(
            &registry,
            &db,
            Caller::local(),
            "manage_messages",
            share(blank),
        )
        .await;
        let message = outcome
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(
            !message.contains("does not accept idempotency_key"),
            "{message}"
        );
    }
    // A blank key on a wired action is an ordinary unkeyed call.
    let blank = call(
        &registry,
        &db,
        Caller::local(),
        "manage_messages",
        json!({"action": "classify", "message_id": message, "conversation_id": room,
               "idempotency_key": "   "}),
    )
    .await
    .unwrap();
    assert_eq!(blank["status"], "classified", "{blank}");
}

// ---------------------------------------------------------------------------
// Slice A1b: artifacts_write
// ---------------------------------------------------------------------------

const HTML_ARTIFACT: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fixture</title></head><body><main><h1>Fixture</h1></main></body></html>";

async fn html_artifact(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Document", "kind": "artifact", "name": name, "body": HTML_ARTIFACT,
               "facets": {"runtime": "native.html.v1"}, "reason": "Keyed artifact fixture."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn collection(registry: &ToolRegistry, db: &Db, kind: &str, name: &str) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Collection", "kind": kind, "name": name, "reason": "Keyed artifact fixture."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn renderer_binding_bind_and_unbind_replay_conflict_and_replay_noops() {
    let registry = registry();
    let db = db().await;
    let artifact = html_artifact(&registry, &db, "bound artifact").await;
    let folder = collection(&registry, &db, "folder", "Folder").await;
    let selection = collection(&registry, &db, "selection", "Selection").await;
    let bind = |target: &str, key: &str| {
        json!({"action": "bind", "artifact_id": artifact, "collection_id": target,
               "idempotency_key": key})
    };
    let unbind = |target: Option<&str>, key: Option<&str>| {
        let mut args = json!({"action": "unbind", "artifact_id": artifact});
        if let Some(target) = target {
            args["collection_id"] = json!(target);
        }
        if let Some(key) = key {
            args["idempotency_key"] = json!(key);
        }
        args
    };

    // unbind of nothing is a keyed no-op that replays as one after a bind.
    let nothing = KeyedCase {
        tool: "manage_renderer_binding",
        args: unbind(None, Some("unbind-noop")),
        conflicting: unbind(Some(&folder), Some("unbind-noop")),
    };
    let (registry_for_disturb, db_for_disturb) = (registry.clone(), db.clone());
    let (artifact_for_disturb, folder_for_disturb) = (artifact.clone(), folder.clone());
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &nothing, || async move {
            unkeyed(
                &registry_for_disturb,
                &db_for_disturb,
                "manage_renderer_binding",
                json!({"action": "bind", "artifact_id": artifact_for_disturb,
                       "collection_id": folder_for_disturb}),
            )
            .await;
        })
        .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &nothing).await;

    // bind of the target already bound is a keyed no-op too.
    let already = KeyedCase {
        tool: "manage_renderer_binding",
        args: bind(&folder, "bind-noop"),
        conflicting: bind(&selection, "bind-noop"),
    };
    let (registry_for_disturb, db_for_disturb) = (registry.clone(), db.clone());
    let artifact_for_disturb = artifact.clone();
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &already, || async move {
            unkeyed(
                &registry_for_disturb,
                &db_for_disturb,
                "manage_renderer_binding",
                json!({"action": "unbind", "artifact_id": artifact_for_disturb}),
            )
            .await;
        })
        .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");

    // bind that changes. The artifact is unbound now (the disturb above).
    let change = KeyedCase {
        tool: "manage_renderer_binding",
        args: bind(&selection, "bind-1"),
        conflicting: bind(&folder, "bind-1"),
    };
    let bound = assert_replays_without_writing(&registry, &db, Caller::local(), &change).await;
    assert_eq!(bound["status"], "bound", "{bound}");
    assert_eq!(bound["changed_collection_id"], json!(selection));
    assert!(
        bound["previous_seq"].is_i64() && bound["act"].is_i64(),
        "{bound}"
    );
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &change).await;
    // Unkeyed, the same bind is a no-op now; the key replays the first receipt
    // even after the artifact is unbound and bound elsewhere.
    unkeyed(
        &registry,
        &db,
        "manage_renderer_binding",
        unbind(None, None),
    )
    .await;
    unkeyed(
        &registry,
        &db,
        "manage_renderer_binding",
        json!({"action": "bind", "artifact_id": artifact, "collection_id": folder}),
    )
    .await;
    let before = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "manage_renderer_binding",
        change.args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &bound, "bind after a later rebind");
    assert_eq!(write_footprint(&db).await, before);

    // unbind that changes: its remaining bindings are pinned to the log at
    // the command, however the artifact is bound afterwards.
    let remove = KeyedCase {
        tool: "manage_renderer_binding",
        args: unbind(Some(&folder), Some("unbind-1")),
        conflicting: unbind(Some(&selection), Some("unbind-1")),
    };
    let removed = assert_replays_without_writing(&registry, &db, Caller::local(), &remove).await;
    assert_eq!(removed["status"], "unbound", "{removed}");
    assert_eq!(removed["bindings"], json!([]));
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &remove).await;
    unkeyed(
        &registry,
        &db,
        "manage_renderer_binding",
        json!({"action": "bind", "artifact_id": artifact, "collection_id": selection}),
    )
    .await;
    let before = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "manage_renderer_binding",
        remove.args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &removed, "unbind after a later bind");
    assert_eq!(write_footprint(&db).await, before);
}

#[tokio::test]
async fn surface_bindings_set_and_reset_replay_conflict_and_replay_noops() {
    let registry = registry();
    let db = db().await;
    let first_artifact = html_artifact(&registry, &db, "home one").await;
    let second_artifact = html_artifact(&registry, &db, "home two").await;
    let set = |target: &str, expected: Value, key: &str| {
        json!({"action": "set", "surface": "home", "scope": "workspace", "target_id": target,
               "expected_target_id": expected, "idempotency_key": key})
    };
    let reset = |expected: Value, key: &str| {
        json!({"action": "reset", "surface": "home", "scope": "workspace",
               "expected_target_id": expected, "idempotency_key": key})
    };

    // reset of nothing: a keyed no-op that replays as one.
    let empty_reset = KeyedCase {
        tool: "manage_surface_bindings",
        args: reset(json!(null), "reset-noop"),
        conflicting: reset(json!(first_artifact), "reset-noop"),
    };
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &empty_reset, || async {})
            .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &empty_reset).await;

    // set that changes.
    let bind = KeyedCase {
        tool: "manage_surface_bindings",
        args: set(&first_artifact, json!(null), "set-1"),
        conflicting: set(&second_artifact, json!(null), "set-1"),
    };
    let bound = assert_replays_without_writing(&registry, &db, Caller::local(), &bind).await;
    assert_eq!(bound["status"], "bound", "{bound}");
    assert_eq!(bound["resolution"]["target_id"], json!(first_artifact));
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &bind).await;

    // Rebinding without the key makes the guarded set stale; the key replays.
    // The command's facts are pinned; `resolution` is the effective binding
    // today, as the first call's was.
    unkeyed(
        &registry,
        &db,
        "manage_surface_bindings",
        set(&second_artifact, json!(first_artifact), "later-set"),
    )
    .await;
    let before = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "manage_surface_bindings",
        bind.args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(write_footprint(&db).await, before);
    for field in ["status", "scope", "source_id", "previous_seq", "act"] {
        assert_eq!(replay[field], bound[field], "{field}");
    }
    assert_eq!(replay["resolution"]["target_id"], json!(second_artifact));

    // set of the target already bound: a keyed no-op that replays as one.
    let already = KeyedCase {
        tool: "manage_surface_bindings",
        args: set(&second_artifact, json!(second_artifact), "set-noop"),
        conflicting: set(&first_artifact, json!(second_artifact), "set-noop"),
    };
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &already, || async {}).await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");

    // reset that changes.
    let clear = KeyedCase {
        tool: "manage_surface_bindings",
        args: reset(json!(second_artifact), "reset-1"),
        conflicting: reset(json!(first_artifact), "reset-1"),
    };
    let cleared = assert_replays_without_writing(&registry, &db, Caller::local(), &clear).await;
    assert_eq!(cleared["status"], "reset", "{cleared}");
    assert_eq!(cleared["removed_target_ids"], json!([second_artifact]));
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &clear).await;
}

fn module_source(label: &str) -> String {
    format!(
        r#"export const nativeModule = {{
  schema: "native.mdx.module.v1",
  inputs: {{}},
  exports: {{ Hello: {{ kind: "component", props: {{ label: {{ type: "string", required: true }} }}, uses_inputs: [] }} }},
  module_inputs: {{}},
  capability_requests: []
}}
export function Hello({{ label }}, native) {{ return <Callout tone="info" title={{{label:?}}}>{{label}}</Callout> }}
"#
    )
}

/// The module's latest body event id and source digest: what `publish` pins.
async fn module_source_pin(db: &Db, module_id: &str) -> (String, String) {
    use sha2::{Digest, Sha256};
    let (event_id, body): (String, String) = sqlx::query_as(
        "SELECT e.id, json_extract(e.payload,'$.body') FROM content_events e
          WHERE e.record_id=? AND json_type(e.payload,'$.body') IS NOT NULL
          ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(module_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    (event_id, hex::encode(Sha256::digest(body.as_bytes())))
}

async fn status_event_seq(
    registry: &ToolRegistry,
    db: &Db,
    module_id: &str,
    publication: &str,
) -> i64 {
    unkeyed(
        registry,
        db,
        "manage_mdx_modules",
        json!({"action": "inspect", "module_id": module_id, "publication_event_id": publication}),
    )
    .await["releases"][0]["status_event_seq"]
        .as_i64()
        .unwrap()
}

#[tokio::test]
async fn mdx_module_publish_deprecate_and_withdraw_replay_and_conflict() {
    let registry = registry();
    let db = db().await;
    let module = uuid::Uuid::new_v4().to_string();
    unkeyed(
        &registry,
        &db,
        "create_record",
        json!({"id": module, "type": "Program", "kind": "module", "name": "Shared UI",
               "body": module_source("one"), "facets": {"runtime": "native.mdx.v2"},
               "reason": "Keyed publication fixture."}),
    )
    .await;
    let (source_event, source_sha) = module_source_pin(&db, &module).await;
    let publish = KeyedCase {
        tool: "manage_mdx_modules",
        args: json!({"action": "publish", "module_id": module,
                     "expected_source_event_id": source_event,
                     "expected_source_sha256": source_sha, "idempotency_key": "publish-1"}),
        conflicting: json!({"action": "publish", "module_id": module,
                            "expected_source_event_id": source_event,
                            "expected_source_sha256": "0".repeat(64),
                            "idempotency_key": "publish-1"}),
    };
    let published = assert_replays_without_writing(&registry, &db, Caller::local(), &publish).await;
    assert_eq!(published["status"], "published", "{published}");
    assert_eq!(published["source_event_id"], json!(source_event));
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &publish).await;
    // Editing the draft makes the pinned source stale: unkeyed the publish
    // would now fail; the key replays the committed release.
    let digest = unkeyed(&registry, &db, "get_record", json!({"ids": [module]})).await["records"]
        [0]["body_digest"]
        .clone();
    assert_replay_is_pinned_after_later_write(
        &registry,
        &db,
        Caller::local(),
        &publish,
        &published,
        (
            "update_record",
            json!({"id": module, "body_set": module_source("two"), "if_body_digest": digest}),
        ),
    )
    .await;

    let publication = published["publication_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let status_seq = status_event_seq(&registry, &db, &module, &publication).await;
    let deprecate = KeyedCase {
        tool: "manage_mdx_modules",
        args: json!({"action": "deprecate", "module_id": module,
                     "publication_event_id": publication,
                     "expected_status_event_seq": status_seq, "idempotency_key": "deprecate-1"}),
        conflicting: json!({"action": "deprecate", "module_id": module,
                            "publication_event_id": publication,
                            "expected_status_event_seq": status_seq + 1,
                            "idempotency_key": "deprecate-1"}),
    };
    let deprecated =
        assert_replays_without_writing(&registry, &db, Caller::local(), &deprecate).await;
    assert_eq!(deprecated["status"], "deprecated", "{deprecated}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &deprecate).await;

    let status_seq = status_event_seq(&registry, &db, &module, &publication).await;
    let withdraw = KeyedCase {
        tool: "manage_mdx_modules",
        args: json!({"action": "withdraw", "module_id": module,
                     "publication_event_id": publication,
                     "expected_status_event_seq": status_seq, "idempotency_key": "withdraw-1"}),
        conflicting: json!({"action": "withdraw", "module_id": module,
                            "publication_event_id": publication,
                            "expected_status_event_seq": status_seq + 1,
                            "idempotency_key": "withdraw-1"}),
    };
    let withdrawn =
        assert_replays_without_writing(&registry, &db, Caller::local(), &withdraw).await;
    assert_eq!(withdrawn["status"], "withdrawn", "{withdrawn}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &withdraw).await;
    // The status moved on, so unkeyed the same withdraw is stale; keyed it replays.
    let mut stale = withdraw.args.clone();
    stale.as_object_mut().unwrap().remove("idempotency_key");
    call(&registry, &db, Caller::local(), "manage_mdx_modules", stale)
        .await
        .unwrap_err();
}

const PORTS_ARTIFACT: &str = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    alpha: { envelope: "native.collection-envelope.v1", required: false, expose_to_root: true },
    beta: { envelope: "native.collection-envelope.v1", required: false, expose_to_root: true },
    gamma: { envelope: "native.collection-envelope.v1", required: false, expose_to_root: true }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "alpha" } },
    { capability: "input.read", scope: { port: "beta" } },
    { capability: "input.read", scope: { port: "gamma" } }
  ]
}

# Ports
"#;

async fn ports_artifact(registry: &ToolRegistry, db: &Db) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Document", "kind": "artifact", "name": "ports",
               "body": PORTS_ARTIFACT, "facets": {"runtime": "native.mdx.v2"},
               "reason": "Keyed named-input fixture."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn artifact_inputs_bind_bind_many_and_unbind_replay_conflict_and_replay_noops() {
    let registry = registry();
    let db = db().await;
    let artifact = ports_artifact(&registry, &db).await;
    let orders = collection(&registry, &db, "selection", "Orders").await;
    let customers = collection(&registry, &db, "selection", "Customers").await;

    // bind that changes: the singular receipt carries no act, as unkeyed.
    let bind = KeyedCase {
        tool: "manage_artifact_inputs",
        args: json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                     "collection_id": orders, "idempotency_key": "inputs-bind"}),
        conflicting: json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                            "collection_id": customers, "idempotency_key": "inputs-bind"}),
    };
    let bound = assert_replays_without_writing(&registry, &db, Caller::local(), &bind).await;
    assert_eq!(bound["status"], "bound", "{bound}");
    assert!(bound["previous_seq"].is_i64(), "{bound}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &bind).await;

    // bind of the exact binding already in place: a keyed no-op with the
    // binding's event_seq, replayed.
    let again = KeyedCase {
        tool: "manage_artifact_inputs",
        args: json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                     "collection_id": orders, "idempotency_key": "inputs-bind-noop"}),
        conflicting: json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                            "collection_id": customers, "idempotency_key": "inputs-bind-noop"}),
    };
    let unchanged =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &again, || async {}).await;
    assert_eq!(unchanged["status"], "unchanged", "{unchanged}");
    assert!(
        unchanged["bindings"][0]["event_seq"].is_i64(),
        "{unchanged}"
    );

    // bind_many: one new port beside the bound one.
    let many = KeyedCase {
        tool: "manage_artifact_inputs",
        args: json!({"action": "bind_many", "artifact_id": artifact,
                     "bindings": [{"port_name": "alpha", "collection_id": orders},
                                  {"port_name": "beta", "collection_id": customers}],
                     "idempotency_key": "inputs-many"}),
        conflicting: json!({"action": "bind_many", "artifact_id": artifact,
                            "bindings": [{"port_name": "beta", "collection_id": orders}],
                            "idempotency_key": "inputs-many"}),
    };
    let many_bound = assert_replays_without_writing(&registry, &db, Caller::local(), &many).await;
    assert_eq!(many_bound["status"], "bound", "{many_bound}");
    assert_eq!(many_bound["bindings"].as_array().unwrap().len(), 2);
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &many).await;

    // bind_many of bindings all in place: a keyed no-op.
    let all_in_place = KeyedCase {
        tool: "manage_artifact_inputs",
        args: json!({"action": "bind_many", "artifact_id": artifact,
                     "bindings": [{"port_name": "alpha", "collection_id": orders},
                                  {"port_name": "beta", "collection_id": customers}],
                     "idempotency_key": "inputs-many-noop"}),
        conflicting: json!({"action": "bind_many", "artifact_id": artifact,
                            "bindings": [{"port_name": "gamma", "collection_id": orders}],
                            "idempotency_key": "inputs-many-noop"}),
    };
    let receipt =
        assert_noop_replays_as_noop(&registry, &db, Caller::local(), &all_in_place, || async {})
            .await;
    assert_eq!(receipt["status"], "unchanged", "{receipt}");

    // unbind: needs the exact binding's event_seq, which a retry no longer matches.
    let event_seq = bound_event_seq(&db, &artifact, "beta").await;
    let unbind = KeyedCase {
        tool: "manage_artifact_inputs",
        args: json!({"action": "unbind", "artifact_id": artifact, "port_name": "beta",
                     "collection_id": customers, "event_seq": event_seq,
                     "idempotency_key": "inputs-unbind"}),
        conflicting: json!({"action": "unbind", "artifact_id": artifact, "port_name": "beta",
                            "collection_id": customers, "event_seq": event_seq + 1,
                            "idempotency_key": "inputs-unbind"}),
    };
    let unbound = assert_replays_without_writing(&registry, &db, Caller::local(), &unbind).await;
    assert_eq!(unbound["status"], "unbound", "{unbound}");
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &unbind).await;
    let mut stale = unbind.args.clone();
    stale.as_object_mut().unwrap().remove("idempotency_key");
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_artifact_inputs",
        stale,
    )
    .await
    .unwrap_err();
}

async fn bound_event_seq(db: &Db, artifact: &str, port: &str) -> i64 {
    sqlx::query_scalar("SELECT event_seq FROM artifact_inputs WHERE artifact_id=? AND port_name=?")
        .bind(artifact)
        .bind(port)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// `advance_artifact_port_pin` is not keyed, and says so by name before any
/// work. A blank key is no key and reaches the tool's own checks.
#[tokio::test]
async fn advance_artifact_port_pin_refuses_a_key_by_name() {
    let registry = registry();
    let db = db().await;
    let artifact = ports_artifact(&registry, &db).await;
    let args = |key: Value| {
        json!({"artifact_id": artifact, "port_name": "alpha", "reason": "Advance the pin.",
               "idempotency_key": key})
    };
    let before = write_footprint(&db).await;
    let refused = call(
        &registry,
        &db,
        Caller::local(),
        "advance_artifact_port_pin",
        args(json!("k")),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("does not accept idempotency_key")
            && refused.contains("retry without a key"),
        "{refused}"
    );
    assert_eq!(write_footprint(&db).await, before);
    for blank in [json!(null), json!(""), json!("  ")] {
        let message = call(
            &registry,
            &db,
            Caller::local(),
            "advance_artifact_port_pin",
            args(blank),
        )
        .await
        .unwrap_err()
        .to_string();
        // Past the key check: the port is simply not bound.
        assert!(message.contains("not bound"), "{message}");
    }
}

// ---------------------------------------------------------------------------
// Lost access for the A1b tools (same table as the A1 tools above)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_a1b_tool_refuses_a_caller_who_lost_access_like_a_fresh_key() {
    use native_ce::authorization::Capability;
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let people = message_people(&db).await;
    let mut cases = Vec::new();

    // manage_messages classify / unclassify / move: Edit on the Message, View
    // on the Conversation (and on the move's destination).
    for (label, action) in [
        ("classify (message Edit)", "classify"),
        ("classify (conversation View)", "classify"),
        ("unclassify (message Edit)", "unclassify"),
        ("unclassify (conversation View)", "unclassify"),
        ("move (message Edit)", "move"),
        ("move (source View)", "move"),
        ("move (destination View)", "move"),
    ] {
        let message = sent_message(&registry, &db, &people).await;
        let room = conversation(&registry, &db, label).await;
        let other_room = conversation(&registry, &db, &format!("{label} destination")).await;
        grant(&db, &message, "acct:alice", Capability::Edit).await;
        let key = format!("lost-{label}");
        let (args, revoke) = match (action, label.contains("View")) {
            ("classify", viewing) => (
                json!({"action": "classify", "message_id": message, "conversation_id": room,
                       "idempotency_key": key}),
                vec![if viewing {
                    room.clone()
                } else {
                    message.clone()
                }],
            ),
            ("unclassify", viewing) => {
                unkeyed(
                    &registry,
                    &db,
                    "manage_messages",
                    json!({"action": "classify", "message_id": message, "conversation_id": room}),
                )
                .await;
                (
                    json!({"action": "unclassify", "message_id": message,
                           "conversation_id": room, "idempotency_key": key}),
                    vec![if viewing {
                        room.clone()
                    } else {
                        message.clone()
                    }],
                )
            }
            (_, viewing) => {
                unkeyed(
                    &registry,
                    &db,
                    "manage_messages",
                    json!({"action": "classify", "message_id": message, "conversation_id": room}),
                )
                .await;
                (
                    json!({"action": "move", "message_id": message,
                           "from_conversation_id": room, "to_conversation_id": other_room,
                           "idempotency_key": key}),
                    vec![if !viewing {
                        message.clone()
                    } else if label.contains("source") {
                        room.clone()
                    } else {
                        other_room.clone()
                    }],
                )
            }
        };
        cases.push(LostAccess {
            label,
            tool: "manage_messages",
            caller: alice.clone(),
            args,
            revoke,
            drop_host_owner: false,
        });
    }

    // manage_renderer_binding bind / unbind: Edit on the artifact, View on the
    // Collection.
    for (label, unbind, revoke_artifact) in [
        ("renderer bind (artifact Edit)", false, true),
        ("renderer bind (collection View)", false, false),
        ("renderer unbind (artifact Edit)", true, true),
        ("renderer unbind (named collection View)", true, false),
    ] {
        let artifact = html_artifact(&registry, &db, label).await;
        let target = collection(&registry, &db, "folder", label).await;
        grant(&db, &artifact, "acct:alice", Capability::Edit).await;
        let key = format!("lost-{label}");
        let args = if unbind {
            unkeyed(
                &registry,
                &db,
                "manage_renderer_binding",
                json!({"action": "bind", "artifact_id": artifact, "collection_id": target}),
            )
            .await;
            json!({"action": "unbind", "artifact_id": artifact, "collection_id": target,
                   "idempotency_key": key})
        } else {
            json!({"action": "bind", "artifact_id": artifact, "collection_id": target,
                   "idempotency_key": key})
        };
        cases.push(LostAccess {
            label,
            tool: "manage_renderer_binding",
            caller: alice.clone(),
            args,
            revoke: vec![if revoke_artifact { artifact } else { target }],
            drop_host_owner: false,
        });
    }

    // manage_surface_bindings set / reset: Edit on the caller's own person
    // record, View on the target artifact. Each case has its own member, so
    // no case starts from another's personal binding.
    for (index, (label, action, revoke_person)) in [
        ("surface set (person Edit)", "set", true),
        ("surface set (target View)", "set", false),
        ("surface reset (person Edit)", "reset", true),
    ]
    .into_iter()
    .enumerate()
    {
        let account = format!("acct:surface-{index}");
        hosted_person(&registry, &db, &account).await;
        let member = hosted(&account);
        let person: String = sqlx::query_scalar(
            "SELECT record_id FROM bindings WHERE system='account' AND identifier=?",
        )
        .bind(&account)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let target = html_artifact(&registry, &db, label).await;
        grant(&db, &person, &account, Capability::Edit).await;
        let key = format!("lost-{label}");
        let args = if action == "set" {
            json!({"action": "set", "surface": "home", "scope": "personal",
                   "target_id": target, "expected_target_id": null, "idempotency_key": key})
        } else {
            unkeyed_as(
                &registry,
                &db,
                member.clone(),
                "manage_surface_bindings",
                json!({"action": "set", "surface": "home", "scope": "personal",
                       "target_id": target, "expected_target_id": null}),
            )
            .await;
            json!({"action": "reset", "surface": "home", "scope": "personal",
                   "expected_target_id": target, "idempotency_key": key})
        };
        cases.push(LostAccess {
            label,
            tool: "manage_surface_bindings",
            caller: member,
            args,
            revoke: vec![if revoke_person { person } else { target }],
            drop_host_owner: false,
        });
    }

    // manage_mdx_modules publish / deprecate / withdraw: Edit on the module.
    for action in ["publish", "deprecate", "withdraw"] {
        let module = uuid::Uuid::new_v4().to_string();
        unkeyed(
            &registry,
            &db,
            "create_record",
            json!({"id": module, "type": "Program", "kind": "module", "name": action,
                   "body": module_source(action), "facets": {"runtime": "native.mdx.v2"},
                   "reason": "Keyed publication fixture."}),
        )
        .await;
        grant(&db, &module, "acct:alice", Capability::Edit).await;
        let (source_event, source_sha) = module_source_pin(&db, &module).await;
        let publish = json!({"action": "publish", "module_id": module,
                             "expected_source_event_id": source_event,
                             "expected_source_sha256": source_sha});
        let args = if action == "publish" {
            let mut args = publish;
            args["idempotency_key"] = json!("lost-publish");
            args
        } else {
            let publication = unkeyed(&registry, &db, "manage_mdx_modules", publish).await
                ["publication_event_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let seq = status_event_seq(&registry, &db, &module, &publication).await;
            json!({"action": action, "module_id": module, "publication_event_id": publication,
                   "expected_status_event_seq": seq, "idempotency_key": format!("lost-{action}")})
        };
        cases.push(LostAccess {
            label: match action {
                "publish" => "mdx publish",
                "deprecate" => "mdx deprecate",
                _ => "mdx withdraw",
            },
            tool: "manage_mdx_modules",
            caller: alice.clone(),
            args,
            revoke: vec![module],
            drop_host_owner: false,
        });
    }

    // manage_mdx_modules publish of a module that imports another: the replay
    // re-checks View on every dependency release in the closure.
    {
        let leaf = uuid::Uuid::new_v4().to_string();
        let parent = uuid::Uuid::new_v4().to_string();
        unkeyed(
            &registry,
            &db,
            "create_record",
            json!({"id": leaf, "type": "Program", "kind": "module", "name": "leaf",
                   "body": module_source("leaf"), "facets": {"runtime": "native.mdx.v2"},
                   "reason": "Keyed publication fixture."}),
        )
        .await;
        let (leaf_event, leaf_sha) = module_source_pin(&db, &leaf).await;
        let leaf_release = unkeyed(
            &registry,
            &db,
            "manage_mdx_modules",
            json!({"action": "publish", "module_id": leaf,
                   "expected_source_event_id": leaf_event,
                   "expected_source_sha256": leaf_sha}),
        )
        .await;
        let publication = leaf_release["publication_event_id"].as_str().unwrap();
        let specifier = format!("native:module/{leaf}@event-{publication}?sha256={leaf_sha}");
        let parent_source = format!(
            r#"import {{ Hello }} from {specifier:?}
export const nativeModule = {{
  schema: "native.mdx.module.v1",
  inputs: {{}},
  exports: {{ Wrapped: {{ kind: "component", props: {{}}, uses_inputs: [] }} }},
  module_inputs: {{ Hello: {{ publication_event_id: {publication:?}, export: "Hello", ports: {{}} }} }},
  capability_requests: []
}}
export function Wrapped() {{ return <Hello label="wrapped" /> }}
"#
        );
        unkeyed(
            &registry,
            &db,
            "create_record",
            json!({"id": parent, "type": "Program", "kind": "module", "name": "parent",
                   "body": parent_source, "facets": {"runtime": "native.mdx.v2"},
                   "reason": "Keyed publication fixture."}),
        )
        .await;
        grant(&db, &parent, "acct:alice", Capability::Edit).await;
        grant(&db, &leaf, "acct:alice", Capability::View).await;
        let (source_event, source_sha) = module_source_pin(&db, &parent).await;
        cases.push(LostAccess {
            label: "mdx publish (dependency View)",
            tool: "manage_mdx_modules",
            caller: alice.clone(),
            args: json!({"action": "publish", "module_id": parent,
                         "expected_source_event_id": source_event,
                         "expected_source_sha256": source_sha,
                         "idempotency_key": "lost-publish-dependency"}),
            revoke: vec![leaf],
            drop_host_owner: false,
        });
    }

    // manage_artifact_inputs bind / bind_many / unbind: Edit on the artifact,
    // View on each Collection.
    for (label, action, revoke_artifact) in [
        ("inputs bind (artifact Edit)", "bind", true),
        ("inputs bind (collection View)", "bind", false),
        ("inputs bind_many (artifact Edit)", "bind_many", true),
        ("inputs bind_many (collection View)", "bind_many", false),
        ("inputs unbind (artifact Edit)", "unbind", true),
    ] {
        let artifact = ports_artifact(&registry, &db).await;
        let orders = collection(&registry, &db, "selection", label).await;
        grant(&db, &artifact, "acct:alice", Capability::Edit).await;
        let key = format!("lost-{label}");
        let args = match action {
            "bind" => json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                             "collection_id": orders, "idempotency_key": key}),
            "bind_many" => json!({"action": "bind_many", "artifact_id": artifact,
                                  "bindings": [{"port_name": "alpha", "collection_id": orders}],
                                  "idempotency_key": key}),
            _ => {
                unkeyed(
                    &registry,
                    &db,
                    "manage_artifact_inputs",
                    json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                           "collection_id": orders}),
                )
                .await;
                let event_seq = bound_event_seq(&db, &artifact, "alpha").await;
                json!({"action": "unbind", "artifact_id": artifact, "port_name": "alpha",
                       "collection_id": orders, "event_seq": event_seq, "idempotency_key": key})
            }
        };
        cases.push(LostAccess {
            label,
            tool: "manage_artifact_inputs",
            caller: alice.clone(),
            args,
            revoke: vec![if revoke_artifact { artifact } else { orders }],
            drop_host_owner: false,
        });
    }

    for case in cases {
        assert_lost_access_gets_the_fresh_key_denial(&registry, &db, case).await;
    }
}

async fn unkeyed_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    call(registry, db, caller, tool, args).await.unwrap()
}

// ---------------------------------------------------------------------------
// Slice C0: A1b review follow-ups
// ---------------------------------------------------------------------------

/// A keyed no-op that bound nothing replays the binding's live `event_seq`
/// ("unchanged"). If the port has been rebound since, that claim would be
/// false, so the replay refuses and writes nothing (A1b review S2).
#[tokio::test]
async fn artifact_inputs_noop_replay_refuses_once_the_port_is_rebound() {
    let registry = registry();
    let db = db().await;
    let artifact = ports_artifact(&registry, &db).await;
    let orders = collection(&registry, &db, "selection", "Orders").await;
    let customers = collection(&registry, &db, "selection", "Customers").await;
    unkeyed(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
               "collection_id": orders}),
    )
    .await;
    let keyed_noops = [
        json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
               "collection_id": orders, "idempotency_key": "rebound-bind"}),
        json!({"action": "bind_many", "artifact_id": artifact,
               "bindings": [{"port_name": "alpha", "collection_id": orders}],
               "idempotency_key": "rebound-bind-many"}),
    ];
    for args in &keyed_noops {
        let first = unkeyed(&registry, &db, "manage_artifact_inputs", args.clone()).await;
        assert_eq!(first["status"], "unchanged", "{first}");
    }
    // Still replays while the binding stands.
    for args in &keyed_noops {
        let replay = unkeyed(&registry, &db, "manage_artifact_inputs", args.clone()).await;
        assert_eq!(replay["status"], "unchanged", "{replay}");
    }

    let event_seq = bound_event_seq(&db, &artifact, "alpha").await;
    unkeyed(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({"action": "unbind", "artifact_id": artifact, "port_name": "alpha",
               "collection_id": orders, "event_seq": event_seq}),
    )
    .await;
    unkeyed(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
               "collection_id": customers}),
    )
    .await;

    let before = write_footprint(&db).await;
    for args in &keyed_noops {
        let error = call(
            &registry,
            &db,
            Caller::local(),
            "manage_artifact_inputs",
            args.clone(),
        )
        .await
        .expect_err("a no-op receipt would now be false")
        .to_string();
        assert!(
            error.contains("is no longer bound as it was"),
            "{}: {error}",
            args["action"]
        );
    }
    assert_eq!(write_footprint(&db).await, before, "a refused replay wrote");
}

/// A no-op anchors only when keyed: an unkeyed one rolls back and leaves no
/// attestation behind (A1b review N7).
#[tokio::test]
async fn unkeyed_noops_on_the_wired_tools_leave_no_attestation() {
    let registry = registry();
    let db = db().await;
    async fn noop(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) {
        let before = write_footprint(db).await;
        let receipt = unkeyed(registry, db, tool, args).await;
        assert_eq!(
            write_footprint(db).await,
            before,
            "{tool}: an unkeyed no-op appended something: {receipt}"
        );
    }

    let people = message_people(&db).await;
    let message = sent_message(&registry, &db, &people).await;
    let room = conversation(&registry, &db, "Room").await;
    let classify = json!({"action": "classify", "message_id": message, "conversation_id": room});
    unkeyed(&registry, &db, "manage_messages", classify.clone()).await;
    noop(&registry, &db, "manage_messages", classify).await;
    let elsewhere = conversation(&registry, &db, "Elsewhere").await;
    noop(
        &registry,
        &db,
        "manage_messages",
        json!({"action": "unclassify", "message_id": message, "conversation_id": elsewhere}),
    )
    .await;

    let artifact = html_artifact(&registry, &db, "renderer").await;
    let folder = collection(&registry, &db, "folder", "Folder").await;
    noop(
        &registry,
        &db,
        "manage_renderer_binding",
        json!({"action": "unbind", "artifact_id": artifact}),
    )
    .await;
    let bind = json!({"action": "bind", "artifact_id": artifact, "collection_id": folder});
    unkeyed(&registry, &db, "manage_renderer_binding", bind.clone()).await;
    noop(&registry, &db, "manage_renderer_binding", bind).await;

    let ports = ports_artifact(&registry, &db).await;
    let orders = collection(&registry, &db, "selection", "Orders").await;
    let bind_port = json!({"action": "bind", "artifact_id": ports, "port_name": "alpha",
                           "collection_id": orders});
    unkeyed(&registry, &db, "manage_artifact_inputs", bind_port.clone()).await;
    noop(&registry, &db, "manage_artifact_inputs", bind_port).await;
    noop(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({"action": "bind_many", "artifact_id": ports,
               "bindings": [{"port_name": "alpha", "collection_id": orders}]}),
    )
    .await;

    noop(
        &registry,
        &db,
        "manage_surface_bindings",
        json!({"action": "reset", "surface": "home", "scope": "workspace",
               "expected_target_id": null}),
    )
    .await;
    let set = json!({"action": "set", "surface": "home", "scope": "workspace",
                     "target_id": artifact, "expected_target_id": null});
    unkeyed(&registry, &db, "manage_surface_bindings", set).await;
    noop(
        &registry,
        &db,
        "manage_surface_bindings",
        json!({"action": "set", "surface": "home", "scope": "workspace",
               "target_id": artifact, "expected_target_id": artifact}),
    )
    .await;
}

/// `claim_unowned_record` checks View after host-owner status. After the
/// claim, a Manage holder can hand the record to someone else and tighten its
/// policy, so the claimer can lose View while still being the host's owner;
/// the replay must then refuse like a fresh key does (A1b review N4).
#[tokio::test]
async fn claim_unowned_record_replay_refuses_a_claimer_who_lost_view() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    hosted_person(&registry, &db, "acct:bob").await;
    let bob: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND identifier='acct:bob'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let claimable = note(&registry, &db, "to be claimed", "").await;
    let alice = hosted("acct:alice").with_hosting_owner(true);
    let args = json!({"record_id": claimable, "reason": "Recover abandoned work",
                      "idempotency_key": "claim-lost-view"});
    let first = call(
        &registry,
        &db,
        alice.clone(),
        "claim_unowned_record",
        args.clone(),
    )
    .await
    .unwrap();
    let replay = call(
        &registry,
        &db,
        alice.clone(),
        "claim_unowned_record",
        args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &first, "claim before the reassignment");

    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id": claimable, "owner_id": bob}),
    )
    .await
    .unwrap();
    grant(
        &db,
        &claimable,
        "acct:bob",
        native_ce::authorization::Capability::Manage,
    )
    .await;

    let before = write_footprint(&db).await;
    let denied = call(
        &registry,
        &db,
        alice.clone(),
        "claim_unowned_record",
        args.clone(),
    )
    .await
    .expect_err("a replay after losing View must be refused")
    .to_string();
    let mut fresh_args = args;
    fresh_args["idempotency_key"] = json!("claim-never-used");
    let fresh = call(&registry, &db, alice, "claim_unowned_record", fresh_args)
        .await
        .expect_err("a fresh key must be refused too")
        .to_string();
    assert_eq!(denied, fresh, "the replay denial must match a fresh key's");
    assert_eq!(write_footprint(&db).await, before, "a denied replay wrote");
}

/// A renderer `unbind` that named no `collection_id` resolved its target from
/// the artifact's single binding. Once the caller can no longer View that
/// Collection the replay refuses (documented on `replay_renderer_unbind_in`),
/// and writes nothing (A1b review N5).
#[tokio::test]
async fn renderer_unbind_without_collection_id_refuses_a_replay_after_lost_view() {
    use native_ce::authorization::Capability;
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let alice = hosted("acct:alice");
    let artifact = html_artifact(&registry, &db, "unbound later").await;
    let folder = collection(&registry, &db, "folder", "Hidden later").await;
    grant(&db, &artifact, "acct:alice", Capability::Edit).await;
    unkeyed(
        &registry,
        &db,
        "manage_renderer_binding",
        json!({"action": "bind", "artifact_id": artifact, "collection_id": folder}),
    )
    .await;
    let args = json!({"action": "unbind", "artifact_id": artifact,
                      "idempotency_key": "unbind-lost-view"});
    let first = call(
        &registry,
        &db,
        alice.clone(),
        "manage_renderer_binding",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["status"], "unbound", "{first}");
    let replay = call(
        &registry,
        &db,
        alice.clone(),
        "manage_renderer_binding",
        args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &first, "unbind while the target is visible");

    grant(&db, &folder, "acct:nobody", Capability::Manage).await;
    let before = write_footprint(&db).await;
    let error = call(
        &registry,
        &db,
        alice.clone(),
        "manage_renderer_binding",
        args,
    )
    .await
    .expect_err("the target is hidden now")
    .to_string();
    assert!(
        error.contains("cannot be resolved without collection_id"),
        "{error}"
    );
    assert_eq!(write_footprint(&db).await, before, "a refused replay wrote");
    // A fresh key on the now-empty artifact is a plain no-op: the refusal is
    // the one bit the replay discloses, as documented.
    let fresh = call(
        &registry,
        &db,
        alice,
        "manage_renderer_binding",
        json!({"action": "unbind", "artifact_id": artifact, "idempotency_key": "fresh"}),
    )
    .await
    .unwrap();
    assert_eq!(fresh["status"], "unchanged", "{fresh}");
}

/// The artifact-is-live check follows the replay lookup for a keyed write: an
/// artifact that stopped being a live v2 artifact after the first call (here its
/// runtime facet no longer names one, which the caller can still Edit and View)
/// must not turn a retry of a committed bind into "invalid artifact". A fresh
/// key still is refused, and an unkeyed call keeps its up-front order (A1b
/// review N3).
#[tokio::test]
async fn artifact_inputs_retry_replays_after_the_artifact_stops_being_live() {
    let registry = registry();
    let db = db().await;
    let artifact = ports_artifact(&registry, &db).await;
    let orders = collection(&registry, &db, "selection", "Orders").await;
    let customers = collection(&registry, &db, "selection", "Customers").await;
    let bind = json!({"action": "bind", "artifact_id": artifact, "port_name": "alpha",
                      "collection_id": orders, "idempotency_key": "live-bind"});
    let bind_many = json!({"action": "bind_many", "artifact_id": artifact,
                           "bindings": [{"port_name": "beta", "collection_id": customers}],
                           "idempotency_key": "live-bind-many"});
    // The first, committing calls are keyed too (`unkeyed` here only means
    // "by the local owner"): the replays below must match them.
    let first = unkeyed(&registry, &db, "manage_artifact_inputs", bind.clone()).await;
    assert_eq!(first["status"], "bound", "{first}");
    let many = unkeyed(&registry, &db, "manage_artifact_inputs", bind_many.clone()).await;
    let unbind = json!({"action": "unbind", "artifact_id": artifact, "port_name": "beta",
                        "collection_id": customers,
                        "event_seq": bound_event_seq(&db, &artifact, "beta").await,
                        "idempotency_key": "live-unbind"});
    let unbound = unkeyed(&registry, &db, "manage_artifact_inputs", unbind.clone()).await;
    assert_eq!(unbound["status"], "unbound", "{unbound}");

    sqlx::query(
        "UPDATE facet_values SET value='native.board.v1' WHERE record_id=? AND key='runtime'",
    )
    .bind(&artifact)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let before = write_footprint(&db).await;
    for (args, expected) in [
        (&bind, "bound"),
        (&bind_many, "bound"),
        (&unbind, "unbound"),
    ] {
        let replay = unkeyed(&registry, &db, "manage_artifact_inputs", args.clone()).await;
        assert_eq!(replay["status"], expected, "{replay}");
    }
    assert_eq!(
        unkeyed(&registry, &db, "manage_artifact_inputs", bind_many).await["bindings"],
        many["bindings"]
    );
    assert_eq!(write_footprint(&db).await, before, "a replay wrote");

    let mut fresh = bind.clone();
    fresh["idempotency_key"] = json!("never-used");
    let error = call(
        &registry,
        &db,
        Caller::local(),
        "manage_artifact_inputs",
        fresh,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("invalid artifact"), "{error}");
    let mut without_key = bind;
    without_key
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    let error = call(
        &registry,
        &db,
        Caller::local(),
        "manage_artifact_inputs",
        without_key,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("invalid artifact"), "{error}");
}
