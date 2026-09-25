//! `batch_write`: one atomic batch of existing single-record writes.
//!
//! Twin-run equivalence (N singular calls vs 1 batch on identical fixtures,
//! compared modulo the event envelope), all-or-nothing refusal, hidden-row
//! opacity, keyed idempotency, and rebuild-and-diff replay.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

// Pinned fixture ids (canonical v4 UUIDs, never generated).
const REC_A: &str = "c0010000-0000-4000-8000-000000000001";
const REC_B: &str = "c0010000-0000-4000-8000-000000000002";
const REC_C: &str = "c0010000-0000-4000-8000-000000000003";
const REC_T: &str = "c0010000-0000-4000-8000-000000000004";
const REC_S: &str = "c0010000-0000-4000-8000-000000000005";
const REC_D: &str = "c0010000-0000-4000-8000-000000000006";
const REC_E: &str = "c0010000-0000-4000-8000-000000000007";
const REC_H1: &str = "c0010000-0000-4000-8000-000000000011";
const REC_H2: &str = "c0010000-0000-4000-8000-000000000012";
const MISSING: &str = "c0010000-0000-4000-8000-000000000099";

const REASON: &str = "batch_write integration test";

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
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    let result = registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await;
    db.drain_captures_for_tests().await;
    result
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    call_as(registry, db, Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    call_as(registry, db, Caller::local(), tool, args)
        .await
        .unwrap_err()
        .to_string()
}

async fn create(registry: &ToolRegistry, db: &Db, id: &str, name: &str) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "id": id, "name": name }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Identical fixtures in a fresh database: fixed ids keep both twins aligned.
async fn seeded(registry: &ToolRegistry) -> Db {
    let db = db().await;
    for (id, name) in [
        (REC_A, "alpha"),
        (REC_B, "beta"),
        (REC_C, "gamma"),
        (REC_T, "hub"),
        (REC_S, "source"),
    ] {
        create(registry, &db, id, name).await;
    }
    db
}

async fn event_count(db: &Db) -> i64 {
    crate::common::count(db, "SELECT COUNT(*) AS n FROM content_events").await
}

/// (record_id, event type, payload minus reason/basis, actor) in seq order.
/// Reason and basis ride batch events by design (and singular reason text
/// matches in twin A), so the equivalence comparison strips both and asserts
/// their presence separately.
async fn comparable_events(db: &Db) -> Vec<(String, String, String, Option<String>)> {
    let rows =
        sqlx::query("SELECT record_id, type, payload, actor FROM content_events ORDER BY seq")
            .fetch_all(&crate::common::fixture_write_pool(db).await)
            .await
            .unwrap();
    rows.iter()
        .map(|row| {
            let record_id: String = row.try_get("record_id").unwrap();
            let event_type: String = row.try_get("type").unwrap();
            let payload: String = row.try_get("payload").unwrap();
            let actor: Option<String> = row.try_get("actor").unwrap();
            let mut value: Value = serde_json::from_str(&payload).unwrap();
            if let Some(object) = value.as_object_mut() {
                object.remove("reason");
                object.remove("basis");
            }
            (record_id, event_type, value.to_string(), actor)
        })
        .collect()
}

async fn raw_payloads(db: &Db, since_seq_exclusive: i64) -> Vec<Value> {
    let rows = sqlx::query("SELECT payload FROM content_events WHERE seq > ? ORDER BY seq")
        .bind(since_seq_exclusive)
        .fetch_all(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    rows.iter()
        .map(|row| {
            let payload: String = row.try_get("payload").unwrap();
            serde_json::from_str(&payload).unwrap()
        })
        .collect()
}

async fn max_seq(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn facet_value(db: &Db, record_id: &str, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
        .bind(record_id)
        .bind(key)
        .fetch_optional(db.pool())
        .await
        .unwrap()
}

async fn record_name(db: &Db, registry: &ToolRegistry, id: &str) -> Option<String> {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["name"]
        .as_str()
        .map(str::to_owned)
}

async fn db_origin(db: &Db) -> String {
    sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton = 1")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

fn normalize_relationship_payload(value: &mut Value) {
    // Origin-bound hashes can never match across twin databases (each mint
    // carries its own origin): the proposition key and the admission digest
    // are derived from origin-embedded refs. They are stripped here and
    // proven separately — the proposition inputs (endpoints, token) are
    // compared below, and `owned_link_auth_digest_uses_the_singular_operation_identity`
    // reconstructs the admission digest exactly. The operation-derived
    // `rationale` stays and must match verbatim.
    const VOLATILE: &[&str] = &[
        "id",
        "event_id",
        "assertion_id",
        "attestation_id",
        "authoring_action_attestation_id",
        "created_event_id",
        "occurred_at",
        "ingested_at",
        "created_at",
        "origin_db_id",
        "issuer_origin_db_id",
        "relationship_origin_db_id",
        "relationship_id",
        "stream_id",
        "canonical_proposition_key",
        "authorization_decision_digest",
    ];
    match value {
        Value::Object(map) => {
            for key in VOLATILE {
                map.remove(*key);
            }
            for child in map.values_mut() {
                normalize_relationship_payload(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_relationship_payload(item);
            }
        }
        _ => {}
    }
}

/// (event type, normalized payload, actor) for relationship events in seq
/// order. Random identity (origins, event/assertion/attestation ids,
/// timestamps) is normalized away; everything semantic — token, endpoints,
/// stance, rationale, and the operation-derived auth digest — must match.
async fn comparable_relationship_events(db: &Db) -> Vec<(String, String, Option<String>)> {
    let origin = db_origin(db).await;
    let rows = sqlx::query("SELECT type, payload, actor FROM relationship_events ORDER BY seq")
        .fetch_all(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    rows.iter()
        .map(|row| {
            let event_type: String = row.try_get("type").unwrap();
            let payload: String = row.try_get("payload").unwrap();
            let actor: Option<String> = row.try_get("actor").unwrap();
            let scrubbed = payload.replace(&origin, "ORIGIN");
            let mut value: Value = serde_json::from_str(&scrubbed).unwrap();
            normalize_relationship_payload(&mut value);
            (event_type, value.to_string(), actor)
        })
        .collect()
}

#[tokio::test]
async fn twin_update_equivalence() {
    let registry = registry();
    let singular = seeded(&registry).await;
    for id in [REC_A, REC_B, REC_C] {
        call(
            &registry,
            &singular,
            "update_record",
            json!({
                "id": id, "reason": REASON,
                "name": format!("{id}-renamed"),
                "summary": "twin summary",
                "facets": { "batch_probe": "done" },
            }),
        )
        .await;
    }
    let singular_events = comparable_events(&singular).await;

    let batched = seeded(&registry).await;
    let items: Vec<Value> = [REC_A, REC_B, REC_C]
        .iter()
        .map(|id| {
            json!({
                "op": "update", "id": id,
                "name": format!("{id}-renamed"),
                "summary": "twin summary",
                "facets": { "batch_probe": "done" },
            })
        })
        .collect();
    let receipt = call(
        &registry,
        &batched,
        "batch_write",
        json!({ "reason": REASON, "items": items }),
    )
    .await;
    assert_eq!(receipt["requested"], 3);
    assert_eq!(receipt["changed"], 3);
    assert!(receipt.get("act").is_some(), "{receipt}");
    assert_eq!(comparable_events(&batched).await, singular_events);

    for db in [&singular, &batched] {
        for id in [REC_A, REC_B, REC_C] {
            assert_eq!(
                facet_value(db, id, "batch_probe").await.as_deref(),
                Some("done")
            );
        }
        assert!(record_name(db, &registry, REC_A)
            .await
            .unwrap()
            .contains("renamed"));
    }
}

/// Twin-run link equivalence for one relationship. `relates_to` exercises the
/// relationship-owned path (legacy adapter, no content event — same as the
/// singular call produces); `member_of` exercises the plain `link.added`
/// content path. Both must match the singular runs event-for-event.
async fn twin_add_link(registry: &ToolRegistry, relationship: &str) {
    let singular = seeded(registry).await;
    for source in [REC_A, REC_B] {
        call(
            registry,
            &singular,
            "manage_links",
            json!({
                "action": "add", "source_id": source, "target_id": REC_T,
                "relationship": relationship, "note": "twin link",
            }),
        )
        .await;
    }
    let singular_events = comparable_events(&singular).await;

    let batched = seeded(registry).await;
    let items: Vec<Value> = [REC_A, REC_B]
        .iter()
        .map(|source| {
            json!({
                "op": "add_link", "source_id": source, "target_id": REC_T,
                "relationship": relationship, "note": "twin link",
            })
        })
        .collect();
    let receipt = call(
        registry,
        &batched,
        "batch_write",
        json!({ "reason": REASON, "items": items }),
    )
    .await;
    assert_eq!(receipt["changed"], 2);
    assert_eq!(comparable_events(&batched).await, singular_events);
    let singular_relationship = comparable_relationship_events(&singular).await;
    let batched_relationship = comparable_relationship_events(&batched).await;
    assert_eq!(batched_relationship, singular_relationship);
    if relationship == "member_of" {
        // The plain content path must not leak into the relationship log.
        assert!(batched_relationship.is_empty(), "{batched_relationship:?}");
    } else {
        // The owned path appends no content link events by design (same as
        // singular) — so a non-empty relationship log here proves the
        // comparison above is not vacuous.
        assert!(!batched_relationship.is_empty());
    }

    for db in [&singular, &batched] {
        for source in [REC_A, REC_B] {
            let listed = call(
                registry,
                db,
                "manage_links",
                json!({ "action": "list", "record_id": source }),
            )
            .await;
            let out = listed["links_out"].as_array().unwrap();
            assert_eq!(out.len(), 1, "{out:?}");
            assert_eq!(out[0]["target_id"], REC_T);
            assert_eq!(out[0]["relationship"], relationship);
        }
    }
}

#[tokio::test]
async fn twin_owned_link_equivalence() {
    twin_add_link(&registry(), "relates_to").await;
}

/// The operation identity an owned link carries: the batch must stamp the
/// singular `manage_links` identity into the relationship event's rationale
/// and admission digest, not its own tool name. The digest input is
/// reconstructed field-for-field from the adapter's construction, so any
/// operation-string drift fails this test.
#[tokio::test]
async fn owned_link_auth_digest_uses_the_singular_operation_identity() {
    let registry = registry();
    let db = seeded(&registry).await;
    call(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [{ "op": "add_link", "source_id": REC_A, "target_id": REC_T,
                        "relationship": "relates_to", "note": "twin link" }],
        }),
    )
    .await;
    let payload: Value = sqlx::query_scalar(
        "SELECT payload FROM relationship_events WHERE type = 'assertion.created.v1' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .map(|payload: String| serde_json::from_str(&payload).unwrap())
    .unwrap();
    assert_eq!(payload["rationale"], "manage_links compatibility add");
    let origin = db_origin(&db).await;
    let input = json!({
        "schema_version": 1,
        "principal": Caller::local().credential(),
        "operation": "manage_links",
        "relationship_type_definition": "legacy_link.v1",
        "admission_class": "source_authorised_support",
        "authority_anchor": {
            "endpoint_role": "source",
            "endpoint_ref": native_ce::identity::encode_native_record(&origin, REC_A).unwrap(),
        },
        "admission_rule": "edit_source_view_target.v1",
    });
    let expected = hex::encode(Sha256::digest(serde_jcs::to_vec(&input).unwrap()));
    assert_eq!(
        payload["origin_admission"]["authorization_decision_digest"],
        expected
    );
}

#[tokio::test]
async fn twin_plain_link_equivalence() {
    twin_add_link(&registry(), "member_of").await;
}

#[tokio::test]
async fn twin_archive_equivalence() {
    let registry = registry();
    let singular = seeded(&registry).await;
    for id in [REC_A, REC_B] {
        call(
            &registry,
            &singular,
            "archive_record",
            json!({ "id": id, "reason": REASON }),
        )
        .await;
    }
    let singular_events = comparable_events(&singular).await;

    let batched = seeded(&registry).await;
    let items: Vec<Value> = [REC_A, REC_B]
        .iter()
        .map(|id| json!({ "op": "archive", "id": id }))
        .collect();
    let receipt = call(
        &registry,
        &batched,
        "batch_write",
        json!({ "reason": REASON, "items": items }),
    )
    .await;
    assert_eq!(receipt["changed"], 2);
    assert_eq!(comparable_events(&batched).await, singular_events);
    for db in [&singular, &batched] {
        assert!(facet_value(db, REC_A, "archived").await.is_some());
    }

    // Re-archiving is a no-op batch: unchanged statuses, no new events.
    let before = event_count(&batched).await;
    let repeat = call(
        &registry,
        &batched,
        "batch_write",
        json!({ "reason": REASON, "items": items }),
    )
    .await;
    assert_eq!(repeat["changed"], 0);
    assert_eq!(repeat["unchanged"], 2);
    assert_eq!(event_count(&batched).await, before);
}

#[tokio::test]
async fn batch_stamps_reason_and_basis_on_every_item() {
    let registry = registry();
    let db = seeded(&registry).await;
    let before = max_seq(&db).await;
    call(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "sources": [{ "record_id": REC_S, "reason": "covers the batch" }],
            "items": [
                { "op": "update", "id": REC_A, "summary": "based update" },
                { "op": "add_link", "source_id": REC_B, "target_id": REC_T,
                  "relationship": "member_of" },
                { "op": "archive", "id": REC_C },
            ],
        }),
    )
    .await;
    let payloads = raw_payloads(&db, before).await;
    // One event per item: record.updated, link.added, archived facet.set.
    assert_eq!(payloads.len(), 3, "{payloads:?}");
    for payload in &payloads {
        assert_eq!(payload["reason"], REASON, "{payload}");
        assert_eq!(
            payload["basis"]["sources"][0]["record_id"], REC_S,
            "{payload}"
        );
    }
    assert_eq!(payloads[0]["summary"], "based update");
    assert_eq!(payloads[1]["target_id"], REC_T);
    assert_eq!(payloads[2]["key"], "archived");
}

#[tokio::test]
async fn guard_failure_on_last_item_writes_nothing() {
    let registry = registry();
    let db = seeded(&registry).await;
    let before = event_count(&db).await;
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": REC_A, "name": "should not land" },
                { "op": "update", "id": REC_B,
                  "facets": { "batch_probe": "done" } },
                { "op": "update", "id": REC_C, "summary": "stale guard",
                  "if_unmodified_since": "2000-01-01T00:00:00Z" },
            ],
        }),
    )
    .await;
    assert!(error.contains("[2]"), "{error}");
    assert!(error.contains("nothing was written"), "{error}");
    assert!(error.contains("conflicted=1"), "{error}");
    assert_eq!(event_count(&db).await, before);
    assert_eq!(
        record_name(&db, &registry, REC_A).await.as_deref(),
        Some("alpha")
    );
    assert_eq!(facet_value(&db, REC_B, "batch_probe").await, None);
}

#[tokio::test]
async fn keyed_reuse_after_partial_change_is_refused() {
    let registry = registry();
    let db = seeded(&registry).await;
    // Item 0 is identical to current state, so only item 1 stores a
    // per-item attestation — the batch anchor is the only row for item 0's key.
    let first = call(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "idempotency_key": "batch-hole-key",
            "items": [
                { "op": "update", "id": REC_A, "name": "alpha" },
                { "op": "update", "id": REC_B, "name": "beta-2" },
            ],
        }),
    )
    .await;
    assert_eq!(first["results"][0]["status"], "unchanged");
    assert_eq!(first["results"][1]["status"], "changed");
    let after_first = event_count(&db).await;
    // Same key, fewer items, different content: must be refused, not committed.
    let conflict = call_as(
        &registry,
        &db,
        Caller::local(),
        "batch_write",
        json!({
            "reason": REASON,
            "idempotency_key": "batch-hole-key",
            "items": [{ "op": "update", "id": REC_A, "name": "changed after all" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(conflict.contains("conflicting action input"), "{conflict}");
    assert_eq!(event_count(&db).await, after_first);
    assert_eq!(
        record_name(&db, &registry, REC_A).await.as_deref(),
        Some("alpha")
    );
}

#[tokio::test]
async fn all_unchanged_keyed_batch_anchors_and_replays() {
    let registry = registry();
    let db = seeded(&registry).await;
    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": REC_B, "reason": REASON }),
    )
    .await;
    let args = json!({
        "reason": REASON,
        "idempotency_key": "batch-noop-key",
        "items": [
            { "op": "update", "id": REC_A, "name": "alpha" },
            { "op": "archive", "id": REC_B },
        ],
    });
    let before = event_count(&db).await;
    let first = call_as(&registry, &db, Caller::local(), "batch_write", args.clone())
        .await
        .unwrap();
    assert_eq!(first["changed"], 0);
    assert_eq!(event_count(&db).await, before);
    // The anchor exists despite zero events: the retry replays, and a
    // same-key different-content call is refused.
    let retry = call_as(&registry, &db, Caller::local(), "batch_write", args.clone())
        .await
        .unwrap();
    assert_eq!(retry, first);
    assert_eq!(event_count(&db).await, before);
    let mut other = args.clone();
    other["items"][0]["name"] = json!("sneaky change");
    let conflict = call_as(&registry, &db, Caller::local(), "batch_write", other)
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("conflicting action input"), "{conflict}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn concurrent_identical_retries_commit_once() {
    let registry = registry();
    let db = seeded(&registry).await;
    let args = json!({
        "reason": REASON,
        "idempotency_key": "batch-race-key",
        "items": [{ "op": "update", "id": REC_A, "summary": "raced" }],
    });
    let before = event_count(&db).await;
    let (first, second) = tokio::join!(
        call_as(&registry, &db, Caller::local(), "batch_write", args.clone()),
        call_as(&registry, &db, Caller::local(), "batch_write", args.clone()),
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(first, second);
    let committed = event_count(&db).await - before;
    let single = {
        let probe = seeded(&registry).await;
        let probe_before = event_count(&probe).await;
        call_as(&registry, &probe, Caller::local(), "batch_write", args)
            .await
            .unwrap();
        event_count(&probe).await - probe_before
    };
    assert_eq!(committed, single);
}

#[tokio::test]
async fn batch_marks_link_events_with_reason_singulars_lack() {
    let registry = registry();
    let singular = seeded(&registry).await;
    call(
        &registry,
        &singular,
        "manage_links",
        json!({
            "action": "add", "source_id": REC_A, "target_id": REC_T,
            "relationship": "member_of",
        }),
    )
    .await;
    let single: Value = raw_payloads(&singular, 0)
        .await
        .into_iter()
        .find(|payload| payload["target_id"] == REC_T)
        .expect("singular link.added event");
    assert!(single.get("reason").is_none(), "{single}");

    let batched = seeded(&registry).await;
    call(
        &registry,
        &batched,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [{ "op": "add_link", "source_id": REC_A, "target_id": REC_T,
                        "relationship": "member_of" }],
        }),
    )
    .await;
    let batched_payloads = raw_payloads(&batched, 0).await;
    let marked = batched_payloads
        .iter()
        .find(|payload| payload["target_id"] == REC_T)
        .expect("batch link.added event");
    assert_eq!(marked["reason"], REASON, "{marked}");
}

#[tokio::test]
async fn demoted_principal_can_replay_but_not_rebatch() {
    use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let registry = registry();
    let db = db().await;
    let alice = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bea_person = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (person, account) in [(&alice, "acct:alice"), (&bea_person, "acct:bea")] {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(person)
        .bind(account)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }
    create(&registry, &db, REC_A, "demotion target").await;
    replace_explicit_policy(
        &db,
        "test:policy",
        REC_A,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let args = json!({
        "reason": REASON,
        "idempotency_key": "batch-demotion-key",
        "items": [{ "op": "update", "id": REC_A, "name": "bea's edit" }],
    });
    let first = call_as(&registry, &db, bea.clone(), "batch_write", args.clone())
        .await
        .unwrap();
    // Demote to viewer: the identical retry still replays its past receipt,
    // but any new batch is refused.
    replace_explicit_policy(
        &db,
        "test:policy",
        REC_A,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .unwrap();
    let replay = call_as(&registry, &db, bea.clone(), "batch_write", args)
        .await
        .unwrap();
    assert_eq!(replay, first);
    let refused = call_as(
        &registry,
        &db,
        bea,
        "batch_write",
        json!({
            "reason": REASON,
            "idempotency_key": "batch-demotion-key-2",
            "items": [{ "op": "update", "id": REC_A, "name": "another edit" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("unavailable: record is unavailable"),
        "{refused}"
    );
}

#[tokio::test]
async fn hidden_and_missing_refuse_identically() {
    use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let registry = registry();
    let db = db().await;
    let alice = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bea_person = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (person, account) in [(&alice, "acct:alice"), (&bea_person, "acct:bea")] {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(person)
        .bind(account)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }
    let visible = create(&registry, &db, REC_A, "open target").await;
    let hidden = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "id": REC_B,
                "name": "Hidden secret name", "owner_id": alice }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let before = event_count(&db).await;

    let error = call_as(
        &registry,
        &db,
        bea.clone(),
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": visible, "name": "bea was here" },
                { "op": "update", "id": hidden, "name": "nope" },
            ],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    let hidden_detail = format!("[1] update {hidden} unavailable: record is unavailable");
    assert!(error.contains(&hidden_detail), "{error}");
    assert!(!error.contains("Hidden secret name"), "{error}");
    assert!(!error.contains("does not exist"), "{error}");
    assert!(!error.contains("capability"), "{error}");

    let missing_error = call_as(
        &registry,
        &db,
        bea,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": visible, "name": "bea was here" },
                { "op": "update", "id": MISSING, "name": "nope" },
            ],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        missing_error.contains(&format!(
            "[1] update {MISSING} unavailable: record is unavailable"
        )),
        "{missing_error}"
    );
    assert!(!missing_error.contains("does not exist"), "{missing_error}");
    assert_eq!(event_count(&db).await, before);
    assert_eq!(
        record_name(&db, &registry, &visible).await.as_deref(),
        Some("open target")
    );
}

#[tokio::test]
async fn keyed_retry_returns_original_and_appends_nothing() {
    let registry = registry();
    let db = seeded(&registry).await;
    let args = json!({
        "reason": REASON,
        "idempotency_key": "batch-key-1",
        "items": [
            { "op": "update", "id": REC_A, "summary": "keyed summary" },
            { "op": "add_link", "source_id": REC_B, "target_id": REC_T,
              "relationship": "relates_to" },
            { "op": "archive", "id": REC_C },
        ],
    });
    let first = call_as(&registry, &db, Caller::local(), "batch_write", args.clone())
        .await
        .unwrap();
    // One action attestation per changed item plus the batch anchor, exactly
    // as singular writes produce plus one key row.
    assert_eq!(first["action_attestation_ids"].as_array().unwrap().len(), 4);
    let after_first = event_count(&db).await;

    let retry = call_as(&registry, &db, Caller::local(), "batch_write", args.clone())
        .await
        .unwrap();
    assert_eq!(retry, first, "retry receipt must equal the original");
    assert_eq!(event_count(&db).await, after_first);

    let mut other = args.clone();
    other["items"][0]["summary"] = json!("different content");
    let conflict = call_as(&registry, &db, Caller::local(), "batch_write", other)
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("conflicting action input"), "{conflict}");
    assert_eq!(event_count(&db).await, after_first);
}

#[tokio::test]
async fn replay_reproduces_the_live_projection() {
    let registry = registry();
    let db = seeded(&registry).await;
    call(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": REC_A, "name": "replayed",
                  "facets": { "batch_probe": "done" } },
                { "op": "add_link", "source_id": REC_B, "target_id": REC_T,
                  "relationship": "depends_on", "note": "replay me" },
                { "op": "archive", "id": REC_C },
            ],
        }),
    )
    .await;
    let rebuilt = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{rebuilt:?}");
}

#[tokio::test]
async fn cap_and_shape_refusals() {
    let registry = registry();
    let db = seeded(&registry).await;
    let too_many: Vec<Value> = (0..26)
        .map(|_| json!({ "op": "update", "id": REC_A, "name": "x" }))
        .collect();
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({ "reason": REASON, "items": too_many }),
    )
    .await;
    assert!(error.contains("at most 25"), "{error}");

    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({ "reason": REASON, "items": [] }),
    )
    .await;
    assert!(error.contains("at least one item"), "{error}");

    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({ "reason": REASON,
                "items": [{ "op": "update", "id": "not-a-uuid" }] }),
    )
    .await;
    assert!(error.contains("canonical"), "{error}");

    // Body operations are out of scope for M0.
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({ "reason": REASON,
                "items": [{ "op": "update", "id": REC_A, "body_set": "nope" }] }),
    )
    .await;
    assert!(error.contains("body_set"), "{error}");
}

#[tokio::test]
async fn relocation_refreshes_policy_anchors_like_multi() {
    async fn anchors(db: &Db) -> Vec<(String, Option<String>)> {
        sqlx::query("SELECT id, policy_anchor_id FROM records WHERE id IN (?, ?) ORDER BY id")
            .bind(REC_A)
            .bind(REC_B)
            .fetch_all(&crate::common::fixture_write_pool(db).await)
            .await
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row.try_get("id").unwrap(),
                    row.try_get("policy_anchor_id").unwrap(),
                )
            })
            .collect()
    }
    async fn relocated_pair(registry: &ToolRegistry) -> Db {
        let db = db().await;
        for (id, kind, name, home) in [
            (REC_H1, "folder", "home one", None),
            (REC_H2, "folder", "home two", None),
            (REC_A, "note", "alpha", Some(REC_H1)),
            (REC_B, "note", "beta", Some(REC_H2)),
        ] {
            let mut args = json!({ "type": "Collection", "kind": kind, "id": id, "name": name });
            if kind == "note" {
                args = json!({ "type": "Document", "kind": kind, "id": id, "name": name });
            }
            if let Some(home) = home {
                args["home_id"] = json!(home);
            }
            call(registry, &db, "create_record", args).await;
        }
        db
    }
    let registry = registry();
    let batched = relocated_pair(&registry).await;
    let receipt = call(
        &registry,
        &batched,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": REC_A, "home_id": REC_H2 },
                { "op": "update", "id": REC_B, "home_id": REC_H1 },
            ],
        }),
    )
    .await;
    assert_eq!(receipt["changed"], 2);

    let multied = relocated_pair(&registry).await;
    for (id, home) in [(REC_A, REC_H2), (REC_B, REC_H1)] {
        call(
            &registry,
            &multied,
            "update_record",
            json!({ "ids": [id], "home_id": home, "reason": REASON }),
        )
        .await;
    }
    assert_eq!(anchors(&batched).await, anchors(&multied).await);
}

#[tokio::test]
async fn heterogeneous_e0_style_batch_succeeds() {
    let registry = registry();
    let db = seeded(&registry).await;
    create(&registry, &db, REC_D, "delta").await;
    create(&registry, &db, REC_E, "echo").await;
    let receipt = call(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": REC_A, "facets": { "e0probe": "done" } },
                { "op": "update", "id": REC_B, "facets": { "e0probe": "done" } },
                { "op": "add_link", "source_id": REC_C, "target_id": REC_T,
                  "relationship": "relates_to", "note": "e0-harness" },
                { "op": "add_link", "source_id": REC_D, "target_id": REC_T,
                  "relationship": "relates_to", "note": "e0-harness" },
                { "op": "archive", "id": REC_E },
                { "op": "update", "id": REC_S,
                  "name": "renamed source", "summary": "rewritten summary" },
            ],
        }),
    )
    .await;
    assert_eq!(receipt["requested"], 6);
    assert_eq!(receipt["changed"], 6);
    assert!(receipt.get("act").is_some(), "{receipt}");
    for outcome in receipt["results"].as_array().unwrap() {
        assert_eq!(outcome["status"], "changed", "{outcome}");
    }
    assert_eq!(
        facet_value(&db, REC_A, "e0probe").await.as_deref(),
        Some("done")
    );
    assert_eq!(
        facet_value(&db, REC_B, "e0probe").await.as_deref(),
        Some("done")
    );
    assert!(facet_value(&db, REC_E, "archived").await.is_some());
    assert_eq!(
        record_name(&db, &registry, REC_S).await.as_deref(),
        Some("renamed source")
    );
}

#[tokio::test]
async fn empty_if_facets_is_refused() {
    let registry = registry();
    let db = seeded(&registry).await;
    let before = event_count(&db).await;
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [{ "op": "update", "id": REC_A, "name": "x", "if_facets": {} }],
        }),
    )
    .await;
    assert!(error.contains("if_facets"), "{error}");
    assert!(error.contains("must not be empty"), "{error}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn update_item_with_no_changes_is_refused() {
    let registry = registry();
    let db = seeded(&registry).await;
    let before = event_count(&db).await;
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({ "reason": REASON, "items": [{ "op": "update", "id": REC_A }] }),
    )
    .await;
    assert!(error.contains("names no changes"), "{error}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn duplicate_primary_ids_are_refused() {
    let registry = registry();
    let db = seeded(&registry).await;
    let before = event_count(&db).await;
    let error = call_err(
        &registry,
        &db,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [
                { "op": "update", "id": REC_A, "name": "first" },
                { "op": "archive", "id": REC_A },
            ],
        }),
    )
    .await;
    assert!(error.contains("duplicates"), "{error}");
    assert!(error.contains(REC_A), "{error}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn naming_home_requires_manage_even_when_unchanged() {
    use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let registry = registry();
    let db = db().await;
    let alice = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bea_person = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    for (person, account) in [(&alice, "acct:alice"), (&bea_person, "acct:bea")] {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(person)
        .bind(account)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }
    create(&registry, &db, REC_A, "managed home target").await;
    replace_explicit_policy(
        &db,
        "test:policy",
        REC_A,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    let current_home: Option<String> =
        sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
            .bind(REC_A)
            .fetch_one(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    // Naming the current home is still structural: Edit is not enough.
    let error = call_as(
        &registry,
        &db,
        bea.clone(),
        "batch_write",
        json!({
            "reason": REASON,
            "items": [{ "op": "update", "id": REC_A, "home_id": current_home }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("unavailable: record is unavailable"),
        "{error}"
    );
    // The same caller may still edit without naming a home.
    let receipt = call_as(
        &registry,
        &db,
        bea,
        "batch_write",
        json!({
            "reason": REASON,
            "items": [{ "op": "update", "id": REC_A, "name": "edited" }],
        }),
    )
    .await
    .unwrap();
    assert_eq!(receipt["changed"], 1);
}
