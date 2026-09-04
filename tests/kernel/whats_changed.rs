//! Acceptance coverage for the stateless, authorization-filtered
//! `whats_changed` tool and its public synchronization cursor.

use std::collections::BTreeSet;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

const SELF: &str = "account:self";
const OTHER: &str = "account:other";
const ROOT_RUN: &str = "scout-chair-a748b2";
const CHILD_RUN: &str = "heron-river-b748b2";
const OTHER_RUN: &str = "otter-field-c748b2";

async fn db() -> Db {
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call_as(registry: &ToolRegistry, db: &Db, actor: &str, arguments: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::authenticated(actor),
            "whats_changed",
            arguments,
        )
        .await
        .unwrap()
}

async fn call(registry: &ToolRegistry, db: &Db, arguments: Value) -> Value {
    call_as(registry, db, SELF, arguments).await
}

async fn call_err(registry: &ToolRegistry, db: &Db, arguments: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::authenticated(SELF),
            "whats_changed",
            arguments,
        )
        .await
        .unwrap_err()
        .to_string()
}

async fn insert_record(db: &Db, id: &str, name: &str, home_id: Option<&str>, deleted: bool) {
    sqlx::query(
        "INSERT INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence, created_at, updated_at, deleted_at)
         VALUES (?, 'Document', 'note', ?, ?, ?, 'enduring',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.000Z', ?)",
    )
    .bind(id)
    .bind(name)
    .bind(home_id)
    .bind(id)
    .bind(deleted.then_some("2026-08-02T01:00:00.000Z"))
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_policies (record_id) VALUES (?)")
        .bind(id)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
            (policy_anchor_id, subject_kind, subject_id, effect, capability)
         VALUES (?, 'members', 'native:members', 'allow', 'view')",
    )
    .bind(id)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn insert_private_record(db: &Db, id: &str, name: &str, account: &str) {
    sqlx::query(
        "INSERT INTO records
            (id, type, kind, name, policy_anchor_id, persistence, created_at, updated_at)
         VALUES (?, 'Document', 'note', ?, ?, 'enduring',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.000Z')",
    )
    .bind(id)
    .bind(name)
    .bind(id)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_policies (record_id) VALUES (?)")
        .bind(id)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
            (policy_anchor_id, subject_kind, subject_id, effect, capability)
         VALUES (?, 'account', ?, 'allow', 'view')",
    )
    .bind(id)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn insert_event(
    db: &Db,
    record_id: &str,
    event_type: &str,
    payload: Option<Value>,
    actor: Option<&str>,
    run_key: Option<&str>,
    parent_key: Option<&str>,
) -> i64 {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id = ?)")
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    if !exists {
        insert_record(db, record_id, record_id, None, false).await;
    }
    let id = format!(
        "event:{}",
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) + 1 FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let result = sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, run_key, parent_key, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, ?, ?, ?, ?, ?,
                 strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || (SELECT COUNT(*) FROM content_events) || ' seconds'), 1, 'legacy_unknown')",
    )
    .bind(id)
    .bind(record_id)
    .bind(event_type)
    .bind(payload.map(|payload| payload.to_string()))
    .bind(actor)
    .bind(run_key)
    .bind(parent_key)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    result.last_insert_rowid()
}

/// Insert an event with a verbatim payload string, so tests can store a
/// payload no JSON parser accepts. `insert_event` above always serializes a
/// `Value` and cannot produce that state.
async fn insert_raw_event(
    db: &Db,
    record_id: &str,
    event_type: &str,
    payload: Option<&str>,
    actor: Option<&str>,
    run_key: Option<&str>,
) {
    let id = format!(
        "event:{}",
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) + 1 FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, run_key, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, ?, ?, ?, ?,
                 strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || (SELECT COUNT(*) FROM content_events) || ' seconds'), 1, 'legacy_unknown')",
    )
    .bind(id)
    .bind(record_id)
    .bind(event_type)
    .bind(payload)
    .bind(actor)
    .bind(run_key)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

fn seqs(value: &Value) -> Vec<i64> {
    value["changes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|change| {
            let first = change["first_local_seq"].as_i64().unwrap();
            let last = change["last_local_seq"].as_i64().unwrap();
            first..=last
        })
        .collect()
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn empty_log_and_invalid_requests_fail_clearly() {
    let db = db().await;
    let registry = registry();

    let empty = call(&registry, &db, json!({})).await;
    assert_eq!(empty["after_local_seq"], 0);
    assert_eq!(empty["scanned_through_local_seq"], 0);
    assert_eq!(empty["high_water_local_seq"], 0);
    assert_eq!(empty["next_after_local_seq"], Value::Null);
    assert_eq!(empty["has_more"], false);
    assert_eq!(empty["scanned_event_count"], 0);
    assert_eq!(empty["matched_event_count"], 0);
    assert_eq!(empty["changes"], json!([]));
    assert_eq!(empty["next_request"], Value::Null);

    insert_event(
        &db,
        "record:one",
        "record.created",
        Some(json!({ "type": "Document", "name": "one" })),
        Some(SELF),
        None,
        None,
    )
    .await;
    for (arguments, expected) in [
        (
            json!({ "after_local_seq": -1 }),
            "after_local_seq must be >= 0",
        ),
        (
            json!({ "through_local_seq": -1 }),
            "through_local_seq must be >= 0",
        ),
        (
            json!({ "through_local_seq": 2 }),
            "beyond available history",
        ),
        (
            json!({ "after_local_seq": 1, "through_local_seq": 0 }),
            "must not exceed high_water_local_seq 0",
        ),
        (json!({ "limit": 0 }), "limit must be between 1 and 1000"),
        (json!({ "limit": 1001 }), "limit must be between 1 and 1000"),
        (
            json!({ "include_child_runs": true }),
            "include_child_runs requires for_run",
        ),
        (
            json!({ "accounts": [] }),
            "accounts must not be an empty array",
        ),
        (
            json!({ "event_families": [] }),
            "event_families must not be an empty array",
        ),
        (
            json!({ "event_families": ["mystery"] }),
            "unknown event family 'mystery'",
        ),
    ] {
        let error = call_err(&registry, &db, arguments).await;
        assert!(error.contains(expected), "{error}");
    }
    let malformed = call_err(&registry, &db, json!({ "after_local_seq": "one" })).await;
    assert!(malformed.contains("invalid arguments for whats_changed"));

    for field in [
        "after_local_seq",
        "through_local_seq",
        "limit",
        "scope_record_id",
        "actor_scope",
        "accounts",
        "for_run",
        "event_families",
    ] {
        let arguments = Value::Object([(field.to_string(), Value::Null)].into_iter().collect());
        let error = call_err(&registry, &db, arguments).await;
        assert!(
            error.contains("invalid arguments for whats_changed"),
            "explicit null for {field} must be rejected: {error}"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn pinned_multi_page_window_excludes_concurrent_events_without_gaps_or_duplicates() {
    let db = db().await;
    let registry = registry();
    for n in 1..=5 {
        insert_event(
            &db,
            &format!("record:{n}"),
            "record.updated",
            Some(json!({ "name": format!("record {n}") })),
            Some(SELF),
            None,
            None,
        )
        .await;
    }

    let first = call(&registry, &db, json!({ "limit": 2 })).await;
    assert_eq!(first["high_water_local_seq"], 5);
    assert_eq!(first["scanned_through_local_seq"], 2);
    assert_eq!(first["has_more"], true);
    insert_event(
        &db,
        "record:concurrent",
        "record.updated",
        Some(json!({ "name": "too new" })),
        Some(SELF),
        None,
        None,
    )
    .await;

    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["high_water_local_seq"], 5);
    assert_eq!(second["scanned_through_local_seq"], 4);
    assert_eq!(second["has_more"], true);
    let third = call(&registry, &db, second["next_request"].clone()).await;
    assert_eq!(third["high_water_local_seq"], 5);
    assert_eq!(third["scanned_through_local_seq"], 5);
    assert_eq!(third["has_more"], false);
    assert_eq!(third["next_request"], Value::Null);

    let mut traversed = seqs(&first);
    traversed.extend(seqs(&second));
    traversed.extend(seqs(&third));
    assert_eq!(traversed, vec![1, 2, 3, 4, 5]);
    db.close().await;
}

#[tokio::test]
async fn newest_first_impact_filter_crosses_a_type_correction_at_event_time() {
    let db = db().await;
    let registry = registry();
    let record_id = "record:corrected-impact";
    insert_record(&db, record_id, "Corrected impact", None, false).await;

    insert_event(
        &db,
        record_id,
        "record.created",
        Some(json!({ "type": "Outcome", "kind": "impact", "name": "Corrected impact" })),
        Some(SELF),
        None,
        None,
    )
    .await;
    insert_event(
        &db,
        record_id,
        "record.updated",
        Some(json!({ "summary": "Still an impact" })),
        Some(SELF),
        None,
        None,
    )
    .await;
    insert_event(
        &db,
        record_id,
        "record.type_corrected.v1",
        Some(json!({
            "from": { "type": "Outcome", "kind": "impact" },
            "to": { "type": "Document", "kind": "note" },
            "mode": "confirmed",
            "reason": "Correct a mistaken impact classification",
            "plan_id": "wpl1:history-fixture",
            "effect_digest": format!("sha256:{}", "a".repeat(64)),
            "schema_state_revision": "schema-state-v1:meta:0:content:2",
            "confirmation_required": true
        })),
        Some(SELF),
        None,
        None,
    )
    .await;
    insert_event(
        &db,
        record_id,
        "record.updated",
        Some(json!({ "summary": "Now an ordinary document" })),
        Some(SELF),
        None,
        None,
    )
    .await;

    let result = call(
        &registry,
        &db,
        json!({ "order": "newest_first", "event_families": ["impacts"] }),
    )
    .await;
    assert_eq!(result["matched_event_count"], 2);
    assert_eq!(result["changes"][0]["first_local_seq"], 1);
    assert_eq!(result["changes"][0]["last_local_seq"], 2);
    assert_eq!(
        strings(&result["changes"][0]["event_types"]),
        ["record.created", "record.updated"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    db.close().await;
}

#[tokio::test]
async fn filter_hidden_only_windows_exhaust_without_empty_continuation_pages() {
    let db = db().await;
    let registry = registry();
    for n in 1..=3 {
        insert_event(
            &db,
            &format!("record:{n}"),
            "record.updated",
            Some(json!({ "summary": n })),
            Some(OTHER),
            None,
            None,
        )
        .await;
    }

    let first = call(&registry, &db, json!({ "limit": 2, "accounts": [SELF] })).await;
    assert_eq!(first["scanned_event_count"], 0);
    assert_eq!(first["matched_event_count"], 0);
    assert_eq!(first["changes"], json!([]));
    assert_eq!(first["next_after_local_seq"], Value::Null);
    assert_eq!(first["scanned_through_local_seq"], 3);
    assert_eq!(first["has_more"], false);
    assert_eq!(first["next_request"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn alice_hidden_only_bea_history_does_not_occupy_a_page_or_set_has_more() {
    let db = db().await;
    let registry = registry();
    let alice = "account:alice";
    let bea = "account:bea";
    insert_private_record(&db, "record:alice", "Alice private", alice).await;
    insert_private_record(&db, "record:bea", "Bea private", bea).await;
    for summary in ["one", "two", "three"] {
        insert_event(
            &db,
            "record:bea",
            "record.updated",
            Some(json!({ "summary": summary })),
            Some(bea),
            None,
            None,
        )
        .await;
    }

    let result = call_as(&registry, &db, alice, json!({ "limit": 1 })).await;
    assert_eq!(result["high_water_local_seq"], 3);
    assert_eq!(result["scanned_through_local_seq"], 3);
    assert_eq!(result["scanned_event_count"], 0);
    assert_eq!(result["matched_event_count"], 0);
    assert_eq!(result["changes"], json!([]));
    assert_eq!(result["has_more"], false);
    assert_eq!(result["next_request"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn alice_pages_fill_across_interleaved_bea_events_and_continue_on_visible_work() {
    let db = db().await;
    let registry = registry();
    let alice = "account:alice";
    let bea = "account:bea";
    insert_private_record(&db, "record:alice", "Alice private", alice).await;
    insert_private_record(&db, "record:bea", "Bea private", bea).await;
    for (record_id, actor, summary) in [
        ("record:bea", bea, "bea one"),
        ("record:alice", alice, "alice one"),
        ("record:bea", bea, "bea two"),
        ("record:alice", alice, "alice two"),
        ("record:bea", bea, "bea three"),
        ("record:alice", alice, "alice three"),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": summary })),
            Some(actor),
            None,
            None,
        )
        .await;
    }

    let first = call_as(&registry, &db, alice, json!({ "limit": 2 })).await;
    assert_eq!(first["high_water_local_seq"], 6);
    assert_eq!(first["scanned_through_local_seq"], 5);
    assert_eq!(first["scanned_event_count"], 2);
    assert_eq!(first["matched_event_count"], 2);
    assert_eq!(first["changes"][0]["first_local_seq"], 2);
    assert_eq!(first["changes"][0]["last_local_seq"], 4);
    assert_eq!(first["changes"][0]["event_count"], 2);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["next_request"]["after_local_seq"], 5);

    let second = call_as(&registry, &db, alice, first["next_request"].clone()).await;
    assert_eq!(second["after_local_seq"], 5);
    assert_eq!(second["scanned_through_local_seq"], 6);
    assert_eq!(second["scanned_event_count"], 1);
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(second["changes"][0]["first_local_seq"], 6);
    assert_eq!(second["changes"][0]["last_local_seq"], 6);
    assert_eq!(second["has_more"], false);
    assert_eq!(second["next_request"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn every_family_and_semantic_field_is_explicit_and_groups_deterministically() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:all", "All changes", None, false).await;
    for (event_type, payload) in [
        (
            "record.created",
            Some(json!({
                "type": "Document", "kind": "note", "name": "All changes",
                "body": "body", "reason": "metadata"
            })),
        ),
        (
            "record.updated",
            Some(json!({ "home_id": "record:parent", "summary": "moved", "reason": "metadata" })),
        ),
        (
            "facet.set",
            Some(json!({ "key": "priority", "value": "high" })),
        ),
        ("facet.unset", Some(json!({ "key": "status" }))),
        ("link.added", Some(json!({}))),
        ("link.removed", Some(json!({}))),
        ("annotation.target.set", Some(json!({}))),
        ("annotation.target.removed", Some(json!({}))),
        ("record.deleted", None),
    ] {
        insert_event(
            &db,
            "record:all",
            event_type,
            payload,
            Some(SELF),
            Some(ROOT_RUN),
            None,
        )
        .await;
    }

    let result = call(&registry, &db, json!({})).await;
    assert_eq!(result["matched_event_count"], 9);
    let changes = result["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    let change = &changes[0];
    assert_eq!(
        change
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        [
            "actor",
            "actor_name",
            "changed_fields",
            "event_count",
            "event_families",
            "event_types",
            "first_event_at",
            "first_local_seq",
            "last_event_at",
            "last_local_seq",
            "record_id",
            "record_name",
            "record_type",
            "run_key",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(change["event_count"], 9);
    assert_eq!(change["first_local_seq"], 1);
    assert_eq!(change["last_local_seq"], 9);
    assert_eq!(change["record_name"], "All changes");
    assert_eq!(change["record_type"], "Document");
    assert_eq!(
        strings(&change["event_families"]),
        EVENT_FAMILY_SET
            .iter()
            .map(|value| value.to_string())
            .collect()
    );
    assert_eq!(
        strings(&change["changed_fields"]),
        [
            "body",
            "facet:priority",
            "facet:status",
            "home_id",
            "kind",
            "name",
            "summary",
            "type",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    assert!(!strings(&change["changed_fields"]).contains("reason"));

    let moved = call(&registry, &db, json!({ "event_families": ["moved"] })).await;
    assert_eq!(moved["matched_event_count"], 1);
    assert_eq!(
        moved["changes"][0]["event_families"],
        json!(["moved", "updated"])
    );
    let created = call(&registry, &db, json!({ "event_families": ["created"] })).await;
    assert_eq!(created["matched_event_count"], 1);
    assert_eq!(created["changes"][0]["event_families"], json!(["created"]));
    db.close().await;
}

const EVENT_FAMILY_SET: [&str; 7] = [
    "annotations",
    "created",
    "deleted",
    "facets",
    "links",
    "moved",
    "updated",
];

#[tokio::test]
async fn actor_scopes_and_accounts_respect_noncaller_identity_redaction() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "person:self", "Self Person", None, false).await;
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES ('person:self', 'account', ?, 1)",
    )
    .bind(SELF)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    for (record_id, actor) in [
        ("record:self", Some(SELF)),
        ("record:other", Some(OTHER)),
        ("record:null", None),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "name": record_id })),
            actor,
            None,
            None,
        )
        .await;
    }

    let all = call(&registry, &db, json!({})).await;
    assert_eq!(all["matched_event_count"], 3);
    let self_only = call(&registry, &db, json!({ "actor_scope": "self" })).await;
    assert_eq!(self_only["matched_event_count"], 1);
    assert_eq!(self_only["changes"][0]["actor_name"], "Self Person");
    let others = call(&registry, &db, json!({ "actor_scope": "others" })).await;
    assert_eq!(others["matched_event_count"], 2);
    assert!(others["changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|change| change["actor"].is_null() && change["actor_name"].is_null()));
    assert!(others["changes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|change| change["actor"].is_null()));
    let account = call(&registry, &db, json!({ "accounts": [OTHER, OTHER] })).await;
    assert_eq!(account["matched_event_count"], 0);
    assert_eq!(account["changes"], json!([]));
    db.close().await;
}

#[tokio::test]
async fn exact_and_descendant_run_filters_compose_with_other_filters() {
    let db = db().await;
    let registry = registry();
    for (record_id, run, parent, actor, event_type) in [
        ("record:root", ROOT_RUN, None, SELF, "record.updated"),
        ("record:child", CHILD_RUN, Some(ROOT_RUN), SELF, "facet.set"),
        ("record:other", OTHER_RUN, None, OTHER, "record.updated"),
    ] {
        insert_event(
            &db,
            record_id,
            event_type,
            Some(if event_type == "facet.set" {
                json!({ "key": "priority", "value": "high" })
            } else {
                json!({ "summary": record_id })
            }),
            Some(actor),
            Some(run),
            parent,
        )
        .await;
    }

    let exact = call(&registry, &db, json!({ "for_run": ROOT_RUN })).await;
    assert_eq!(exact["matched_event_count"], 1);
    let tree = call(
        &registry,
        &db,
        json!({ "for_run": ROOT_RUN, "include_child_runs": true }),
    )
    .await;
    assert_eq!(tree["matched_event_count"], 2);
    let composed = call(
        &registry,
        &db,
        json!({
            "for_run": ROOT_RUN,
            "include_child_runs": true,
            "actor_scope": "self",
            "event_families": ["facets"]
        }),
    )
    .await;
    assert_eq!(composed["matched_event_count"], 1);
    assert_eq!(composed["changes"][0]["record_id"], "record:child");
    db.close().await;
}

#[tokio::test]
async fn subtree_scope_uses_current_live_visible_unarchived_membership() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "scope:root", "Root", None, false).await;
    insert_record(&db, "scope:child", "Child", Some("scope:root"), false).await;
    insert_record(
        &db,
        "scope:grandchild",
        "Grandchild",
        Some("scope:child"),
        false,
    )
    .await;
    insert_record(&db, "scope:outside", "Outside", None, false).await;
    insert_record(&db, "scope:archived", "Archived", Some("scope:root"), false).await;
    insert_record(&db, "scope:deleted", "Deleted", Some("scope:root"), true).await;
    sqlx::query(
        "INSERT INTO facet_values (id, record_id, key, value)
         VALUES ('facet:archive', 'scope:archived', 'archived', 'true')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    for id in [
        "scope:root",
        "scope:child",
        "scope:grandchild",
        "scope:outside",
        "scope:archived",
        "scope:deleted",
    ] {
        insert_event(
            &db,
            id,
            "record.updated",
            Some(json!({ "summary": id })),
            Some(SELF),
            None,
            None,
        )
        .await;
    }

    let scoped = call(&registry, &db, json!({ "scope_record_id": "scope:root" })).await;
    let ids = scoped["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| change["record_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["scope:root", "scope:child", "scope:grandchild"]);
    for invalid in ["scope:archived", "scope:deleted", "scope:missing"] {
        let error = call_err(&registry, &db, json!({ "scope_record_id": invalid })).await;
        assert!(
            error.contains("record") && error.contains("does not exist"),
            "{error}"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn missing_or_deleted_records_do_not_leak_global_history_events() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:deleted", "Former name", None, true).await;
    insert_event(
        &db,
        "record:deleted",
        "record.deleted",
        None,
        Some(SELF),
        None,
        None,
    )
    .await;
    insert_event(
        &db,
        "record:missing",
        "record.deleted",
        None,
        Some(SELF),
        None,
        None,
    )
    .await;
    sqlx::query("DELETE FROM records WHERE id = 'record:missing'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let result = call(&registry, &db, json!({})).await;
    assert_eq!(result["matched_event_count"], 0);
    assert_eq!(result["scanned_event_count"], 0);
    assert_eq!(result["changes"], json!([]));
    assert_eq!(result["has_more"], false);
    db.close().await;
}

#[tokio::test]
async fn next_request_is_normalized_passable_and_does_not_create_server_state() {
    let db = db().await;
    let registry = registry();
    for (record_id, actor) in [
        ("record:self-1", SELF),
        ("record:other", OTHER),
        ("record:self-2", SELF),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": record_id })),
            Some(actor),
            Some(ROOT_RUN),
            None,
        )
        .await;
    }

    let first = call(
        &registry,
        &db,
        json!({
            "limit": 1,
            "actor_scope": "all",
            "accounts": ["account:z", SELF, SELF],
            "for_run": ROOT_RUN,
            "event_families": ["updated", "moved", "updated"]
        }),
    )
    .await;
    // The cursor advances across the actor-filtered gap exactly as the
    // unfiltered window did: seq 2 never enters a raw page, yet the
    // look-ahead parks the cursor on it before the seq 3 continuation.
    assert_eq!(
        first["next_request"],
        json!({
            "after_local_seq": 2,
            "through_local_seq": 3,
            "limit": 1,
            "actor_scope": "all",
            "accounts": [SELF, "account:z"],
            "for_run": ROOT_RUN,
            "include_child_runs": false,
            "event_families": ["moved", "updated"]
        })
    );
    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["after_local_seq"], 2);
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(second["has_more"], false);
    assert_eq!(second["next_request"], Value::Null);

    // Re-running a different filter from the same explicit cursor is a fresh
    // traversal: no hidden server watermark was advanced by the calls above.
    let other = call(
        &registry,
        &db,
        json!({ "after_local_seq": 0, "accounts": [OTHER] }),
    )
    .await;
    assert_eq!(other["matched_event_count"], 0);
    assert_eq!(other["changes"], json!([]));
    db.close().await;
}

#[tokio::test]
async fn page_boundaries_can_repeat_a_group_without_inventing_a_group_cursor() {
    let db = db().await;
    let registry = registry();
    for field in ["one", "two", "three"] {
        insert_event(
            &db,
            "record:repeat",
            "record.updated",
            Some(json!({ "summary": field })),
            Some(SELF),
            Some(ROOT_RUN),
            None,
        )
        .await;
    }
    let first = call(&registry, &db, json!({ "limit": 2 })).await;
    assert_eq!(first["changes"].as_array().unwrap().len(), 1);
    assert_eq!(first["changes"][0]["event_count"], 2);
    assert_eq!(first["next_after_local_seq"], 2);
    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["changes"].as_array().unwrap().len(), 1);
    assert_eq!(second["changes"][0]["record_id"], "record:repeat");
    assert_eq!(second["changes"][0]["first_local_seq"], 3);
    assert_eq!(second["changes"][0]["event_count"], 1);
    db.close().await;
}

#[tokio::test]
async fn raw_window_reader_is_public_query_machinery_not_tool_local_state() {
    let db = db().await;
    for n in 1..=3 {
        insert_event(
            &db,
            &format!("record:{n}"),
            "record.updated",
            Some(json!({ "summary": n })),
            Some(SELF),
            None,
            None,
        )
        .await;
    }
    let page = native_ce::query::events::change_window(&db, 0, None, 2)
        .await
        .unwrap();
    assert_eq!(page.high_water_seq, 3);
    assert_eq!(page.scanned_through_seq, 2);
    assert_eq!(
        page.events
            .iter()
            .map(|event| event.local_seq)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(page.has_more);

    let next = native_ce::query::events::change_window(
        &db,
        page.scanned_through_seq,
        Some(page.high_water_seq),
        2,
    )
    .await
    .unwrap();
    assert_eq!(next.events[0].local_seq, 3);
    assert_eq!(next.scanned_through_seq, 3);
    assert!(!next.has_more);

    let max: i64 = sqlx::query("SELECT MAX(seq) AS seq FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("seq");
    assert_eq!(max, 3);
    db.close().await;
}

#[tokio::test]
async fn newest_first_returns_the_most_recent_visible_events_and_pages_back_through_the_pin() {
    let db = db().await;
    let registry = registry();
    let alice = "account:alice";
    let bea = "account:bea";
    insert_private_record(&db, "record:alice", "Alice private", alice).await;
    insert_private_record(&db, "record:bea", "Bea private", bea).await;
    for (record_id, actor, summary) in [
        ("record:bea", bea, "bea one"),
        ("record:alice", alice, "alice one"),
        ("record:bea", bea, "bea two"),
        ("record:alice", alice, "alice two"),
        ("record:bea", bea, "bea three"),
        ("record:alice", alice, "alice three"),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": summary })),
            Some(actor),
            None,
            None,
        )
        .await;
    }

    let first = call_as(
        &registry,
        &db,
        alice,
        json!({ "limit": 2, "order": "newest_first" }),
    )
    .await;
    assert_eq!(first["high_water_local_seq"], 6);
    // The omitted opening cursor is clamped to just above the pin rather than
    // rejected, and the caller is told the position it actually got.
    assert_eq!(first["after_local_seq"], 7);
    assert_eq!(first["scanned_through_local_seq"], 3);
    assert_eq!(first["scanned_event_count"], 2);
    assert_eq!(first["matched_event_count"], 2);
    assert_eq!(first["changes"][0]["first_local_seq"], 4);
    assert_eq!(first["changes"][0]["last_local_seq"], 6);
    assert_eq!(first["changes"][0]["event_count"], 2);
    assert_eq!(first["changes"][1], Value::Null);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["next_request"]["after_local_seq"], 3);
    assert_eq!(first["next_request"]["through_local_seq"], 6);
    assert_eq!(first["next_request"]["order"], "newest_first");

    let second = call_as(&registry, &db, alice, first["next_request"].clone()).await;
    assert_eq!(second["after_local_seq"], 3);
    assert_eq!(second["high_water_local_seq"], 6);
    // Descending exhaustion lands the traversal cursor at the bottom of the log.
    assert_eq!(second["scanned_through_local_seq"], 0);
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(second["changes"][0]["first_local_seq"], 2);
    assert_eq!(second["changes"][0]["last_local_seq"], 2);
    assert_eq!(second["has_more"], false);
    assert_eq!(second["next_request"], Value::Null);

    // Descending pages do not overlap and leave no visible event behind: page
    // one covers Alice's seq 4 and 6, page two the remaining seq 2.
    assert_eq!(seqs(&first), vec![4, 5, 6]);
    assert_eq!(seqs(&second), vec![2]);
    db.close().await;
}

#[tokio::test]
async fn newest_first_sorts_groups_by_their_most_recent_event() {
    let db = db().await;
    let registry = registry();
    for (record_id, summary) in [
        ("record:early-late", "early"),
        ("record:early-late", "early again"),
        ("record:middle", "middle"),
        ("record:middle", "middle again"),
        ("record:early-late", "late"),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": summary })),
            Some(SELF),
            None,
            None,
        )
        .await;
    }

    let newest = call(&registry, &db, json!({ "order": "newest_first" })).await;
    // Sorting on first_local_seq descending would bury the record touched just now
    // behind the one whose only activity is older.
    assert_eq!(newest["changes"][0]["record_id"], "record:early-late");
    assert_eq!(newest["changes"][0]["last_local_seq"], 5);
    assert_eq!(newest["changes"][1]["record_id"], "record:middle");
    assert_eq!(newest["changes"][1]["last_local_seq"], 4);

    let oldest = call(&registry, &db, json!({})).await;
    assert_eq!(oldest["changes"][0]["record_id"], "record:early-late");
    assert_eq!(oldest["changes"][0]["first_local_seq"], 1);
    assert_eq!(oldest["changes"][1]["record_id"], "record:middle");
    assert_eq!(oldest["changes"][1]["first_local_seq"], 3);
    db.close().await;
}

#[tokio::test]
async fn newest_first_group_extents_stay_oldest_to_newest() {
    let db = db().await;
    let registry = registry();
    for summary in ["one", "two", "three"] {
        insert_event(
            &db,
            "record:span",
            "record.updated",
            Some(json!({ "summary": summary })),
            Some(SELF),
            Some(ROOT_RUN),
            None,
        )
        .await;
    }

    let result = call(&registry, &db, json!({ "order": "newest_first" })).await;
    let group = &result["changes"][0];
    assert_eq!(group["event_count"], 3);
    assert_eq!(group["first_local_seq"], 1);
    assert_eq!(group["last_local_seq"], 3);
    // Coalescing must not read arrival order as sequence order: descending
    // traversal reaches a group's oldest event last.
    assert!(group["first_local_seq"].as_i64().unwrap() < group["last_local_seq"].as_i64().unwrap());
    assert!(group["first_event_at"].as_str().unwrap() <= group["last_event_at"].as_str().unwrap());
    db.close().await;
}

/// Every declared content event type must summarize, not fail the page.
///
/// `event_families` used to enumerate the types it knew and return an error for
/// the rest. `EVENT_TYPES` grows independently of it and grew past it: one
/// `message.send_evaluated.v1` in the scanned window failed the whole call, and
/// Home's bands went dark in production against durable data. This walks the
/// declared list so the next type added cannot reintroduce that.
#[tokio::test]
async fn every_declared_content_event_type_is_summarized_rather_than_fatal() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:types", "Every declared type", None, false).await;
    for event_type in native_ce::events::EVENT_TYPES {
        // Two types carry a payload the read path genuinely requires, and both
        // are modelled rather than unknown: `facet.*` carries the key reported
        // as a changed field, and `receipt.committed.v1` is rewritten into a
        // body-only `record.updated` before any caller sees it. An absent
        // payload on either is a real integrity failure and stays fatal; that
        // is a different thing from failing on a type nobody taught this
        // aggregate about, which is what this test is here to prevent.
        let payload = match event_type {
            "facet.set" | "facet.unset" => Some(json!({ "key": "priority", "value": "high" })),
            "receipt.committed.v1" => Some(json!({ "body": "committed" })),
            _ => None,
        };
        insert_event(
            &db,
            "record:types",
            event_type,
            payload,
            Some(SELF),
            Some(ROOT_RUN),
            None,
        )
        .await;
    }

    // Four declared types do not reach a caller, each for a stated reason
    // rather than for want of an arm in `event_families`. Being deliberately
    // invisible is a different outcome from failing the page, so they are named
    // here rather than allowed to make the count vague.
    let withheld: BTreeSet<&str> = [
        // Aggregate bookkeeping, filtered out of public history entirely.
        "reconciliation.recorded.v1",
        "unit.superseded.v1",
        "receipt.dependency_audited.v1",
        // Visible only when its payload names an artefact revision the caller
        // may view, which the bare row inserted above does not.
        "occurrence.bound.v1",
    ]
    .into_iter()
    .collect();

    let result = call(&registry, &db, json!({ "limit": 1000 })).await;
    assert_eq!(
        result["matched_event_count"].as_u64().unwrap() as usize,
        native_ce::events::EVENT_TYPES.len() - withheld.len()
    );
    let change = &result["changes"][0];
    // Every type that does reach a caller is reported under its own name,
    // except the one the read path deliberately renames: `receipt.committed.v1`
    // arrives as `record.updated`, which is already in the set.
    assert_eq!(
        strings(&change["event_types"]),
        native_ce::events::EVENT_TYPES
            .iter()
            .filter(|value| !withheld.contains(*value) && **value != "receipt.committed.v1")
            .map(|value| (*value).to_string())
            .collect()
    );
    // An unmodelled type reports `updated` — something happened here — so the
    // family set stays non-empty and the exact type is still readable above.
    assert!(strings(&change["event_families"]).contains("updated"));
    db.close().await;
}

/// The exact production failure: a message event in the window returned
/// `400 whats_changed encountered unknown content event type
/// 'message.send_evaluated.v1'`, which emptied both Home bands on every load.
#[tokio::test]
async fn a_message_event_in_the_window_does_not_fail_the_page() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:note", "A note", None, false).await;
    insert_event(
        &db,
        "record:note",
        "record.updated",
        Some(json!({ "summary": "edited" })),
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;
    insert_event(
        &db,
        "record:note",
        "message.send_evaluated.v1",
        None,
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;

    // On its own record, so its group holds nothing but the unmodelled type.
    // Grouped with an ordinary edit, `updated` would be supplied by the edit
    // and the assertion below would pass however the message event was
    // classified — including as nothing at all, which would drop the group from
    // any `event_families` filter and blank the band a second way.
    insert_record(&db, "record:message", "A message", None, false).await;
    insert_event(
        &db,
        "record:message",
        "message.send_evaluated.v1",
        None,
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;

    let result = call(&registry, &db, json!({ "order": "newest_first" })).await;
    assert_eq!(result["matched_event_count"], 3);
    let alone = &result["changes"][0];
    assert_eq!(alone["record_id"], "record:message");
    assert_eq!(alone["event_count"], 1);
    assert_eq!(alone["event_types"], json!(["message.send_evaluated.v1"]));
    assert_eq!(alone["event_families"], json!(["updated"]));

    let note = &result["changes"][1];
    assert_eq!(note["record_id"], "record:note");
    assert_eq!(note["event_count"], 2);
    assert_eq!(
        strings(&note["event_types"]),
        ["message.send_evaluated.v1", "record.updated"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(note["event_families"], json!(["updated"]));

    // The family is what makes the group survive a filter, so assert it the way
    // a caller would actually feel it.
    let filtered = call(
        &registry,
        &db,
        json!({ "order": "newest_first", "event_families": ["updated"] }),
    )
    .await;
    assert_eq!(filtered["changes"][0]["record_id"], "record:message");
    db.close().await;
}

/// The reorder must not change answers: every actor/run/family pre-filter is
/// a superset of its post-redaction check, so each filtered query agrees with
/// the manual intersection of the unfiltered page, in both directions.
#[tokio::test]
async fn prefilters_agree_with_the_unfiltered_intersection_in_both_orders() {
    for order in ["oldest_first", "newest_first"] {
        let db = db().await;
        let registry = registry();
        for (record_id, actor, run_key, event_type, payload) in [
            (
                "record:a",
                Some(SELF),
                Some(ROOT_RUN),
                "record.updated",
                json!({ "summary": "a" }),
            ),
            (
                "record:b",
                Some(OTHER),
                Some(ROOT_RUN),
                "record.updated",
                json!({ "summary": "b" }),
            ),
            (
                "record:c",
                Some(SELF),
                Some(CHILD_RUN),
                "facet.set",
                json!({ "key": "priority", "value": "high" }),
            ),
            (
                "record:d",
                None,
                None,
                "record.updated",
                json!({ "home_id": "record:a", "summary": "moved" }),
            ),
        ] {
            insert_event(
                &db,
                record_id,
                event_type,
                Some(payload),
                actor,
                run_key,
                None,
            )
            .await;
        }
        let order_arg = || {
            if order == "newest_first" {
                json!({ "order": "newest_first", "limit": 1000 })
            } else {
                json!({ "limit": 1000 })
            }
        };
        let base = order_arg().as_object().unwrap().clone();

        let all = call(&registry, &db, Value::Object(base.clone())).await;
        assert_eq!(all["matched_event_count"], 4);

        let with_filter = |filter: Value| {
            let mut arguments = base.clone();
            for (key, value) in filter.as_object().unwrap() {
                arguments.insert(key.clone(), value.clone());
            }
            let registry = &registry;
            let db = &db;
            async move { call(registry, db, Value::Object(arguments)).await }
        };
        let others = with_filter(json!({ "actor_scope": "others" })).await;
        assert_eq!(others["matched_event_count"], 2);
        let accounts = with_filter(json!({ "accounts": [SELF] })).await;
        assert_eq!(accounts["matched_event_count"], 2);
        let run = with_filter(json!({ "for_run": ROOT_RUN })).await;
        // The other-authored event passes the raw run pre-filter but is still
        // dropped: its undisclosable author takes the run key with it during
        // redaction, before the post-redaction run check.
        assert_eq!(run["matched_event_count"], 1);
        assert_eq!(run["changes"][0]["record_id"], "record:a");
        let facets = with_filter(json!({ "event_families": ["facets"] })).await;
        assert_eq!(facets["matched_event_count"], 1);
        assert_eq!(facets["changes"][0]["record_id"], "record:c");
        let moved = with_filter(json!({ "event_families": ["moved"] })).await;
        assert_eq!(moved["matched_event_count"], 1);
        assert_eq!(moved["changes"][0]["record_id"], "record:d");
        let composed =
            with_filter(json!({ "actor_scope": "self", "event_families": ["updated"] })).await;
        assert_eq!(composed["matched_event_count"], 1);
        assert_eq!(composed["changes"][0]["record_id"], "record:a");
        db.close().await;
    }
}

/// The motivating sparse case: an `others` newest-first read over a
/// predominantly single-author log returns only the minority events and pages
/// back through the pin without gaps or duplicates.
#[tokio::test]
async fn sparse_others_pages_newest_first_through_a_single_author_log() {
    let db = db().await;
    let registry = registry();
    for n in 1..=10 {
        let actor = if n == 3 || n == 8 { OTHER } else { SELF };
        insert_event(
            &db,
            &format!("record:{n}"),
            "record.updated",
            Some(json!({ "summary": n })),
            Some(actor),
            None,
            None,
        )
        .await;
    }

    let first = call(
        &registry,
        &db,
        json!({ "order": "newest_first", "actor_scope": "others", "limit": 1 }),
    )
    .await;
    assert_eq!(first["high_water_local_seq"], 10);
    assert_eq!(first["after_local_seq"], 11);
    assert_eq!(first["matched_event_count"], 1);
    assert_eq!(first["changes"][0]["last_local_seq"], 8);
    // The minority author is undisclosable, so attribution stays nulled even
    // though the event itself is visible on its viewable record.
    assert_eq!(first["changes"][0]["actor"], Value::Null);
    assert_eq!(first["has_more"], true);
    // Descending gap proof: seqs 7..4 never enter a raw page, yet the
    // look-ahead parks the cursor on seq 4 — where the unfiltered window
    // scanned through — before the seq 3 continuation.
    assert_eq!(first["next_after_local_seq"], 4);
    assert_eq!(first["next_request"]["after_local_seq"], 4);

    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["after_local_seq"], 4);
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(second["changes"][0]["last_local_seq"], 3);
    assert_eq!(second["has_more"], false);
    assert_eq!(second["next_request"], Value::Null);
    assert_eq!(second["scanned_through_local_seq"], 0);
    db.close().await;
}

/// Pre-filtering on the raw run key is a narrowing step, not the decision:
/// redaction still nulls the run key of a hidden actor, so an event whose
/// author the caller may not see never matches a run or account filter.
#[tokio::test]
async fn hidden_actor_events_do_not_match_run_or_account_prefilters() {
    let db = db().await;
    let registry = registry();
    insert_event(
        &db,
        "record:hidden-run",
        "record.updated",
        Some(json!({ "summary": "hidden author" })),
        Some(OTHER),
        Some(ROOT_RUN),
        None,
    )
    .await;
    insert_event(
        &db,
        "record:visible-run",
        "record.updated",
        Some(json!({ "summary": "visible author" })),
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;

    let run = call(&registry, &db, json!({ "for_run": ROOT_RUN })).await;
    assert_eq!(run["matched_event_count"], 1);
    assert_eq!(run["changes"][0]["record_id"], "record:visible-run");

    let accounts = call(&registry, &db, json!({ "accounts": [OTHER] })).await;
    assert_eq!(accounts["matched_event_count"], 0);
    assert_eq!(accounts["changes"], json!([]));
    assert_eq!(accounts["has_more"], false);
    db.close().await;
}

/// The tolerant default must survive the pre-authorization family gate: an
/// unmodelled type still reports `updated`, still matches that filter, and a
/// filter it cannot match still exhausts the window cleanly.
#[tokio::test]
async fn unknown_event_types_survive_the_family_prefilter() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "record:odd", "Odd", None, false).await;
    insert_event(
        &db,
        "record:odd",
        "record.updated",
        Some(json!({ "summary": "ordinary" })),
        Some(SELF),
        None,
        None,
    )
    .await;
    insert_event(
        &db,
        "record:odd",
        "future.hologram.projected.v9",
        Some(json!({ "brightness": 11 })),
        Some(SELF),
        None,
        None,
    )
    .await;

    let unfiltered = call(&registry, &db, json!({})).await;
    assert_eq!(unfiltered["matched_event_count"], 2);
    assert_eq!(
        unfiltered["changes"][0]["event_families"],
        json!(["updated"])
    );
    let updated = call(&registry, &db, json!({ "event_families": ["updated"] })).await;
    assert_eq!(updated["matched_event_count"], 2);
    let created = call(&registry, &db, json!({ "event_families": ["created"] })).await;
    assert_eq!(created["matched_event_count"], 0);
    assert_eq!(created["changes"], json!([]));
    assert_eq!(created["has_more"], false);
    assert_eq!(created["next_request"], Value::Null);
    assert_eq!(created["scanned_through_local_seq"], 2);
    db.close().await;
}

/// An unauthorized row carrying a malformed stored payload is rejected by
/// authorization before anything parses it: the cheap pre-authorization
/// classifier reads the row as null and never errors, and the identity
/// reconstruction (which runs post-authorization and can fail SQLite JSON on
/// corrupt history, exactly as before this change) is never reached for the
/// denied row. The authorized valid control alongside it proves the call
/// itself stays healthy.
///
/// No claim is made here about authorized malformed rows: historically those
/// reached `event_time_identity` before redaction and could fail the call,
/// and this change deliberately preserves that behavior precisely.
#[tokio::test]
async fn unauthorized_malformed_rows_are_rejected_before_parsing() {
    let db = db().await;
    let registry = registry();
    let alice = "account:alice";
    let bea = "account:bea";
    insert_record(&db, "record:control", "Control", None, false).await;
    insert_event(
        &db,
        "record:control",
        "record.updated",
        Some(json!({ "summary": "control" })),
        Some(alice),
        None,
        None,
    )
    .await;
    insert_private_record(&db, "record:hidden-garbage", "Hidden garbage", bea).await;
    insert_raw_event(
        &db,
        "record:hidden-garbage",
        "record.updated",
        Some("{not json"),
        Some(bea),
        None,
    )
    .await;

    let unfiltered = call_as(&registry, &db, alice, json!({})).await;
    assert_eq!(unfiltered["matched_event_count"], 1);
    assert_eq!(unfiltered["changes"][0]["record_id"], "record:control");

    // Family gates run the same path: the corrupt row is denied, never
    // parsed, under both a matching and a rejecting filter.
    let updated = call_as(
        &registry,
        &db,
        alice,
        json!({ "event_families": ["updated"] }),
    )
    .await;
    assert_eq!(updated["matched_event_count"], 1);
    let created = call_as(
        &registry,
        &db,
        alice,
        json!({ "event_families": ["created"] }),
    )
    .await;
    assert_eq!(created["matched_event_count"], 0);
    assert_eq!(created["changes"], json!([]));
    assert_eq!(created["has_more"], false);
    assert_eq!(created["next_request"], Value::Null);
    assert_eq!(created["scanned_through_local_seq"], 2);
    db.close().await;
}

/// More than `MAX` distinct accounts cannot become SQL `IN` placeholders:
/// the call is rejected before any traversal starts. Exactly the cap is
/// still accepted.
#[tokio::test]
async fn oversized_account_lists_are_rejected_before_the_traversal() {
    let db = db().await;
    let registry = registry();
    insert_event(
        &db,
        "record:one",
        "record.updated",
        Some(json!({ "summary": "one" })),
        Some(SELF),
        None,
        None,
    )
    .await;

    let too_many: Vec<Value> = (0..1001)
        .map(|n| Value::String(format!("account:{n:04}")))
        .collect();
    let error = call_err(&registry, &db, json!({ "accounts": too_many })).await;
    assert!(
        error.contains("accounts must not exceed 1000 values"),
        "{error}"
    );

    let exactly_capped: Vec<Value> = (0..1000)
        .map(|n| Value::String(format!("account:{n:04}")))
        .collect();
    let result = call(&registry, &db, json!({ "accounts": exactly_capped })).await;
    assert_eq!(result["matched_event_count"], 0);
    assert_eq!(result["has_more"], false);
    db.close().await;
}

/// The `impacts` family stays behind authorization: an impact row the caller
/// may not view never matches the filter and never leaks its record, and a
/// corrupt payload on such a row is rejected silently rather than failing
/// the call — proving identity reconstruction never runs pre-auth.
#[tokio::test]
async fn impacts_filter_neither_leaks_nor_fails_on_unauthorized_rows() {
    let db = db().await;
    let registry = registry();
    let alice = "account:alice";
    let bea = "account:bea";

    insert_record(&db, "record:visible-impact", "Visible impact", None, false).await;
    insert_event(
        &db,
        "record:visible-impact",
        "record.created",
        Some(json!({ "type": "Outcome", "kind": "impact", "name": "Visible impact" })),
        Some(alice),
        None,
        None,
    )
    .await;
    insert_private_record(&db, "record:hidden-impact", "Hidden impact", bea).await;
    insert_event(
        &db,
        "record:hidden-impact",
        "record.created",
        Some(json!({ "type": "Outcome", "kind": "impact", "name": "Hidden impact" })),
        Some(bea),
        None,
        None,
    )
    .await;
    // Unauthorized and corrupt: rejected by authorization, never by parsing.
    insert_raw_event(
        &db,
        "record:hidden-impact",
        "record.updated",
        Some("{not json"),
        Some(bea),
        None,
    )
    .await;

    let impacts = call_as(
        &registry,
        &db,
        alice,
        json!({ "event_families": ["impacts"] }),
    )
    .await;
    assert_eq!(impacts["matched_event_count"], 1);
    assert_eq!(impacts["changes"][0]["record_id"], "record:visible-impact");
    assert_eq!(
        impacts["changes"][0]["event_families"],
        json!(["created", "impacts"])
    );

    // The newest-first direction reconstructs the same event-time identity:
    // later kind changes cannot rewrite historical family membership, and
    // hidden rows stay hidden either way.
    let newest = call_as(
        &registry,
        &db,
        alice,
        json!({ "event_families": ["impacts"], "order": "newest_first" }),
    )
    .await;
    assert_eq!(newest["matched_event_count"], 1);
    assert_eq!(newest["changes"][0]["record_id"], "record:visible-impact");

    let unfiltered = call_as(&registry, &db, alice, json!({})).await;
    assert_eq!(unfiltered["matched_event_count"], 1);
    db.close().await;
}

/// A family filter composes with the caller-visible look-ahead: the page
/// fills past rejected rows and `has_more` still means another matching
/// event, not another raw row.
#[tokio::test]
async fn family_filter_pages_through_rejected_rows_with_limit_lookahead() {
    let db = db().await;
    let registry = registry();
    for (record_id, event_type, payload) in [
        (
            "record:plain",
            "record.updated",
            json!({ "summary": "rejected by the filter" }),
        ),
        (
            "record:first",
            "facet.set",
            json!({ "key": "priority", "value": "high" }),
        ),
        (
            "record:second",
            "facet.set",
            json!({ "key": "status", "value": "open" }),
        ),
    ] {
        insert_event(
            &db,
            record_id,
            event_type,
            Some(payload),
            Some(SELF),
            None,
            None,
        )
        .await;
    }

    let first = call(
        &registry,
        &db,
        json!({ "limit": 1, "event_families": ["facets"] }),
    )
    .await;
    assert_eq!(first["matched_event_count"], 1);
    assert_eq!(first["changes"][0]["record_id"], "record:first");
    assert_eq!(first["has_more"], true);
    assert_eq!(first["next_request"]["after_local_seq"], 2);

    let second = call(&registry, &db, first["next_request"].clone()).await;
    assert_eq!(second["matched_event_count"], 1);
    assert_eq!(second["changes"][0]["record_id"], "record:second");
    assert_eq!(second["has_more"], false);
    assert_eq!(second["next_request"], Value::Null);
    db.close().await;
}

/// Claim attribution travels with disclosure: an event carrying claim
/// metadata loses its run key unless the caller is the claim holder, so a
/// run pre-filter drops it while an ordinary event under the same run stays.
#[tokio::test]
async fn claim_events_lose_their_run_without_holder_visibility() {
    let db = db().await;
    let registry = registry();
    insert_event(
        &db,
        "record:ordinary",
        "record.updated",
        Some(json!({ "summary": "ordinary" })),
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;
    insert_event(
        &db,
        "record:claimed",
        "record.updated",
        Some(json!({
            "summary": "claimed",
            "claimed_by_account": SELF,
            "claimed_run_key": ROOT_RUN,
        })),
        Some(SELF),
        Some(ROOT_RUN),
        None,
    )
    .await;

    // Tool callers carry no run key, so nobody here is the claim holder and
    // the claimed event's run is nulled before the run check.
    let run = call(&registry, &db, json!({ "for_run": ROOT_RUN })).await;
    assert_eq!(run["matched_event_count"], 1);
    assert_eq!(run["changes"][0]["record_id"], "record:ordinary");

    let all = call(&registry, &db, json!({})).await;
    assert_eq!(all["matched_event_count"], 2);
    db.close().await;
}

/// Subtree scope composes with the actor pre-filters: scope narrows records,
/// actor filters narrow attribution, and both apply in one traversal.
#[tokio::test]
async fn scope_and_actor_prefilters_compose() {
    let db = db().await;
    let registry = registry();
    insert_record(&db, "scope:root", "Root", None, false).await;
    insert_record(&db, "scope:child", "Child", Some("scope:root"), false).await;
    insert_record(&db, "scope:outside", "Outside", None, false).await;
    for (record_id, actor) in [
        ("scope:child", SELF),
        ("scope:child", OTHER),
        ("scope:outside", OTHER),
    ] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": record_id })),
            Some(actor),
            None,
            None,
        )
        .await;
    }

    let scoped_others = call(
        &registry,
        &db,
        json!({ "scope_record_id": "scope:root", "actor_scope": "others" }),
    )
    .await;
    assert_eq!(scoped_others["matched_event_count"], 1);
    assert_eq!(scoped_others["changes"][0]["record_id"], "scope:child");

    let scoped_accounts = call(
        &registry,
        &db,
        json!({ "scope_record_id": "scope:root", "accounts": [OTHER] }),
    )
    .await;
    // The other author is undisclosable, so the account filter matches
    // nothing even inside the scope that contains the row.
    assert_eq!(scoped_accounts["matched_event_count"], 0);
    assert_eq!(scoped_accounts["has_more"], false);
    db.close().await;
}

/// An unsatisfiable actor conjunction matches nothing in one window round
/// trip: no page occupancy, no continuation, cursor parked at the far end.
#[tokio::test]
async fn unsatisfiable_actor_conjunctions_match_nothing() {
    let db = db().await;
    let registry = registry();
    for (record_id, actor) in [("record:self", SELF), ("record:other", OTHER)] {
        insert_event(
            &db,
            record_id,
            "record.updated",
            Some(json!({ "summary": record_id })),
            Some(actor),
            None,
            None,
        )
        .await;
    }

    for arguments in [
        json!({ "actor_scope": "self", "accounts": [OTHER] }),
        json!({ "actor_scope": "others", "accounts": [SELF] }),
    ] {
        let result = call(&registry, &db, arguments).await;
        assert_eq!(result["matched_event_count"], 0);
        assert_eq!(result["changes"], json!([]));
        assert_eq!(result["has_more"], false);
        assert_eq!(result["next_request"], Value::Null);
        assert_eq!(result["scanned_through_local_seq"], 2);
    }
    db.close().await;
}
