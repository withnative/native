//! Regression coverage for task 653f08e's pre-write version affordance.
//!
//! The contract is deliberately exercised through the registry: callers see
//! one record-scoped sequence captured before a direct write, even when the
//! handler appends several authoritative events.

use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::Digest;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

async fn latest_seq(db: &Db, record_id: &str) -> i64 {
    sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn record_at(registry: &ToolRegistry, db: &Db, record_id: &str, seq: Value) -> Value {
    let out = call(
        registry,
        db,
        "get_record",
        json!({ "ids": [record_id], "as_of": { "content_seq": seq } }),
    )
    .await;
    json!({ "record": out["records"][0].clone() })
}

#[tokio::test]
async fn create_returns_null_and_multi_event_update_reconstructs_the_pre_call_state() {
    let db = db().await;
    let registry = registry();

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "name": "Original",
            "body": "before",
            "facets": { "confidence": "tentative" }
        }),
    )
    .await;
    assert_eq!(created["previous_seq"], Value::Null);
    let id = created["id"].as_str().unwrap();
    let before_update = latest_seq(&db, id).await;

    // Raise the global head without touching this record. The echoed cursor is
    // the record's stream head, not the global event head.
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "Unrelated" }),
    )
    .await;

    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "name": "Changed",
            "body": "after",
            "if_body_digest": hex::encode(sha2::Sha256::digest(b"before")),
            "facets": {
                "confidence": "likely",
                "effort": 3
            }
        }),
    )
    .await;
    assert_eq!(updated["previous_seq"], before_update);
    assert_eq!(updated["name"], "Changed");

    let version = record_at(&registry, &db, id, updated["previous_seq"].clone()).await;
    assert_eq!(version["record"]["name"], "Original");
    assert_eq!(version["record"]["body"], "before");
    assert_eq!(version["record"]["facets"][0]["key"], "confidence");
    assert_eq!(version["record"]["facets"][0]["value"], "tentative");

    // The next direct write points to the LAST event from the prior call, not
    // its first event. Replaying there includes the complete atomic batch.
    let after_multi_event_update = latest_seq(&db, id).await;
    let second = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "summary": "one more change" }),
    )
    .await;
    assert_eq!(second["previous_seq"], after_multi_event_update);
    let before_second = record_at(&registry, &db, id, second["previous_seq"].clone()).await;
    assert_eq!(before_second["record"]["name"], "Changed");
    assert_eq!(
        before_second["record"]["facets"].as_array().unwrap().len(),
        2
    );
}

#[tokio::test]
async fn link_archive_restore_and_delete_echo_a_replayable_source_record_cursor() {
    let db = db().await;
    let registry = registry();
    let source = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "name": "Source" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let target = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Outcome", "name": "Target" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let source_created = latest_seq(&db, &source).await;
    let added = call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": source,
            "target_id": target,
            "relationship": "part_of"
        }),
    )
    .await;
    assert_eq!(added["action"], "add");
    assert_eq!(added["format"], "native.manage-links-write.v1");
    assert_eq!(added["status"], "added");
    assert_eq!(added["previous_seq"], source_created);
    assert_eq!(added["write_receipt"]["kind"], "content_event");
    assert_eq!(added["write_receipt"]["event"]["event_type"], "link.added");
    assert_eq!(added["write_receipt"]["event"]["record_id"], source);
    assert_eq!(
        added["write_receipt"]["event"]["seq"],
        latest_seq(&db, &source).await
    );
    assert!(added["write_receipt"]["event"]["event_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(added["write_receipt"]["event"]["created_at"]
        .as_str()
        .is_some_and(|created_at| !created_at.is_empty()));
    let rendered_added = render::render("manage_links", &added).unwrap();
    assert!(
        rendered_added.starts_with("Link add write committed via \"content_event\"."),
        "{rendered_added}"
    );
    for expected in [
        source.as_str(),
        target.as_str(),
        "part_of",
        "link.added",
        added["write_receipt"]["event"]["event_id"]
            .as_str()
            .unwrap(),
    ] {
        assert!(
            rendered_added.contains(expected),
            "missing {expected}: {rendered_added}"
        );
    }
    assert!(
        rendered_added.contains(&format!("previous_seq: {source_created}")),
        "{rendered_added}"
    );
    let before_add = record_at(&registry, &db, &source, added["previous_seq"].clone()).await;
    assert!(before_add["record"]["links_out"]
        .as_array()
        .unwrap()
        .is_empty());

    let link_added_seq = latest_seq(&db, &source).await;
    let removed = call(
        &registry,
        &db,
        "manage_links",
        json!({
            "action": "remove",
            "source_id": source,
            "target_id": target,
            "relationship": "part_of"
        }),
    )
    .await;
    assert_eq!(removed["action"], "remove");
    assert_eq!(removed["format"], "native.manage-links-write.v1");
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["previous_seq"], link_added_seq);
    assert_eq!(removed["write_receipt"]["kind"], "content_event");
    assert_eq!(
        removed["write_receipt"]["event"]["event_type"],
        "link.removed"
    );
    assert_eq!(removed["write_receipt"]["event"]["record_id"], source);
    assert_eq!(
        removed["write_receipt"]["event"]["seq"],
        latest_seq(&db, &source).await
    );
    assert!(removed["write_receipt"]["event"]["event_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert!(removed["write_receipt"]["event"]["created_at"]
        .as_str()
        .is_some_and(|created_at| !created_at.is_empty()));
    let rendered_removed = render::render("manage_links", &removed).unwrap();
    assert!(
        rendered_removed.starts_with("Link remove write committed via \"content_event\"."),
        "{rendered_removed}"
    );
    for expected in [
        source.as_str(),
        target.as_str(),
        "part_of",
        "link.removed",
        removed["write_receipt"]["event"]["event_id"]
            .as_str()
            .unwrap(),
    ] {
        assert!(
            rendered_removed.contains(expected),
            "missing {expected}: {rendered_removed}"
        );
    }
    assert!(
        rendered_removed.contains(&format!("previous_seq: {link_added_seq}")),
        "{rendered_removed}"
    );
    let before_remove = record_at(&registry, &db, &source, removed["previous_seq"].clone()).await;
    assert_eq!(
        before_remove["record"]["links_out"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let before_archive_seq = latest_seq(&db, &source).await;
    let archived = call(&registry, &db, "archive_record", json!({ "id": source })).await;
    assert_eq!(archived["previous_seq"], before_archive_seq);
    let before_archive = record_at(&registry, &db, &source, archived["previous_seq"].clone()).await;
    assert_eq!(before_archive["record"]["archived"], false);

    let archive_seq = latest_seq(&db, &source).await;
    let restored = call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": source, "archived": false }),
    )
    .await;
    assert_eq!(restored["previous_seq"], archive_seq);
    let before_restore = record_at(&registry, &db, &source, restored["previous_seq"].clone()).await;
    assert_eq!(before_restore["record"]["archived"], true);

    // Idempotent archive/restore calls are still direct-write tool responses;
    // they echo the current pre-call cursor even though no event is appended.
    let restore_seq = latest_seq(&db, &source).await;
    let restore_noop = call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": source, "archived": false }),
    )
    .await;
    assert_eq!(restore_noop["changed"], false);
    assert_eq!(restore_noop["previous_seq"], restore_seq);

    let deleted = call(&registry, &db, "delete_record", json!({ "id": source })).await;
    assert_eq!(deleted["previous_seq"], restore_seq);
    let before_delete = record_at(&registry, &db, &source, deleted["previous_seq"].clone()).await;
    assert_eq!(before_delete["record"]["deleted_at"], Value::Null);
}

#[test]
fn tool_descriptions_explain_the_two_call_recovery_pattern_and_limits() {
    let registry = registry();
    let description = |name: &str| {
        registry
            .specs()
            .find(|spec| spec.name == name)
            .unwrap()
            .description
            .clone()
    };

    let update = description("update_record");
    for phrase in [
        "non-destructive",
        "do not create a v2 copy",
        "previous_seq",
        "get_record",
        "record fields only",
        "not atomic",
    ] {
        assert!(update.contains(phrase), "missing '{phrase}' in: {update}");
    }
    for tool in ["delete_record", "archive_record", "manage_links"] {
        let description = description(tool);
        assert!(
            description.contains("previous_seq"),
            "{tool}: {description}"
        );
        assert!(description.contains("as_of"), "{tool}: {description}");
    }
}

#[test]
fn default_text_renderings_preserve_the_pre_write_handle() {
    for (tool, value) in [
        (
            "create_record",
            json!({ "id": "new", "type": "WorkItem", "previous_seq": null }),
        ),
        (
            "update_record",
            json!({ "id": "changed", "type": "WorkItem", "previous_seq": 41 }),
        ),
        (
            "delete_record",
            json!({ "id": "gone", "deleted": true, "previous_seq": 42 }),
        ),
        (
            "archive_record",
            json!({ "id": "hidden", "archived": true, "changed": true, "previous_seq": 43 }),
        ),
        (
            "manage_links",
            json!({
                "action": "add",
                "format": "native.manage-links-write.v1",
                "status": "added",
                "source_id": "source",
                "target_id": "target",
                "relationship": "renders",
                "previous_seq": 44,
                "write_receipt": {
                    "kind": "content_event",
                    "event": {
                        "seq": 45,
                        "event_id": "event",
                        "record_id": "source",
                        "event_type": "link.added",
                        "created_at": "2026-08-29T00:00:00.000Z"
                    }
                }
            }),
        ),
    ] {
        let rendered = native_ce::mcp::render::render(tool, &value).unwrap();
        assert!(rendered.contains("previous_seq:"), "{tool}: {rendered}");
        if tool != "create_record" {
            assert!(rendered.contains("as_of"), "{tool}: {rendered}");
        }
    }
}
