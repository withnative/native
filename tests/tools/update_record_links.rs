//! `update_record` links: the create_record-compatible add-only `links[]`
//! array applied atomically with the record edit in one write transaction.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::Db;
use serde_json::{json, Value};

async fn db() -> Db {
    // create_database installs the meta tier (lifecycle axes included);
    // seed_vocabularies tops up the value sets idempotently.
    let db = native_ce::create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    let result = registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    result
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string();
    db.drain_captures_for_tests().await;
    error
}

async fn create(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn body_of(registry: &ToolRegistry, db: &Db, id: &str) -> Option<String> {
    let record = call(registry, db, "get_record", json!({ "ids": [id] })).await;
    record["records"][0]["body"].as_str().map(str::to_owned)
}

async fn digest_of(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    let record = call(registry, db, "get_record", json!({ "ids": [id] })).await;
    record["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn links_out(registry: &ToolRegistry, db: &Db, id: &str) -> Vec<Value> {
    let listed = call(
        registry,
        db,
        "manage_links",
        json!({ "action": "list", "record_id": id }),
    )
    .await;
    listed["links_out"].as_array().unwrap().clone()
}

#[tokio::test]
async fn body_edit_and_link_commit_in_one_call() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore", "body": "before" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let digest = digest_of(&registry, &db, &source).await;
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source,
            "body_set": "after",
            "if_body_digest": digest,
            "links": [{ "target_id": target, "relationship": "depends_on", "note": "needs it" }],
        }),
    )
    .await;
    assert!(updated.get("previous_seq").is_some(), "{updated}");
    assert_eq!(
        body_of(&registry, &db, &source).await.as_deref(),
        Some("after")
    );
    let out = links_out(&registry, &db, &source).await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0]["target_id"], target);
    assert_eq!(out[0]["relationship"], "depends_on");
    assert_eq!(out[0]["note"], "needs it");
    db.close().await;
}

#[tokio::test]
async fn bad_link_target_writes_neither_edit_nor_link() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore", "body": "before" }),
    )
    .await;
    let digest = digest_of(&registry, &db, &source).await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source,
            "body_set": "after",
            "if_body_digest": digest,
            "links": [{ "target_id": "00000000-0000-4000-8000-000000000000", "relationship": "depends_on" }],
        }),
    )
    .await;
    assert!(err.contains("does not exist"), "{err}");
    assert_eq!(
        body_of(&registry, &db, &source).await.as_deref(),
        Some("before")
    );
    assert!(links_out(&registry, &db, &source).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn links_alone_are_no_changes() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": source, "links": [{ "target_id": target, "relationship": "depends_on" }] }),
    )
    .await;
    assert!(err.contains("no changes"), "{err}");
    db.close().await;
}

#[tokio::test]
async fn reserved_blank_and_addressed_to_links_fail_without_writing() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore", "body": "before" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let digest = digest_of(&registry, &db, &source).await;
    for (link, expected) in [
        (
            json!({ "target_id": target, "relationship": "surface_binding" }),
            "reserved",
        ),
        (
            json!({ "target_id": target, "relationship": "   " }),
            "non-whitespace",
        ),
        (
            json!({ "target_id": target, "relationship": "addressed_to" }),
            "addressed_to",
        ),
    ] {
        let err = call_err(
            &registry,
            &db,
            "update_record",
            json!({ "id": source, "body_set": "after", "if_body_digest": digest, "links": [link] }),
        )
        .await;
        assert!(err.contains(expected), "{err}");
    }
    assert_eq!(
        body_of(&registry, &db, &source).await.as_deref(),
        Some("before")
    );
    assert!(links_out(&registry, &db, &source).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn content_and_relationship_owned_links_share_one_call() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let peer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    // `part_of` is content-owned; `depends_on` routes through the sealed
    // relationship adapter. Both must land in the same call.
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source,
            "summary": "linking edit",
            "links": [
                { "target_id": bearer, "relationship": "part_of" },
                { "target_id": peer, "relationship": "depends_on" },
            ],
        }),
    )
    .await;
    let mut relationships: Vec<String> = links_out(&registry, &db, &source)
        .await
        .iter()
        .map(|link| link["relationship"].as_str().unwrap().to_string())
        .collect();
    relationships.sort();
    assert_eq!(relationships, ["depends_on", "part_of"]);
    db.close().await;
}

#[tokio::test]
async fn comment_bearer_stays_immutable_on_update_links() {
    let db = db().await;
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let other = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let comment = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "comment", "body": "note", "lifecycle": "open",
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
        }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": comment,
            "summary": "reword",
            "links": [{ "target_id": other, "relationship": "part_of" }],
        }),
    )
    .await;
    assert!(err.contains("immutable"), "{err}");
    // The original bearer link survives; the rejected second bearer was
    // never added.
    let out = links_out(&registry, &db, &comment).await;
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0]["target_id"], bearer);
    db.close().await;
}

#[tokio::test]
async fn link_rejection_after_edit_append_rolls_everything_back() {
    // `participates_in` passes update_record's preflight (non-blank,
    // unreserved, viewed target) but the projector admits it only for a
    // Message source with a Conversation target. The record.updated edit is
    // already appended in the same write transaction when link emission
    // fails, so this proves the rollback covers post-append link failures —
    // not just preflight rejections.
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source,
            "summary": "linking edit",
            "links": [{ "target_id": target, "relationship": "participates_in" }],
        }),
    )
    .await;
    assert!(err.contains("participates_in"), "{err}");
    let record = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    assert!(
        record["records"][0]
            .get("summary")
            .is_none_or(Value::is_null),
        "{record}"
    );
    assert!(links_out(&registry, &db, &source).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn denied_link_target_view_leaves_the_edit_unwritten() {
    let db = db().await;
    let registry = registry();
    let editor = create(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Editor" }),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, 'account', 'acct:editor', 1)",
    )
    .bind(&editor)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    let target = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "update-links:test",
        &source,
        vec![AllowEntry::account("acct:editor", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(&db, "update-links:test", &target, vec![])
        .await
        .unwrap();

    let caller = Caller::authenticated("acct:editor")
        .with_hosting_context("host:editor", "db:update-links-test")
        .with_hosting_owner(false);
    let err = registry
        .call(
            db.clone(),
            caller,
            "update_record",
            crate::common::with_test_reason(
                "update_record",
                json!({
                    "id": source,
                    "summary": "must roll back",
                    "links": [{ "target_id": target, "relationship": "depends_on" }],
                }),
            ),
        )
        .await
        .unwrap_err()
        .to_string();
    db.drain_captures_for_tests().await;
    assert!(
        err.contains("does not exist") && err.contains(&target),
        "{err}"
    );
    let record = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    assert!(record["records"][0]
        .get("summary")
        .is_none_or(Value::is_null));
    assert!(links_out(&registry, &db, &source).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn singular_schema_advertises_links_and_batch_rejects_them() {
    let db = db().await;
    let registry = registry();
    let singular = &registry.get("update_record").unwrap().input_schema["oneOf"][0]["allOf"][0];
    let items = &singular["properties"]["links"]["items"];
    assert_eq!(singular["properties"]["links"]["type"], "array");
    assert!(items["required"]
        .as_array()
        .unwrap()
        .contains(&json!("target_id")));
    assert!(items["required"]
        .as_array()
        .unwrap()
        .contains(&json!("relationship")));
    let source = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "chore" }),
    )
    .await;
    // The batch branch keeps its singular-vs-batch separation: `links`
    // belongs to exactly one target, so it is not a batch field.
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "ids": [source], "facets": { "x": "y" }, "links": [] }),
    )
    .await;
    assert!(err.contains("links"), "{err}");
    db.close().await;
}
