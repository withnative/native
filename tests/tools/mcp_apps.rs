use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};

use native_ce::create_database;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use serde_json::json;
use sha2::{Digest, Sha256};

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

#[tokio::test]
async fn version_diff_launcher_composes_historical_head_and_ordered_events() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let created = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Document", "kind": "note", "name": "Versioned", "body": "before", "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();
    let before_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({
                "id": id, "body": "after", "summary": "changed",
                "if_body_digest": hex::encode(Sha256::digest(b"before")),
                "reason": "fixture update"
            }),
        )
        .await
        .unwrap();
    let payload = registry
        .call(
            db.clone(),
            Caller::local(),
            "render_record_version_diff",
            json!({
                "record_id": id, "before_seq": before_seq
            }),
        )
        .await
        .unwrap();
    assert_eq!(payload["view"], "record_version_diff");
    assert_eq!(payload["before"]["record"]["body"], "before");
    assert_eq!(payload["after"]["record"]["body"], "after");
    assert!(payload["after"]["as_of_seq"].as_i64().unwrap() > before_seq);
    assert!(!payload["events"].as_array().unwrap().is_empty());
    assert!(payload["events"]
        .as_array()
        .unwrap()
        .windows(2)
        .all(|pair| pair[0]["seq"].as_i64() < pair[1]["seq"].as_i64()));
    db.close().await;
}

#[tokio::test]
async fn suggestion_review_launcher_is_a_small_bootstrap_not_an_aggregated_reader() {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    let registry = registry();
    let target = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Document", "kind": "note", "name": "Target", "body": "body", "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let target_id = target["id"].as_str().unwrap();
    registry.call(db.clone(), Caller::local(), "create_record", json!({
        "type": "Annotation", "kind": "suggestion", "name": "Suggestion",
        "links": [{ "target_id": target_id, "relationship": "part_of" }],
        "lifecycle": "open", "body": "replacement", "facets": { "proposal.precondition": "none" }, "reason": "fixture"
    })).await.unwrap();
    let payload = registry
        .call(
            db.clone(),
            Caller::local(),
            "render_suggestion_review",
            json!({ "record_id": target_id }),
        )
        .await
        .unwrap();
    assert_eq!(payload["view"], "suggestion_review");
    assert_eq!(payload["target"]["id"], target_id);
    assert_eq!(payload["target"]["body"], "body");
    assert_eq!(
        payload["target"]["body_digest"],
        hex::encode(Sha256::digest(b"body"))
    );
    assert_eq!(payload["target"]["body_is_null"], false);
    assert!(payload["target"]["current_seq"].as_i64().unwrap() > 0);
    assert_eq!(payload["suggestion_count"], 1);
    assert!(
        payload.get("suggestions").is_none(),
        "rows stay on the decided bridge read path"
    );
    db.close().await;
}

#[tokio::test]
async fn suggestion_review_count_deduplicates_candidates_and_excludes_multi_bearer_shapes() {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    let registry = registry();
    let target = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Document", "kind": "note", "name": "Review target",
                "body": "body", "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let target_id = target["id"].as_str().unwrap();
    let extra_bearer = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "WorkItem", "kind": "task", "name": "Extra bearer",
                "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let extra_bearer_id = extra_bearer["id"].as_str().unwrap();
    for bearer in [target_id, extra_bearer_id] {
        replace_explicit_policy(
            &db,
            "test:policy",
            bearer,
            vec![AllowEntry::account("acct:bea", Capability::View)],
        )
        .await
        .unwrap();
    }
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Annotation", "kind": "suggestion", "name": "Valid suggestion",
                "links": [{ "target_id": target_id, "relationship": "part_of" }],
                "lifecycle": "open", "body": "valid replacement",
                "facets": { "proposal.precondition": "none" }, "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let malformed = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Annotation", "kind": "suggestion", "name": "Malformed suggestion",
                "links": [{ "target_id": target_id, "relationship": "part_of" }],
                "lifecycle": "open", "body": "malformed replacement",
                "facets": { "proposal.precondition": "none" }, "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship)
         VALUES ('suggestion-review-extra-bearer', ?, ?, 'part_of')",
    )
    .bind(malformed["id"].as_str().unwrap())
    .bind(extra_bearer_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let payload = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:bea")
                .with_hosting_context("host:bea", "db:test")
                .with_hosting_owner(false),
            "render_suggestion_review",
            json!({ "record_id": target_id }),
        )
        .await
        .unwrap();
    assert_eq!(payload["suggestion_count"], 1);
    db.close().await;
}

#[tokio::test]
async fn suggestion_review_bootstrap_preserves_null_body_semantics() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let target = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "type": "Document", "kind": "note", "name": "Null target", "reason": "fixture"
            }),
        )
        .await
        .unwrap();
    let payload = registry
        .call(
            db.clone(),
            Caller::local(),
            "render_suggestion_review",
            json!({ "record_id": target["id"] }),
        )
        .await
        .unwrap();
    assert_eq!(payload["target"]["body"], serde_json::Value::Null);
    assert_eq!(payload["target"]["body_digest"], serde_json::Value::Null);
    assert_eq!(payload["target"]["body_is_null"], true);
    assert!(payload["target"]["current_seq"].as_i64().unwrap() > 0);
    db.close().await;
}
