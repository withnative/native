//! Integration-review regressions for absolute values/vocabulary binding and
//! authoritative transaction placement (task ccbfccd).

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    promote_value, propose_value_with_kind_metadata_as, KindMetadataV1, VocabularyValueTerminality,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. Pinned literals, never generated.
const BAD_VALUES: &str = "facebb00-0000-4000-8000-000000000001";
const BAD_MEMBER: &str = "facebb00-0000-4000-8000-000000000002";
const GOAL: &str = "facebb00-0000-4000-8000-000000000003";
const PARENT: &str = "facebb00-0000-4000-8000-000000000004";
const RACED: &str = "facebb00-0000-4000-8000-000000000005";
const RESULT_KIND: &str = "facebb00-0000-4000-8000-000000000006";

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

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string()
}

async fn active_value(registry: &ToolRegistry, db: &Db, vocabulary: &str, value: &str) -> String {
    let proposed = call(
        registry,
        db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": vocabulary, "value": value }),
    )
    .await;
    call(
        registry,
        db,
        "manage_vocabularies",
        json!({ "action": "promote_value", "value_id": proposed["value_id"] }),
    )
    .await;
    proposed["value_id"].as_str().unwrap().to_string()
}

async fn govern_outcome_kind(db: &Db, token: &str) {
    let id = propose_value_with_kind_metadata_as(
        db,
        "kind:Outcome",
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Outcome", token)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

#[tokio::test]
async fn values_and_governing_vocab_bind_on_create_update_and_attachment_paths() {
    let db = db().await;
    let registry = registry();
    let theme = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "theme" }),
    )
    .await;
    let other = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "create_vocabulary", "name": "other" }),
    )
    .await;
    let offsite_id = active_value(&registry, &db, "theme", "offsite").await;
    active_value(&registry, &db, "theme", "planning").await;
    active_value(&registry, &db, "other", "offsite").await;

    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Outcome": { "facets": {
                "stage": { "values": ["draft", "live"] },
                "theme": { "vocab": "theme" }
            } },
            "Document:attachment": { "facets": {
                "stage": { "values": ["draft", "live"] },
                "theme": { "vocab_ref": "theme" }
            } }
        } } }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "id": BAD_VALUES, "type": "Outcome", "facets": { "stage": "unknown" } }),
    )
    .await;
    assert!(err.contains("not in the declared values set"), "{err}");

    // Omitting caller vocab_ref cannot bypass the governing vocabulary.
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "id": BAD_MEMBER, "type": "Outcome", "facets": { "theme": "banana" } }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": GOAL,
            "type": "Outcome",
            "facets": { "stage": "draft", "theme": "offsite" }
        }),
    )
    .await;

    let goal_vocab_ref: String = sqlx::query_scalar(
        "SELECT vocab_ref FROM facet_values WHERE record_id = ? AND key = 'theme'",
    )
    .bind(GOAL)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(goal_vocab_ref, theme["vocab_ref"]);
    let err = call_err(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "delete_value", "value_id": offsite_id }),
    )
    .await;
    assert!(err.contains("facet assignment(s) reference it"), "{err}");

    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": GOAL, "facets": { "stage": "unknown" } }),
    )
    .await;
    assert!(err.contains("not in the declared values set"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": GOAL, "facets": { "theme": "banana" } }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": GOAL, "facets": {
            "theme": { "value": "offsite", "vocab_ref": other["vocab_ref"] }
        } }),
    )
    .await;
    assert!(err.contains("conflicting vocab_ref"), "{err}");
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": GOAL, "facets": {
            "theme": { "value": "planning", "vocab_ref": "theme" }
        } }),
    )
    .await;
    let updated_vocab_ref: String = sqlx::query_scalar(
        "SELECT vocab_ref FROM facet_values WHERE record_id = ? AND key = 'theme'",
    )
    .bind(GOAL)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(updated_vocab_ref, theme["vocab_ref"]);

    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": PARENT, "type": "Collection" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "propose_value", "vocabulary": "theme", "value": "proposed-only" }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "bad", "facets": { "stage": "unknown" } }),
    )
    .await;
    assert!(err.contains("not in the declared values set"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "bad", "facets": { "theme": "banana" } }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "bad", "facets": {
            "theme": { "value": "proposed-only", "vocab_ref": "theme" }
        } }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");
    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "bad", "facets": {
            "theme": { "value": "planning", "vocab_ref": other["vocab_ref"] }
        } }),
    )
    .await;
    assert!(err.contains("conflicting vocab_ref"), "{err}");
    let blobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(blobs, 0, "fast failure must precede blob insertion");

    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({
            "record_id": PARENT,
            "text": "ok",
            "facets": {
                "stage": "live",
                "theme": { "value": "planning", "vocab_ref": "theme" }
            }
        }),
    )
    .await;
    let attachment_id = attachment["attachment_id"].as_str().unwrap();
    let attachment_vocab_ref: String = sqlx::query_scalar(
        "SELECT vocab_ref FROM facet_values WHERE record_id = ? AND key = 'theme'",
    )
    .bind(attachment_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(attachment_vocab_ref, theme["vocab_ref"]);
    assert!(theme["vocab_ref"].is_string());
}

#[tokio::test]
async fn schema_tightening_waiting_ahead_of_create_is_seen_inside_the_write_transaction() {
    let db = db().await;
    let mut blocker = crate::common::fixture_write_pool(&db)
        .await
        .begin_with("BEGIN IMMEDIATE")
        .await
        .unwrap();

    // The tool starts while another writer owns the lock. Its eventual
    // authoritative snapshot must be taken only after that writer commits.
    let worker_db = db.clone();
    let worker = tokio::spawn(async move {
        let registry = registry();
        call_err(
            &registry,
            &worker_db,
            "create_record",
            json!({ "id": RACED, "type": "Outcome", "facets": { "stage": "invalid" } }),
        )
        .await
    });
    tokio::task::yield_now().await;
    sqlx::query("INSERT INTO schema_config (id, layer, data) VALUES ('tightening', 'user', ?)")
        .bind(
            json!({ "shapes": { "Outcome": { "facets": {
        "stage": { "values": ["allowed"] }
    } } } })
            .to_string(),
        )
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    let err = worker.await.unwrap();
    assert!(err.contains("not in the declared values set"), "{err}");
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id = ?")
        .bind(RACED)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events, 0);
}

#[tokio::test]
async fn update_value_predicates_use_the_resulting_kind_and_roll_back_together() {
    let db = db().await;
    let registry = registry();
    govern_outcome_kind(&db, "objective").await;
    govern_outcome_kind(&db, "key_result").await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Outcome:key_result": { "facets": { "stage": { "values": ["live"] } } }
        } } }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": RESULT_KIND, "type": "Outcome", "kind": "objective" }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": RESULT_KIND,
            "kind": "key_result",
            "facets": { "stage": "draft" }
        }),
    )
    .await;
    assert!(err.contains("not in the declared values set"), "{err}");
    let kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
        .bind(RESULT_KIND)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "objective");
}
