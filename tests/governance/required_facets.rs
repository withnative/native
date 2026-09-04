//! Required facets bind post-batch and comparatively (task 28ddc83).

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    promote_value, propose_value_with_kind_metadata_as, KindMetadataV1, VocabularyValueTerminality,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

/// Fixture record ids. A record id must now be a canonical lowercase UUID, so
/// the readable name lives in the constant rather than in the id itself. These
/// are pinned literals — never generated — so every assertion stays
/// deterministic. Nothing here depends on an id's text, only on its identity.
const MISSING_CREATE: &str = "facce700-0000-4000-8000-000000000001";
const OBJECTIVE: &str = "facce700-0000-4000-8000-000000000002";
const LEGACY: &str = "facce700-0000-4000-8000-000000000003";
const LEGACY_KIND: &str = "facce700-0000-4000-8000-000000000004";
const PARENT: &str = "facce700-0000-4000-8000-000000000005";
const OWNER: &str = "facce700-0000-4000-8000-000000000006";

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

async fn require_key_result_target(registry: &ToolRegistry, db: &Db) {
    govern_outcome_kind(db, "objective").await;
    govern_outcome_kind(db, "key_result").await;
    call(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Outcome:key_result": { "facets": { "target": { "required": true } } }
        } } }),
    )
    .await;
}

#[tokio::test]
async fn create_kind_flip_unset_and_same_batch_repair_follow_non_worsening() {
    let db = db().await;
    let registry = registry();
    require_key_result_target(&registry, &db).await;

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "id": MISSING_CREATE, "type": "Outcome", "kind": "key_result" }),
    )
    .await;
    assert!(err.contains("missing required facet 'target'"), "{err}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
        .bind(MISSING_CREATE)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "refused create must roll back its whole batch");

    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": OBJECTIVE, "type": "Outcome", "kind": "objective" }),
    )
    .await;
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": OBJECTIVE, "kind": "key_result" }),
    )
    .await;
    assert!(err.contains("missing required facet 'target'"), "{err}");
    let kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
        .bind(OBJECTIVE)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "objective");

    // The resulting state, not event order, is judged: entering the kind and
    // supplying its required facet in one batch succeeds.
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": OBJECTIVE,
            "kind": "key_result",
            "facets": { "target": "10" }
        }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": OBJECTIVE, "facets": { "target": null } }),
    )
    .await;
    assert!(err.contains("missing required facet 'target'"), "{err}");
    let target: String =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = 'target'")
            .bind(OBJECTIVE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(target, "10");
}

#[tokio::test]
async fn later_shape_tightening_does_not_brick_legacy_record_edits() {
    let db = db().await;
    let registry = registry();

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": LEGACY,
            "type": "Outcome",
            "kind": "key_result",
            "name": "Before"
        }),
    )
    .await;
    require_key_result_target(&registry, &db).await;

    // Before and after both contain the same violation, so unrelated edits
    // remain possible instead of retroactively bricking the record.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": LEGACY, "name": "After" }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": LEGACY, "facets": { "target": "20" } }),
    )
    .await;
}

#[tokio::test]
async fn kind_change_with_same_legacy_missing_key_is_not_a_new_violation() {
    let db = db().await;
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": LEGACY_KIND, "type": "Outcome", "kind": "objective" }),
    )
    .await;
    govern_outcome_kind(&db, "objective").await;
    govern_outcome_kind(&db, "key_result").await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Outcome": {
                "facets": { "target": { "required": true } }
            }
        } } }),
    )
    .await;

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": LEGACY_KIND, "kind": "key_result" }),
    )
    .await;
    let kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
        .bind(LEGACY_KIND)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "key_result");
}

#[tokio::test]
async fn attachments_enforce_required_facets_after_their_full_event_batch() {
    let db = db().await;
    let registry = registry();
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
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Document:attachment": {
                "facets": { "classification": { "required": true } }
            }
        } } }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "missing" }),
    )
    .await;
    assert!(
        err.contains("missing required facet 'classification'"),
        "{err}"
    );

    let attached = call(
        &registry,
        &db,
        "attach_text",
        json!({
            "record_id": PARENT,
            "text": "classified",
            "facets": { "classification": "internal" }
        }),
    )
    .await;
    assert!(attached["attachment_id"].is_string());
}

#[tokio::test]
async fn attachments_can_supply_every_permitted_required_spine_facet() {
    let db = db().await;
    let registry = registry();
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
        "create_record",
        json!({ "id": OWNER, "type": "Entity" }),
    )
    .await;
    call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Document:attachment": { "facets": {
                "lifecycle": { "required": true },
                "owner": { "required": true },
                "persistence": { "required": true },
                "maturity": { "required": true }
            } }
        } } }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": PARENT, "text": "missing spine" }),
    )
    .await;
    assert!(err.contains("'lifecycle'"), "{err}");
    assert!(err.contains("'owner'"), "{err}");
    assert!(err.contains("'maturity'"), "{err}");
    assert!(
        !err.contains("'persistence'"),
        "default enduring satisfies it: {err}"
    );

    let attached = call(
        &registry,
        &db,
        "attach_text",
        json!({
            "record_id": PARENT,
            "text": "complete spine",
            "lifecycle": "active",
            "owner_id": OWNER,
            "persistence": "occurrent",
            "maturity": "proposed"
        }),
    )
    .await;
    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT lifecycle, owner_id, persistence, maturity FROM records WHERE id = ?",
    )
    .bind(attached["attachment_id"].as_str().unwrap())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "active".into(),
            OWNER.into(),
            "occurrent".into(),
            "proposed".into()
        )
    );
}
