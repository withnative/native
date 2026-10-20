//! Physical `record_body_json_nodes` projection beyond the live fold:
//! Unit-revision maintenance, canonical import parity, and lifecycle
//! append funnelling through `record.updated`.

use native_ce::authorization::Principal;
use native_ce::freshness::{
    current_record_body_revision, promote_idea, revise_unit, ExpressionRole, IdempotencyKey,
    OccurrenceSelector, PromoteIdeaInput, ReviseUnitInput, UnitContent,
};
use native_ce::interchange::{
    export_canonical_interchange, import_canonical_interchange, ImportContinuity,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{create_record, update_record};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

async fn nodes(db: &Db, id: &str) -> Vec<(i64, String, String)> {
    sqlx::query_as(
        "SELECT ordinal,path,node_type FROM record_body_json_nodes WHERE record_id=? ORDER BY ordinal",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn all_nodes(db: &Db) -> Vec<(String, i64, String, String)> {
    sqlx::query_as(
        "SELECT record_id,ordinal,path,node_type FROM record_body_json_nodes ORDER BY record_id,ordinal",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
}

/// A Unit revision is the fourth writer of `records.body`: JSON content
/// projects nodes, and revising to prose clears them.
#[tokio::test]
async fn unit_revision_replaces_and_clears_body_nodes() {
    const ACCOUNT: &str = "acct:body-json-nodes-unit";
    const ACTOR: &str = "test:body-json-nodes-unit";
    let db = db().await;
    let source = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"Idea source","body":"Audience: technical founders."}),
    )
    .await
    .unwrap();
    let promoted = promote_idea(
        &db,
        Principal::bound(ACCOUNT, true),
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Audience: technical founders.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("[1, {\"k\": true}]").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("body-nodes-unit-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let unit_id = promoted.unit_id.as_str().to_owned();
    assert_eq!(
        nodes(&db, &unit_id).await,
        vec![
            (0, "".into(), "array".into()),
            (1, "/0".into(), "number".into()),
            (2, "/1".into(), "object".into()),
            (3, "/1/k".into(), "boolean".into()),
        ]
    );
    revise_unit(
        &db,
        Principal::bound(ACCOUNT, true),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text("Revised audience: plain markdown.").unwrap(),
            rationale: "Clear JSON nodes with prose.".into(),
            idempotency_key: IdempotencyKey::new("body-nodes-unit-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(nodes(&db, &unit_id).await, Vec::new());
}

/// Canonical export carries no node section; import rebuilds nodes from the
/// imported body text, converging with the source projection.
#[tokio::test]
async fn canonical_import_rebuilds_body_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let source = create_database(dir.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    native_ce::meta::seed_vocabularies(&source).await.unwrap();
    let obj = create_record(
        &source,
        json!({"type":"Document","kind":"note","body":{"a":1}}),
    )
    .await
    .unwrap();
    let arr = create_record(
        &source,
        json!({"type":"Document","kind":"note","body":[true]}),
    )
    .await
    .unwrap();
    let scalar = create_record(
        &source,
        json!({"type":"Document","kind":"note","body":"plain"}),
    )
    .await
    .unwrap();
    let before = all_nodes(&source).await;
    assert_eq!(before.len(), 4);
    let bundle = export_canonical_interchange(&source).await.unwrap();
    source.close().await;
    let imported = import_canonical_interchange(
        &bundle,
        &dir.path().join("imported.db"),
        ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    assert_eq!(all_nodes(&imported).await, before);
    assert_eq!(nodes(&imported, &obj).await.len(), 2);
    assert_eq!(nodes(&imported, &arr).await.len(), 2);
    assert_eq!(nodes(&imported, &scalar).await, Vec::new());
}

/// `body_append` resolves to the full coerced body through `record.updated`,
/// so appending the closing brace to partial JSON text projects nodes.
#[tokio::test]
async fn lifecycle_append_funnels_through_record_updated() {
    let db = db().await;
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let created: Value = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({"type":"Document","kind":"note","body":"{\"a\": 1"}),
            ),
        )
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(nodes(&db, &id).await, Vec::new());
    let append_args = {
        let mut map = serde_json::Map::new();
        map.insert("id".to_owned(), Value::String(id.clone()));
        map.insert("body_append".to_owned(), Value::String("}".to_owned()));
        Value::Object(map)
    };
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            crate::common::with_test_reason("update_record", append_args),
        )
        .await
        .unwrap();
    let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(body.as_deref(), Some("{\"a\": 1}"));
    assert_eq!(
        nodes(&db, &id).await,
        vec![
            (0, "".into(), "object".into()),
            (1, "/a".into(), "number".into()),
        ]
    );
    // The store-level full replacement used above exercises the same path
    // that `body_replace` resolves through. Same-shaped replacement
    // ({a:1} -> {a:2}) keeps ordinal/path/type identical, so assert the
    // number lexeme too: stale values would pass the shape check above.
    update_record(&db, &id, json!({"body": "{\"a\": 2}"}))
        .await
        .unwrap();
    assert_eq!(
        nodes(&db, &id).await,
        vec![
            (0, "".into(), "object".into()),
            (1, "/a".into(), "number".into()),
        ]
    );
    let number_text: Option<String> = sqlx::query_scalar(
        "SELECT number_text FROM record_body_json_nodes WHERE record_id=? AND path='/a'",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(number_text.as_deref(), Some("2"));
}
