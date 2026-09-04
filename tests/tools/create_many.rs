//! Integration coverage for the graph-aware `create_many` operation.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
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

async fn call(registry: &ToolRegistry, db: &Db, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), "create_many", arguments)
        .await
        .unwrap()
}

#[tokio::test]
async fn forward_parent_link_and_body_refs_are_materialized_before_create() {
    let db = db().await;
    let registry = registry();
    let receipt = call(
        &registry,
        &db,
        json!({
            "reason": "Create one connected graph without follow-up mutations.",
            "records": [
                {
                    "ref": "child",
                    "type": "Document",
                    "kind": "note",
                    "name": "Child",
                    "parent_ref": "folder",
                    "body": "Filed under [[folder]] and linked to it.",
                    "links": [{"target_ref":"folder", "relationship":"relates_to"}]
                },
                {
                    "ref": "folder",
                    "type": "Collection",
                    "kind": "folder",
                    "name": "Folder",
                    "persistence": "enduring"
                }
            ]
        }),
    )
    .await;

    assert_eq!(receipt["ok"], true);
    let child = receipt["ids"][0].as_str().unwrap();
    let folder = receipt["ids"][1].as_str().unwrap();
    let row: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT home_id,body FROM records WHERE id=?")
            .bind(child)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(row.0.as_deref(), Some(folder));
    let expected_body = format!("Filed under [[{folder}]] and linked to it.");
    assert_eq!(row.1.as_deref(), Some(expected_body.as_str()));
    let target: String = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id=? AND relationship='relates_to'",
    )
    .bind(child)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(target, folder);
    assert_eq!(receipt["body_digests"][0]["index"], 0);
}

#[tokio::test]
async fn failed_item_blocks_dependants_but_not_independent_branches() {
    let db = db().await;
    let registry = registry();
    let receipt = call(
        &registry,
        &db,
        json!({
            "reason": "Exercise the indexed partial-success contract.",
            "records": [
                {"ref":"bad", "type":"Collection", "kind":"", "name":"Bad"},
                {"type":"Document", "kind":"note", "parent_ref":"bad", "name":"Blocked"},
                {"type":"Document", "kind":"note", "name":"Independent"}
            ]
        }),
    )
    .await;

    assert_eq!(receipt["ok"], false);
    assert!(receipt["ids"][0].is_null());
    assert!(receipt["ids"][1].is_null());
    assert!(receipt["ids"][2].is_string());
    assert_eq!(receipt["errors"][0]["index"], 0);
    assert_eq!(receipt["errors"][0]["code"], "create_failed");
    assert_eq!(receipt["errors"][1]["index"], 1);
    assert_eq!(receipt["errors"][1]["code"], "dependency_failed");
    assert_eq!(receipt["errors"][1]["dependency_indexes"], json!([0]));
}

#[tokio::test]
async fn cycle_rejection_happens_before_any_authoritative_write() {
    let db = db().await;
    let registry = registry();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_many",
            json!({
                "reason": "This graph must be refused as a unit.",
                "records": [
                    {"ref":"a", "type":"Document", "kind":"note", "body":"[[b]]"},
                    {"ref":"b", "type":"Document", "kind":"note", "body":"[[a]]"}
                ]
            }),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("dependency cycle"));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn every_item_enforces_ordinary_destination_authorization_without_partial_leakage() {
    let db = db().await;
    let registry = registry();
    let destination = call(
        &registry,
        &db,
        json!({
            "reason":"Create the authorization fixture.",
            "records":[{
                "type":"Collection",
                "kind":"folder",
                "name":"Private batch destination"
            }]
        }),
    )
    .await["ids"][0]
        .as_str()
        .unwrap()
        .to_owned();
    replace_explicit_policy(
        &db,
        "create-many:test",
        &destination,
        vec![AllowEntry::account("acct:owner", Capability::Manage)],
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let receipt = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:viewer"),
            "create_many",
            json!({
                "reason":"This caller cannot edit the destination.",
                "records":[{
                    "type":"Document",
                    "kind":"note",
                    "name":"Must not be created",
                    "home_id":destination
                }]
            }),
        )
        .await
        .unwrap();
    assert_eq!(receipt["ok"], false);
    assert!(receipt["ids"][0].is_null());
    assert_eq!(receipt["errors"][0]["code"], "create_failed");
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
}
