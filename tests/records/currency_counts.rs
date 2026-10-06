//! E3 M1 (v73): physical currency counts (`records.is_current`,
//! `records.successor_count`) folded by the content projector.
//!
//! Contract under test: `is_current` is tri-state (`1` iff zero live
//! incoming `supersedes`, `NULL` when replacement scope is unknown, `0`
//! reserved and never written); `successor_count` counts live incoming
//! successors (tombstoned source excluded) and never stores names.
//! `archived` stays orthogonal. Caller-visible SQL/catalog exposure is an
//! explicit follow-on, so these tests read the physical projection only.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::events::{LinkAddedPayload, LinkRemovedPayload};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{add_link, archive_record, create_record, delete_record, remove_link};
use native_ce::{create_database, Db};
use serde_json::json;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn doc(db: &Db, name: &str) -> String {
    create_record(
        db,
        json!({"type": "Document", "kind": "note", "name": name}),
    )
    .await
    .unwrap()
}

async fn link_supersedes(db: &Db, source: &str, target: &str) {
    add_link(
        db,
        LinkAddedPayload {
            id: None,
            source_id: source.to_string(),
            target_id: target.to_string(),
            relationship: "supersedes".to_string(),
            note: None,
        },
    )
    .await
    .unwrap();
}

async fn unlink_supersedes(db: &Db, source: &str, target: &str) {
    remove_link(
        db,
        LinkRemovedPayload {
            source_id: source.to_string(),
            target_id: target.to_string(),
            relationship: "supersedes".to_string(),
        },
    )
    .await
    .unwrap();
}

/// Physical counts straight from the projection.
async fn physical(db: &Db, id: &str) -> (Option<i64>, i64) {
    sqlx::query_as("SELECT is_current, successor_count FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

#[tokio::test]
async fn fresh_record_is_current_with_zero_successors() {
    let db = db().await;
    let id = doc(&db, "fresh").await;
    assert_eq!(physical(&db, &id).await, (Some(1), 0));
}

#[tokio::test]
async fn supersedes_link_add_nulls_target_and_counts() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let first = doc(&db, "first").await;
    let second = doc(&db, "second").await;
    link_supersedes(&db, &first, &target).await;
    assert_eq!(physical(&db, &target).await, (None, 1));
    link_supersedes(&db, &second, &target).await;
    assert_eq!(physical(&db, &target).await, (None, 2));
    // Successors themselves stay current with zero counts.
    assert_eq!(physical(&db, &first).await, (Some(1), 0));
}

#[tokio::test]
async fn link_remove_recounts_and_restores_current_when_cleared() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let first = doc(&db, "first").await;
    let second = doc(&db, "second").await;
    link_supersedes(&db, &first, &target).await;
    link_supersedes(&db, &second, &target).await;
    unlink_supersedes(&db, &first, &target).await;
    assert_eq!(physical(&db, &target).await, (None, 1));
    unlink_supersedes(&db, &second, &target).await;
    assert_eq!(physical(&db, &target).await, (Some(1), 0));
}

#[tokio::test]
async fn tombstoned_successor_stops_counting() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let live = doc(&db, "live").await;
    let dead = doc(&db, "dead").await;
    link_supersedes(&db, &live, &target).await;
    link_supersedes(&db, &dead, &target).await;
    assert_eq!(physical(&db, &target).await, (None, 2));
    delete_record(&db, &dead).await.unwrap();
    assert_eq!(physical(&db, &target).await, (None, 1));
}

#[tokio::test]
async fn unrelated_relationship_leaves_currency_alone() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let other = doc(&db, "other").await;
    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: other.clone(),
            target_id: target.clone(),
            relationship: "relates_to".to_string(),
            note: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(physical(&db, &target).await, (Some(1), 0));
}

#[tokio::test]
async fn archived_stays_orthogonal_to_currency() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let successor = doc(&db, "successor").await;
    link_supersedes(&db, &successor, &target).await;
    // Archiving the successor does not tombstone it: it still counts.
    archive_record(&db, &successor).await.unwrap();
    assert_eq!(physical(&db, &target).await, (None, 1));
    // Archiving the target does not clear its scope-unknown state.
    archive_record(&db, &target).await.unwrap();
    assert_eq!(physical(&db, &target).await, (None, 1));
    let archived: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
        .bind(&target)
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(archived, 1);
}

#[tokio::test]
async fn invisible_successor_counts_without_disclosing_its_name() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let hidden = doc(&db, "hidden successor").await;
    link_supersedes(&db, &hidden, &target).await;
    replace_explicit_policy(
        &db,
        "test:currency-hidden-successor",
        &hidden,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    assert_eq!(physical(&db, &target).await, (None, 1));

    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let bea = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false);
    let payload = registry
        .call(db.clone(), bea, "get_record", json!({ "ids": [target] }))
        .await
        .unwrap();
    let record = &payload["records"][0];
    assert_eq!(record["superseded_by"]["total_count"], 1);
    assert_eq!(record["superseded_by"]["items"], json!([]));
    let text = record.to_string();
    assert!(!text.contains("hidden successor"), "{text}");
    assert!(!text.contains(&hidden), "{text}");
}

#[tokio::test]
async fn reserved_zero_is_never_written() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let successor = doc(&db, "successor").await;
    link_supersedes(&db, &successor, &target).await;
    unlink_supersedes(&db, &successor, &target).await;
    delete_record(&db, &successor).await.unwrap();
    let reserved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE is_current = 0")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(reserved, 0);
}

#[tokio::test]
async fn currency_folds_converge_under_replay() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let first = doc(&db, "first").await;
    let second = doc(&db, "second").await;
    link_supersedes(&db, &first, &target).await;
    link_supersedes(&db, &second, &target).await;
    unlink_supersedes(&db, &first, &target).await;
    delete_record(&db, &first).await.unwrap();
    let result = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(
        result.equal,
        "rebuild drift with currency folds: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
}

#[tokio::test]
async fn relationship_owned_successor_is_an_input_to_content_rebuild() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let content_successor = doc(&db, "content successor").await;
    let relationship_successor = doc(&db, "relationship successor").await;
    link_supersedes(&db, &content_successor, &target).await;

    // A relationship-ledger fold owns `rel:` rows. Plant its compatibility
    // output and the corresponding currency projection as external inputs to
    // the content lane; the relationship lane proves the ledger fold itself.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO links(id,source_id,target_id,relationship,note,created_at)
         VALUES('rel:test:currency',?1,?2,'supersedes',NULL,'2026-09-30T00:00:00.000Z')",
    )
    .bind(&relationship_successor)
    .bind(&target)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE records SET successor_count=2,is_current=NULL WHERE id=?1")
        .bind(&target)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(physical(&db, &target).await, (None, 2));

    let rebuilt = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{rebuilt:#?}");
}

#[tokio::test]
async fn relationship_compatibility_id_is_reserved_for_content_links() {
    let db = db().await;
    let target = doc(&db, "target").await;
    let successor = doc(&db, "successor").await;
    let error = add_link(
        &db,
        LinkAddedPayload {
            id: Some("rel:test:content-successor".to_string()),
            source_id: successor,
            target_id: target.clone(),
            relationship: "supersedes".to_string(),
            note: None,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("rel: link ids are reserved"));
    assert_eq!(physical(&db, &target).await, (Some(1), 0));
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='link.added'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(events, 0);
}
