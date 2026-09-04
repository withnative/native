use native_ce::events::EventRow;

use native_ce::events::LinkAddedPayload;
use native_ce::query::{fts, tree};
use native_ce::store::{add_link, archive_record, create_record, delete_record, update_record};
use native_ce::{create_database, schema};
use serde_json::json;

fn persistence_event(record_id: &str, value: &str) -> EventRow {
    EventRow {
        local_seq: 10_000,
        id: format!("raw-persistence-{record_id}-{value}"),
        record_id: record_id.into(),
        event_type: "facet.set".into(),
        payload: Some(
            json!({
                "key": "persistence",
                "value": value,
                "observation_only": false,
            })
            .to_string(),
        ),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-08-01T12:00:00.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
    }
}

#[tokio::test]
async fn raw_facet_set_cannot_demote_a_folder_that_has_homed_members() {
    let db = create_database(":memory:").await.unwrap();
    let folder = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Folder" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Member", "home_id": folder }),
    )
    .await
    .unwrap();

    let mut conn = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    let error = native_ce::projector::project(&mut conn, &persistence_event(&folder, "occurrent"))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("still has live homed members"), "{error}");
    let persistence: String = sqlx::query_scalar("SELECT persistence FROM records WHERE id = ?")
        .bind(&folder)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(persistence, "enduring");
}

#[tokio::test]
async fn raw_facet_set_cannot_change_engine_filing_persistence() {
    let db = create_database(":memory:").await.unwrap();
    for id in [schema::ROOT_RECORD_ID, schema::UNFILED_RECORD_ID] {
        let mut conn = crate::common::fixture_write_pool(&db)
            .await
            .acquire()
            .await
            .unwrap();
        let error = native_ce::projector::project(&mut conn, &persistence_event(id, "occurrent"))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("immutable persistence"), "{id}: {error}");
    }
}

#[tokio::test]
async fn raw_unfiled_creation_must_match_the_canonical_filing_shape() {
    let db = native_ce::open_database(":memory:").await.unwrap();
    native_ce::apply_schema(&db).await.unwrap();
    let root = EventRow {
        local_seq: 1,
        id: "raw-root".into(),
        record_id: schema::ROOT_RECORD_ID.into(),
        event_type: "record.created".into(),
        payload: Some(
            json!({
                "type": "Collection",
                "kind": "folder",
                "name": "Workspace",
                "home_id": null,
                "persistence": "enduring",
            })
            .to_string(),
        ),
        actor: Some("engine:seed".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        created_at: "2026-08-01T12:00:00.000Z".into(),
    };
    let mut conn = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    native_ce::projector::project(&mut conn, &root)
        .await
        .unwrap();
    let malformed = EventRow {
        local_seq: 2,
        id: "raw-unfiled".into(),
        record_id: schema::UNFILED_RECORD_ID.into(),
        event_type: "record.created".into(),
        payload: Some(
            json!({
                "type": "Document",
                "kind": "note",
                "name": "Unfiled",
                "home_id": schema::ROOT_RECORD_ID,
                "persistence": "enduring",
            })
            .to_string(),
        ),
        actor: Some("engine:seed".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        created_at: "2026-08-01T12:00:01.000Z".into(),
    };
    let error = native_ce::projector::project(&mut conn, &malformed)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("cannot create canonical Unfiled"), "{error}");
}

#[tokio::test]
async fn fresh_census_required_homes_typed_targets_cycles_and_extra_appearances() {
    let db = create_database(":memory:").await.unwrap();
    let null_homes: Vec<String> =
        sqlx::query_scalar("SELECT id FROM records WHERE home_id IS NULL ORDER BY id")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(null_homes, [schema::ROOT_RECORD_ID]);

    let home_a = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "A" }),
    )
    .await
    .unwrap();
    let home_b = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "B", "home_id": home_a }),
    )
    .await
    .unwrap();
    let ordinary = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Ordinary" }),
    )
    .await
    .unwrap();
    let default_home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
        .bind(&ordinary)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(default_home, schema::UNFILED_RECORD_ID);

    let nonfolder = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Not a home" }),
    )
    .await
    .unwrap();
    let error = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Bad", "home_id": nonfolder }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("must be a live, unarchived, enduring Collection kind:folder"));

    let occurrent_folder = create_record(
        &db,
        json!({
            "type": "Collection",
            "kind": "folder",
            "name": "Occurrent folder",
            "persistence": "occurrent",
        }),
    )
    .await
    .unwrap();
    let archived_folder = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Archived folder" }),
    )
    .await
    .unwrap();
    archive_record(&db, &archived_folder).await.unwrap();
    let deleted_folder = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Deleted folder" }),
    )
    .await
    .unwrap();
    delete_record(&db, &deleted_folder).await.unwrap();
    for invalid_home in [occurrent_folder, archived_folder, deleted_folder] {
        let error = create_record(
            &db,
            json!({ "type": "Document", "kind": "note", "name": "Invalid home member", "home_id": invalid_home }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("must be a live, unarchived, enduring Collection kind:folder"),
            "{invalid_home}: {error}"
        );
    }

    let error = update_record(&db, &home_a, json!({ "home_id": home_b }))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("would create a cycle"), "{error}");

    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: ordinary.clone(),
            target_id: home_b,
            relationship: "member_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let unchanged_home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
        .bind(&ordinary)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(unchanged_home, schema::UNFILED_RECORD_ID);

    let home_check = native_ce::conformance::check_home_contract(&db)
        .await
        .unwrap();
    assert!(home_check.ok, "{:?}", home_check.violations);
}

#[tokio::test]
async fn a_folder_with_live_homed_members_cannot_be_archived_or_deleted() {
    let db = create_database(":memory:").await.unwrap();
    let folder = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Occupied" }),
    )
    .await
    .unwrap();
    let member = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Member", "home_id": folder }),
    )
    .await
    .unwrap();

    for error in [
        archive_record(&db, &folder).await.unwrap_err().to_string(),
        delete_record(&db, &folder).await.unwrap_err().to_string(),
    ] {
        assert!(error.contains("still has live homed members"), "{error}");
        assert!(error.contains(&member), "{error}");
    }
}

#[tokio::test]
async fn archived_leaf_scope_is_consistent_between_browse_and_search() {
    let db = create_database(":memory:").await.unwrap();
    let leaf = create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Archived lantern leaf",
            "body": "archived-scope-proof",
        }),
    )
    .await
    .unwrap();
    archive_record(&db, &leaf).await.unwrap();

    assert!(tree::descendants(
        &db,
        &leaf,
        tree::TreeOptions {
            max_depth: 0,
            include_archived: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .iter()
    .any(|node| node.id == leaf));
    let hidden = fts::search(
        &db,
        "test-account",
        "archived scope proof",
        &fts::FtsOptions {
            scope: Some(leaf.clone()),
            include_archived: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(hidden.is_empty());
    let visible = fts::search(
        &db,
        "test-account",
        "archived scope proof",
        &fts::FtsOptions {
            scope: Some(leaf.clone()),
            include_archived: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, leaf);
}

#[tokio::test]
async fn deleted_records_do_not_keep_their_former_homes_structurally_live() {
    let db = create_database(":memory:").await.unwrap();

    let deleted_home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Delete me" }),
    )
    .await
    .unwrap();
    let deleted_child = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Deleted child", "home_id": deleted_home }),
    )
    .await
    .unwrap();
    delete_record(&db, &deleted_child).await.unwrap();
    delete_record(&db, &deleted_home).await.unwrap();

    let demoted_home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Demote me" }),
    )
    .await
    .unwrap();
    let demoted_child = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Other deleted child", "home_id": demoted_home }),
    )
    .await
    .unwrap();
    delete_record(&db, &demoted_child).await.unwrap();
    update_record(&db, &demoted_home, json!({ "persistence": "occurrent" }))
        .await
        .unwrap();

    let check = native_ce::conformance::check_home_contract(&db)
        .await
        .unwrap();
    assert!(check.ok, "{:?}", check.violations);
}

#[tokio::test]
async fn conformance_rejects_a_home_collection_with_a_null_kind() {
    let db = create_database(":memory:").await.unwrap();
    let folder = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Malformed later" }),
    )
    .await
    .unwrap();
    let child = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Child", "home_id": folder }),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET kind = NULL WHERE id = ?")
        .bind(&folder)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let check = native_ce::conformance::check_home_contract(&db)
        .await
        .unwrap();
    assert!(!check.ok);
    assert!(
        check
            .violations
            .iter()
            .any(|violation| violation.contains(&child)),
        "{:?}",
        check.violations
    );
}
