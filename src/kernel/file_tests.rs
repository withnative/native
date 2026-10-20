use super::*;
use crate::db::{self, DatabaseVersionState};

#[tokio::test]
async fn v2_file_marker_refuses_v1_paths_and_ready_open_does_not_repair() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.db");
    assert!(db::open_existing_v2_file(missing.to_str().unwrap())
        .await
        .is_err());
    assert!(!missing.exists());
    assert!(open_v2_database(missing.to_str().unwrap()).await.is_err());
    assert!(!missing.exists());
    let path = dir.path().join("v2.db");
    let url = path.to_str().unwrap();
    let (db, _) = create_v2_database(url, "account", "Admin", "test:admin")
        .await
        .unwrap();
    assert_eq!(
        db::probe_database(&path, i64::MAX).await,
        DatabaseVersionState::KernelV2
    );
    for error in [
        db::open_v1_database(url).await.err().unwrap(),
        db::create_database(url).await.err().unwrap(),
        db::open_existing_database(url).await.err().unwrap(),
        db::open_existing_database_standby_read_only(url)
            .await
            .err()
            .unwrap(),
        db::open_member_database_read_only(url).await.err().unwrap(),
        db::open_current_database_read_only_at(&path)
            .await
            .err()
            .unwrap(),
        db::open_current_database_wal_read_only_at(&path)
            .await
            .err()
            .unwrap(),
        db::validate_current_engine_shape_read_only(&path)
            .await
            .unwrap_err(),
        crate::migrations::preflight_production_migration_read_only(&path)
            .await
            .unwrap_err(),
        crate::standby::read_release_act_head_from_path(&path)
            .await
            .unwrap_err(),
        db::apply_schema(&db).await.unwrap_err(),
    ] {
        assert!(
            error.to_string().contains("this is a v2 database"),
            "{error}"
        );
    }
    let before: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let reopened = open_v2_database(url).await.unwrap();
    let after: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    reopened.close().await;
    // A previously ready, unmarked v2 file is stamped on its next v2 open.
    sqlx::query("PRAGMA application_id=0")
        .execute(db.write_pool())
        .await
        .unwrap();
    let error = open_marked_v2_database(url).await.err().unwrap();
    assert!(error.to_string().contains("requires a marked v2 database"));
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(marker, 0, "hosted admission must not stamp legacy files");
    let reopened = open_v2_database(url).await.unwrap();
    assert_eq!(
        db::probe_database(&path, i64::MAX).await,
        DatabaseVersionState::KernelV2
    );
    reopened.close().await;
    sqlx::query("DROP INDEX idx_kernel_links_target")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("PRAGMA application_id=0")
        .execute(db.write_pool())
        .await
        .unwrap();
    let error = open_v2_database(url).await.err().unwrap();
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(marker, 0, "an incomplete legacy file must not be stamped");
    assert!(
        error
            .to_string()
            .contains("not ready: missing idx_kernel_links_target"),
        "{error}"
    );
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='idx_kernel_links_target')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!exists);
    prepare_v2_database(&db).await.unwrap();
    verify_v2_ready(&db).await.unwrap();
    // Raw opens must not repair even the formerly open-time blob schema.
    sqlx::query("DROP TABLE kernel_blob_handles")
        .execute(db.write_pool())
        .await
        .unwrap();
    let raw = db::open_database(url).await.unwrap();
    let error = verify_v2_ready(&raw).await.unwrap_err();
    assert!(
        error.to_string().contains("missing kernel_blob_handles"),
        "{error}"
    );
    raw.close().await;
    let error = open_v2_database(url).await.err().unwrap();
    assert!(
        error.to_string().contains("missing kernel_blob_handles"),
        "{error}"
    );
    prepare_v2_database(&db).await.unwrap();
    let reopened = open_v2_database(url).await.unwrap();
    reopened.close().await;
    // Imported control and messaging projections follow the same preparation
    // boundary: older files refuse without DDL, then upgrade explicitly.
    for (kind, name) in [
        ("TABLE", "kernel_v1_state"),
        ("TABLE", "kernel_messages"),
        ("TABLE", "kernel_message_receipts"),
        ("TABLE", "kernel_message_interactions"),
        ("TABLE", "kernel_personas"),
        ("TABLE", "kernel_message_destinations"),
        ("TABLE", "kernel_message_people"),
        ("INDEX", "idx_kernel_hosted_event_lookup"),
    ] {
        sqlx::query(&format!("DROP {kind} {name}"))
            .execute(db.write_pool())
            .await
            .unwrap();
        let before: i64 = sqlx::query_scalar("PRAGMA schema_version")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let error = open_v2_database(url).await.err().unwrap();
        assert!(
            error.to_string().contains(&format!("missing {name}")),
            "{error}"
        );
        let after: i64 = sqlx::query_scalar("PRAGMA schema_version")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        prepare_v2_database(&db).await.unwrap();
        let reopened = open_v2_database(url).await.unwrap();
        reopened.close().await;
    }
    db.close().await;
}

#[tokio::test]
async fn v1_database_refuses_kernel_events_before_append() {
    let db = db::create_database(":memory:").await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let mut tx = db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let error = crate::store::append_with_event_id_in(
        &db,
        &mut tx,
        Uuid::new_v4().to_string(),
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: KERNEL_GENESIS_EVENT.into(),
            payload: serde_json::json!({}),
            actor: Some(KERNEL_GENESIS_ACTOR.into()),
        },
        &mut acts,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("refusing a v1 database destination"),
        "{error}"
    );
    let error = crate::store::append_kernel_import_receipts_in(
        &db,
        &mut tx,
        KERNEL_GENESIS_ACTOR,
        &[(KERNEL_ROOT_ID, "legacy-event")],
        &mut acts,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("refusing a v1 database destination"),
        "{error}"
    );
    // Even committing after either refusal cannot persist a partial event.
    tx.commit().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    db.close().await;
}
