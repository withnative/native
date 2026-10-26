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
        ("TABLE", "kernel_identity_bindings"),
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

#[tokio::test]
async fn native_member_profile_marker_never_admits_a_canonical_v2_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("member.db");
    let url = path.to_str().unwrap();
    let (source, _) = create_v2_database(url, "account", "Synthetic member", "test:member")
        .await
        .unwrap();
    sqlx::query(&format!(
        "PRAGMA application_id={}",
        db::V2_MEMBER_APPLICATION_ID
    ))
    .execute(source.write_pool())
    .await
    .unwrap();
    source.close().await;
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        db::probe_database(&path, i64::MAX).await,
        DatabaseVersionState::KernelV2Member
    );
    assert!(open_marked_v2_database(url).await.is_err());
    assert!(open_v2_database(url).await.is_err());
    let error = db::open_existing_v2_file(url).await.err().unwrap();
    assert!(
        error.to_string().contains("member-profile admission"),
        "{error}"
    );
    assert!(crate::standby::kernel_v2::verify_path(&path).await.is_err());
    assert!(db::open_kernel_v2_standby_read_only(url).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn v2_realtime_index_is_optional_and_preparation_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("older-v2.db");
    let path = path.to_str().unwrap();
    let (db, _) = create_v2_database(path, "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let expected = notifications::vector(db.pool()).await.unwrap();
    let digest = projection_dump::dump(&db).await.unwrap();
    // Reconstruct the inventory from before any optional accelerator.
    for name in [
        "idx_kernel_realtime_authority",
        "idx_kernel_named_view_admissions",
        "idx_kernel_named_view_lifecycle",
    ] {
        sqlx::query(&format!("DROP INDEX {name}"))
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    let unindexed_schema: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    verify_v2_ready(&db).await.unwrap();
    let legacy_schema: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetch_all(db.pool()).await.unwrap();
    let legacy_hash =
        crate::standby_snapshot::sha256_bytes(&serde_jcs::to_vec(&legacy_schema).unwrap());
    let mut conn = db.pool().acquire().await.unwrap();
    let old_coordinates = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        old_coordinates.schema_sha256, legacy_hash,
        "keep build A's pre-index schema hash"
    );
    drop(conn);
    let reopened = open_marked_v2_database(path).await.unwrap();
    assert_eq!(
        notifications::vector(reopened.pool()).await.unwrap(),
        expected
    );
    assert_eq!(
        projection_dump::dump(&reopened).await.unwrap(),
        digest,
        "N1's logical projection digest must ignore an optional physical index"
    );
    reopened.close().await;
    let after_read: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        unindexed_schema, after_read,
        "serving must not create the index"
    );
    prepare_v2_database(&db).await.unwrap();
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND name='idx_kernel_realtime_authority')").fetch_one(db.pool()).await.unwrap();
    assert!(exists);
    assert_eq!(notifications::vector(db.pool()).await.unwrap(), expected);
    assert_eq!(projection_dump::dump(&db).await.unwrap(), digest);
    let prepared_schema: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    prepare_v2_database(&db).await.unwrap();
    let repeated_schema: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(prepared_schema, repeated_schema);
    let mut conn = db.pool().acquire().await.unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap(),
        old_coordinates,
        "build B's index cannot change generation identity or delta continuity"
    );
    drop(conn);
    // DDL across pooled connections can retain a stale SQLite schema cache.
    // Keep the deliberate substitution on one connection, and observe it.
    let mut schema_conn = db.write_pool().acquire().await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_realtime_authority")
        .execute(&mut *schema_conn)
        .await
        .unwrap();
    let absent: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='idx_kernel_realtime_authority')",
    )
    .fetch_one(&mut *schema_conn)
    .await
    .unwrap();
    assert!(absent);
    sqlx::query("CREATE INDEX idx_kernel_realtime_authority ON content_events(seq)")
        .execute(&mut *schema_conn)
        .await
        .unwrap();
    drop(schema_conn);
    let mut conn = db.pool().acquire().await.unwrap();
    let error = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("optional realtime index differs"),
        "{error}"
    );
    drop(conn);
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn v2_named_view_index_preserves_coordinates_and_rejects_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("named-view-coordinates.db");
    let (db, _) = create_v2_database(path.to_str().unwrap(), "account", "Owner", "acct:owner")
        .await
        .unwrap();
    // Use one physical connection across DDL and inventory reads so SQLite
    // cannot supply a pooled connection's pre-DDL schema cache.
    let mut conn = db.write_pool().acquire().await.unwrap();
    let indexed = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let projection = projection_dump::dump_on(&mut conn).await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_named_view_admissions")
        .execute(&mut *conn)
        .await
        .unwrap();
    let unindexed = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    assert_eq!(indexed.schema_sha256, unindexed.schema_sha256);
    assert_eq!(
        indexed, unindexed,
        "optional index presence cannot change generation coordinates"
    );
    assert_eq!(
        projection_dump::dump_on(&mut conn).await.unwrap(),
        projection
    );
    sqlx::query(NAMED_VIEW_EVENT_INDEX_DDL)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap(),
        indexed
    );
    sqlx::query("DROP INDEX idx_kernel_named_view_admissions")
        .execute(&mut *conn)
        .await
        .unwrap();
    // A same-named index with different DDL must never be silently omitted.
    sqlx::query("CREATE INDEX idx_kernel_named_view_admissions ON content_events(seq)")
        .execute(&mut *conn)
        .await
        .unwrap();
    let error = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("optional named-view index differs"),
        "{error}"
    );
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn v2_named_view_lifecycle_index_is_optional_and_coordinate_neutral() {
    let (db, _) = create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(crate::named_views::storage::verify_index_on(&mut conn)
        .await
        .unwrap());
    let indexed = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let projection = projection_dump::dump_on(&mut conn).await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(&mut *conn)
        .await
        .unwrap();
    verify_v2_ready_on(&mut conn).await.unwrap();
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap(),
        indexed
    );
    assert_eq!(
        projection_dump::dump_on(&mut conn).await.unwrap(),
        projection
    );
    drop(conn);
    prepare_v2_database(&db).await.unwrap();
    prepare_v2_database(&db).await.unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(crate::named_views::storage::verify_index_on(&mut conn)
        .await
        .unwrap());
    assert_eq!(
        crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap(),
        indexed
    );
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("CREATE INDEX idx_kernel_named_view_lifecycle ON content_events(seq)")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .is_err());
    assert!(verify_v2_ready_on(&mut conn).await.is_err());
    assert!(crate::named_views::storage::verify_index_on(&mut conn)
        .await
        .is_err());
}
