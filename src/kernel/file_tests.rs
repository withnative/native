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
    let mut legacy_schema: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetch_all(db.pool()).await.unwrap();
    // The historical owned-schema floor predates receipt carriage. Current
    // coordinates validate these exact receipt and lookup-accelerator objects
    // before normalizing them out. Keep them physically present for serving
    // admission while reconstructing the historical compatibility inventory.
    legacy_schema.retain(|(_, name, _, _)| {
        name != "kernel_mcp_write_receipts"
            && name != mcp_write_receipts::INDEX
            && name != "idx_kernel_record_names"
            && name != "idx_kernel_record_logical_homes"
            && name != "idx_kernel_link4_edges_source"
            && name != "idx_kernel_link4_edges_target"
            && name != "idx_kernel_provider_link_rows_source"
            && name != "idx_kernel_provider_link_rows_target"
    });
    // The disposable SQL event cache postdates build A. Coordinates exempt
    // its closed table/index name set from logical certification.
    legacy_schema.retain(|object| {
        !crate::kernel::sql_event_projection::certification_object(object)
            && !crate::kernel::sql_record_projection::certification_object(object)
    });
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

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn v2_historical_realtime_indexes_preserve_coordinates_and_new_authority_reads() {
    for ddl in [
        notifications::REALTIME_AUTHORITY_INDEX_V1,
        notifications::REALTIME_AUTHORITY_INDEX_V2,
    ] {
        let (db, _) = create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let before = crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap();
        sqlx::query("DROP INDEX idx_kernel_realtime_authority")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(ddl).execute(&mut *conn).await.unwrap();
        let schema_version: i64 = sqlx::query_scalar("PRAGMA schema_version")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            crate::standby::kernel_v2::coordinates(&mut conn)
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA schema_version")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            schema_version
        );
        drop(conn);
        // Query-only fixtures isolate the canonical authorization selector.
        // These events are absent from the old partial-index predicate; an
        // older accelerator must never hide them from the current reader.
        for (event_type, payload) in [
            ("kernel.record_type_corrected.v1", serde_json::json!({})),
            (
                "kernel.identity_binding_removed.v1",
                serde_json::json!({"binding":{"system":"native-principal"}}),
            ),
            (
                "kernel.identity_bindings_reconciled.v1",
                serde_json::json!({"bindings":[{"system":"native-principal"}]}),
            ),
        ] {
            let seq = sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(crate::events::KERNEL_ROOT_ID).bind(event_type).bind(payload.to_string()).bind("fixture:actor").bind("2026-11-08T00:00:00Z")
                .execute(db.write_pool()).await.unwrap().last_insert_rowid();
            assert_eq!(
                notifications::vector(db.pool())
                    .await
                    .unwrap()
                    .authorization,
                seq,
                "{event_type}"
            );
        }
        db.close().await;
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn v2_inspection_opens_never_maintain_sql_event_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inspection.db");
    let url = path.to_str().unwrap();
    let (db, _) = create_v2_database(url, "account", "Owner", "acct:owner")
        .await
        .unwrap();
    prepare_v2_database(&db).await.unwrap();
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(
        sql_event_projection::cache_objects_on(&mut conn)
            .await
            .unwrap()
            .is_empty(),
        "creation and preparation must defer the disposable schema to serving"
    );
    drop(conn);
    db.close().await;

    let before = crate::v1_import::cutover::snapshot_digest(&path)
        .await
        .unwrap();
    let inspector = open_marked_v2_database(url).await.unwrap();
    // The same post-commit wake used by successful writes must remain inert
    // for a tooling handle, even when it owns writable connections.
    inspector.spawn_sql_event_projection_fold();
    inspector.settle_sql_event_projection().await;
    inspector.close().await;
    assert_eq!(
        before,
        crate::v1_import::cutover::snapshot_digest(&path)
            .await
            .unwrap()
    );

    let frozen = open_marked_v2_database(url).await.unwrap();
    frozen.start_serving_sql_event_projection_with_barrier(
        crate::mcp::DeploymentMutationBarrier::boot_frozen(),
    );
    frozen.settle_sql_event_projection().await;
    frozen.close().await;
    assert_eq!(
        before,
        crate::v1_import::cutover::snapshot_digest(&path)
            .await
            .unwrap(),
        "a physically writable serving handle still needs deployment write admission"
    );

    let serving = open_marked_v2_database(url).await.unwrap();
    serving.start_serving_sql_event_projection_with_barrier(Default::default());
    serving.settle_sql_event_projection().await;
    let frontier: i64 =
        sqlx::query_scalar("SELECT frontier_seq FROM kernel_sql_event_projection_state")
            .fetch_one(serving.pool())
            .await
            .unwrap();
    assert!(
        frontier > 0,
        "admitted serving handles still rebuild the cache"
    );
    serving.close().await;

    // A valid populated cache must also remain byte-for-byte logically stable
    // on a new inspection open, including its generation and lease timestamp.
    let before = crate::v1_import::cutover::snapshot_digest(&path)
        .await
        .unwrap();
    let inspector = open_marked_v2_database(url).await.unwrap();
    inspector.spawn_sql_event_projection_fold();
    inspector.settle_sql_event_projection().await;
    inspector.close().await;
    assert_eq!(
        before,
        crate::v1_import::cutover::snapshot_digest(&path)
            .await
            .unwrap()
    );

    let readonly = db::open_marked_v2_database_read_only_at(&path)
        .await
        .unwrap();
    readonly.start_serving_sql_event_projection();
    readonly.settle_sql_event_projection().await;
    readonly.close().await;
    assert_eq!(
        before,
        crate::v1_import::cutover::snapshot_digest(&path)
            .await
            .unwrap()
    );
}

/// Stored-visibility marking objects (73ad275 C1) are local accelerators:
/// installing exactly the compiled set leaves the standby schema coordinate
/// and the projection digest unchanged, so a primary that marks still
/// certifies; any drifted marking object moves the coordinate and fails.
#[tokio::test]
async fn stored_visibility_marking_objects_are_exempt_only_when_exact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marking.db");
    let (db, admin) = create_v2_database(path.to_str().unwrap(), "account", "Admin", "test:admin")
        .await
        .unwrap();
    create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    let coordinates = |db: Db| async move {
        let mut conn = db.pool().acquire().await.unwrap();
        crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .map(|c| c.schema_sha256)
    };
    let before = coordinates(db.clone()).await.unwrap();
    let digest = projection_dump::dump(&db).await.unwrap().sha256;
    let mut tx = db::begin_write(db.write_pool()).await.unwrap();
    stored_visibility::install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(coordinates(db.clone()).await.unwrap(), before);
    assert_eq!(projection_dump::dump(&db).await.unwrap().sha256, digest);
    // Marked writes change no certified schema state.
    create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    assert_eq!(coordinates(db.clone()).await.unwrap(), before);
    let mut tx = db::begin_write(db.write_pool()).await.unwrap();
    stored_visibility::drop_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(coordinates(db.clone()).await.unwrap(), before);
    let mut tx = db::begin_write(db.write_pool()).await.unwrap();
    stored_visibility::install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query("DROP TRIGGER main.p_mark_kernel_records_update; CREATE TRIGGER p_mark_kernel_records_update AFTER UPDATE ON kernel_records BEGIN SELECT 1; END")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(
        coordinates(db.clone())
            .await
            .map_or(true, |schema| schema != before),
        "a drifted marking trigger must not certify"
    );
}

/// Accelerator drift survives export and still fails the receiver's real
/// owned-schema verification, including unknown triggers and indexes of any
/// name attached to an exact marking table. Without the whole-set guard, the
/// exact table drop erases the attached object and the copy would be wrongly
/// accepted.
#[tokio::test]
async fn exported_accelerator_drift_still_fails_receiver_schema_verification() {
    async fn verify(path: &std::path::Path) -> Result<String> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true);
        let mut conn = sqlx::ConnectOptions::connect(&options).await?;
        let result = crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .map(|c| c.schema_sha256);
        sqlx::Connection::close(conn).await?;
        result
    }
    let dir = tempfile::tempdir().unwrap();
    for (index, drift) in [
        None,
        Some("CREATE INDEX dirty_by_key ON p_dirty(key)"),
        Some("CREATE INDEX p_dirty_by_key ON p_dirty(key)"),
        Some("CREATE TRIGGER evil AFTER INSERT ON p_dirty BEGIN SELECT 1; END"),
        Some("CREATE TRIGGER p_evil AFTER INSERT ON p_marking BEGIN SELECT 1; END"),
        Some("CREATE TABLE p_unknown(x)"),
    ]
    .into_iter()
    .enumerate()
    {
        let path = dir.path().join(format!("drift-{index}.db"));
        let (db, admin) =
            create_v2_database(path.to_str().unwrap(), "account", "Admin", "test:admin")
                .await
                .unwrap();
        create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let mut tx = db::begin_write(db.write_pool()).await.unwrap();
        stored_visibility::install_on(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        if let Some(drift) = drift {
            sqlx::query(drift).execute(db.write_pool()).await.unwrap();
        }
        let export = crate::export::export_connected_db(&db, None).await.unwrap();
        let verified = verify(&export.path()).await;
        match drift {
            None => {
                verified.unwrap();
            }
            Some(drift) => {
                assert!(
                    verified.is_err(),
                    "{drift}: drift must fail receiver verification"
                );
                if drift.contains("ON p_dirty") {
                    // The guard is what keeps it: the unguarded strip makes a
                    // copy that verifies even though it lost the drift.
                    let mut conn = sqlx::ConnectOptions::connect(
                        &sqlx::sqlite::SqliteConnectOptions::new().filename(export.path()),
                    )
                    .await
                    .unwrap();
                    let mut tx = sqlx::Connection::begin(&mut conn).await.unwrap();
                    stored_visibility::strip_without_dependency_guard_for_test(&mut tx)
                        .await
                        .unwrap();
                    tx.commit().await.unwrap();
                    sqlx::Connection::close(conn).await.unwrap();
                    assert!(
                        verify(&export.path()).await.is_ok(),
                        "{drift}: the unguarded strip hides the drift"
                    );
                }
            }
        }
        export.cleanup().await;
        db.close().await;
    }
}
