use super::*;
use crate::Db;
use std::path::{Path, PathBuf};

async fn fixture() -> (tempfile::TempDir, PathBuf, Db) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel.db");
    let (db, _) =
        crate::kernel::create_v2_database(path.to_str().unwrap(), "account", "Owner", "acct:owner")
            .await
            .unwrap();
    // This suite qualifies the frozen FORMAT-1 preparation floor, not the
    // current format-2 emitter. No rows exist yet in this disposable fixture.
    sqlx::query("DROP TABLE kernel_mcp_write_receipts")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("DROP INDEX IF EXISTS idx_kernel_mcp_write_fence_events")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("CREATE TABLE kernel_mcp_write_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,operation,operation_key))").execute(db.write_pool()).await.unwrap();
    (directory, path, db)
}

async fn omit_preparation_indexes(db: &Db) {
    for (name, _) in crate::kernel::webhooks::PREPARATION_INDEXES {
        sqlx::query(&format!("DROP INDEX {name}"))
            .execute(db.write_pool())
            .await
            .unwrap();
    }
}

fn generation(head: &ReleaseTenantHead) -> &super::super::kernel_v2::KernelGeneration {
    match head {
        ReleaseTenantHead::KernelV2(head) => &head.generation,
        ReleaseTenantHead::V1(_) => panic!("expected a kernel-v2 release head"),
    }
}

// SQLite can coordinate read marks in SHM. Equality must not change either
// database bytes or committed WAL bytes; live fixtures retain their writer
// connections so the test also observes committed WAL, not just a cold file.
fn database_bytes(path: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    (
        std::fs::read(path).unwrap(),
        std::fs::read(path.with_extension("db-wal")).ok(),
    )
}

#[tokio::test]
async fn release_v2_preparation_floor_preserves_actual_hash_and_strict_admission() {
    let (_directory, path, db) = fixture().await;
    let ready = read_release_tenant_head_from_path(&path).await.unwrap();
    // Fresh files retain both exact lookup accelerators, but compatibility
    // coordinates must stay at the frozen pre-accelerator target hash.
    assert_eq!(
        generation(&ready).schema_sha256,
        super::super::kernel_v2::RELEASE_PRE_WEBHOOK_SOURCE_V1_TARGET_SCHEMA_SHA256
    );
    omit_preparation_indexes(&db).await;
    let before = database_bytes(&path);
    let unprepared = read_release_tenant_head_from_path(&path).await.unwrap();
    unprepared.validate().unwrap();
    assert!(generation(&unprepared).validate().is_err());
    for (reader_format, schema_sha256) in [
        (
            generation(&unprepared).reader_format + 1,
            generation(&unprepared).schema_sha256.clone(),
        ),
        (generation(&unprepared).reader_format, "0".repeat(64)),
    ] {
        let mut invalid = unprepared.clone();
        let ReleaseTenantHead::KernelV2(head) = &mut invalid else {
            unreachable!()
        };
        head.generation.reader_format = reader_format;
        head.generation.schema_sha256 = schema_sha256;
        assert!(invalid.validate().is_err());
    }
    assert_eq!(
        generation(&unprepared).schema_sha256,
        super::super::kernel_v2::RELEASE_PRE_WEBHOOK_SOURCE_V1_SCHEMA_SHA256
    );
    assert_ne!(
        generation(&unprepared).schema_sha256,
        generation(&ready).schema_sha256
    );
    assert_eq!(
        generation(&unprepared).projection_tables,
        generation(&ready).projection_tables
    );
    assert_eq!(
        generation(&unprepared).head_act,
        generation(&ready).head_act
    );
    assert_eq!(
        generation(&unprepared).content_event_seq,
        generation(&ready).content_event_seq
    );
    let mut connection = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .read_only(true),
    )
    .await
    .unwrap();
    assert!(crate::kernel::verify_v2_ready_on(&mut connection)
        .await
        .is_err());
    assert!(super::super::kernel_v2::coordinates(&mut connection)
        .await
        .is_err());
    connection.close().await.unwrap();
    assert!(crate::kernel::verify_marked_v2_file_read_only(&path)
        .await
        .is_err());
    assert!(
        crate::kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .is_err()
    );
    assert_eq!(database_bytes(&path), before);
    // Exercise the existing actual preparation operator, not a test-only
    // substitute. Adding the three indexes restores the original ready head.
    crate::kernel::webhooks::prepare_existing_indexes(&db)
        .await
        .unwrap();
    assert_eq!(
        read_release_tenant_head_from_path(&path).await.unwrap(),
        ready
    );
    crate::kernel::verify_marked_v2_file_read_only(&path)
        .await
        .unwrap();
    let serving = crate::kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    serving.close().await;
    db.close().await;
}

#[tokio::test]
async fn release_v2_preparation_floor_refuses_partial_unrelated_and_data_drift() {
    for drift in [
        crate::kernel::webhooks::INDEX,
        crate::kernel::webhooks::CONFIG_KEY,
        crate::kernel::webhooks::KEYS,
        "DROP INDEX idx_kernel_saved_tab_active",
        "CREATE TABLE unexpected_release_shape(id)",
        "PRAGMA user_version=94",
        "PRAGMA application_id=0",
        "UPDATE kernel_search_meta SET version=-1",
    ] {
        let (_directory, path, db) = fixture().await;
        omit_preparation_indexes(&db).await;
        sqlx::query(drift).execute(db.write_pool()).await.unwrap();
        let before = database_bytes(&path);
        assert!(
            read_release_tenant_head_from_path(&path).await.is_err(),
            "{drift}"
        );
        assert_eq!(database_bytes(&path), before, "{drift}");
        db.close().await;
    }
    let (_directory, path, db) = fixture().await;
    let mut writer = db.write_pool().acquire().await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_webhook_events")
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query("CREATE INDEX idx_kernel_webhook_events ON content_events(seq)")
        .execute(&mut *writer)
        .await
        .unwrap();
    let ddl: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE name='idx_kernel_webhook_events'")
            .fetch_one(&mut *writer)
            .await
            .unwrap();
    assert_eq!(
        ddl,
        "CREATE INDEX idx_kernel_webhook_events ON content_events(seq)"
    );
    drop(writer);
    let before = database_bytes(&path);
    assert!(read_release_tenant_head_from_path(&path).await.is_err());
    assert_eq!(database_bytes(&path), before);
    db.close().await;
}

#[tokio::test]
async fn release_v2_preparation_floor_observes_changed_wal_coordinates() {
    let (_directory, path, db) = fixture().await;
    omit_preparation_indexes(&db).await;
    let original = read_release_tenant_head_from_path(&path).await.unwrap();
    let mut writer = db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA wal_autocheckpoint=0")
        .execute(&mut *writer)
        .await
        .unwrap();
    let main_before = std::fs::read(&path).unwrap();
    sqlx::query("UPDATE act_state SET next_act=next_act+1 WHERE singleton=1")
        .execute(&mut *writer)
        .await
        .unwrap();
    drop(writer);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        main_before,
        "the changed act must still be in WAL"
    );
    let before = database_bytes(&path);
    assert!(before.1.as_ref().is_some_and(|wal| !wal.is_empty()));
    let changed = read_release_tenant_head_from_path(&path).await.unwrap();
    assert_ne!(
        changed, original,
        "a prepared receipt cannot hide an advanced act"
    );
    assert_eq!(
        generation(&changed).schema_sha256,
        generation(&original).schema_sha256
    );
    assert_eq!(
        generation(&changed).head_act,
        generation(&original).head_act + 1
    );
    assert_eq!(database_bytes(&path), before);
    db.close().await;
}

#[tokio::test]
async fn release_v2_preparation_floor_matches_actual_unique_index_constraints() {
    for (event_type, left, right, accepted) in [
        (crate::kernel::webhooks::CONFIGURED, "{}", "{}", false),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":"same"}"#,
            r#"{"submission_key":"same"}"#,
            false,
        ),
        (crate::kernel::webhooks::ACCEPTED, "{}", "{}", true),
        (crate::kernel::webhooks::ACCEPTED, "[]", "[]", true),
        (crate::kernel::webhooks::ACCEPTED, "7", "7", true),
        (
            crate::kernel::webhooks::ACCEPTED,
            "not-json",
            "not-json",
            false,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":""}"#,
            r#"{"submission_key":""}"#,
            false,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":true}"#,
            r#"{"submission_key":1}"#,
            false,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":9007199254740992}"#,
            r#"{"submission_key":9007199254740992.0}"#,
            false,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":9007199254740993}"#,
            r#"{"submission_key":9007199254740992.0}"#,
            true,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":null}"#,
            r#"{"submission_key":null}"#,
            true,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":1}"#,
            r#"{"submission_key":"1"}"#,
            true,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":1}"#,
            r#"{"submission_key":1.0}"#,
            false,
        ),
        (
            crate::kernel::webhooks::ACCEPTED,
            r#"{"submission_key":"left"}"#,
            r#"{"submission_key":"right"}"#,
            true,
        ),
    ] {
        for same_record in [true, false] {
            let unreadable = left == "not-json" || right == "not-json";
            let accepted = !unreadable && (accepted || !same_record);
            let (_directory, path, db) = fixture().await;
            omit_preparation_indexes(&db).await;
            for (index, payload) in [left, right].into_iter().enumerate() {
                sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(if same_record || index == 0 { "fixture-webhook" } else { "other-webhook" })
                .bind(event_type).bind(payload).bind("fixture-actor")
                .execute(db.write_pool()).await.unwrap();
            }
            let before = database_bytes(&path);
            let observed = read_release_tenant_head_diagnosed(&path).await;
            assert_eq!(observed.is_ok(), accepted, "{event_type} {left} {right}");
            if let Err(failure) = observed {
                assert_eq!(
                    failure.phase,
                    if unreadable {
                        ReleaseHeadObservationPhase::V2WebhookKeysUnreadable
                    } else {
                        ReleaseHeadObservationPhase::V2WebhookKeysConflict
                    }
                );
            }
            assert_eq!(database_bytes(&path), before);
            assert_eq!(
                crate::kernel::webhooks::prepare_existing_indexes(&db)
                    .await
                    .is_ok(),
                accepted,
                "{event_type} {left} {right}"
            );
            db.close().await;
        }
    }
}

#[tokio::test]
async fn release_v2_lookup_accelerator_normalization_keeps_readiness_strict() {
    for omit_webhooks in [false, true] {
        for changes in [
            vec!["DROP INDEX idx_kernel_record_names"],
            vec!["DROP INDEX idx_kernel_record_logical_homes"],
            vec![
                "DROP INDEX idx_kernel_record_names",
                "DROP INDEX idx_kernel_record_logical_homes",
            ],
            vec![
                "DROP INDEX idx_kernel_record_names",
                "CREATE INDEX idx_kernel_record_names ON kernel_record_fields(record_id)",
            ],
            vec![
                "DROP INDEX idx_kernel_record_logical_homes",
                "CREATE INDEX idx_kernel_record_logical_homes ON content_events(record_id)",
            ],
        ] {
            let (_directory, path, db) = fixture().await;
            if omit_webhooks {
                omit_preparation_indexes(&db).await;
            }
            let mut writer = db.write_pool().acquire().await.unwrap();
            for change in &changes {
                sqlx::query(change).execute(&mut *writer).await.unwrap();
            }
            drop(writer);
            let before = database_bytes(&path);
            let failure = read_release_tenant_head_diagnosed(&path).await.unwrap_err();
            let wrong_definition = changes.iter().any(|sql| sql.starts_with("CREATE"));
            assert_eq!(
                failure.phase,
                if wrong_definition {
                    ReleaseHeadObservationPhase::V2Schema
                } else {
                    ReleaseHeadObservationPhase::V2Readiness
                },
                "omit_webhooks={omit_webhooks}; changes={changes:?}"
            );
            assert_eq!(database_bytes(&path), before);
            assert!(crate::kernel::verify_marked_v2_file_read_only(&path)
                .await
                .is_err());
            assert_eq!(database_bytes(&path), before);
            db.close().await;
        }
    }
}

#[tokio::test]
async fn release_head_diagnostics_are_bounded_and_do_not_create_missing_files() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("private-tenant-must-not-appear.db");
    let failure = read_release_tenant_head_diagnosed(&missing)
        .await
        .unwrap_err();
    assert_eq!(failure.phase, ReleaseHeadObservationPhase::Open);
    assert_eq!(failure.phase.code(), "head_open");
    assert!(!missing.exists());
    let (_directory, path, db) = fixture().await;
    omit_preparation_indexes(&db).await;
    sqlx::query("CREATE TABLE unexpected_release_shape(id)")
        .execute(db.write_pool())
        .await
        .unwrap();
    let before = database_bytes(&path);
    let failure = read_release_tenant_head_diagnosed(&path).await.unwrap_err();
    assert_eq!(failure.phase, ReleaseHeadObservationPhase::V2Schema);
    assert_eq!(failure.phase.code(), "head_v2_schema");
    assert_eq!(database_bytes(&path), before);
    db.close().await;
}
