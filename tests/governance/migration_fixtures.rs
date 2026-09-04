//! Migration-mechanism tests that do not imply compatibility with a historical
//! product schema. Product compatibility starts only when a release baseline is
//! deliberately selected.

use flate2::read::GzDecoder;
use futures::FutureExt;
use native_ce::backup::{BackupSink, FsSink};
use native_ce::migrations::{
    migrate_database, EngineMigration, EngineMigrationRegistry, EngineMigrationStep, FenceFn,
    MigrationPreimageStore, PreimageBackup,
};
use native_ce::store::create_record;
use native_ce::{
    create_database, open_existing_database_at, Db, Error, CURRENT_ENGINE_SCHEMA_VERSION,
    SUPPORTED_ENGINE_SCHEMA_BASELINE,
};
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

/// The fixture record ids must be canonical lowercase UUIDs; the readable name
/// lives in the constant. Pinned literal, never generated.
const MIGRATION_KERNEL_RECORD: &str = "607a0000-0000-4000-8000-000000000001";

fn always_fenced() -> FenceFn {
    Arc::new(|| async { Ok(()) }.boxed())
}

#[derive(Clone)]
struct FixturePreimageStore {
    sink: Arc<dyn BackupSink>,
}

impl MigrationPreimageStore for FixturePreimageStore {
    fn store_verified_preimage(
        &self,
        run_id: &str,
        db_id: &str,
        source: &Path,
    ) -> futures::future::BoxFuture<'static, native_ce::Result<PreimageBackup>> {
        let sink = self.sink.clone();
        let key = format!("_migrations/{run_id}/{db_id}.preimage.db");
        let source = source.to_path_buf();
        async move {
            let expected = tokio::fs::read(&source).await?;
            let digest = hex::encode(Sha256::digest(&expected));
            sink.put(key.clone(), source.clone()).await?;
            let readback = source.with_extension("readback.db");
            sink.get(key.clone(), readback.clone()).await?;
            let actual = tokio::fs::read(&readback).await?;
            let _ = tokio::fs::remove_file(&readback).await;
            if actual != expected {
                return Err(Error::engine("test pre-image readback mismatch"));
            }
            Ok(PreimageBackup { key, digest })
        }
        .boxed()
    }
}

fn preimage_store(offbox: &Path, data_dir: &Path) -> FixturePreimageStore {
    FixturePreimageStore {
        sink: Arc::new(FsSink::outside(offbox, data_dir).unwrap()),
    }
}

fn step(from: i64, to: i64, name: &str, apply: &[&str]) -> Arc<dyn EngineMigrationStep> {
    Arc::new(EngineMigration {
        from,
        to,
        name: name.into(),
        preflight: vec![],
        apply: apply.iter().map(|statement| (*statement).into()).collect(),
    })
}

fn one_step_future_registry(apply: &[&str]) -> EngineMigrationRegistry {
    EngineMigrationRegistry::new(
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        CURRENT_ENGINE_SCHEMA_VERSION,
        vec![step(
            CURRENT_ENGINE_SCHEMA_VERSION,
            CURRENT_ENGINE_SCHEMA_VERSION + 1,
            "synthetic-next",
            apply,
        )],
    )
    .unwrap()
}

#[tokio::test]
async fn failed_step_rolls_back_version_and_ddl_after_verified_preimage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("user.db");
    create_database(&path.to_string_lossy())
        .await
        .unwrap()
        .close()
        .await;
    let offbox = tempdir().unwrap();
    let registry = one_step_future_registry(&[
        "CREATE TABLE synthetic_partial (id INTEGER)",
        "INSERT INTO table_that_does_not_exist VALUES (1)",
    ]);
    let report = migrate_database(
        &path,
        "user",
        "run",
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        &registry,
        &preimage_store(offbox.path(), dir.path()),
        always_fenced(),
    )
    .await;
    assert_eq!(report.outcome, "failed");
    assert!(report.backup.is_some());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        CURRENT_ENGINE_SCHEMA_VERSION
    );
    let exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'synthetic_partial'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 0);
}

#[tokio::test]
async fn stale_fence_cannot_reach_the_first_mutation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("user.db");
    create_database(&path.to_string_lossy())
        .await
        .unwrap()
        .close()
        .await;
    let offbox = tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let fence: FenceFn = Arc::new({
        let calls = calls.clone();
        move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(())
                } else {
                    Err(native_ce::Error::engine("lease taken over"))
                }
            }
            .boxed()
        }
    });
    let report = migrate_database(
        &path,
        "user",
        "stale-run",
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        &one_step_future_registry(&["CREATE TABLE must_not_exist (id INTEGER)"]),
        &preimage_store(offbox.path(), dir.path()),
        fence,
    )
    .await;
    assert_eq!(report.error_kind.as_deref(), Some("fence"));
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        CURRENT_ENGINE_SCHEMA_VERSION
    );
    let exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'must_not_exist'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 0);
}

#[tokio::test]
async fn preflight_is_physically_read_only_and_runs_before_backup() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("user.db");
    create_database(&path.to_string_lossy())
        .await
        .unwrap()
        .close()
        .await;
    let offbox = tempdir().unwrap();
    let registry = EngineMigrationRegistry::new(
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        CURRENT_ENGINE_SCHEMA_VERSION,
        vec![Arc::new(EngineMigration {
            from: CURRENT_ENGINE_SCHEMA_VERSION,
            to: CURRENT_ENGINE_SCHEMA_VERSION + 1,
            name: "bad-preflight".into(),
            preflight: vec!["CREATE TABLE forbidden_preflight_write (id INTEGER)".into()],
            apply: vec!["CREATE TABLE must_not_apply (id INTEGER)".into()],
        })],
    )
    .unwrap();
    let report = migrate_database(
        &path,
        "user",
        "run",
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        &registry,
        &preimage_store(offbox.path(), dir.path()),
        always_fenced(),
    )
    .await;
    assert_eq!(report.error_kind.as_deref(), Some("preflight"));
    assert!(report.backup.is_none());
    assert!(std::fs::read_dir(offbox.path()).unwrap().next().is_none());
    let connection = Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('forbidden_preflight_write','must_not_apply')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

async fn seed_current_database(path: &Path) -> Db {
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    create_record(
        &db,
        json!({
            "id": MIGRATION_KERNEL_RECORD,
            "type": "Document",
            "kind": "note",
            "name": "Preserve me",
            "body": "migration safety kernel"
        }),
    )
    .await
    .unwrap();
    db
}

fn install_engine_39_fixture(path: &Path) {
    const GZIP_SHA256: &str = "96e0e67102ca98d61c107d339812fd78a3825dce25eef83792896e89b24ba971";
    const DB_SHA256: &str = "189a64f4e4e429e6cc9739503f677eaccf3f3b956648cb9f10cd9d99e170dc76";
    let fixture = include_bytes!("../fixtures/engine-v39-30350c0e.db.gz");
    assert_eq!(hex::encode(Sha256::digest(fixture)), GZIP_SHA256);
    let mut database = Vec::new();
    GzDecoder::new(fixture.as_slice())
        .read_to_end(&mut database)
        .unwrap();
    assert_eq!(hex::encode(Sha256::digest(&database)), DB_SHA256);
    std::fs::write(path, database).unwrap();
}

fn seed_v39_action_attestation(path: &Path) -> (String, String) {
    let connection = Connection::open(path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let event_id: String = connection
        .query_row(
            "SELECT id FROM content_events WHERE record_id=? ORDER BY seq LIMIT 1",
            [MIGRATION_KERNEL_RECORD],
            |row| row.get(0),
        )
        .unwrap();
    let origin: String = connection
        .query_row(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let attestation_id = "frozen-v39-action-attestation".to_owned();
    let operation = "fixture_migration";
    let principal = "local:fixture";
    let commitment = json!({
        "operation": operation,
        "arguments_digest": native_ce::derivation::digest_json(&json!({})),
    });
    let commitment_text =
        String::from_utf8(native_ce::derivation::canonical_json(&commitment)).unwrap();
    let action_digest = native_ce::derivation::digest_json(&commitment);
    let output_digest = native_ce::derivation::digest_json(&json!([event_id]));
    connection
        .execute(
            "INSERT INTO provenance_action_attestations
             (id,schema_version,principal,executor_kind,operation,action_commitment,
              action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES (?1,1,?2,'local',?3,?4,?5,?6,'native-ce',?7,'2026-08-19T00:00:00.000Z')",
            rusqlite::params![
                attestation_id,
                principal,
                operation,
                commitment_text,
                action_digest,
                output_digest,
                origin,
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provenance_local_attestation_authority
             (attestation_id,issuer_origin_database_id,principal,operation,anchored_at)
             VALUES (?1,?2,?3,?4,'2026-08-19T00:00:00.000Z')",
            rusqlite::params![attestation_id, origin, principal, operation],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provenance_action_outputs
             (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES (?1,0,'content',?2)",
            rusqlite::params![attestation_id, event_id],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO provenance_action_events
             (action_attestation_id,ordinal,output_event_id) VALUES (?1,0,?2)",
            rusqlite::params![attestation_id, event_id],
        )
        .unwrap();
    (attestation_id, event_id)
}

/// The production registry must span exactly the baseline it declares.
///
/// This test previously asserted the opposite — that there was no baseline and
/// no historical path at all. That was the correct invariant while both schema
/// tracks were pre-baseline, and engine 40 ended it: with a baseline of `None`
/// the capability attestation reads `engine_minimum` as the *current* version,
/// which claims the protocol has dropped support for every v39 database. The
/// invariant is no longer "there is no path" but "the declared path is real
/// and complete", which is what is checked here.
#[test]
fn production_registry_spans_exactly_its_declared_baseline() {
    let baseline = SUPPORTED_ENGINE_SCHEMA_BASELINE
        .expect("engine 40 requires a declared baseline; see FIRST_ENGINE_BASELINE");
    let registry = EngineMigrationRegistry::production();
    assert_eq!(registry.supported_baseline, Some(baseline));

    // Every step from the baseline to current must be reachable, or a database
    // at the baseline is refused by a registry that claims to support it.
    let steps = registry
        .pending(baseline, CURRENT_ENGINE_SCHEMA_VERSION)
        .expect("the declared baseline must be reachable");
    assert_eq!(
        steps.len(),
        (CURRENT_ENGINE_SCHEMA_VERSION - baseline) as usize
    );
    for (offset, step) in steps.iter().enumerate() {
        assert_eq!(step.from(), baseline + offset as i64);
        assert_eq!(step.to(), baseline + offset as i64 + 1);
    }

    // A current database still needs no work.
    assert!(registry
        .pending(CURRENT_ENGINE_SCHEMA_VERSION, CURRENT_ENGINE_SCHEMA_VERSION)
        .unwrap()
        .is_empty());

    // Below the declared baseline is still refused rather than attempted.
    assert!(registry
        .pending(baseline - 1, CURRENT_ENGINE_SCHEMA_VERSION)
        .is_err());
}

#[tokio::test]
async fn production_runner_accepts_the_frozen_v39_shape_and_rejects_a_restamp() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("released-v39.db");
    install_engine_39_fixture(&path);
    let (attestation_id, event_id) = seed_v39_action_attestation(&path);

    assert_eq!(
        native_ce::migrations::preflight_production_migration_read_only(&path)
            .await
            .unwrap(),
        39
    );
    let offbox = tempdir().unwrap();
    let registry = EngineMigrationRegistry::production();
    let report = migrate_database(
        &path,
        "released-v39",
        "production-v39-v40",
        CURRENT_ENGINE_SCHEMA_VERSION,
        &registry,
        &preimage_store(offbox.path(), dir.path()),
        always_fenced(),
    )
    .await;
    assert_eq!(report.outcome, "migrated", "{report:?}");
    let migrated = Connection::open(&path).unwrap();
    assert_eq!(
        migrated
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert!(migrated
        .prepare("SELECT channel FROM provenance_action_attestations")
        .is_ok());
    assert_eq!(
        migrated
            .query_row(
                "SELECT channel FROM provenance_action_attestations WHERE id=?",
                [&attestation_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "unknown"
    );
    assert_eq!(
        migrated
            .query_row(
                "SELECT output_event_id FROM provenance_action_events WHERE action_attestation_id=?",
                [&attestation_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        event_id
    );
    assert_eq!(
        migrated
            .query_row(
                "SELECT COUNT(*) FROM provenance_local_attestation_authority WHERE attestation_id=?",
                [&attestation_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        migrated
            .query_row(
                "SELECT COUNT(*) FROM provenance_action_outputs WHERE action_attestation_id=?",
                [&attestation_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    // The 40→41 drill hop must have materialized on the multi-hop path too:
    // exactly one append-only drill row, recording the edge it crossed.
    assert_eq!(
        migrated
            .query_row(
                "SELECT COUNT(*) FROM engine_migration_drills WHERE from_version=40 AND to_version=41",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );

    let restamped = dir.path().join("restamped-current.db");
    seed_current_database(&restamped).await.close().await;
    Connection::open(&restamped)
        .unwrap()
        .pragma_update(None, "user_version", 39)
        .unwrap();
    assert!(
        native_ce::migrations::preflight_production_migration_read_only(&restamped)
            .await
            .is_err()
    );
}

#[test]
fn registry_rejects_invalid_shapes_and_selects_contiguous_ranges() {
    for (case, result) in [
        (
            "minimum above current",
            EngineMigrationRegistry::new(1, 2, vec![]),
        ),
        (
            "registry gap",
            EngineMigrationRegistry::new(3, 1, vec![step(1, 2, "one", &[])]),
        ),
        (
            "non-forward edge",
            EngineMigrationRegistry::new(1, 1, vec![step(1, 1, "flat", &[])]),
        ),
        (
            "duplicate edge",
            EngineMigrationRegistry::new(
                2,
                1,
                vec![step(1, 2, "one", &[]), step(1, 2, "duplicate", &[])],
            ),
        ),
    ] {
        assert!(result.is_err(), "{case} was accepted");
    }

    let registry = EngineMigrationRegistry::new(
        4,
        1,
        vec![
            step(1, 2, "one", &[]),
            step(2, 3, "two", &[]),
            step(3, 4, "three", &[]),
        ],
    )
    .unwrap();
    assert_eq!(
        registry
            .pending(2, 4)
            .unwrap()
            .iter()
            .map(|migration| migration.name())
            .collect::<Vec<_>>(),
        vec!["two", "three"]
    );
    assert!(registry.pending(0, 2).is_err());
    assert!(registry.pending(3, 2).is_err());
    assert!(registry.pending(1, 5).is_err());
    assert!(registry.pending(4, 4).unwrap().is_empty());
}

#[tokio::test]
async fn synthetic_forward_migration_preserves_public_writes_and_preimage() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("synthetic-forward.db");
    seed_current_database(&path).await.close().await;

    let offbox = tempdir().unwrap();
    let backup = preimage_store(offbox.path(), dir.path());
    let report = migrate_database(
        &path,
        "synthetic-user",
        "synthetic-run",
        CURRENT_ENGINE_SCHEMA_VERSION + 1,
        &one_step_future_registry(&["CREATE TABLE migration_marker (id INTEGER)"]),
        &backup,
        always_fenced(),
    )
    .await;
    assert_eq!(report.outcome, "migrated", "{report:?}");

    let migrated = Connection::open(&path).unwrap();
    assert_eq!(
        migrated
            .query_row(
                "SELECT body FROM records WHERE id=?1",
                [MIGRATION_KERNEL_RECORD],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "migration safety kernel"
    );
    assert_eq!(
        migrated
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        CURRENT_ENGINE_SCHEMA_VERSION + 1
    );

    let captured = report.backup.expect("verified preimage");
    let restored = dir.path().join("restored.db");
    backup
        .sink
        .get(captured.key, restored.clone())
        .await
        .unwrap();
    let restored = open_existing_database_at(&restored).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
            .bind(MIGRATION_KERNEL_RECORD)
            .fetch_one(restored.pool())
            .await
            .unwrap(),
        "migration safety kernel"
    );
    restored.close().await;
}

#[tokio::test]
async fn multi_hop_commits_completed_steps_and_rolls_back_only_the_failure() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("multi-hop.db");
    seed_current_database(&path).await.close().await;
    let registry = EngineMigrationRegistry::new(
        CURRENT_ENGINE_SCHEMA_VERSION + 2,
        CURRENT_ENGINE_SCHEMA_VERSION,
        vec![
            step(
                CURRENT_ENGINE_SCHEMA_VERSION,
                CURRENT_ENGINE_SCHEMA_VERSION + 1,
                "first-hop",
                &["CREATE TABLE committed_hop (id INTEGER)"],
            ),
            step(
                CURRENT_ENGINE_SCHEMA_VERSION + 1,
                CURRENT_ENGINE_SCHEMA_VERSION + 2,
                "failing-second-hop",
                &[
                    "CREATE TABLE rolled_back_hop (id INTEGER)",
                    "INSERT INTO absent_table VALUES (1)",
                ],
            ),
        ],
    )
    .unwrap();
    let offbox = tempdir().unwrap();
    let report = migrate_database(
        &path,
        "multi-hop-user",
        "multi-hop-run",
        CURRENT_ENGINE_SCHEMA_VERSION + 2,
        &registry,
        &preimage_store(offbox.path(), dir.path()),
        always_fenced(),
    )
    .await;
    assert_eq!(report.error_kind.as_deref(), Some("apply"));

    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        CURRENT_ENGINE_SCHEMA_VERSION + 1
    );
    let objects: Vec<String> = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE name IN ('committed_hop', 'rolled_back_hop') ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(objects, vec!["committed_hop"]);
}
