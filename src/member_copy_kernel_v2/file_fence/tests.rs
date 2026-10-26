use super::*;
use crate::{
    db::Db,
    kernel,
    member_copy_transport::{test_consumer, CredentialSelection},
    replica_generation::{
        ReplicaOrdering, ReplicaOwnWrites, REPLICA_GENERATION_CONTRACT, REPLICA_GENERATION_VERSION,
    },
    standby_snapshot::{
        StandbyGenerationMaterialization, StandbySnapshotBytes, StandbySnapshotEngineIdentity,
        STANDBY_SNAPSHOT_MEDIA_TYPE,
    },
};
use rusqlite::OpenFlags;
use std::path::Path;

const ACCOUNT: &str = "acct_00000000000000000000000000000001";

struct Fixture {
    dir: tempfile::TempDir,
    db: Db,
    cut: NativeMemberCut,
    manifest: ReplicaGenerationManifest,
    context: MemberCopyContext,
    destination: NativeMemberFileBuilder,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, _) = kernel::create_v2_database(
            dir.path().join("source.db").to_str().unwrap(),
            "account",
            "Owner",
            ACCOUNT,
        )
        .await
        .unwrap();
        super::super::tests::activate(&db, ACCOUNT, &[ACCOUNT]).await;
        let mut source = db.pool().begin().await.unwrap();
        let generation = crate::standby::kernel_v2::coordinates(&mut source)
            .await
            .unwrap();
        let origin = crate::standby::kernel_v2::origin(&mut source, &generation)
            .await
            .unwrap();
        let cut =
            super::super::tests::ready(capture_in(&mut source, &origin, ACCOUNT).await.unwrap());
        source.rollback().await.unwrap();
        let context = MemberCopyContext::new(
            ACCOUNT.into(),
            "https://example.invalid".into(),
            "route-test".into(),
            origin.clone(),
            test_consumer(),
            "scope-one".into(),
            CredentialSelection::for_test(b"authenticated fixture credential"),
        );
        let manifest = ReplicaGenerationManifest {
            contract: REPLICA_GENERATION_CONTRACT.into(),
            version: REPLICA_GENERATION_VERSION,
            origin_database_id: origin,
            hosted_route_database_id: "route-test".into(),
            captured_at: "2026-10-22T00:00:00Z".into(),
            snapshot_completed_at: "2026-10-22T00:00:01Z".into(),
            producer: StandbySnapshotEngineIdentity {
                name: "native-ce".into(),
                source_sha: "a".repeat(40),
                schema_version: 1,
                ddl_sha256: "b".repeat(64),
            },
            consumer: test_consumer(),
            bytes: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                size_bytes: 1024,
                sha256: "c".repeat(64),
            },
            materialization: StandbyGenerationMaterialization::Snapshot,
            scope: ReplicaScope::Member {
                scope_ref: "scope-one".into(),
            },
            ordering: ReplicaOrdering::Scoped { ordinal: 1 },
            holding: crate::holding::HoldingDisclosureV2::member("scope-one".into(), 1),
            profile: ReplicaProfile::MemberReadKernelV2 {
                engine: crate::standby::kernel_v2::ENGINE.into(),
                // A declaration for testing the identity component, not a
                // compiled production schema or a publishable generation.
                member_schema_digest: "d".repeat(64),
                identity: cut.profile_identity(),
            },
            content_digest: "e".repeat(64),
            own_writes: ReplicaOwnWrites::not_computed(),
            frontier: None,
            schema_incomplete_for: vec![],
        };
        let destination = NativeMemberFileBuilder::new_in(dir.path()).unwrap();
        Self {
            destination,
            dir,
            db,
            cut,
            manifest,
            context,
        }
    }
    fn file(&self) -> std::path::PathBuf {
        self.destination._file.path().to_owned()
    }
    async fn initialize(&mut self) {
        let mut source = self.db.pool().begin().await.unwrap();
        initialize_in(
            &mut source,
            &self.cut,
            &mut self.destination,
            &self.manifest,
        )
        .await
        .unwrap();
        source.rollback().await.unwrap();
    }
    fn expected(&self) -> ExpectedFileFence {
        ExpectedFileFence::from_authenticated_context(&self.context, &self.manifest).unwrap()
    }
}
fn read_only(path: &Path) -> Connection {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

#[tokio::test]
async fn native_file_fence_matches_authenticated_footing_but_never_admits_a_profile() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let connection = read_only(&fixture.file());
    verify_on(&connection, &fixture.expected()).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<String, _>(None, "journal_mode", |r| r.get(0))
            .unwrap(),
        "delete"
    );
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    assert_eq!(tables, ["kernel_member_identity"]);
    assert!(!fixture.file().with_extension("db-wal").exists());
    assert!(!fixture.file().with_extension("db-journal").exists());
    assert!(
        crate::member_copy_admission::validate_manifest(&fixture.manifest.canonical_bytes())
            .is_err()
    );
    assert!(crate::db::open_database(fixture.file().to_str().unwrap())
        .await
        .is_err());
    // Component success deliberately returns (), not a Db or serving lease.
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_uses_actual_read_only_connection() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let connection = Connection::open(fixture.file()).unwrap();
    connection.pragma_update(None, "query_only", true).unwrap();
    assert_eq!(
        verify_on(&connection, &fixture.expected()),
        Err(FileFenceRefusal::WritableConnection)
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_rejects_canonical_file_even_with_copied_identity() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let connection = Connection::open(fixture.file()).unwrap();
    for marker in [crate::db::V2_APPLICATION_ID, 0] {
        connection
            .pragma_update(None, "application_id", marker)
            .unwrap();
        assert_eq!(
            verify_on(&read_only(&fixture.file()), &fixture.expected()),
            Err(FileFenceRefusal::Marker)
        );
    }
    // The real canonical source is rejected before inspecting domain tables.
    assert_eq!(
        verify_on(
            &read_only(&fixture.dir.path().join("source.db")),
            &fixture.expected()
        ),
        Err(FileFenceRefusal::Marker)
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_foreign_origin_account_scope_route_and_consumer() {
    let fixture = Fixture::new().await;
    // No candidate file is opened or even exists in this test.
    for change in ["origin", "account", "scope", "route", "consumer"] {
        let mut manifest = fixture.manifest.clone();
        match change {
            "origin" => manifest.origin_database_id = format!("ndb_{}", "f".repeat(32)),
            "account" => {
                let ReplicaProfile::MemberReadKernelV2 { identity, .. } = &mut manifest.profile
                else {
                    unreachable!()
                };
                identity.account_binding = "other-account".into();
            }
            "scope" => {
                manifest.scope = ReplicaScope::Member {
                    scope_ref: "other-scope".into(),
                };
                manifest.holding =
                    crate::holding::HoldingDisclosureV2::member("other-scope".into(), 1);
            }
            "route" => manifest.hosted_route_database_id = "other-route".into(),
            "consumer" => manifest.consumer.source_sha = "f".repeat(40),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                ExpectedFileFence::from_authenticated_context(&fixture.context, &manifest),
                Err(FileFenceRefusal::AuthenticatedBinding)
            ),
            "{change}"
        );
    }
    assert_eq!(std::fs::metadata(fixture.file()).unwrap().len(), 0);
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_non_native_or_malformed_manifests() {
    let fixture = Fixture::new().await;
    for profile in [
        ReplicaProfile::CanonicalEngine,
        ReplicaProfile::MemberReadV1 {
            member_schema_digest: "a".repeat(64),
        },
    ] {
        let mut manifest = fixture.manifest.clone();
        manifest.profile = profile;
        assert!(matches!(
            ExpectedFileFence::from_authenticated_context(&fixture.context, &manifest),
            Err(FileFenceRefusal::Manifest)
        ));
    }
    let mut manifest = fixture.manifest.clone();
    manifest.consumer.source_sha = "invalid".into();
    assert!(matches!(
        ExpectedFileFence::from_authenticated_context(&fixture.context, &manifest),
        Err(FileFenceRefusal::Manifest)
    ));
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_every_changed_identity_coordinate() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let expected = fixture.expected();
    for column in [
        "engine",
        "member_schema_digest",
        "origin_database_id",
        "account_binding",
        "principal_id",
        "genesis_event_id",
        "scope_ref",
        "generation_id",
    ] {
        let mut connection = Connection::open(fixture.file()).unwrap();
        let tx = connection.transaction().unwrap();
        tx.execute(
            &format!("UPDATE kernel_member_identity SET {column}='foreign-value'"),
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            verify_on(&read_only(&fixture.file()), &expected),
            Err(FileFenceRefusal::Identity),
            "{column}"
        );
        drop(connection);
        fixture.destination = NativeMemberFileBuilder::new_in(fixture.dir.path()).unwrap();
        fixture.initialize().await;
    }
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_missing_row_or_changed_schema() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let connection = Connection::open(fixture.file()).unwrap();
    connection
        .execute("DELETE FROM kernel_member_identity", [])
        .unwrap();
    assert_eq!(
        verify_on(&read_only(&fixture.file()), &fixture.expected()),
        Err(FileFenceRefusal::Identity)
    );
    connection
        .execute(
            "ALTER TABLE kernel_member_identity ADD COLUMN hidden_data TEXT",
            [],
        )
        .unwrap();
    assert_eq!(
        verify_on(&read_only(&fixture.file()), &fixture.expected()),
        Err(FileFenceRefusal::Schema)
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_requires_live_source_read_transaction() {
    let mut fixture = Fixture::new().await;
    let mut source = fixture.db.pool().acquire().await.unwrap();
    let destination = &mut fixture.destination;
    assert_eq!(
        initialize_in(&mut source, &fixture.cut, destination, &fixture.manifest).await,
        Err(FileFenceRefusal::SourceTransaction)
    );
    assert_eq!(
        destination
            .connection
            .pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
            .unwrap(),
        0
    );
    drop(source);
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_retargeted_declaration_before_writing() {
    let mut fixture = Fixture::new().await;
    let mut source = fixture.db.pool().begin().await.unwrap();
    let destination = &mut fixture.destination;
    fixture.cut.principal_id = "foreign-principal".into();
    // A manifest changed along with the declaration is still insufficient:
    // the cut's private source authorization fence must compare as well.
    let ReplicaProfile::MemberReadKernelV2 { identity, .. } = &mut fixture.manifest.profile else {
        unreachable!()
    };
    identity.principal_id = "foreign-principal".into();
    assert_eq!(
        initialize_in(&mut source, &fixture.cut, destination, &fixture.manifest).await,
        Err(FileFenceRefusal::SourceChanged)
    );
    source.rollback().await.unwrap();
    assert_eq!(
        destination
            .connection
            .pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
            .unwrap(),
        0
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_foreign_manifest_before_writing() {
    let mut fixture = Fixture::new().await;
    let mut manifest = fixture.manifest.clone();
    manifest.origin_database_id = format!("ndb_{}", "f".repeat(32));
    let mut source = fixture.db.pool().begin().await.unwrap();
    let destination = &mut fixture.destination;
    assert_eq!(
        initialize_in(&mut source, &fixture.cut, destination, &manifest).await,
        Err(FileFenceRefusal::AuthenticatedBinding)
    );
    assert!(destination.phase == BuilderPhase::Attempted);
    assert!(matches!(
        initialize_in(&mut source, &fixture.cut, destination, &fixture.manifest).await,
        Err(FileFenceRefusal::DestinationNotEmpty)
    ));
    source.rollback().await.unwrap();
    assert_eq!(
        destination
            .connection
            .pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
            .unwrap(),
        0
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_never_overwrites_an_existing_destination() {
    let mut fixture = Fixture::new().await;
    let prior = fixture.dir.path().join("existing.db");
    let connection = Connection::open(&prior).unwrap();
    connection.execute_batch("CREATE TABLE secret(value); INSERT INTO secret VALUES('hidden old bytes'); DROP TABLE secret").unwrap();
    drop(connection);
    let before = std::fs::read(&prior).unwrap();
    fixture.initialize().await;
    assert_ne!(fixture.file(), prior);
    assert_eq!(std::fs::read(&prior).unwrap(), before);
    assert!(!std::fs::read(fixture.file())
        .unwrap()
        .windows(b"hidden old bytes".len())
        .any(|bytes| bytes == b"hidden old bytes"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(fixture.file())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let path = fixture.file();
    fixture.db.close().await;
    drop(fixture.destination);
    assert!(!path.exists());
}

#[tokio::test]
async fn native_file_fence_refuses_reinitialization_and_nonempty_builders() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let before = std::fs::read(fixture.file()).unwrap();
    let mut source = fixture.db.pool().begin().await.unwrap();
    assert_eq!(
        initialize_in(
            &mut source,
            &fixture.cut,
            &mut fixture.destination,
            &fixture.manifest
        )
        .await,
        Err(FileFenceRefusal::DestinationNotEmpty)
    );
    assert_eq!(std::fs::read(fixture.file()).unwrap(), before);
    fixture.destination = NativeMemberFileBuilder::new_in(fixture.dir.path()).unwrap();
    // The underscore is literal, not SQL LIKE's single-character wildcard.
    fixture
        .destination
        .connection
        .execute_batch(
            "CREATE TABLE sqlitex_secret(value); INSERT INTO sqlitex_secret VALUES('untouched')",
        )
        .unwrap();
    assert_eq!(
        initialize_in(
            &mut source,
            &fixture.cut,
            &mut fixture.destination,
            &fixture.manifest
        )
        .await,
        Err(FileFenceRefusal::DestinationNotEmpty)
    );
    let value: String = fixture
        .destination
        .connection
        .query_row("SELECT value FROM sqlitex_secret", [], |r| r.get(0))
        .unwrap();
    assert_eq!(value, "untouched");
    source.rollback().await.unwrap();
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_refuses_wal_on_creation_and_verification() {
    let mut fixture = Fixture::new().await;
    fixture
        .destination
        .connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    let mut source = fixture.db.pool().begin().await.unwrap();
    assert_eq!(
        initialize_in(
            &mut source,
            &fixture.cut,
            &mut fixture.destination,
            &fixture.manifest
        )
        .await,
        Err(FileFenceRefusal::JournalMode)
    );
    source.rollback().await.unwrap();
    assert_eq!(
        fixture
            .destination
            .connection
            .pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
            .unwrap(),
        0
    );
    fixture.destination = NativeMemberFileBuilder::new_in(fixture.dir.path()).unwrap();
    fixture.initialize().await;
    fixture
        .destination
        .connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    assert_eq!(
        verify_on(&read_only(&fixture.file()), &fixture.expected()),
        Err(FileFenceRefusal::JournalMode)
    );
    fixture.db.close().await;
}

#[tokio::test]
async fn native_file_fence_ignores_temp_shadows_and_refuses_v1_schema_version() {
    let mut fixture = Fixture::new().await;
    fixture.initialize().await;
    let connection = read_only(&fixture.file());
    connection
        .execute_batch("CREATE TEMP TABLE kernel_member_identity(unrelated_column)")
        .unwrap();
    verify_on(&connection, &fixture.expected()).unwrap();
    drop(connection);
    let connection = Connection::open(fixture.file()).unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    assert_eq!(
        verify_on(&read_only(&fixture.file()), &fixture.expected()),
        Err(FileFenceRefusal::Schema)
    );
    fixture.db.close().await;
}
