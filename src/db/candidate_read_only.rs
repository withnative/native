//! WAL-aware observation of an already owned current-engine file. This is a
//! database handle, not candidate startup, custody or private serving authority.

use super::*;
use std::io::Read;
use std::path::PathBuf;

fn refusal(message: impl fmt::Display) -> Error {
    Error::engine(format!("refusing WAL-aware read-only open: {message}"))
}

fn readable_regular_file(path: &Path) -> Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path).map_err(refusal)?;
    if !metadata.is_file() {
        return Err(refusal(format!("not a regular file: {}", path.display())));
    }
    std::fs::File::open(path).map_err(refusal)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn literal_options(path: &Path) -> Result<(PathBuf, SqliteConnectOptions)> {
    // SQLx enables SQLITE_OPEN_URI even with filename(). An absolute filename
    // cannot start with 'file:', so relative file: names cannot become URIs.
    // Never strip a prefix, percent-decode or use a lossy path conversion.
    let path = std::path::absolute(path).map_err(refusal)?;
    if path.to_str().is_none() {
        return Err(refusal("SQLx requires a lossless UTF-8 filename"));
    }
    let mut file = readable_regular_file(&path)?;
    let mut header = [0_u8; 100];
    file.read_exact(&mut header).map_err(refusal)?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(refusal("not a SQLite database header"));
    }
    match (header[18], header[19]) {
        (1, 1) => {}
        (2, 2) => {
            // Read-only WAL access can otherwise bootstrap sidecars in a
            // writable directory. Require a retained WAL lifecycle instead.
            // SHM still participates in SQLite's reader coordination; it is
            // not promised byte-immutable. The owner must retain all files
            // and prevent replacement/journal changes throughout handle use.
            readable_regular_file(&sidecar(&path, "-wal"))?;
            readable_regular_file(&sidecar(&path, "-shm"))?;
        }
        _ => return Err(refusal("unsupported SQLite journal header")),
    }
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .read_only(true)
        .immutable(false)
        .foreign_keys(true)
        .with_regexp()
        .busy_timeout(Duration::from_secs(5));
    Ok((path, options))
}

async fn validate_snapshot(options: &SqliteConnectOptions) -> Result<()> {
    let mut connection = SqliteConnection::connect_with(options).await?;
    let validation: Result<()> = async {
        let mut snapshot = connection.begin().await?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *snapshot)
            .await?;
        if version != CURRENT_ENGINE_SCHEMA_VERSION {
            return Err(refusal(format!(
                "engine schema {version}; expected {CURRENT_ENGINE_SCHEMA_VERSION}"
            )));
        }
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut *snapshot)
            .await?;
        if integrity != "ok" {
            return Err(refusal(format!("SQLite quick_check failed: {integrity}")));
        }
        if !validate_engine_shape_on(&mut snapshot, CURRENT_ENGINE_SCHEMA_VERSION).await? {
            return Err(refusal("current engine structural shape mismatch"));
        }
        snapshot.rollback().await?;
        Ok(())
    }
    .await;
    // Await close on *every* returned validation failure, including SQL errors.
    let closed = connection.close().await;
    validation?;
    closed?;
    Ok(())
}

async fn open_pool(options: &SqliteConnectOptions) -> Result<SqlitePool> {
    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .before_acquire(count_read_pool_reuse)
        .after_connect(count_read_pool_new_connection)
        .connect_with(options.clone())
        .await?)
}

async fn validate_state(db: &Db) -> Result<()> {
    // Keep the complete current-engine validators, including control replay
    // into a separate scratch database. No repair/seed/migration of this file.
    // These existing validators use several read snapshots: stable external
    // custody is a caller obligation, not authority manufactured by this API.
    for (label, violations) in [
        (
            "authorization revision state",
            crate::authorization_revision::state_violations(db).await?,
        ),
        (
            "grant revision state",
            crate::authorization_grant::state_violations(db).await?,
        ),
        (
            "authorization state",
            crate::authorization::state_violations(db).await?,
        ),
        (
            "policy event log",
            crate::policy::state_violations(db).await?,
        ),
        (
            "instruction control event log",
            crate::control::state_violations(db).await?,
        ),
        (
            "identity state",
            crate::identity::state_violations(db).await?,
        ),
    ] {
        if !violations.is_empty() {
            return Err(refusal(format!(
                "malformed {label}: {}",
                violations.join("; ")
            )));
        }
    }
    Ok(())
}

/// Observe an existing current-engine database through physical read-only
/// pools, with ordinary WAL visibility and locking (never immutable).
///
/// `path` is a literal filename, not a SQLite URL. All persistent query tiers
/// use SQLITE_OPEN_READONLY without CREATE, including the governed tier. No
/// capture worker, declaration writer, advisors, embedder or realtime/index
/// scheduler is installed. TEMP connection-local SQL is not a persistent write
/// capability; this does not rely on a toggleable `PRAGMA query_only` barrier.
///
/// WAL-mode files require readable existing WAL/SHM sidecars. Retain them and
/// exclude file replacement, active writers and journal-mode changes for the
/// entire lifetime. A closed WAL database with absent sidecars is refused, not
/// repaired. SQLite reader coordination can update SHM; main/WAL are read-only.
///
/// This is **not** a private Hosting constructor or startup permit. A future
/// constructor must continuously retain candidate/users/catalog authority,
/// validate journals and conformance, and enforce fresh outgoing custody.
pub async fn open_current_database_wal_read_only_at(path: &Path) -> Result<Db> {
    let (path, options) = literal_options(path)?;
    validate_snapshot(&options).await?;
    let write_pool = open_pool(&options).await?;
    let read_pool = match open_pool(&options).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            return Err(error);
        }
    };
    let governed_pool = match open_pool(&options).await {
        Ok(pool) => pool,
        Err(error) => {
            write_pool.close().await;
            read_pool.close().await;
            return Err(error);
        }
    };
    let db = Db {
        execution_owner: None,
        execution_jobs: Arc::new(enrolled::HandleJobs::default()),
        body_jobs: Arc::new(enrolled::BodyHandleJobs::default()),
        body_retirement: Arc::new(OnceLock::new()),
        capture_pool: Arc::new(tokio::sync::OnceCell::new()),
        pending_commit_probes: None,
        write_pool,
        read_pool,
        governed_pool,
        location: Arc::new(DatabaseLocation {
            path,
            // Reuse the existing physical-read-only query surface. Opening
            // through this function does not change standby's immutable API.
            open_mode: DatabaseOpenMode::StandbyReadOnly,
        }),
        handle_id: uuid::Uuid::new_v4(),
        embedder: None,
        advisors: AdvisorRegistry::default(),
        rollup_cache: Arc::new(Mutex::new(RollupCache::default())),
        visible_set_cache: Arc::new(Mutex::new(
            crate::visible_set_cache::VisibleSetCache::default(),
        )),
        inbox_snapshots: Arc::new(Mutex::new(HashMap::new())),
        realtime_hub: None,
        workspace_index: Arc::new(tokio::sync::RwLock::new(None)),
        workspace_index_fold: Arc::new(AtomicBool::new(false)),
        workspace_index_refused: Arc::new(Mutex::new(None)),
        workspace_snapshots: Arc::new(Mutex::new(
            crate::workspace_snapshot::SnapshotStore::default(),
        )),
        portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
        capture_queue: crate::mcp::interactions::CaptureQueue::inert(),
        database_id_cache: Arc::new(tokio::sync::OnceCell::new()),
        _tmp: None,
    };
    if let Err(error) = validate_state(&db).await {
        db.close().await;
        return Err(error);
    }
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "e5555555-5555-4555-8555-555555555555";
    const NAME: &str = "Candidate — 雪 ❄️";
    const BODY: &str = "Exact WAL body: café e\u{301} 🦉\n第二行";

    struct WalFixture {
        _directory: TempDir,
        path: PathBuf,
        producer: Db,
        main_before: Vec<u8>,
    }

    impl WalFixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("candidate.db");
            let producer = create_database(path.to_str().unwrap()).await.unwrap();
            // Keep this producer alive, with no active write transaction, so
            // SQLite's last-connection checkpoint cannot erase the WAL proof.
            sqlx::query("PRAGMA wal_autocheckpoint=0")
                .execute(producer.write_pool())
                .await
                .unwrap();
            sqlx::query(&format!(
                "PRAGMA user_version={}",
                CURRENT_ENGINE_SCHEMA_VERSION - 1
            ))
            .execute(producer.write_pool())
            .await
            .unwrap();
            let checkpoint = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .fetch_one(producer.write_pool())
                .await
                .unwrap();
            assert_eq!(checkpoint.get::<i64, _>(0), 0);
            let main_before = std::fs::read(&path).unwrap();
            assert_eq!(
                u32::from_be_bytes(main_before[60..64].try_into().unwrap()) as i64,
                CURRENT_ENGINE_SCHEMA_VERSION - 1
            );
            crate::store::create_record(
                &producer,
                serde_json::json!({
                    "id": ID, "type": "Document", "kind": "note",
                    "name": NAME, "body": BODY
                }),
            )
            .await
            .unwrap();
            sqlx::query(&format!(
                "PRAGMA user_version={CURRENT_ENGINE_SCHEMA_VERSION}"
            ))
            .execute(producer.write_pool())
            .await
            .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), main_before);
            assert!(std::fs::metadata(sidecar(&path, "-wal")).unwrap().len() > 32);
            assert!(sidecar(&path, "-shm").is_file());
            Self {
                _directory: directory,
                path,
                producer,
                main_before,
            }
        }

        async fn change(&self, sql: &str) {
            sqlx::query(sql)
                .execute(self.producer.write_pool())
                .await
                .unwrap();
        }

        async fn refused(&self, diagnostic: &str) {
            let main = std::fs::read(&self.path).unwrap();
            let wal = std::fs::read(sidecar(&self.path, "-wal")).unwrap();
            let error = match open_current_database_wal_read_only_at(&self.path).await {
                Ok(db) => {
                    db.close().await;
                    panic!("malformed candidate was admitted");
                }
                Err(error) => error,
            };
            assert!(error.to_string().contains(diagnostic), "{error}");
            assert_eq!(std::fs::read(&self.path).unwrap(), main);
            assert_eq!(std::fs::read(sidecar(&self.path, "-wal")).unwrap(), wal);
        }
    }

    #[tokio::test]
    async fn committed_wal_stamp_and_unicode_are_read_without_checkpoint() {
        let fixture = WalFixture::new().await;
        let wal = std::fs::read(sidecar(&fixture.path, "-wal")).unwrap();
        let db = open_current_database_wal_read_only_at(&fixture.path)
            .await
            .unwrap();
        assert_eq!(db.open_mode(), DatabaseOpenMode::StandbyReadOnly);
        assert!(db.embedder.is_none());
        assert!(db.advisors.is_empty());
        assert!(db.realtime_hub.is_none());
        assert!(db.workspace_index.read().await.is_none());
        for pool in [db.write_pool(), db.pool(), db.governed_pool()] {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(version, CURRENT_ENGINE_SCHEMA_VERSION);
            let row = sqlx::query("SELECT id,name,body FROM records WHERE id=?")
                .bind(ID)
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(row.get::<String, _>(0), ID);
            assert_eq!(row.get::<String, _>(1), NAME);
            assert_eq!(row.get::<String, _>(2), BODY);
        }
        db.close().await;
        assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.main_before);
        assert_eq!(std::fs::read(sidecar(&fixture.path, "-wal")).unwrap(), wal);
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn every_pool_refuses_persistent_writes_even_with_query_only_disabled() {
        let fixture = WalFixture::new().await;
        let wal = std::fs::read(sidecar(&fixture.path, "-wal")).unwrap();
        let db = open_current_database_wal_read_only_at(&fixture.path)
            .await
            .unwrap();
        for pool in [db.write_pool(), db.pool(), db.governed_pool()] {
            // Keep one connection: a pool could otherwise run the toggle and
            // attempted writes on different connections.
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("PRAGMA query_only=OFF")
                .execute(&mut *connection)
                .await
                .unwrap();
            for sql in [
                "CREATE TABLE candidate_write_probe(value TEXT)",
                "UPDATE records SET body='changed'",
                "DELETE FROM records",
                "INSERT INTO records(id,type) VALUES('e6666666-6666-4666-8666-666666666666','Document')",
                "PRAGMA user_version=1",
            ] {
                let error = sqlx::query(sql)
                    .execute(&mut *connection)
                    .await
                    .expect_err("physical read-only connection admitted a write");
                assert!(error.to_string().contains("readonly"), "{sql}: {error}");
            }
        }
        assert!(crate::store::create_record(
            &db,
            serde_json::json!({"id":"e6666666-6666-4666-8666-666666666666", "type":"Document", "kind":"note", "name":"write"})
        )
        .await
        .is_err());
        db.close().await;
        assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.main_before);
        assert_eq!(std::fs::read(sidecar(&fixture.path, "-wal")).unwrap(), wal);
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn missing_directory_and_non_sqlite_files_are_not_created_or_repaired() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.db");
        for path in [&missing, directory.path()] {
            assert!(open_current_database_wal_read_only_at(path).await.is_err());
        }
        assert!(!missing.exists());
        assert!(!sidecar(&missing, "-wal").exists());
        assert!(!sidecar(&missing, "-shm").exists());
        let malformed = directory.path().join("malformed.db");
        std::fs::write(&malformed, [0_u8; 100]).unwrap();
        assert!(open_current_database_wal_read_only_at(&malformed)
            .await
            .is_err());
        assert_eq!(std::fs::read(malformed).unwrap(), [0_u8; 100]);
    }

    #[tokio::test]
    async fn wal_mode_without_retained_sidecars_is_refused_without_bootstrap() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("checkpointed-source.db");
        let producer = create_database(source.to_str().unwrap()).await.unwrap();
        checkpoint_and_close_hosted_adoption_database(producer)
            .await
            .unwrap();
        // Verified checkpoint completion makes main self-contained; awaited
        // pool closure does not promise sidecar deletion. Copy only that main
        // to a fresh name, without touching possibly retained source sidecars.
        let source_main = std::fs::read(&source).unwrap();
        let path = directory.path().join("closed.db");
        assert!(!path.exists(), "fixture destination must be fresh");
        std::fs::copy(&source, &path).unwrap();
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-shm").exists());
        let main = std::fs::read(&path).unwrap();
        assert!(
            main.len() >= 100,
            "fixture must contain a complete SQLite header"
        );
        assert_eq!(
            main, source_main,
            "fixture must copy checkpointed main exactly"
        );
        assert_eq!(&main[..16], b"SQLite format 3\0");
        assert_eq!(&main[18..20], &[2, 2], "fixture must advertise WAL mode");
        assert_eq!(
            u32::from_be_bytes(main[60..64].try_into().unwrap()) as i64,
            CURRENT_ENGINE_SCHEMA_VERSION,
            "fixture main must contain the independently checkpointed current stamp"
        );
        match open_current_database_wal_read_only_at(&path).await {
            Err(error) => assert!(
                error
                    .to_string()
                    .starts_with("refusing WAL-aware read-only open"),
                "unexpected refusal: {error}"
            ),
            Ok(db) => {
                db.close().await;
                panic!("sidecarless WAL database was admitted");
            }
        }
        assert_eq!(std::fs::read(&path).unwrap(), main);
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-shm").exists());
    }

    #[tokio::test]
    async fn old_future_and_unversioned_wal_stamps_are_refused() {
        for version in [
            0,
            CURRENT_ENGINE_SCHEMA_VERSION - 1,
            CURRENT_ENGINE_SCHEMA_VERSION + 1,
        ] {
            let fixture = WalFixture::new().await;
            fixture
                .change(&format!("PRAGMA user_version={version}"))
                .await;
            fixture.refused(&format!("engine schema {version}")).await;
            fixture.producer.close().await;
        }
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_partial_shape() {
        let fixture = WalFixture::new().await;
        fixture
            .change("DROP INDEX idx_database_identity_audit_act")
            .await;
        fixture
            .change(&format!(
                "PRAGMA user_version={CURRENT_ENGINE_SCHEMA_VERSION}"
            ))
            .await;
        fixture.refused("structural shape mismatch").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_missing_grant_revision_state() {
        let fixture = WalFixture::new().await;
        fixture
            .change("DELETE FROM authorization_grant_revision WHERE id=1")
            .await;
        fixture.refused("grant revision state").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_missing_authorization_revision_state() {
        let fixture = WalFixture::new().await;
        fixture
            .change("DELETE FROM authorization_revision WHERE id=1")
            .await;
        fixture.refused("authorization revision state").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_missing_identity_state() {
        let fixture = WalFixture::new().await;
        fixture
            .change("DELETE FROM database_identity WHERE singleton=1")
            .await;
        fixture.refused("identity state").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_authorization_anchor_drift() {
        let fixture = WalFixture::new().await;
        fixture
            .change(&format!(
                "UPDATE records SET policy_anchor_id=NULL WHERE id='{ID}'"
            ))
            .await;
        fixture.refused("authorization state").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_malformed_policy_event() {
        let fixture = WalFixture::new().await;
        fixture.change(&format!("INSERT INTO policy_events(id,record_id,type,payload,actor,reason,created_at) VALUES('malformed-policy','{ID}','policy.replaced','not-json','fixture','fixture','2026-10-01T00:00:00Z')")).await;
        fixture.refused("policy event log").await;
        fixture.producer.close().await;
    }

    #[tokio::test]
    async fn current_stamp_cannot_admit_control_projection_drift() {
        let fixture = WalFixture::new().await;
        fixture.change("INSERT INTO onboarding_programmes(id,trigger_key,position,created_by,created_at,updated_at) VALUES('unlogged-programme','fixture',0,'fixture','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z')").await;
        fixture.refused("control projection drift").await;
        fixture.producer.close().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn literal_filename_keeps_file_prefix_percent_question_and_fragment() {
        // A relative filename beginning file: must remain a filename even
        // though SQLx enables SQLite URI interpretation at the C boundary.
        // No process-global cwd change is needed for this regression.
        let directory = tempfile::Builder::new()
            .prefix("file:candidate-path-")
            .tempdir_in(".")
            .unwrap();
        let baseline = directory.path().join("baseline.db");
        let producer = create_database(baseline.to_str().unwrap()).await.unwrap();
        crate::store::create_record(
            &producer,
            serde_json::json!({
                "id":ID, "type":"Document", "kind":"note", "name":NAME, "body":BODY
            }),
        )
        .await
        .unwrap();
        checkpoint_and_close_hosted_adoption_database(producer)
            .await
            .unwrap();
        let path = directory.path().join("file:literal%3F?mode=rw#雪.db");
        std::fs::copy(&baseline, &path).unwrap();
        let absolute = std::path::absolute(&path).unwrap();
        let cwd = std::env::current_dir().unwrap();
        let relative = absolute.strip_prefix(cwd).unwrap();
        assert!(relative.to_str().unwrap().starts_with("file:"));
        let mut keeper = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(&absolute)
                .create_if_missing(false),
        )
        .await
        .unwrap();
        sqlx::query("PRAGMA wal_autocheckpoint=0")
            .execute(&mut keeper)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=0")
            .execute(&mut keeper)
            .await
            .unwrap();
        sqlx::query(&format!(
            "PRAGMA user_version={CURRENT_ENGINE_SCHEMA_VERSION}"
        ))
        .execute(&mut keeper)
        .await
        .unwrap();
        let before: std::collections::BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let db = open_current_database_wal_read_only_at(relative)
            .await
            .unwrap();
        assert_eq!(db.path(), absolute);
        let actual: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(actual, BODY);
        db.close().await;
        let after: std::collections::BTreeSet<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after, before, "opening reinterpreted or created a filename");
        keeper.close().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_utf8_filename_is_refused_without_lossy_alias() {
        use std::os::unix::ffi::OsStringExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(std::ffi::OsString::from_vec(b"candidate-\xff.db".to_vec()));
        std::fs::write(&path, [0_u8; 100]).unwrap();
        let error = open_current_database_wal_read_only_at(&path)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lossless UTF-8"), "{error}");
        assert!(!directory.path().join("candidate-�.db").exists());
        assert_eq!(std::fs::read(path).unwrap(), [0_u8; 100]);
    }
}
