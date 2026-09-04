use native_ce::{
    create_database, open_existing_database_at, probe_database, DatabaseVersionState,
    CURRENT_ENGINE_SCHEMA_VERSION,
};
use rusqlite::Connection;
use std::io::{Seek, SeekFrom, Write};
use tempfile::tempdir;

#[tokio::test]
async fn probe_is_non_creating_and_classifies_file_states() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.db");
    assert_eq!(
        probe_database(&missing, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::Missing
    );
    assert!(!missing.exists());

    let empty = dir.path().join("empty.db");
    Connection::open(&empty).unwrap();
    assert_eq!(
        probe_database(&empty, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::Empty
    );

    let unversioned = dir.path().join("unversioned.db");
    Connection::open(&unversioned)
        .unwrap()
        .execute("CREATE TABLE extra (id INTEGER)", [])
        .unwrap();
    assert_eq!(
        probe_database(&unversioned, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::UnversionedNonEmpty
    );

    let future = dir.path().join("future.db");
    Connection::open(&future)
        .unwrap()
        .execute_batch("CREATE TABLE t (id INTEGER); PRAGMA user_version = 99")
        .unwrap();
    assert_eq!(
        probe_database(&future, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::Future(99)
    );
}

#[tokio::test]
async fn probe_does_not_change_a_wal_database_or_its_sidecars() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("wal.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    sqlx::query(
        "INSERT INTO jobs (id, kind, status, created_at) VALUES ('probe', 'test', 'queued', 'now')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let wal = path.with_extension("db-wal");
    let shm = path.with_extension("db-shm");
    assert!(wal.exists());
    assert!(shm.exists());
    let before_db = std::fs::read(&path).unwrap();
    let before_wal = std::fs::read(&wal).unwrap();
    let before_sidecars = (wal.exists(), shm.exists());

    assert_eq!(
        probe_database(&path, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::Known(CURRENT_ENGINE_SCHEMA_VERSION)
    );

    assert_eq!(std::fs::read(&path).unwrap(), before_db);
    assert_eq!(std::fs::read(&wal).unwrap(), before_wal);
    assert_eq!((wal.exists(), shm.exists()), before_sidecars);
    db.close().await;
}

#[tokio::test]
async fn probe_rejects_corruption_without_changing_the_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("corrupt.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "user_version", CURRENT_ENGINE_SCHEMA_VERSION)
        .unwrap();
    connection
        .execute_batch(
            "CREATE TABLE corruption_payload (body BLOB);
             INSERT INTO corruption_payload VALUES (zeroblob(200000));",
        )
        .unwrap();
    let page_size: u64 = connection
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap();
    let page_count: u64 = connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    drop(connection);

    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start((page_count - 1) * page_size))
        .unwrap();
    file.write_all(&vec![0xff; page_size as usize]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let corrupted = std::fs::read(&path).unwrap();

    assert!(matches!(
        probe_database(&path, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::Unreadable(_)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    assert!(!path.with_extension("db-wal").exists());
}

#[tokio::test]
async fn existing_open_accepts_current_and_refuses_every_other_state() {
    let dir = tempdir().unwrap();
    let current = dir.path().join("current.db");
    create_database(&current.to_string_lossy())
        .await
        .unwrap()
        .close()
        .await;
    open_existing_database_at(&current)
        .await
        .unwrap()
        .close()
        .await;

    let pre_cutover = dir.path().join("pre-cutover-v7.db");
    create_database(&pre_cutover.to_string_lossy())
        .await
        .unwrap()
        .close()
        .await;
    Connection::open(&pre_cutover)
        .unwrap()
        .pragma_update(None, "user_version", 7)
        .unwrap();
    let error = open_existing_database_at(&pre_cutover).await.unwrap_err();
    let message = error.to_string();
    assert!(message.contains("recreate this database"), "{message}");
    assert!(!message.contains("operator migrate-db"), "{message}");

    let future_version = CURRENT_ENGINE_SCHEMA_VERSION + 1;
    for (name, setup) in [
        (
            "abandoned-v36.db",
            "CREATE TABLE t (id INTEGER); PRAGMA user_version = 36".to_string(),
        ),
        (
            "stale.db",
            "CREATE TABLE t (id INTEGER); PRAGMA user_version = 0".to_string(),
        ),
        (
            "future.db",
            format!("CREATE TABLE t (id INTEGER); PRAGMA user_version = {future_version}"),
        ),
    ] {
        let path = dir.path().join(name);
        Connection::open(&path)
            .unwrap()
            .execute_batch(&setup)
            .unwrap();
        let err = open_existing_database_at(&path).await.unwrap_err();
        let message = err.to_string();
        // 36, 0 and a future version all sit outside the supported window, so
        // recreating really is the only remedy.
        assert!(
            message.contains("outside the supported schema window"),
            "{message}"
        );
        assert!(message.contains("reset or recreate"), "{message}");
        assert!(!message.contains("operator migrate-db"), "{message}");
    }

    // A database *inside* the supported window is a different case, and telling
    // its owner to recreate would be advice to destroy recoverable data.
    // Serving still refuses to migrate it; it just names the right remedy.
    if let Some(baseline) = native_ce::SUPPORTED_ENGINE_SCHEMA_BASELINE {
        let supported = dir.path().join("supported-baseline.db");
        Connection::open(&supported)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE t (id INTEGER); PRAGMA user_version = {baseline}"
            ))
            .unwrap();
        let message = open_existing_database_at(&supported)
            .await
            .unwrap_err()
            .to_string();
        assert!(message.contains("operator migrate-db"), "{message}");
        assert!(!message.contains("reset or recreate"), "{message}");
    }

    let missing = dir.path().join("missing.db");
    let err = open_existing_database_at(&missing).await.unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
    assert!(!missing.exists());
}
