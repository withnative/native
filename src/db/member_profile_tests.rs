use super::*;
use std::path::PathBuf;

const REFUSAL: &str = "this is a v2 database member profile; use member-profile admission";

async fn fixture(path: &Path) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("CREATE TABLE member_fixture(value TEXT)")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO member_fixture VALUES ('synthetic member bytes')")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!(
        "PRAGMA user_version={CURRENT_ENGINE_SCHEMA_VERSION}"
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    connection
}

#[tokio::test]
async fn native_member_marker_refuses_raw_v1_openers_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("member.db");
    let url = path.to_str().unwrap();
    let mut connection = fixture(&path).await;
    sqlx::query(&format!("PRAGMA application_id={V2_MEMBER_APPLICATION_ID}"))
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        probe_database(&path, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::KernelV2Member
    );
    assert_eq!(DatabaseVersionState::KernelV2Member.to_string(), REFUSAL);
    for error in [
        open_database(url).await.err().unwrap(),
        open_v1_database(url).await.err().unwrap(),
        create_database(url).await.err().unwrap(),
        open_existing_database(url).await.err().unwrap(),
        open_member_database_read_only(url).await.err().unwrap(),
        open_existing_database_standby_read_only(url)
            .await
            .err()
            .unwrap(),
        validate_current_engine_shape_read_only(&path)
            .await
            .unwrap_err(),
        crate::migrations::preflight_production_migration_read_only(&path)
            .await
            .unwrap_err(),
    ] {
        assert!(error.to_string().contains(REFUSAL), "{error}");
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!PathBuf::from(format!("{}{suffix}", path.display())).exists());
    }
}

#[tokio::test]
async fn native_member_marker_in_wal_is_not_mistaken_for_canonical_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("member.db");
    let mut connection = fixture(&path).await;
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query(&format!("PRAGMA application_id={V2_MEMBER_APPLICATION_ID}"))
        .execute(&mut connection)
        .await
        .unwrap();
    // SQLite's live marker is authoritative: the main header is still zero.
    let header = std::fs::read(&path).unwrap();
    assert_eq!(&header[68..72], &[0, 0, 0, 0]);
    assert_eq!(
        probe_database(&path, CURRENT_ENGINE_SCHEMA_VERSION).await,
        DatabaseVersionState::KernelV2Member
    );
    let error = open_database(path.to_str().unwrap()).await.err().unwrap();
    assert_eq!(error.to_string(), REFUSAL);
    let error = open_member_database_read_only(path.to_str().unwrap())
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), REFUSAL);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM member_fixture")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(count, 1);
    connection.close().await.unwrap();
}

#[tokio::test]
async fn canonical_marker_in_wal_overrides_stale_member_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("canonical.db");
    let mut connection = fixture(&path).await;
    sqlx::query(&format!("PRAGMA application_id={V2_MEMBER_APPLICATION_ID}"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA application_id=0")
        .execute(&mut connection)
        .await
        .unwrap();
    let header = std::fs::read(&path).unwrap();
    assert_eq!(
        u32::from_be_bytes(header[68..72].try_into().unwrap()),
        V2_MEMBER_APPLICATION_ID as u32
    );
    // A checkpointed header is insufficient whenever a WAL exists.
    refuse_member_profile_before_write_pool(path.to_str().unwrap())
        .await
        .unwrap();
    let opened = open_database(path.to_str().unwrap()).await.unwrap();
    opened.close().await;
    connection.close().await.unwrap();
}

#[tokio::test]
async fn member_marker_preflight_does_not_wait_for_an_exclusive_wal_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.db");
    let mut connection = fixture(&path).await;
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA locking_mode=EXCLUSIVE")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut connection)
        .await
        .unwrap();
    let refusal = tokio::time::timeout(
        Duration::from_secs(1),
        refuse_member_profile_before_write_pool(path.to_str().unwrap()),
    )
    .await
    .expect("routing preflight must not wait five seconds for a busy file");
    assert!(
        refusal.is_err(),
        "an unreadable live marker must fail closed"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
async fn member_marker_preflight_tolerates_a_short_wal_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transient-lock.db");
    let mut connection = fixture(&path).await;
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA locking_mode=EXCLUSIVE")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut connection)
        .await
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(75)).await;
        connection.close().await.unwrap();
    });
    refuse_member_profile_before_write_pool(path.to_str().unwrap())
        .await
        .unwrap();
    release.await.unwrap();
    let opened = open_database(path.to_str().unwrap()).await.unwrap();
    opened.close().await;
}

#[tokio::test]
async fn native_member_marker_changed_after_preflight_is_refused_on_opened_connection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("changed.db");
    let url = path.to_str().unwrap();
    fixture(&path).await.close().await.unwrap();
    refuse_member_profile_before_write_pool(url).await.unwrap();
    let mut connection =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    sqlx::query(&format!("PRAGMA application_id={V2_MEMBER_APPLICATION_ID}"))
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    // Exercise the exact post-preflight path used by the raw opener.
    let error = open_raw_write_pool(url, false, WritePoolKind::Workspace, None)
        .await
        .expect_err("the opened file must be checked again");
    assert_eq!(error.to_string(), REFUSAL);
    // Refusal closes its pool; the file remains readable by the fixture owner.
    let mut connection =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM member_fixture")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(count, 1);
    connection.close().await.unwrap();
}
