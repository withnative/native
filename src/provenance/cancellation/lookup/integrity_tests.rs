use super::*;
use crate::mcp::{registry::ToolRegistry, Caller};

async fn fixture() -> (tempfile::TempDir, Db, ToolRegistry) {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::create_database(dir.path().join("workspace.db").to_str().unwrap())
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    (dir, db, registry)
}

async fn record(registry: &ToolRegistry, db: &Db, name: &str) {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type":"Document", "kind":"note", "name":name, "body":"merge fixture",
                "reason":"Qualify fresh STOP integrity observation."
            }),
        )
        .await
        .unwrap();
}

fn bytes(db: &Db) -> (Vec<u8>, Option<Vec<u8>>) {
    (
        std::fs::read(db.path()).unwrap(),
        std::fs::read(format!("{}-wal", db.path().display())).ok(),
    )
}

#[tokio::test]
async fn fresh_stop_integrity_survives_cross_connection_fts_merge_under_write_fence() {
    let (_dir, db, registry) = fixture().await;
    // Fixture-only merge threshold; never alter the product's FTS settings.
    sqlx::query("INSERT INTO records_name_idx(records_name_idx,rank) VALUES('crisismerge',2)")
        .execute(db.write_pool())
        .await
        .unwrap();
    record(&registry, &db, "initial segment").await;
    // A is a dedicated connection opened only now, after the initial record is
    // committed. It must not come from the write pool: pooled connections were
    // used by the fixture's genesis and by the writes above, and SQLite FTS5
    // segment structures are connection-local, so which idle connection the
    // pool hands back decides whether its cache already predates the initial
    // record. A pooled A made this precondition (and the warm-cache premise
    // below) depend on pool scheduling. A new connection has no prior cache, so
    // its first quick_check reads the committed state and also warms A. The
    // native create_record below MUST still use a different writer B.
    let mut a = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(db.path())
            .create_if_missing(false)
            .busy_timeout(std::time::Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA quick_check(1)")
            .fetch_one(&mut a)
            .await
            .unwrap(),
        "ok"
    );
    record(&registry, &db, "merged segment").await;
    let mut tx = a.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let warm: String = sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(
        warm.contains("malformed inverted index"),
        "warm result: {warm}"
    );
    let before = bytes(&db);
    fresh_integrity(&db, &mut tx).await.unwrap();
    assert_eq!(bytes(&db), before); // Controlled fixture; exclude SHM read marks.

    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db.path())
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_millis(20));
    let mut competitor = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let error = competitor.begin_with("BEGIN IMMEDIATE").await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("5")
    );
    // The private reader has closed, while the original write fence still holds.
    fresh_integrity(&db, &mut tx).await.unwrap();
    tx.rollback().await.unwrap();
    competitor
        .begin_with("BEGIN IMMEDIATE")
        .await
        .unwrap()
        .rollback()
        .await
        .unwrap();
    competitor.close().await.unwrap();
    a.close().await.unwrap();
}

#[tokio::test]
async fn fresh_stop_integrity_refuses_real_fts_leaf_damage_without_repair() {
    let (_dir, db, registry) = fixture().await;
    record(&registry, &db, "real index content").await;
    let affected = sqlx::query("UPDATE records_name_idx_data SET block=x'00' WHERE id>10")
        .execute(db.write_pool())
        .await
        .unwrap()
        .rows_affected();
    assert!(affected > 0);
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let before = bytes(&db);
    assert!(fresh_integrity(&db, &mut tx).await.is_err());
    assert_eq!(bytes(&db), before);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn fresh_stop_integrity_refuses_canonical_foreign_key_violation() {
    let (_dir, db, _registry) = fixture().await;
    let mut writer = db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *writer)
        .await
        .unwrap();
    // Use the existing embedding FK; leave the authoritative policy-write
    // funnel closed even in this corruption fixture.
    sqlx::query("INSERT INTO embeddings(record_id,provider,dim,vector) VALUES('absent-record','fixture',1,x'00')")
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *writer)
        .await
        .unwrap();
    let mut tx = writer.begin_with("BEGIN IMMEDIATE").await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("PRAGMA quick_check(1)")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pragma_foreign_key_check WHERE \"table\"='embeddings'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap(),
        1
    );
    let before = bytes(&db);
    assert!(fresh_integrity(&db, &mut tx).await.is_err());
    assert_eq!(bytes(&db), before);
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn fresh_stop_integrity_refuses_wrong_database_binding_and_missing_file() {
    let (_dir, db, _registry) = fixture().await;
    let (_other_dir, other, _) = fixture().await;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    // Even an otherwise healthy different file cannot attest this transaction.
    assert!(fresh_integrity(&other, &mut tx).await.is_err());
    let moved = other.path().with_extension("retained");
    std::fs::rename(other.path(), &moved).unwrap();
    assert!(fresh_integrity(&other, &mut tx).await.is_err());
    assert!(!other.path().exists()); // Read failure must never initialize storage.
    std::fs::rename(moved, other.path()).unwrap();
    tx.rollback().await.unwrap();
}
