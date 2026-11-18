use super::*;

const OWNER: &str = "acct_00000000000000000000000000000001";
const VIEWER: &str = "acct_00000000000000000000000000000002";

#[tokio::test]
async fn keyed_receipt_maintenance_refuses_missing_and_foreign_files_without_creating() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.db");
    assert!(prepare_keyed_receipts(&missing, OWNER).await.is_err());
    assert!(!missing.exists());
    let foreign = dir.path().join("foreign.db");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&foreign)
        .create_if_missing(true);
    let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("CREATE TABLE foreign_data(value TEXT)")
        .execute(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    let before = std::fs::read(&foreign).unwrap();
    assert!(prepare_keyed_receipts(&foreign, OWNER).await.is_err());
    assert_eq!(std::fs::read(&foreign).unwrap(), before);
}

#[tokio::test]
async fn keyed_receipt_maintenance_authorizes_before_legacy_v2_backfill_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("canonical.db");
    let (db, admin) = kernel::create_v2_database(path.to_str().unwrap(), "account", "Owner", OWNER)
        .await
        .unwrap();
    kernel::create_principal(&db, "account", "Viewer", VIEWER, &admin)
        .await
        .unwrap();
    // Model an existing pre-carriage ledger. The receipt bytes must survive
    // canonical preparation exactly, while its legacy request is normalized.
    sqlx::query("CREATE TABLE IF NOT EXISTS kernel_mcp_write_receipts(principal_id TEXT NOT NULL,operation TEXT NOT NULL,operation_key TEXT NOT NULL,request_json TEXT NOT NULL,receipt_json TEXT NOT NULL,PRIMARY KEY(principal_id,operation,operation_key))")
        .execute(db.write_pool()).await.unwrap();
    let receipt =
        json!({"id":"legacy-target","result":{"body":"original full response"},"changed":false})
            .to_string();
    sqlx::query(
        "INSERT INTO kernel_mcp_write_receipts VALUES(?,'update_record','legacy-key','{}',?)",
    )
    .bind(&admin)
    .bind(&receipt)
    .execute(db.write_pool())
    .await
    .unwrap();
    db.close().await;
    assert!(prepare_keyed_receipts(&path, VIEWER).await.is_err());
    let db = crate::db::open_existing_v2_file(path.to_str().unwrap())
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_receipt_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 0, "a non-owner cannot backfill canonical state");
    let request: String = sqlx::query_scalar(
        "SELECT request_json FROM kernel_mcp_write_receipts WHERE operation_key='legacy-key'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        request, "{}",
        "authorization must precede ledger normalization"
    );
    db.close().await;
    for _ in 0..2 {
        assert_eq!(
            prepare_keyed_receipts(&path, OWNER).await.unwrap(),
            json!({"outcome":"ready","engine":"v2","maintenance":"keyed-receipts"})
        );
    }
    let db = crate::db::open_existing_v2_file(path.to_str().unwrap())
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_receipt_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "rerunning maintenance must not append another receipt fact"
    );
    let actual: String = sqlx::query_scalar(
        "SELECT receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='legacy-key'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(actual, receipt);
    let mut read = db.pool().begin().await.unwrap();
    kernel::mcp_write_receipts::require_covered_on(&mut read)
        .await
        .unwrap();
    read.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn keyed_receipt_maintenance_requires_existing_v1_account_and_root_manage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("canonical-v1.db");
    let db = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let account = crate::identity::resolve_stdio_account_identity(&db, None)
        .await
        .unwrap();
    // A stale seed projection would make the ordinary writable opener append
    // meta events. Unauthorized maintenance must never reach that opener.
    let seed_id: String = sqlx::query_scalar(
        "SELECT id FROM vocabulary_values WHERE gloss IS NOT NULL ORDER BY id LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE vocabulary_values SET gloss=NULL WHERE id=?")
        .bind(&seed_id)
        .execute(db.write_pool())
        .await
        .unwrap();
    let meta_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    db.close().await;
    assert!(
        prepare_keyed_receipts(&path, OWNER).await.is_err(),
        "a token without a canonical person binding confers no authority"
    );
    assert!(
        prepare_keyed_receipts(&path, &account).await.is_err(),
        "a personal-home grant does not confer root Manage"
    );
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .read_only(true);
    let mut read = SqliteConnection::connect_with(&options).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
            .fetch_one(&mut read)
            .await
            .unwrap(),
        meta_before
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT gloss FROM vocabulary_values WHERE id=?")
            .bind(&seed_id)
            .fetch_one(&mut read)
            .await
            .unwrap(),
        None
    );
    read.close().await.unwrap();
    let db = crate::db::open_existing_database(path.to_str().unwrap())
        .await
        .unwrap();
    crate::authorization::add_account_grant(
        &db,
        &account,
        crate::schema::ROOT_RECORD_ID,
        &account,
        Capability::Manage,
    )
    .await
    .unwrap();
    db.close().await;
    assert_eq!(
        prepare_keyed_receipts(&path, &account).await.unwrap()["engine"],
        "v1"
    );
}
