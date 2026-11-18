//! Deterministic SQLx settlement proofs; no timing sleep is an ordering oracle.
use super::*;
use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};

pub(crate) async fn database() -> Db {
    let (mut db, _) =
        crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let single = SqlitePoolOptions::new()
        .max_connections(1)
        .after_release(|connection, _| Box::pin(sanitize_released_write_connection(connection)))
        .connect_with(db.write_pool().connect_options().as_ref().clone())
        .await
        .unwrap();
    db.write_pool.close().await;
    db.write_pool = single;
    db
}

#[tokio::test]
async fn borrowed_commit_disposes_original_before_pool_reuse() {
    let db = database().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    sqlx::query("CREATE TEMP TABLE owned_connection_marker(value INTEGER)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO owned_connection_marker VALUES(41)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        db.commit_owned_kernel_content(&mut tx).await,
        KernelCommitOutcome::Committed
    ));
    assert_eq!(SqliteTransactionManager::get_transaction_depth(&tx), 0);
    // SQLx 0.8.6 queues a depth-zero no-op rollback on this original Drop.
    // The fixture uses a single writer connection; the TEMP marker proves
    // the later transaction is running on that exact pooled connection.
    drop(tx);
    let mut reused = begin_write(db.write_pool()).await.unwrap();
    let value: i64 = sqlx::query_scalar("SELECT value FROM owned_connection_marker")
        .fetch_one(&mut *reused)
        .await
        .unwrap();
    assert_eq!(value, 41);
    sqlx::query("UPDATE owned_connection_marker SET value=42")
        .execute(&mut *reused)
        .await
        .unwrap();
    assert!(matches!(
        db.commit_owned_kernel_content(&mut reused).await,
        KernelCommitOutcome::Committed
    ));
    drop(reused);
    let value: i64 = sqlx::query_scalar("SELECT value FROM owned_connection_marker")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(value, 42);
}

#[tokio::test]
async fn failed_commit_is_known_rollback_only_after_explicit_settlement() {
    let db = database().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    sqlx::query("CREATE TABLE settlement_parent(id INTEGER PRIMARY KEY)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE settlement_child(parent INTEGER REFERENCES settlement_parent(id) DEFERRABLE INITIALLY DEFERRED)")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO settlement_child VALUES(7)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        db.commit_owned_kernel_content(&mut tx).await,
        KernelCommitOutcome::RolledBack(_)
    ));
    assert_eq!(SqliteTransactionManager::get_transaction_depth(&tx), 0);
    drop(tx);
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_schema WHERE name IN ('settlement_parent','settlement_child')",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(tables, 0);
}

#[tokio::test]
async fn nested_transaction_cannot_be_mistaken_for_durable_commit() {
    let db = database().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    SqliteTransactionManager::begin(&mut tx, None)
        .await
        .unwrap();
    assert!(matches!(
        db.commit_owned_kernel_content(&mut tx).await,
        KernelCommitOutcome::Refused(_)
    ));
    assert_eq!(SqliteTransactionManager::get_transaction_depth(&tx), 2);
    assert!(Db::rollback_owned_kernel_content(&mut tx).await.is_err());
    SqliteTransactionManager::rollback(&mut tx).await.unwrap();
    Db::rollback_owned_kernel_content(&mut tx).await.unwrap();
    drop(tx);
}

#[tokio::test]
async fn rollback_failure_keeps_connection_owned_until_explicit_recovery() {
    let db = database().await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    // Deliberately desynchronize SQLite from SQLx's depth accounting to force
    // deterministic worker COMMIT and ROLLBACK errors, without timing hooks.
    sqlx::query("ROLLBACK").execute(&mut *tx).await.unwrap();
    assert!(matches!(
        db.commit_owned_kernel_content(&mut tx).await,
        KernelCommitOutcome::Uncertain(_)
    ));
    assert_eq!(SqliteTransactionManager::get_transaction_depth(&tx), 1);
    assert!(db.write_pool().try_acquire().is_none());
    // Only this test repairs its intentionally corrupted accounting. Product
    // code must retain this transaction in quarantine instead of pooling it.
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    Db::rollback_owned_kernel_content(&mut tx).await.unwrap();
    drop(tx);
    let mut reused = begin_write(db.write_pool()).await.unwrap();
    Db::rollback_owned_kernel_content(&mut reused)
        .await
        .unwrap();
    drop(reused);
}
