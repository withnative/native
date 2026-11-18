//! Shipping-database regressions, not a holder or authorization fixture.
use super::*;
use crate::mcp::{registry::ToolRegistry, Caller};

async fn fixture() -> (tempfile::TempDir, Db, ToolRegistry) {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::create_database(dir.path().join("fts.db").to_str().unwrap())
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
                "type":"Document", "kind":"note", "name":name, "body":"alpha body",
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

async fn quick(tx: &mut Transaction<'_, Sqlite>) -> Vec<String> {
    sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_all(&mut **tx)
        .await
        .unwrap()
}

#[tokio::test]
async fn refreshes_stale_fts_state_in_same_snapshot_without_writes() {
    {
        let (_empty_dir, empty_db, _) = fixture().await;
        let mut connection = empty_db.write_pool().acquire().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
                .fetch_one(&mut *connection)
                .await
                .unwrap(),
            1
        );
        let seeded: Vec<String> = sqlx::query_scalar("SELECT id FROM records ORDER BY id")
            .fetch_all(&mut *connection)
            .await
            .unwrap();
        assert_eq!(
            seeded,
            [
                crate::schema::ROOT_RECORD_ID,
                crate::schema::UNFILED_RECORD_ID
            ]
        );
        // Physical-integrity fixture only, not a serving/replay-valid workspace:
        // remove the two genuine seed projections with all shipping FK/triggers.
        assert_eq!(
            sqlx::query("DELETE FROM records WHERE id IN (?,?)")
                .bind(crate::schema::ROOT_RECORD_ID)
                .bind(crate::schema::UNFILED_RECORD_ID)
                .execute(&mut *connection)
                .await
                .unwrap()
                .rows_affected(),
            2
        );
        for index in ["records_fts", "records_name_idx"] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {index}"))
                    .fetch_one(&mut *connection)
                    .await
                    .unwrap(),
                0
            );
        }
        let mut empty = connection.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let changes: i64 = sqlx::query_scalar("SELECT total_changes()")
            .fetch_one(&mut *empty)
            .await
            .unwrap();
        let before = bytes(&empty_db);
        fresh_integrity(&empty_db, &mut empty).await.unwrap();
        assert_eq!(bytes(&empty_db), before);
        assert_eq!(quick(&mut empty).await, ["ok"]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT total_changes()")
                .fetch_one(&mut *empty)
                .await
                .unwrap(),
            changes
        );
        empty.rollback().await.unwrap();
    }
    // Keep the normal seeded workspace intact for actual tool writes below.
    let (_dir, db, registry) = fixture().await;
    let mut a = db.write_pool().acquire().await.unwrap();
    for index in ["records_fts", "records_name_idx"] {
        // Fixture-only merge threshold, never a production setting.
        sqlx::query(&format!(
            "INSERT INTO {index}({index},rank) VALUES('crisismerge',2)"
        ))
        .execute(&mut *a)
        .await
        .unwrap();
    }
    let mut b = db.write_pool().acquire().await.unwrap();
    let mut stale_checks = 0;
    for i in 0..40_i64 {
        let name = format!("alpha name {i}");
        // A and B are retained, so the actual writer uses another connection.
        record(&registry, &db, &name).await;
        for statement in [
            "SELECT count(*) FROM records_fts WHERE records_fts MATCH 'alpha'",
            "SELECT count(*) FROM records_name_idx WHERE records_name_idx MATCH 'alpha'",
        ] {
            let _: i64 = sqlx::query_scalar(statement)
                .fetch_one(&mut *a)
                .await
                .unwrap();
        }
        // Deliberate fixture-only projection update exercises both shipping
        // FTS triggers; it is not a legitimate content-event producer.
        assert_eq!(
            sqlx::query("UPDATE records SET body=? WHERE name=?")
                .bind(format!("body {i}"))
                .bind(&name)
                .execute(&mut *b)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        let mut tx = a.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let old = quick(&mut tx).await;
        if old != ["ok"] {
            assert!(old[0].starts_with("malformed inverted index for FTS5 table main.records_"));
            stale_checks += 1;
        }
        let changes: i64 = sqlx::query_scalar("SELECT total_changes()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let before = bytes(&db);
        // The actual product helper opens a fresh WAL-aware read-only reader
        // under A's unwritten write fence; it does not repair A's cache.
        fresh_integrity(&db, &mut tx).await.unwrap();
        assert_eq!(bytes(&db), before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT total_changes()")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            changes
        );
        tx.rollback().await.unwrap();
        let mut other = b.begin_with("BEGIN IMMEDIATE").await.unwrap();
        assert_eq!(quick(&mut other).await, ["ok"]);
        other.rollback().await.unwrap();
    }
    // Preserve the existing test ID, but qualify the merged actual helper,
    // not the retired cursor refresh or two already-healthy checks.
    assert!(stale_checks > 0);
}

#[tokio::test]
async fn refreshed_cursors_still_refuse_each_malformed_fts_index() {
    for index in ["records_fts", "records_name_idx"] {
        let (_dir, db, registry) = fixture().await;
        record(&registry, &db, "alpha name").await;
        // SQL-permitted corruption of this throwaway fixture's index leaf.
        // This is intentionally not a legitimate product write or repair.
        let changed = sqlx::query(&format!(
            "UPDATE {index}_data SET block=zeroblob(length(block)) WHERE id=(SELECT min(id) FROM {index}_data WHERE id>10)"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        assert_eq!(changed.rows_affected(), 1);
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let changes: i64 = sqlx::query_scalar("SELECT total_changes()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let before = bytes(&db);
        assert!(fresh_integrity(&db, &mut tx).await.is_err());
        assert_eq!(bytes(&db), before);
        assert_eq!(
            quick(&mut tx).await,
            [format!(
                "malformed inverted index for FTS5 table main.{index}"
            )]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT total_changes()")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            changes
        );
        tx.rollback().await.unwrap();
    }
}
