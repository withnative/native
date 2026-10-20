//! Disposable source/target digest cost at HQ-sized synthetic file sizes.
use sqlx::Connection;
use std::{path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn measure(root: &Path, name: &str, mib: usize) -> Result<serde_json::Value> {
    let path = root.join(format!("{name}.db"));
    let mut db = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true),
    )
    .await?;
    sqlx::query("PRAGMA journal_mode=OFF")
        .execute(&mut db)
        .await?;
    sqlx::query("PRAGMA synchronous=OFF")
        .execute(&mut db)
        .await?;
    sqlx::query("CREATE TABLE synthetic_payload(id INTEGER PRIMARY KEY, body BLOB NOT NULL)")
        .execute(&mut db)
        .await?;
    for _ in 0..(mib / 8) {
        sqlx::query("INSERT INTO synthetic_payload(body) VALUES(zeroblob(8388608))")
            .execute(&mut db)
            .await?;
    }
    if !mib.is_multiple_of(8) {
        sqlx::query("INSERT INTO synthetic_payload(body) VALUES(zeroblob(?))")
            .bind(((mib % 8) * 1024 * 1024) as i64)
            .execute(&mut db)
            .await?;
    }
    db.close().await?;
    let size = std::fs::metadata(&path)?.len();
    let started = Instant::now();
    let digest = native_ce::v1_import::cutover::snapshot_digest(&path).await?;
    let seconds = started.elapsed().as_secs_f64();
    Ok(
        serde_json::json!({"label":name,"bytes":size,"digest_seconds":seconds,"digest_sha256":digest}),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = tempfile::Builder::new()
        .prefix("v2-hq-digest-bench-")
        .tempdir_in("/tmp")?;
    let source = measure(dir.path(), "source", 2537).await?;
    let target = measure(dir.path(), "target", 2630).await?;
    let source_seconds = source["digest_seconds"].as_f64().ok_or("source seconds")?;
    let target_seconds = target["digest_seconds"].as_f64().ok_or("target seconds")?;
    println!(
        "{}",
        serde_json::json!({"schema":"native.v2-hq-digest-bench.v1","source":source,"target":target,"in_freeze_digest_counts":{"source":3,"target":4},"in_freeze_digest_seconds":3.0*source_seconds+4.0*target_seconds})
    );
    Ok(())
}
