//! Compare the cutover snapshot digest against its reference formulation on a
//! real database copy: wall time for each, and whether every output agrees.
//! Prints timings and digests only, never values. Use a private copy; the
//! scan is read-only but opens the file's WAL index.
//! Usage: v2-digest-compare <snapshot.db> [rounds]
use native_ce::v1_import::cutover::{reference_snapshot_evidence, snapshot_evidence};
use std::{path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = Path::new(
        args.get(1)
            .ok_or("usage: v2-digest-compare <snapshot.db> [rounds]")?,
    );
    let rounds: usize = args.get(2).map(|r| r.parse()).transpose()?.unwrap_or(1);
    let mut results = Vec::new();
    for round in 0..rounds {
        for partition in [false, true] {
            let started = Instant::now();
            let fast = snapshot_evidence(path, partition).await?;
            let fast_seconds = started.elapsed().as_secs_f64();
            let started = Instant::now();
            let reference = reference_snapshot_evidence(path, partition).await?;
            let reference_seconds = started.elapsed().as_secs_f64();
            results.push(serde_json::json!({
                "round": round,
                "partition": partition,
                "fast_seconds": fast_seconds,
                "reference_seconds": reference_seconds,
                "digest": fast.digest,
                "identical": fast.digest == reference.digest
                    && fast.environment == reference.environment
                    && fast.records == reference.records,
                "partitions": fast.records.len(),
            }));
        }
    }
    let bytes = std::fs::metadata(path)?.len();
    println!(
        "{}",
        serde_json::json!({"schema":"native.v2-digest-compare.v1","bytes":bytes,"results":results})
    );
    Ok(())
}
