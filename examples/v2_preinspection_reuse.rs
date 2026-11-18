//! Local benchmark: pre-inspect snapshot A, then count how many observations a
//! later snapshot B reuses. Prints counts and timings only, never content.
//! Usage: v2-preinspection-reuse <snapshot-a.db> <snapshot-b.db> <members.txt>
use std::{collections::BTreeSet, path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, a, b, members] = args.as_slice() else {
        return Err(
            "usage: v2-preinspection-reuse <snapshot-a.db> <snapshot-b.db> <members.txt>".into(),
        );
    };
    let members: BTreeSet<String> = std::fs::read_to_string(members)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let started = Instant::now();
    let evidence_a = native_ce::v1_import::cutover::snapshot_evidence(Path::new(a), true).await?;
    let evidence_a_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    // SAFETY: both snapshots are private scratch copies; nothing writes them.
    let receipt = unsafe {
        native_ce::kernel::imported_content::preinspect(
            Path::new(a),
            &members,
            &evidence_a,
            &mut |_, _, _| {},
        )
    }
    .await?;
    let preinspect_seconds = started.elapsed().as_secs_f64();
    let evidence_b = native_ce::v1_import::cutover::snapshot_evidence(Path::new(b), true).await?;
    let started = Instant::now();
    let reuse = native_ce::kernel::imported_content::reuse_probe(
        &receipt,
        Path::new(b),
        &members,
        &evidence_b,
    )
    .await?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "native.v2-preinspection-reuse-bench.v1",
            "members": members.len(),
            "snapshot_digests_equal": evidence_a.digest == evidence_b.digest,
            "evidence_a_seconds": evidence_a_seconds,
            "preinspect_a_seconds": preinspect_seconds,
            "receipt_cacheable": receipt.summary["cacheable"],
            "receipt_uncacheable": receipt.summary["uncacheable"],
            "probe_b_seconds": started.elapsed().as_secs_f64(),
            "reuse_on_b": reuse,
        })
    );
    Ok(())
}
