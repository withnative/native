//! End-to-end cost of one private `as_of` fold, as the lens runs it.
//!
//! A measurement tool, not a test: a `dev-tools` binary like
//! `board-render-cost`, so a plain build or test does not pay for it. It times
//! `lens::replay_projection` — prefix load, fold, flush, FTS rebuild and
//! commit together — into a fresh scratch, the same call every `as_of` reader
//! makes, and prints the peak resident set size of the process.
//!
//! ```text
//! TMPDIR=$HOME/asof-bench/tmp ASOF_CORPUS=$HOME/asof-bench/corpus.db ASOF_N=76816 \
//!   cargo run --release --features dev-tools --bin asof-fold-time
//! ```
//!
//! `ASOF_CORPUS` is opened read-write like a live handle, so point it only at
//! a private copy, never a real database. Set `TMPDIR` to a roomy filesystem:
//! the scratch is an engine `:memory:` temp file under it.

use std::time::Instant;

use native_ce::query::lens;
use native_ce::{apply_schema, open_database};

fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix(field)?
                    .trim()
                    .strip_suffix("kB")?
                    .trim()
                    .parse()
                    .ok()
            })
        })
        .unwrap_or(0)
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|load| load.trim().to_owned())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    let corpus =
        std::env::var("ASOF_CORPUS").unwrap_or_else(|_| format!("{home}/asof-bench/corpus.db"));
    let requested: i64 = std::env::var("ASOF_N")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(5000);
    println!("asof-fold-time corpus={corpus} requested_N={requested}");
    println!("loadavg_start={}", loadavg());

    let live = open_database(&corpus).await.unwrap();
    let max_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(live.pool())
        .await
        .unwrap();
    let n = requested.clamp(1, max_seq.max(1));
    println!("max_seq={max_seq} N={n}");

    let scratch = open_database(":memory:").await.unwrap();
    apply_schema(&scratch).await.unwrap();
    let started = Instant::now();
    lens::replay_projection(&live, &scratch, n).await.unwrap();
    let secs = started.elapsed().as_secs_f64();
    println!("replay_projection_secs={secs:.1}");

    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(scratch.pool())
        .await
        .unwrap();
    let hits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records_fts WHERE records_fts MATCH 'native'")
            .fetch_one(scratch.pool())
            .await
            .unwrap();
    println!("records={records} fts_native_hits={hits}");
    println!("peak_rss_mib={:.0}", status_kib("VmHWM:") as f64 / 1024.0);
    println!("loadavg_end={}", loadavg());
    scratch.close().await;
    live.close().await;
}
