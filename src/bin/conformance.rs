//! Conformance CLI — `cargo run --bin conformance [-- path/to/native.db]`
//! (installed: `conformance [path]`).
//!
//! With a path (or file: URL), validates that database against the frozen v1
//! spine contract. With no argument, stands up a fresh database from this
//! build's DDL and validates it — the install self-check. Exits non-zero on any
//! violation, so it slots directly into CI and a forker's install pipeline.

use std::process::ExitCode;

use native_ce::conformance::{format_report, run_conformance};
use native_ce::{create_database, open_existing_database};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("conformance failed to run: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> native_ce::Result<bool> {
    let arg = std::env::args().nth(1);
    let db = match &arg {
        None => create_database(":memory:").await?,
        Some(path) => open_existing_database(path).await?,
    };
    println!(
        "{}",
        match &arg {
            None => "Validating a fresh install (in-memory) against the frozen v1 spine contract…"
                .to_string(),
            Some(path) => format!("Validating {path} against the frozen v1 spine contract…"),
        }
    );
    let report = run_conformance(&db).await;
    println!("{}", format_report(&report));
    db.close().await;
    Ok(report.ok)
}
