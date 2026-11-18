//! Shared deployed consumer CLI contract and bounded stderr diagnostics.
//!
//! `runtime` deliberately remains `mcp-stdio` for both executable names: it is
//! the v1 consumer compatibility label used by existing installers/admitters,
//! not the executable basename. The observed artifact hash identifies the bytes.
//! Changing this label requires a versioned transition for external consumers.

use crate::standby::{observe_installed_consumer_identity, GenerationStore, StandbyRuntimeConfig};
use std::process::ExitCode;

pub(super) const CONSUMER_RUNTIME_LABEL: &str = "mcp-stdio";

const STANDBY_PREPARE_CONSUMER_CONTRACT: &str = "native.standby-prepare-consumer.v1";

/// One-shot `--standby-prepare-consumer`: verify the accepted generation for
/// this build and publish its consumer-rebind receipt, while another build may
/// still be serving the same replica root. It never serves, so it records no
/// reader marker or lock, and it neither refreshes nor contacts hosted.
pub fn run_standby_prepare_consumer(program: &str, args: &[String]) -> ExitCode {
    let started = std::time::Instant::now();
    let result = (|| -> crate::Result<serde_json::Value> {
        if args.len() != 1 {
            return Err(crate::Error::engine(format!(
                "usage: {program} --standby-prepare-consumer <standby-config.json>"
            )));
        }
        let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
        let store = GenerationStore::open(
            runtime.replica_root,
            runtime.hosted_route_database_id,
            Some(runtime.origin_database_id),
        )?;
        let observed = observe_installed_consumer_identity()?;
        let prepared = store.prepare_consumer_binding_blocking(observed.clone())?;
        Ok(serde_json::json!({
            "contract": STANDBY_PREPARE_CONSUMER_CONTRACT,
            "generation_id": prepared.generation_id,
            "outcome": prepared.outcome,
            "trusted_at_rest": prepared.trusted_at_rest,
            "accepted_consumer": observed,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        }))
    })();
    match result {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{program}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Machine-readable identity used by the release packager and installer. It
/// deliberately comes from the compiled binary itself, rather than from a
/// caller-supplied label or a package manifest.
pub fn print_standby_identity(program: &str) -> ExitCode {
    match observe_installed_consumer_identity() {
        Ok(observed) => {
            let identity = standby_identity(observed);
            println!("{identity}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("{program}: cannot observe standby identity");
            ExitCode::FAILURE
        }
    }
}

/// Serialize the unchanged v1 CLI identity envelope for either executable.
pub(super) fn standby_identity(
    observed: crate::standby_snapshot::ObservedInstalledConsumerIdentity,
) -> serde_json::Value {
    let consumer = crate::standby_snapshot::StandbyConsumerIdentity {
        kernel_v2_reader: observed.kernel_v2_reader,
        contract: crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: observed.platform,
        source_sha: observed.source_sha,
        artifact_sha256: observed.artifact_sha256,
        engine_schema_version: observed.engine_schema_version,
        ddl_sha256: observed.ddl_sha256,
    };
    let mut identity = serde_json::to_value(consumer).expect("consumer identity serializes");
    identity["runtime"] = serde_json::json!(CONSUMER_RUNTIME_LABEL);
    identity["standby_required"] = serde_json::json!(true);
    identity["accepted_shapes"] =
        serde_json::from_str::<serde_json::Value>(&crate::standby::shapes::advertisement())
            .expect("static receiver shapes");
    identity
}

pub fn enable_bounded_verification_diagnostics() {
    use tracing_subscriber::prelude::*;
    // Keep protocol stdout untouched; admit only payload-free standby diagnostics.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                    metadata.target() == "native_ce::standby::verification"
                        || metadata.target() == "native_ce::standby::vault"
                        || metadata.target() == "native_ce::standby::transport"
                })),
        )
        .init();
    crate::standby::enable_bounded_verification_diagnostics();
}
