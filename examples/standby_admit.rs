//! Separate authenticated acquisition and offline admission of a standby snapshot.
//! The default admission mode makes no hosted requests or manifest rewrites. It uses GenerationStore's
//! complete checks for an explicitly observed installed consumer executable.
//! Usage: standby_admit <runtime.json> <consumer-executable> <snapshot.db> <manifest.json>
//! Acquisition: standby_admit --acquire-only <runtime.json> <consumer-executable> <refresh.json>
//! Acquisition does not admit or publish a generation. Run the default mode separately.
//! TMPDIR may point to private disposable memory-backed storage for replay scratch.

use std::path::Path;

use native_ce::standby::{
    GenerationStore, StandbyRefreshConfig, StandbyRefreshController, StandbyRuntimeConfig,
};
use native_ce::standby_snapshot::{ObservedInstalledConsumerIdentity, StandbyConsumerIdentity};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn digest(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn validate_identity(
    bytes: &[u8],
    executable_digest: &str,
) -> Result<ObservedInstalledConsumerIdentity> {
    // The executable reports two CLI-only fields in addition to the typed
    // consumer contract. Reject unexpected fields rather than accepting labels.
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or("consumer identity must be an object")?;
    if object.remove("runtime") != Some(serde_json::json!("mcp-stdio"))
        || object.remove("standby_required") != Some(serde_json::json!(true))
    {
        return Err("installed executable is not a standby consumer".into());
    }
    let identity: StandbyConsumerIdentity = serde_json::from_value(value)?;
    identity.validate_declaration()?;
    if identity.artifact_sha256 != executable_digest
        || identity.engine_schema_version != native_ce::CURRENT_ENGINE_SCHEMA_VERSION
        || identity.ddl_sha256 != native_ce::schema::FROZEN_DDL_SHA256
    {
        return Err("installed consumer bytes or admission engine are incompatible".into());
    }
    Ok(ObservedInstalledConsumerIdentity {
        platform: identity.platform,
        source_sha: identity.source_sha,
        artifact_sha256: identity.artifact_sha256,
        engine_schema_version: identity.engine_schema_version,
        ddl_sha256: identity.ddl_sha256,
    })
}

async fn observe_consumer(path: &Path) -> Result<ObservedInstalledConsumerIdentity> {
    let executable = std::fs::canonicalize(path)?;
    let before = digest(&executable)?;
    let mut command = tokio::process::Command::new(&executable);
    command.arg("--standby-identity").kill_on_drop(true);
    let output =
        tokio::time::timeout(std::time::Duration::from_secs(30), command.output()).await??;
    if !output.status.success() || output.stdout.len() > 4096 || digest(&executable)? != before {
        return Err("installed consumer identity could not be observed stably".into());
    }
    validate_identity(&output.stdout, &before)
}

async fn acquire(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("usage: standby_admit --acquire-only <runtime.json> <consumer-executable> <refresh.json>".into());
    }
    let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
    let observed = observe_consumer(Path::new(&args[1])).await?;
    let config = StandbyRefreshConfig::from_json(&std::fs::read(&args[2])?)?;
    let store = GenerationStore::open(
        &runtime.replica_root,
        &runtime.hosted_route_database_id,
        Some(runtime.origin_database_id.clone()),
    )?;
    let controller = StandbyRefreshController::new(runtime, config, store, observed)?;
    let started = std::time::Instant::now();
    eprintln!("standby_admit: acquiring one producer-bound snapshot; admission remains separate");
    let download = controller.acquire_snapshot_only().await?;
    let (snapshot, manifest) = download.preserve();
    println!(
        "{}",
        serde_json::json!({
            "acquired": true,
            "admitted": false,
            "snapshot_path": snapshot,
            "manifest_path": manifest,
            "acquisition_elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    Ok(())
}

async fn admit(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err("usage: standby_admit <runtime.json> <consumer-executable> <snapshot.db> <manifest.json>".into());
    }
    let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
    let observed = observe_consumer(Path::new(&args[1])).await?;
    let store = GenerationStore::open(
        runtime.replica_root,
        runtime.hosted_route_database_id,
        Some(runtime.origin_database_id),
    )?;
    // The kernel accepts only direct private staging children. Keep the
    // preserved originals untouched and let these owned copies clean up on
    // success or refusal; publication makes its own durable immutable copy.
    let mut snapshot = tempfile::NamedTempFile::new_in(store.staging_dir())?;
    let mut manifest = tempfile::NamedTempFile::new_in(store.staging_dir())?;
    std::io::copy(&mut std::fs::File::open(&args[2])?, snapshot.as_file_mut())?;
    std::io::copy(&mut std::fs::File::open(&args[3])?, manifest.as_file_mut())?;
    snapshot.as_file().sync_all()?;
    manifest.as_file().sync_all()?;
    let started = std::time::Instant::now();
    eprintln!("standby_admit: running complete offline admission checks");
    let generation = store
        .install_staged(snapshot.path(), manifest.path(), &observed)
        .await?;
    eprintln!("standby_admit: complete offline admission succeeded");
    println!(
        "{}",
        serde_json::json!({
            "generation_id": generation.id,
            "admitted": true,
            "admission_elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::prelude::*;
    // Only bounded verification events; stdout remains the final JSON receipt.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_filter(filter_fn(|metadata| {
                    metadata.target() == "native_ce::standby::verification"
                })),
        )
        .init();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if args.first().is_some_and(|arg| arg == "--acquire-only") {
        acquire(&args[1..]).await
    } else {
        admit(&args).await
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            // Verification errors can contain projection or SQL details.
            eprintln!("standby_admit: operation failed; no successful receipt");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> serde_json::Value {
        serde_json::json!({
            "contract": native_ce::standby_snapshot::STANDBY_CONSUMER_CONTRACT,
            "version": 1, "runtime": "mcp-stdio", "standby_required": true,
            "platform": "linux-x86_64", "source_sha": "a".repeat(40),
            "artifact_sha256": "b".repeat(64),
            "engine_schema_version": native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
            "ddl_sha256": native_ce::schema::FROZEN_DDL_SHA256,
        })
    }

    #[test]
    fn rejects_unobserved_bytes_and_incompatible_engine() {
        let good = identity();
        assert!(validate_identity(&serde_json::to_vec(&good).unwrap(), &"b".repeat(64)).is_ok());
        assert!(validate_identity(&serde_json::to_vec(&good).unwrap(), &"c".repeat(64)).is_err());
        let mut wrong_engine = good;
        wrong_engine["engine_schema_version"] = serde_json::json!(0);
        assert!(
            validate_identity(&serde_json::to_vec(&wrong_engine).unwrap(), &"b".repeat(64))
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_runtime_and_unknown_identity_fields() {
        let mut wrong = identity();
        wrong["runtime"] = serde_json::json!("operator");
        assert!(validate_identity(&serde_json::to_vec(&wrong).unwrap(), &"b".repeat(64)).is_err());
        let mut unknown = identity();
        unknown["unchecked"] = serde_json::json!(true);
        assert!(
            validate_identity(&serde_json::to_vec(&unknown).unwrap(), &"b".repeat(64)).is_err()
        );
    }
}
