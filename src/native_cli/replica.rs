//! Internal acquisition, admission, delta and audit entry points shared with the legacy example.

use std::path::Path;

use crate::standby::{
    GenerationStore, StandbyRefreshConfig, StandbyRefreshController, StandbyRuntimeConfig,
};
use crate::standby_snapshot::{ObservedInstalledConsumerIdentity, StandbyConsumerIdentity};
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
    // Strip only the known CLI envelope fields before strict typed validation.
    // Both executable names retain the legacy v1 runtime compatibility label.
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let object = value
        .as_object_mut()
        .ok_or("consumer identity must be an object")?;
    if object.remove("runtime") != Some(serde_json::json!(super::consumer::CONSUMER_RUNTIME_LABEL))
        || object.remove("standby_required") != Some(serde_json::json!(true))
    {
        return Err("installed executable is not a standby consumer".into());
    }
    // Current consumers advertise receiver shapes in this known CLI-only field.
    // This is informational here; GenerationStore enforces actual admission.
    object.remove("accepted_shapes");
    let identity: StandbyConsumerIdentity = serde_json::from_value(value)?;
    identity.validate_declaration()?;
    if identity.artifact_sha256 != executable_digest
        || identity.engine_schema_version != crate::CURRENT_ENGINE_SCHEMA_VERSION
        || identity.ddl_sha256 != crate::schema::FROZEN_DDL_SHA256
    {
        return Err("installed consumer bytes or admission engine are incompatible".into());
    }
    Ok(ObservedInstalledConsumerIdentity {
        kernel_v2_reader: identity.kernel_v2_reader,
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

async fn delta(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err(
            "usage: standby_admit --delta <runtime.json> <consumer-executable> <refresh.json>"
                .into(),
        );
    }
    let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
    let observed = observe_consumer(Path::new(&args[1])).await?;
    // Consumers built before in-place deltas open generations `immutable`
    // and must never serve a copy that a delta advances.
    if observed.source_sha != crate::FULL_GIT_SHA {
        return Err("delta requires the consumer built from this helper's source".into());
    }
    let config = StandbyRefreshConfig::from_json(&std::fs::read(&args[2])?)?;
    let store = GenerationStore::open(
        &runtime.replica_root,
        &runtime.hosted_route_database_id,
        Some(runtime.origin_database_id.clone()),
    )?;
    let controller = StandbyRefreshController::new(runtime, config, store, observed)?;
    let started = std::time::Instant::now();
    let outcome = controller.refresh_delta_only().await?;
    let mut receipt = serde_json::to_value(&outcome)?;
    receipt["delta_elapsed_seconds"] = serde_json::json!(started.elapsed().as_secs_f64());
    println!("{receipt}");
    Ok(())
}

async fn audit(args: &[String]) -> Result<()> {
    if args.len() != 2 {
        return Err("usage: standby_admit --audit <runtime.json> <consumer-executable>".into());
    }
    let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
    let observed = observe_consumer(Path::new(&args[1])).await?;
    let store = GenerationStore::open(
        runtime.replica_root,
        runtime.hosted_route_database_id,
        Some(runtime.origin_database_id),
    )?;
    let started = std::time::Instant::now();
    eprintln!("standby_admit: auditing the current copy with the full verifier");
    let outcome = store.audit_current(&observed).await?;
    let mut receipt = serde_json::to_value(&outcome)?;
    receipt["audit_elapsed_seconds"] = serde_json::json!(started.elapsed().as_secs_f64());
    println!("{receipt}");
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

/// Legacy entry point; retains its flags, receipts and failure diagnostics.
pub async fn run_legacy(args: &[String]) -> std::process::ExitCode {
    let result = match args.first().map(String::as_str) {
        Some("--acquire-only") => acquire(&args[1..]).await,
        Some("--delta") => delta(&args[1..]).await,
        Some("--audit") => audit(&args[1..]).await,
        _ => admit(args).await,
    };
    finish(result)
}

fn finish(result: Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            // Verification errors can contain projection or SQL details.
            eprintln!("standby_admit: operation failed; no successful receipt");
            std::process::ExitCode::FAILURE
        }
    }
}

pub const USAGE: &str = "usage: native node replica acquire|delta <runtime.json> <consumer-executable> <refresh.json>\n       native node replica admit <runtime.json> <consumer-executable> <snapshot.db> <manifest.json>\n       native node replica audit <runtime.json> <consumer-executable>\nInternal maintenance commands: acquisition does not admit; delta never downloads a FULL snapshot.";

/// Internal product entry point; validates shape before opening files or networking.
pub async fn run_cli(args: &[String]) -> std::process::ExitCode {
    if args.is_empty() || matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }
    let result = match (args[0].as_str(), args.len()) {
        ("acquire", 4) => acquire(&args[1..]).await,
        ("delta", 4) => delta(&args[1..]).await,
        ("audit", 3) => audit(&args[1..]).await,
        ("admit", 5) => admit(&args[1..]).await,
        _ => {
            eprintln!("{USAGE}");
            return std::process::ExitCode::from(2);
        }
    };
    finish(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> serde_json::Value {
        serde_json::json!({
            "contract": crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT,
            "version": 1, "runtime": "mcp-stdio", "standby_required": true,
            "platform": "linux-x86_64", "source_sha": "a".repeat(40),
            "artifact_sha256": "b".repeat(64),
            "engine_schema_version": crate::CURRENT_ENGINE_SCHEMA_VERSION,
            "ddl_sha256": crate::schema::FROZEN_DDL_SHA256,
        })
    }

    #[test]
    fn accepts_shared_identity_envelope_and_preserves_legacy_runtime_label() {
        let observed =
            validate_identity(&serde_json::to_vec(&identity()).unwrap(), &"b".repeat(64)).unwrap();
        let advertised = super::super::consumer::standby_identity(observed.clone());
        assert_eq!(advertised["runtime"], "mcp-stdio");
        assert!(advertised.get("accepted_shapes").is_some());
        assert_eq!(
            validate_identity(
                &serde_json::to_vec(&advertised).unwrap(),
                &observed.artifact_sha256
            )
            .unwrap(),
            observed
        );
    }

    #[tokio::test]
    async fn rejects_unknown_or_malformed_commands_before_io() {
        for args in [
            vec!["admit"],
            vec!["delta", "missing.json"],
            vec!["unknown", "a", "b", "c"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(run_cli(&args).await, std::process::ExitCode::from(2));
        }
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
