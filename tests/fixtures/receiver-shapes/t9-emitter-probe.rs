use std::{error::Error, path::PathBuf};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn main() -> Result<(), Box<dyn Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 5, "private database clone, output, actual product identity, common receiver identity");
    let db_path = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    assert!(db_path.starts_with("/tmp/receiver-t9-f587"));
    assert!(!out.exists());
    std::fs::create_dir_all(&out)?;
    let identity: Value = serde_json::from_slice(&std::fs::read(&args[3])?)?;
    assert_eq!(identity["source_sha"], native_ce::FULL_GIT_SHA);
    assert_eq!(identity["engine_schema_version"], 94);
    let consumer: native_ce::standby_snapshot::StandbyConsumerIdentity =
        serde_json::from_slice(&std::fs::read(&args[4])?)?;
    let db = native_ce::db::open_existing_database(db_path.to_str().unwrap()).await?;
    let head = native_ce::standby::delta_transport::observe_authority_act_head(&db, "receiver-t9-route").await?;
    std::fs::write(out.join("head.json"), serde_json::to_vec(&head)?)?;
    let delta = native_ce::standby::delta_transport::observe_authority_act_delta(&db, "receiver-t9-route", 0).await?;
    std::fs::write(out.join("delta.json"), serde_json::to_vec(&delta)?)?;
    let captured = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let export = native_ce::export::export_connected_db(&db, Some(&out)).await?;
    let completed = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let bytes = std::fs::read(export.path())?;
    std::fs::write(out.join("full.sqlite"), &bytes)?;
    let context = native_ce::standby_snapshot::HostedStandbyManifestContext::new("receiver-t9-route".into(), consumer)?;
    let manifest = native_ce::standby_snapshot::manifest_from_completed_export(
        &export.path(), bytes.len() as u64, digest(&bytes), captured.clone(), completed.clone(), context
    ).await?;
    assert_eq!(manifest.engine.source_sha, native_ce::FULL_GIT_SHA);
    assert_eq!(manifest.engine.schema_version, 94);
    std::fs::write(out.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    std::fs::write(out.join("provenance.json"), serde_json::to_vec_pretty(&json!({
        "compiled_full_sha":native_ce::FULL_GIT_SHA,
        "observed_product_identity":identity,
        "manifest_compiled_producer_sha":manifest.engine.source_sha,
        "capture_started":captured,"snapshot_completed":completed,
        "full_sha256":digest(&bytes),"full_size":bytes.len(),
        "evidence_kind":"product-linked emitter component, not HTTP/auth process"
    }))?)?;
    export.cleanup().await;
    db.close().await;
    Ok(())
}
