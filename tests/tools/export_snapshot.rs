use std::sync::Arc;

use base64::Engine as _;
use native_ce::export::{ExportCoordinator, LocalSnapshotSource};
use native_ce::mcp::{
    register_builtin_tools, register_snapshot_tool, register_surface_tools, Caller, ToolRegistry,
    SNAPSHOT_MAX_PAGE_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn local_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_snapshot_tool(&mut registry, Arc::new(LocalSnapshotSource::new())).unwrap();
    registry
}

fn registry_with_coordinator(coordinator: ExportCoordinator) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_snapshot_tool(
        &mut registry,
        Arc::new(LocalSnapshotSource::with_coordinator(coordinator)),
    )
    .unwrap();
    registry
}

#[test]
fn export_snapshot_is_advertised_by_the_local_registry() {
    let local = local_registry();
    let spec = local
        .get("export_snapshot")
        .expect("stdio registry advertises export_snapshot");
    assert_eq!(
        spec.input_schema["properties"]["length"]["maximum"],
        SNAPSHOT_MAX_PAGE_BYTES
    );
    assert_eq!(
        spec.input_schema["properties"]["standby_consumer"]["properties"]["contract"]["const"],
        "native.standby-consumer.v1"
    );
}

async fn call(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    caller: Caller,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry
        .call(db.clone(), caller, "export_snapshot", arguments)
        .await
}

#[tokio::test]
async fn pages_are_consistent_retryable_principal_bound_and_single_flight() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("source.db");
    let db = native_ce::create_database(&db_path.to_string_lossy())
        .await
        .unwrap();
    native_ce::store::create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "in-export" }),
    )
    .await
    .unwrap();
    // Keep the first call non-final without relying on schema size.
    sqlx::query(
        "INSERT INTO blobs
         (id, bytes, size_bytes, storage_tier, created_at)
         VALUES ('padding', zeroblob(200000), 200000, 'inline', '2026-07-31T00:00:00Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let coordinator = ExportCoordinator::new();
    let registry = registry_with_coordinator(coordinator.clone());
    let caller = Caller::authenticated("user-a");
    let first = call(&registry, &db, caller.clone(), json!({ "length": 4096 }))
        .await
        .unwrap();
    assert_eq!(first["offset"], 0);
    assert_eq!(first["eof"], false);
    assert!(first.get("manifest").is_none());
    let export_id = first["export_id"].as_str().unwrap().to_string();
    assert!(
        std::fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("native-ce-export-")
        }),
        "the local source must retain its VACUUM snapshot beside the source .db"
    );

    let retry = call(
        &registry,
        &db,
        caller.clone(),
        json!({ "export_id": export_id, "offset": 0, "length": 4096 }),
    )
    .await
    .unwrap();
    assert_eq!(retry["data_base64"], first["data_base64"]);
    assert_eq!(retry["sha256"], first["sha256"]);

    let wrong_principal = call(
        &registry,
        &db,
        Caller::authenticated("user-b"),
        json!({ "export_id": export_id, "offset": 0, "length": 4096 }),
    )
    .await
    .unwrap_err();
    assert!(matches!(wrong_principal, native_ce::Error::Auth(_)));

    let concurrent = call(&registry, &db, caller.clone(), json!({ "length": 4096 }))
        .await
        .unwrap_err();
    assert!(concurrent
        .to_string()
        .contains("already in progress for this account"));
    assert!(
        coordinator.try_begin("user-a".into()).is_none(),
        "the HTTP frontend's shared coordinator must see the tool lease"
    );

    let mut assembled = base64::engine::general_purpose::STANDARD
        .decode(first["data_base64"].as_str().unwrap())
        .unwrap();
    let mut offset = first["length"].as_u64().unwrap();
    let final_page = loop {
        let page = call(
            &registry,
            &db,
            caller.clone(),
            json!({
                "export_id": export_id,
                "offset": offset,
                "length": SNAPSHOT_MAX_PAGE_BYTES,
            }),
        )
        .await
        .unwrap();
        assembled.extend(
            base64::engine::general_purpose::STANDARD
                .decode(page["data_base64"].as_str().unwrap())
                .unwrap(),
        );
        offset += page["length"].as_u64().unwrap();
        if page["eof"] == true {
            break page;
        }
    };
    assert_eq!(assembled.len() as u64, final_page["size_bytes"]);
    assert_eq!(
        hex::encode(Sha256::digest(&assembled)),
        final_page["sha256"]
    );

    let output = dir.path().join("assembled.db");
    std::fs::write(&output, &assembled).unwrap();
    let exported = native_ce::open_database_at(&output).await.unwrap();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM records WHERE id NOT IN ('native:root', 'native:unfiled') ORDER BY name",
    )
    .fetch_all(exported.pool())
    .await
    .unwrap();
    assert_eq!(names, ["in-export"]);
    exported.close().await;

    // EOF releases the snapshot + single-flight lease, but a bounded final
    // page cache makes a lost response safe to retry.
    coordinator.wait_for_idle().await;
    let final_retry = call(
        &registry,
        &db,
        caller.clone(),
        json!({
            "export_id": export_id,
            "offset": final_page["offset"],
            "length": SNAPSHOT_MAX_PAGE_BYTES,
        }),
    )
    .await
    .unwrap();
    assert_eq!(final_retry["data_base64"], final_page["data_base64"]);

    let next = call(&registry, &db, caller, json!({ "length": 4096 }))
        .await
        .unwrap();
    assert_ne!(next["export_id"], export_id);
    coordinator.drain().await;
    coordinator.wait_for_idle().await;
    db.close().await;
}

#[tokio::test]
async fn local_export_never_claims_hosted_standby_provenance() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let error = call(
        &local_registry(),
        &db,
        Caller::authenticated("local"),
        json!({
            "standby_consumer": {
                "contract": "native.standby-consumer.v1",
                "version": 1,
                "platform": "linux-x86_64",
                "source_sha": "0123456789abcdef0123456789abcdef01234567",
                "artifact_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "engine_schema_version": native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
                "ddl_sha256": native_ce::schema::FROZEN_DDL_SHA256,
            }
        }),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("requires an authenticated hosted source"));
    db.close().await;
}

#[tokio::test]
async fn continuation_cannot_rebind_a_standby_consumer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let error = call(
        &local_registry(), &db, Caller::authenticated("local"),
        json!({
            "export_id": "opaque", "offset": 0,
            "standby_consumer": {
                "contract": "native.standby-consumer.v1", "version": 1,
                "platform": "linux-x86_64",
                "source_sha": "0123456789abcdef0123456789abcdef01234567",
                "artifact_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "engine_schema_version": native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
                "ddl_sha256": native_ce::schema::FROZEN_DDL_SHA256
            }
        }),
    ).await.unwrap_err();
    assert!(error.to_string().contains("valid only when starting"));
    db.close().await;
}

#[tokio::test]
async fn shutdown_drain_reclaims_an_abandoned_paged_snapshot() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    sqlx::query(
        "INSERT INTO blobs
         (id, bytes, size_bytes, storage_tier, created_at)
         VALUES ('padding', zeroblob(200000), 200000, 'inline', '2026-07-31T00:00:00Z')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let coordinator = ExportCoordinator::new();
    let registry = Arc::new(registry_with_coordinator(coordinator.clone()));
    let first = call(
        &registry,
        &db,
        Caller::authenticated("user-a"),
        json!({ "length": 1024 }),
    )
    .await
    .unwrap();
    assert_eq!(first["eof"], false);

    coordinator.drain().await;
    let after = call(
        &registry,
        &db,
        Caller::authenticated("user-a"),
        json!({
            "export_id": first["export_id"],
            "offset": first["length"],
            "length": 1024,
        }),
    )
    .await
    .unwrap_err();
    assert!(after.to_string().contains("does not exist or has expired"));
    let late = call(
        &registry,
        &db,
        Caller::authenticated("user-a"),
        json!({ "length": 1024 }),
    )
    .await
    .unwrap_err();
    assert!(
        late.to_string().contains("already in progress")
            || late.to_string().contains("shutting down")
    );
    db.close().await;
}
