//! N1 probes use synthetic databases and disposable generation stores only.
use super::delta_transport::*;
use super::generation_store::tests::{observed, stage};
use super::*;
use crate::mcp::standby_stdio::{StandbySessionConfig, StandbyStdioSession};
use crate::mcp::{ExperimentalExecutors, ExposureProfile, McpSurfaceMode};
use serde_json::{json, Value};
use std::sync::Arc;

struct Hosted(crate::Db);
impl AuthorityActHttpClient for Hosted {
    fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
        let db = self.0.clone();
        Box::pin(async move {
            let args = &body["params"]["arguments"];
            let value = if args["operation"] == "authority_act_head" {
                serde_json::to_value(observe_authority_act_head(&db, "route-1").await?)?
            } else {
                serde_json::to_value(
                    observe_authority_act_delta_with_inventory(
                        &db,
                        "route-1",
                        args["arguments"]["from_exclusive_act"].as_i64().unwrap(),
                        Some(
                            &serde_json::from_value::<Vec<String>>(
                                args["arguments"]["blob_inventory"].clone(),
                            )
                            .unwrap(),
                        ),
                    )
                    .await?,
                )?
            };
            Ok(serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":body["id"],"result":{"isError":false,"content":[],"structuredContent":value}}),
            )?)
        })
    }
}
async fn session(store: GenerationStore, origin: String, binding: &str) -> StandbyStdioSession {
    let runtime = StandbyRuntimeConfig {
        replica_root: store.staging_dir().parent().unwrap().to_path_buf(),
        hosted_route_database_id: "route-1".into(),
        origin_database_id: origin,
    };
    let provider = StandbyStatusProvider::for_status_only_reason(
        runtime.clone(),
        store.clone(),
        Some(observed()),
        StandbyStatusOnly {
            reason: "fixture".into(),
            candidate_count: 0,
            unusable_candidate_count: 0,
        },
        false,
        false,
    );
    StandbyStdioSession::new(
        StandbySessionConfig {
            runtime,
            store,
            observed: observed(),
            surface: McpSurfaceMode::Executor,
            profile: ExposureProfile::Complete,
            experimental: ExperimentalExecutors::empty(),
            selected_account: Some(binding.into()),
            refresh_configured: false,
            refresh_available: false,
        },
        provider,
    )
    .unwrap()
}
async fn activate(session: &StandbyStdioSession, store: &GenerationStore) {
    let StandbyStartupOutcome::Serving(active) =
        store.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("fixture generation unavailable")
    };
    session.install_startup(*active).await.unwrap();
}
async fn read(session: &StandbyStdioSession, operation: &str, arguments: Value) -> Value {
    let executor = if operation == "query_sql" {
        "sql_read"
    } else {
        "records_read"
    };
    session.handle_message(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":executor,"arguments":{"operation":operation,"arguments":arguments,"format":"json"}}})).await.unwrap()
}

#[tokio::test]
async fn kernel_v2_snapshot_delta_and_outage_reads_use_real_kernel_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
    let first = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "v2").await;
    let installed = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    assert!(installed.manifest.kernel_v2.is_some());
    let session = session(store.clone(), origin.clone(), "acct:owner").await;
    activate(&session, &store).await;
    let answer = read(&session, "get_record", json!({"ids":[first]})).await;
    assert_eq!(answer["result"]["isError"], false, "{answer}");
    assert_eq!(
        answer["result"]["structuredContent"]["standby_context"]["read_only"],
        true
    );
    let bootstrap = session.handle_message(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}})).await.unwrap();
    assert_eq!(bootstrap["result"]["isError"], false, "{bootstrap}");
    assert_eq!(
        bootstrap["result"]["structuredContent"]["run"]["read_only"], true,
        "{bootstrap}"
    );
    assert!(bootstrap["result"]["structuredContent"]["run"]["run_key"].is_null());
    for (operation, args) in [
        ("search", json!({"query":"fixture"})),
        (
            "query_sql",
            json!({"sql":"SELECT id FROM records LIMIT 10"}),
        ),
    ] {
        let reply = read(&session, operation, args).await;
        assert_eq!(reply["result"]["isError"], false, "{operation}: {reply}");
    }
    let new_record = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    // The delta must carry new meta events and actual attachment bytes too.
    let package = crate::v2_standard::v1_compat::package();
    crate::kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &db,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &package,
        Some(&package.identity().unwrap()),
        &[],
    )
    .await
    .unwrap();
    let host = crate::kernel::resolve_principal_by_binding(&db, crate::kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let bytes = b"N1 synthetic attachment bytes";
    let blob = crate::blob::new_blob_meta(bytes, Some("text/plain"), Some("n1.txt"));
    let pin = &package.definitions[0];
    let attachment = uuid::Uuid::new_v4().to_string();
    let state = crate::kernel::ImportRecordState {
        definition: Some(crate::kernel::ImportDefinition {
            pin: crate::meta::definition_artifact::RevisionIdentity {
                family: pin.family.clone(),
                version: pin.version,
                digest: pin.digest.clone(),
            },
            primary_type: "V1".into(),
            kind: crate::v2_standard::v1_compat::KIND.into(),
            fields: crate::v2_standard::v1_compat::compat_fields(
                "Document",
                "attachment",
                Some("N1 attachment"),
                None,
                None,
            ),
        }),
        facets: vec![crate::kernel::FacetObservation {
            key: "blob_ref".into(),
            value: Some(blob.id.clone()),
            value_num: None,
            vocab_ref: None,
            as_of: blob.created_at.clone(),
        }],
        ..Default::default()
    };
    crate::kernel::import_record_with_blob_as(
        &db,
        &host,
        &attachment,
        crate::events::KERNEL_ROOT_ID,
        Some(&admin),
        &state,
        Some((bytes, &blob)),
    )
    .await
    .unwrap();
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "test-token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    let trusted = transport
        .kernel_delta(head.head().head_act(), &[])
        .await
        .unwrap();
    assert!(
        !trusted.delta().sections[1].rows.is_empty(),
        "meta tail is carried"
    );
    assert_eq!(
        trusted.delta().sections[2].rows.len(),
        1,
        "blob addition is carried"
    );
    let old_bytes = std::fs::read(&installed.snapshot_path).unwrap();
    let prepared = store
        .prepare_kernel_delta(&installed, &trusted, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&installed.snapshot_path).unwrap(), old_bytes);
    // An EXCLUSIVE lock on replay output cannot block the serving inode.
    use sqlx::Connection as _;
    let mut locked = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(prepared.snapshot_path()),
    )
    .await
    .unwrap();
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut locked)
        .await
        .unwrap();
    let old_read = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read(&session, "get_record", json!({"ids":[first]})),
    )
    .await
    .unwrap();
    assert_eq!(old_read["result"]["isError"], false);
    sqlx::query("ROLLBACK").execute(&mut locked).await.unwrap();
    locked.close().await.unwrap();
    // Simulate process abort after replay but before publication. Reopening
    // the store still selects the old verified generation.
    drop(prepared);
    assert_eq!(
        store.current_for_head_probe().unwrap().unwrap().id,
        installed.id
    );
    activate(&session, &store).await;
    let before_swap = read(&session, "get_record", json!({"ids":[new_record]})).await;
    assert_ne!(
        before_swap["result"]["structuredContent"]["records"][0]["status"],
        "found"
    );
    let prepared = store
        .prepare_kernel_delta(&installed, &trusted, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let installed = store
        .publish_kernel_delta(prepared, &observed())
        .await
        .unwrap();
    assert!(
        store
            .prepare_kernel_delta(&installed, &trusted, &chrono::Utc::now().to_rfc3339())
            .await
            .is_err(),
        "duplicate delta refuses"
    );
    store
        .record_synced(
            &installed,
            trusted.delta().head.head_act,
            &chrono::Utc::now().to_rfc3339(),
        )
        .unwrap();
    activate(&session, &store).await;
    let answer = read(&session, "get_record", json!({"ids":[new_record]})).await;
    assert_eq!(answer["result"]["isError"], false, "{answer}");
    assert_eq!(
        answer["result"]["structuredContent"]["records"][0]["status"], "found",
        "{answer}"
    );
    let reopened =
        crate::db::open_kernel_v2_standby_read_only(installed.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&db).await.unwrap(),
        crate::kernel::dump_all_kernel_tables(&reopened)
            .await
            .unwrap()
    );
    assert!(sqlx::query("DELETE FROM content_events")
        .execute(reopened.write_pool())
        .await
        .is_err());
    let copied: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM kernel_blobs WHERE sha256=?")
        .bind(&blob.sha256)
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(copied, bytes);
    let status = session.handle_message(json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"standby_status","arguments":{}}})).await.unwrap();
    assert_eq!(status["result"]["isError"], false, "{status}");
    assert_eq!(status["result"]["structuredContent"]["mode"], "standby");
    reopened.close().await;
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_generation_marker_and_manifest_mismatch_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", None).unwrap();
    let (snapshot, manifest_path) = stage(&store, &db, "v2").await;
    let mut manifest: crate::standby_snapshot::StandbySnapshotManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest.contract = crate::standby_snapshot::STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into();
    assert!(manifest.validate().is_err());
    let v1 = crate::create_database(":memory:").await.unwrap();
    let export = crate::export::export_connected_db(&v1, None).await.unwrap();
    assert!(super::kernel_v2::verify_path(&export.path()).await.is_err());
    assert!(
        crate::db::open_existing_database_standby_read_only(snapshot.to_str().unwrap())
            .await
            .is_err()
    );
    export.cleanup().await;
    v1.close().await;
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_switch_fetches_fresh_generation_and_retains_v1_for_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&v1).await.unwrap();
    let account = crate::identity::resolve_stdio_account_identity(&v1, None)
        .await
        .unwrap();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &v1, "before").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let session = session(store.clone(), origin.clone(), &account).await;
    activate(&session, &store).await;
    let (v2, admin) = crate::kernel::create_v2_database(":memory:", "account", "Owner", &account)
        .await
        .unwrap();
    let record = crate::kernel::create_record_as(&v2, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let host = crate::kernel::resolve_principal_by_binding(&v2, crate::kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    crate::kernel::import_event_as(
        &v2,
        &host,
        &record,
        &crate::kernel::LegacyEvent {
            source: None,
            id: "snapshot-provenance-fixture".into(),
            event_type: "v1.snapshot_provenance".into(),
            created_at: "2026-10-18T00:00:00Z".into(),
            actor: None,
            run_key: None,
            payload: json!({"source_origin":origin,"record_id":record}),
        },
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &v2, "after").await;
    let new = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    assert_ne!(old.id, new.id);
    assert!(
        old.snapshot_path.is_file(),
        "old engine generation retained"
    );
    activate(&session, &store).await;
    let answer = read(&session, "get_record", json!({"ids":[record]})).await;
    assert_eq!(
        answer["result"]["structuredContent"]["records"][0]["status"], "found",
        "{answer}"
    );
    assert_eq!(
        answer["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
        new.id
    );
    let (snapshot, manifest) = stage(&store, &v1, "rollback").await;
    assert!(
        store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .is_err(),
        "no automatic v2 to v1 hot rollback"
    );
    assert!(old.snapshot_path.is_file());
    assert_eq!(
        store.pinned_v1_generation().unwrap().as_deref(),
        Some(old.id.as_str())
    );
    for n in 0..5 {
        crate::kernel::create_record_as(&v2, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
        let (snapshot, manifest) = stage(&store, &v2, &format!("v2-full-{n}")).await;
        store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        store.prune_retention(&observed()).await.unwrap();
        assert!(
            old.snapshot_path.is_file(),
            "v1 pin survives several v2 FULLs"
        );
    }
    store.release_v1_pin(&observed(), true).await.unwrap();
    assert!(store.pinned_v1_generation().unwrap().is_none());
    assert_eq!(store.current_for_head_probe().unwrap().unwrap().id, old.id);
    let restarted =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let super::generation_store::StandbyStartupOutcome::Serving(active) =
        restarted.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("explicit rollback must survive restart");
    };
    assert_eq!(active.generation.id, old.id);
    assert!(restarted
        .handoff_candidates_hint()
        .unwrap()
        .iter()
        .all(|hint| hint.generation_id() == old.id));
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn kernel_v2_refuses_unordered_and_other_genesis_and_applies_blob_only_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:tails")
            .await
            .unwrap();
    let initial = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = initial.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "tails").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let first = transport
        .kernel_delta(initial.head().head_act(), &[])
        .await
        .unwrap();
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let second = transport
        .kernel_delta(first.delta().head.head_act, &[])
        .await
        .unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    assert!(
        store
            .prepare_kernel_delta(&old, &second, &timestamp)
            .await
            .is_err(),
        "out-of-order delta refused"
    );
    let (other, other_admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Other", "acct:other")
            .await
            .unwrap();
    crate::kernel::create_record_as(&other, &other_admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let other_head = observe_authority_act_head(&other, "route-1").await.unwrap();
    let other_transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        other_head.head().origin_database_id(),
        "token",
        Arc::new(Hosted(other.clone())),
    )
    .unwrap();
    let foreign = other_transport
        .kernel_delta(initial.head().head_act(), &[])
        .await
        .unwrap();
    assert!(
        store
            .prepare_kernel_delta(&old, &foreign, &timestamp)
            .await
            .is_err(),
        "other genesis refused"
    );
    assert_eq!(store.current_for_head_probe().unwrap().unwrap().id, old.id);
    let first = store
        .prepare_kernel_delta(&old, &first, &timestamp)
        .await
        .unwrap();
    let current = store
        .publish_kernel_delta(first, &observed())
        .await
        .unwrap();
    let second = store
        .prepare_kernel_delta(&current, &second, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let current = store
        .publish_kernel_delta(second, &observed())
        .await
        .unwrap();
    let head = current.manifest.head_act.unwrap();
    let bytes = b"unbound immutable bytes, not an attachment event";
    let digest = crate::standby_snapshot::sha256_bytes(bytes);
    sqlx::query("INSERT INTO kernel_blobs(sha256,bytes,size_bytes,mime) VALUES(?,?,?,NULL)")
        .bind(&digest)
        .bind(bytes.as_slice())
        .bind(bytes.len() as i64)
        .execute(db.write_pool())
        .await
        .unwrap();
    let blob_only = transport.kernel_delta(head, &[]).await.unwrap();
    assert_eq!(blob_only.delta().head.head_act, head);
    assert!(blob_only.delta().sections[0].rows.is_empty());
    let prepared = store
        .prepare_kernel_delta(&current, &blob_only, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let next = store
        .publish_kernel_delta(prepared, &observed())
        .await
        .unwrap();
    let read = crate::db::open_kernel_v2_standby_read_only(next.snapshot_path.to_str().unwrap())
        .await
        .unwrap();
    let actual: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM kernel_blobs WHERE sha256=?")
        .bind(&digest)
        .fetch_one(read.pool())
        .await
        .unwrap();
    assert_eq!(actual, bytes);
    read.close().await;
    db.close().await;
    other.close().await;
}

#[tokio::test]
async fn kernel_v2_delta_sends_only_missing_blobs_and_incremental_matches_full_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
    for n in 0..128_u32 {
        let bytes = n.to_le_bytes().repeat(1024);
        sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
            .bind(crate::standby_snapshot::sha256_bytes(&bytes))
            .bind(&bytes)
            .bind(bytes.len() as i64)
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    // Build A's published base lacks all three optional indexes. Build B adds them
    // only on the host before exporting a delta; schema hashes must agree.
    for name in [
        "idx_kernel_realtime_authority",
        "idx_kernel_named_view_admissions",
        "idx_kernel_named_view_lifecycle",
    ] {
        sqlx::query(&format!("DROP INDEX IF EXISTS {name}"))
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "base").await;
    let base = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let inventory = kernel_v2::blob_inventory_path(&base.snapshot_path)
        .await
        .unwrap();
    assert_eq!(inventory.len(), 128);
    // Observe the current schema before recreating indexes on a pooled handle.
    let mut schema_conn = db.write_pool().acquire().await.unwrap();
    for (name, ddl) in [
        (
            "idx_kernel_realtime_authority",
            crate::kernel::notifications::REALTIME_AUTHORITY_INDEX,
        ),
        (
            "idx_kernel_named_view_admissions",
            crate::kernel::NAMED_VIEW_EVENT_INDEX_DDL,
        ),
        (
            "idx_kernel_named_view_lifecycle",
            crate::named_views::INDEX_DDL,
        ),
    ] {
        let absent: bool =
            sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?)")
                .bind(name)
                .fetch_one(&mut *schema_conn)
                .await
                .unwrap();
        assert!(absent, "snapshot staging must not recreate {name}");
        sqlx::query(ddl).execute(&mut *schema_conn).await.unwrap();
    }
    drop(schema_conn);
    let bytes = b"one newly added unbound blob";
    sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
        .bind(crate::standby_snapshot::sha256_bytes(bytes))
        .bind(bytes.as_slice())
        .bind(bytes.len() as i64)
        .execute(db.write_pool())
        .await
        .unwrap();
    // New content and metadata both fold through the same routes as FULL.
    let definition = br#"{"family":"test.delta","version":1,"interpreter":"native.defn/4","primary_type":"Fixture","kinds":[{"token":"note","fields":[{"name":"title","type":"text","required":false}],"identity":{"mode":"record"},"links":[],"maturity":"current","description":"Fixture."}]}"#;
    let revision = crate::kernel::install_definition_as(&db, &admin, "test.delta", 1, definition)
        .await
        .unwrap();
    crate::kernel::adopt_definition_as(&db, &admin, "test.delta", Some(&revision))
        .await
        .unwrap();
    crate::kernel::create_as(
        &db,
        &admin,
        "test.delta",
        "note",
        json!({"title":"Tail search text"}).as_object().unwrap(),
        crate::events::KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let record = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let second = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    crate::kernel::link_records_as(&db, &admin, &record, &second)
        .await
        .unwrap();
    append_projection_coverage_fixture(&db, &admin, &record).await;
    // Reader-only future payload travels through the real delta, then FULL replay.
    let facet_pin = crate::named_views::inject_v2_reader_fixture(&db, &record).await;
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    let delta = transport
        .kernel_delta(head.head().head_act(), &inventory)
        .await
        .unwrap();
    assert_eq!(delta.delta().sections[2].rows.len(), 1);
    assert!(
        delta.delta().bytes().unwrap().len() < 256_000,
        "old blob bytes never enter the delta"
    );
    let prepared = store
        .prepare_kernel_delta(&base, &delta, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let generation = store
        .publish_kernel_delta(prepared, &observed())
        .await
        .unwrap();
    // Compare every kernel projection with hosted and an independent FULL fold.
    let copy = dir.path().join("full-replay.db");
    // Create a fresh writable file rather than inheriting the immutable
    // serving generation's read-only permissions.
    std::io::copy(
        &mut std::fs::File::open(&generation.snapshot_path).unwrap(),
        &mut std::fs::File::create(&copy).unwrap(),
    )
    .unwrap();
    let replay = crate::db::open_kernel_v2_head_writer(&copy).await.unwrap();
    let incremental = crate::kernel::dump_all_kernel_tables(&replay)
        .await
        .unwrap();
    let mut snapshot = replay.pool().begin().await.unwrap();
    let state = crate::named_views::load_prefix(&mut snapshot, i64::MAX, None)
        .await
        .unwrap();
    assert!(state.revisions.contains_key(&facet_pin.revision_id));
    snapshot.rollback().await.unwrap();
    assert_eq!(
        incremental,
        crate::kernel::dump_all_kernel_tables(&db).await.unwrap()
    );
    for name in [
        "kernel_legacy_history",
        "kernel_legacy_subjects",
        "kernel_attachment_blobs",
        "kernel_blob_handles",
        "kernel_search_meta",
        "kernel_messages",
        "kernel_comment_anchors",
        "kernel_provider_state",
        "kernel_provider_receipts",
        "kernel_provider_link_meta",
        "kernel_provider_link_heads",
        "kernel_provider_link_rows",
    ] {
        assert!(
            incremental
                .projections
                .tables
                .iter()
                .any(|t| t.name == name && t.rows > 0),
            "nonempty projection coverage: {name}"
        );
    }
    let search: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT record_id,title,summary,body FROM kernel_search_fts ORDER BY record_id",
    )
    .fetch_all(replay.pool())
    .await
    .unwrap();
    assert!(search.iter().any(|row| row.1 == "Tail search text"));
    crate::kernel::replay_all_projections(&replay)
        .await
        .unwrap();
    let full_search: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT record_id,title,summary,body FROM kernel_search_fts ORDER BY record_id",
    )
    .fetch_all(replay.pool())
    .await
    .unwrap();
    assert_eq!(search, full_search);
    assert_eq!(
        incremental,
        crate::kernel::dump_all_kernel_tables(&replay)
            .await
            .unwrap()
    );
    // Reverse direction: an indexed base accepts an index-free writer's
    // same-schema delta and keeps its own optional physical accelerators.
    let reverse_store = GenerationStore::open(
        dir.path().join("reverse-replica"),
        "route-1",
        Some(origin.clone()),
    )
    .unwrap();
    let reverse_head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let (snapshot, manifest) = stage(&reverse_store, &db, "indexed-base").await;
    let reverse_base = reverse_store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let reverse_inventory = kernel_v2::blob_inventory_path(&reverse_base.snapshot_path)
        .await
        .unwrap();
    for name in [
        "idx_kernel_realtime_authority",
        "idx_kernel_named_view_admissions",
        "idx_kernel_named_view_lifecycle",
    ] {
        sqlx::query(&format!("DROP INDEX {name}"))
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let reverse_delta = transport
        .kernel_delta(reverse_head.head().head_act(), &reverse_inventory)
        .await
        .unwrap();
    let reverse_prepared = reverse_store
        .prepare_kernel_delta(
            &reverse_base,
            &reverse_delta,
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .unwrap();
    let reverse_generation = reverse_store
        .publish_kernel_delta(reverse_prepared, &observed())
        .await
        .unwrap();
    use sqlx::Connection;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&reverse_generation.snapshot_path)
        .read_only(true)
        .create_if_missing(false);
    let mut reverse_conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    assert!(
        crate::named_views::storage::verify_index_on(&mut reverse_conn)
            .await
            .unwrap()
    );
    assert!(
        !crate::named_views::storage::verify_index_on(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap()
    );
    reverse_conn.close().await.unwrap();
    replay.close().await;
    db.close().await;
}

// Exercise real producer routes, not hand-written projection rows.
async fn append_projection_coverage_fixture(db: &crate::Db, admin: &str, record: &str) {
    use crate::kernel as k;
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
    use crate::v2_standard as standard;
    for manifest in [
        standard::v1_compat::package(),
        standard::document3_package(),
        standard::relates_to::package(),
    ] {
        let identity = k::install_package_as(db, admin, &manifest).await.unwrap();
        k::adopt_package_at(
            db,
            admin,
            crate::events::KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &manifest.declared_reads,
        )
        .await
        .unwrap();
    }
    let revision = k::read_record_as(db, admin, record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    k::set_body_as(db, admin, record, "Tail anchor text", revision)
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry.call_engine(EngineHandle::KernelV2(db.clone()), Caller::authenticated("acct:owner"), "create_record", json!({
        "type":"Annotation", "kind":"comment", "body":"Tail comment", "home_id":crate::events::KERNEL_ROOT_ID,
        "links":[{"target_id":record,"relationship":"part_of"}],
        "target":{"target_record_id":record,"source_slot":"body","selectors":[{"type":"text_quote","exact":"anchor"},{"type":"data_position","start":5,"end":11}]}
    })).await.unwrap();
    // Reuse the one newly added CAS value, so the delta still carries one blob.
    registry.call_engine(EngineHandle::KernelV2(db.clone()), Caller::authenticated("acct:owner"), "attach_text",
        json!({"record_id":record,"text":"one newly added unbound blob","filename":"delta.txt"})).await.unwrap();
    let host = k::resolve_principal_by_binding(db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let carrier = standard::v1_compat::package().definitions.remove(0);
    let message = k::ImportRecordState {
        message: Some(k::MessageState {
            author: Some(admin.into()),
            origin: json!({"kind":"manual"}),
            ..Default::default()
        }),
        definition: Some(k::ImportDefinition {
            pin: crate::meta::definition_artifact::RevisionIdentity {
                family: carrier.family,
                version: carrier.version,
                digest: carrier.digest,
            },
            primary_type: "V1".into(),
            kind: "record".into(),
            fields: json!({"v1_type":"Message","v1_kind":"message","title":"Imported message"})
                .as_object()
                .unwrap()
                .clone(),
        }),
        body: Some("Imported message body".into()),
        ..Default::default()
    };
    k::import_record_as(
        db,
        &host,
        "delta-imported-message",
        crate::events::KERNEL_ROOT_ID,
        Some(admin),
        &message,
    )
    .await
    .unwrap();
    k::import_event_as(db,&host,record,&k::LegacyEvent {
        source:Some(json!({"subjects":[record],"stream":"relationship_events","original_subjects":[record],"metadata":{"record_id":record}})),
        id:uuid::Uuid::new_v4().to_string(),event_type:"relationship.created".into(),payload:json!({"record_id":record,"endpoints":[{"record_id":record}]}),
        created_at:"2026-01-01T00:00:00Z".into(),actor:None,run_key:None,
    }).await.unwrap();
    let note = k::create_json_as(
        db,
        admin,
        standard::DOCUMENT_FAMILY,
        "note",
        "{}",
        crate::events::KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let request = k::prepare_provider_as(
        db,
        admin,
        &note,
        record,
        "delta-provider",
        standard::relates_to::Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    k::commit_provider_as(db, admin, &request).await.unwrap();
}

#[tokio::test]
async fn kernel_v2_projection_dump_discovers_new_tables_and_columns() {
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let before = crate::kernel::projection_dump::dump(&db).await.unwrap();
    sqlx::query("CREATE TABLE kernel_future_projection(id TEXT PRIMARY KEY,value REAL)")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_future_projection VALUES('fixture',1.25)")
        .execute(db.write_pool())
        .await
        .unwrap();
    let after = crate::kernel::projection_dump::dump(&db).await.unwrap();
    assert_ne!(before, after);
    assert!(after
        .tables
        .iter()
        .any(|t| t.name == "kernel_future_projection" && t.rows == 1));
    sqlx::query("ALTER TABLE kernel_future_projection ADD COLUMN extra TEXT")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert_ne!(
        after,
        crate::kernel::projection_dump::dump(&db).await.unwrap()
    );
    db.close().await;
}

// Shared with the importer app-custody fixture: exercise the authenticated
// transport and verified scratch publication, not just the projector in isolation.
pub(crate) async fn assert_projection_delta_equivalence<F, Fut>(
    db: &crate::Db,
    append_tail: F,
) -> crate::kernel::projection_dump::ProjectionDump
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let dir = tempfile::tempdir().unwrap();
    let head = observe_authority_act_head(db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, db, "app-base").await;
    let base = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let inventory = kernel_v2::blob_inventory_path(&base.snapshot_path)
        .await
        .unwrap();
    append_tail().await;
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    let delta = transport
        .kernel_delta(head.head().head_act(), &inventory)
        .await
        .unwrap();
    let hosted = crate::kernel::projection_dump::dump(db).await.unwrap();
    assert_eq!(delta.delta().head.projection_sha256, hosted.sha256);
    let prepared = store
        .prepare_kernel_delta(&base, &delta, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let generation = store
        .publish_kernel_delta(prepared, &observed())
        .await
        .unwrap();
    let copy = dir.path().join("full-replay.db");
    std::io::copy(
        &mut std::fs::File::open(&generation.snapshot_path).unwrap(),
        &mut std::fs::File::create(&copy).unwrap(),
    )
    .unwrap();
    let replay = crate::db::open_kernel_v2_head_writer(&copy).await.unwrap();
    let incremental = crate::kernel::projection_dump::dump(&replay).await.unwrap();
    assert_eq!(
        incremental, hosted,
        "incremental vs hosted: every logical projection"
    );
    crate::kernel::replay_all_projections(&replay)
        .await
        .unwrap();
    assert_eq!(
        incremental,
        crate::kernel::projection_dump::dump(&replay).await.unwrap(),
        "incremental vs FULL: every logical projection"
    );
    replay.close().await;
    incremental
}

/// Delivery bridge: use accepted N1 generations and the real background N2
/// collector/publisher. Every database and vault belongs to this temp tree.
#[cfg(unix)]
#[tokio::test]
async fn kernel_v2_vault_cutover_delta_revocation_restart_and_unavailable() {
    use crate::kernel as k;
    use crate::mcp::standby_stdio::StandbySupervisor;
    use std::path::Path;
    use std::time::Duration;
    fn state(vault: &Path) -> Value {
        std::fs::read(vault.join(".native/state.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null)
    }
    fn status(vault: &Path) -> String {
        std::fs::read_to_string(vault.join(".native/STATUS.md")).unwrap_or_default()
    }
    fn content(root: &Path) -> String {
        let mut text = String::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".native" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                text.push_str(&content(&entry.path()));
            } else {
                text.push_str(&std::fs::read_to_string(entry.path()).unwrap());
            }
        }
        text
    }
    async fn wait(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("accepted generation must reach the background vault");
    }
    async fn delta(db: &crate::Db, store: &GenerationStore, origin: &str) -> InstalledGeneration {
        let base = store.current_for_head_probe().unwrap().unwrap();
        let inventory = kernel_v2::blob_inventory_path(&base.snapshot_path)
            .await
            .unwrap();
        let transport = AuthorityActTransport::with_client(
            "https://fixture.example",
            "route-1",
            origin,
            "synthetic-token",
            Arc::new(Hosted(db.clone())),
        )
        .unwrap();
        let tail = transport
            .kernel_delta(base.manifest.head_act.unwrap(), &inventory)
            .await
            .unwrap();
        let prior = std::fs::read(&base.snapshot_path).unwrap();
        let prepared = store
            .prepare_kernel_delta(&base, &tail, &chrono::Utc::now().to_rfc3339())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&base.snapshot_path).unwrap(),
            prior,
            "collection continues to own the prior verified inode during folding"
        );
        store
            .publish_kernel_delta(prepared, &observed())
            .await
            .unwrap()
    }
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let vault = root.join("vault");
    let v1 = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&v1).await.unwrap();
    let account = crate::identity::resolve_stdio_account_identity(&v1, None)
        .await
        .unwrap();
    crate::store::create_record_as(&v1, json!({"type":"Document","kind":"note","name":"Delivery fixture", "body":"v1 delivery text"}), Some(&account)).await.unwrap();
    let store =
        GenerationStore::open(root.join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &v1, "vault-v1").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let first_session = Arc::new(
        session(store.clone(), origin.clone(), &account)
            .await
            .with_markdown_folder(Some(vault.clone())),
    );
    let supervisor = StandbySupervisor::start_with_startup(first_session.clone()).unwrap();
    wait(|| state(&vault)["successful_generation"] == old.id).await;
    assert!(content(&vault).contains("v1 delivery text"));
    assert_eq!(state(&vault)["account"], account);

    let (v2, admin) = k::create_v2_database(":memory:", "account", "Fixture admin", "acct:admin")
        .await
        .unwrap();
    let viewer = k::create_principal(&v2, "account", "Fixture viewer", &account, &admin)
        .await
        .unwrap();
    k::replace_home_policy(
        &v2,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&viewer, "view")],
    )
    .await
    .unwrap();
    let home = k::create_home(
        &v2,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let record = k::create_record_as(&v2, &admin, &home).await.unwrap();
    let revision = k::read_record_as(&v2, &admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    k::set_body_as(&v2, &admin, &record, "v2 delivery first", revision)
        .await
        .unwrap();
    let host = k::resolve_principal_by_binding(&v2, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::import_event_as(
        &v2,
        &host,
        &record,
        &k::LegacyEvent {
            source: None,
            id: "vault-source-origin".into(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"source_origin":origin,"record_id":record}),
            created_at: "2026-10-20T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &v2, "vault-v2").await;
    let full = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    wait(|| state(&vault)["successful_generation"] == full.id).await;
    assert_eq!(
        state(&vault)["account"],
        account,
        "actual resolve_kernel_account must preserve the credential through cutover"
    );
    assert_eq!(state(&vault)["origin"], origin);
    assert!(content(&vault).contains("v2 delivery first"));
    assert!(!content(&vault).contains("v1 delivery text"));

    let revision = k::read_record_as(&v2, &admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    k::set_body_as(&v2, &admin, &record, "v2 delivery delta", revision)
        .await
        .unwrap();
    let advanced = delta(&v2, &store, &origin).await;
    wait(|| state(&vault)["successful_generation"] == advanced.id).await;
    assert!(content(&vault).contains("v2 delivery delta"));
    assert!(!content(&vault).contains("v2 delivery first"));
    k::replace_home_policy(&v2, &admin, &home, &[])
        .await
        .unwrap();
    let revoked = delta(&v2, &store, &origin).await;
    wait(|| state(&vault)["successful_generation"] == revoked.id).await;
    assert!(!content(&vault).contains("v2 delivery delta"));
    assert_eq!(state(&vault)["account"], account);
    supervisor.shutdown().await.unwrap();
    drop(first_session);

    let previous_render = state(&vault)["rendered_at"].clone();
    let restarted = Arc::new(
        session(store.clone(), origin.clone(), &account)
            .await
            .with_markdown_folder(Some(vault.clone())),
    );
    let supervisor = StandbySupervisor::start_with_startup(restarted.clone()).unwrap();
    wait(|| {
        state(&vault)["rendered_at"] != previous_render
            && status(&vault).contains("authorized copy available")
    })
    .await;
    assert_eq!(state(&vault)["successful_generation"], revoked.id);
    assert_eq!(state(&vault)["account"], account);
    assert!(!content(&vault).contains("v2 delivery delta"));
    supervisor.shutdown().await.unwrap();
    drop(restarted);
    let successful = state(&vault);
    // Actual authority loss, not a missing-file shortcut: the accepted NKV2
    // generation remains device-valid but this caller no longer has root View.
    k::replace_home_policy(
        &v2,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &[(&admin, "manage")],
    )
    .await
    .unwrap();
    let denied = delta(&v2, &store, &origin).await;
    let unavailable = Arc::new(
        session(store.clone(), origin, &account)
            .await
            .with_markdown_folder(Some(vault.clone())),
    );
    let supervisor = StandbySupervisor::start_with_startup(unavailable.clone()).unwrap();
    wait(|| status(&vault).contains("Availability: unavailable")).await;
    let refused = unavailable.handle_message(json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"standby_status","arguments":{}}})).await.unwrap();
    assert!(refused
        .to_string()
        .contains("startup_readiness_unavailable"));
    let after = state(&vault);
    assert_ne!(after["successful_generation"], denied.id);
    for field in ["successful_generation", "successful_act", "rendered_at"] {
        assert_eq!(
            after[field], successful[field],
            "status-only cannot claim another successful content cycle"
        );
    }
    assert!(!content(&vault).contains("v2 delivery delta"));
    supervisor.shutdown().await.unwrap();
    v2.close().await;
    v1.close().await;
}
