//! N1 probes use synthetic databases and disposable generation stores only.
use super::delta_transport::*;
use super::generation_store::tests::{observed, stage};
use super::*;
use crate::mcp::standby_stdio::{StandbySessionConfig, StandbyStdioSession};
use crate::mcp::{ExperimentalExecutors, ExposureProfile, McpSurfaceMode};
use serde_json::{json, Value};
use sha2::Digest;
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
    let global_pin = crate::named_views::inject_global_reader_fixture(&db, &record).await;
    let named_pin = crate::named_views::inject_global_name_reader_fixture(&db, &record).await;
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
    assert!(state.revisions.contains_key(&global_pin.revision_id));
    assert!(state.revisions.contains_key(&named_pin.revision_id));
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
    assert_eq!(
        delta.delta().head.projection_sha256.as_deref(),
        Some(hosted.sha256.as_str())
    );
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

#[tokio::test]
async fn kernel_v2_in_place_delta_is_visible_to_a_live_serving_session_without_reactivation() {
    use super::generation_store::kernel_in_place::InPlaceApplied;
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
    let session = session(store.clone(), origin.clone(), "acct:owner").await;
    activate(&session, &store).await;
    let found =
        |reply: &Value| reply["result"]["structuredContent"]["records"][0]["status"] == "found";
    assert!(found(
        &read(&session, "get_record", json!({"ids":[first]})).await
    ));

    let added = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(!found(
        &read(&session, "get_record", json!({"ids":[added]})).await
    ));
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
    let applied = store
        .apply_kernel_delta_in_place(
            &installed,
            &trusted,
            &chrono::Utc::now().to_rfc3339(),
            &crate::standby::phase_timings::PhaseTimings::default(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(applied, InPlaceApplied::Applied);

    // The session was activated before the apply and never re-activated: its
    // pooled readers pick up the WAL commit, authorisation included.
    let reply = read(&session, "get_record", json!({"ids":[added]})).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(found(&reply), "{reply}");
    assert!(found(
        &read(&session, "get_record", json!({"ids":[first]})).await
    ));
    let listing = read(
        &session,
        "query_sql",
        json!({"sql":"SELECT COUNT(*) AS n FROM records"}),
    )
    .await;
    assert_eq!(listing["result"]["isError"], false, "{listing}");
    let status = session.handle_message(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"standby_status","arguments":{}}})).await.unwrap();
    assert_eq!(status["result"]["isError"], false, "{status}");
    let serving = &status["result"]["structuredContent"]["serving_generation"];
    assert_eq!(serving["materialization"], "delta", "{status}");
    assert_eq!(
        serving["head_act"],
        trusted.delta().head.head_act,
        "{status}"
    );
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_fold_asserts_foreign_key_enforcement_and_a_normal_delta_applies() {
    use super::kernel_v2_delta::{apply, FOREIGN_KEYS_OFF};
    use super::phase_timings::PhaseTimings;
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
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
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
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
    // Without enforcement the fold is refused before it changes anything.
    let off = dir.path().join("fk-off.db");
    std::fs::copy(&installed.snapshot_path, &off).unwrap();
    std::fs::set_permissions(&off, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let writer = crate::db::open_kernel_v2_head_writer_without_foreign_keys(&off)
        .await
        .unwrap();
    let error = apply(&writer, &trusted, &PhaseTimings::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, crate::Error::Engine(m) if m == FOREIGN_KEYS_OFF),
        "{error:?}"
    );
    writer.close().await;
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&off)
            .await
            .unwrap()
            .head_act,
        head.head().head_act()
    );
    // With enforcement on, the same delta applies.
    let on = dir.path().join("fk-on.db");
    std::fs::copy(&installed.snapshot_path, &on).unwrap();
    std::fs::set_permissions(&on, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let writer = crate::db::open_kernel_v2_head_writer(&on).await.unwrap();
    apply(&writer, &trusted, &PhaseTimings::default())
        .await
        .unwrap();
    writer.close().await;
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&on).await.unwrap(),
        trusted.delta().head.generation
    );
    db.close().await;
}

/// A staged copy, a record on hosted, and the version-3 and (audit) version-2
/// deltas cut for it by a host that advertises version 3. Nothing in
/// production serves version 3 yet.
async fn staged_deltas(
    corrupt_hosted: bool,
) -> (
    tempfile::TempDir,
    crate::Db,
    std::path::PathBuf,
    super::kernel_v2_delta::TrustedKernelDelta,
    super::kernel_v2_delta::TrustedKernelDelta,
) {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
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
    let id = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    if corrupt_hosted {
        // Only hosted's projection moves: folding the events cannot reproduce it.
        sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
            .bind(&id)
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    let (transport, _client, _) = scripted_transport(&db, true, false, true, false).await;
    transport.head().await.unwrap();
    let from = head.head().head_act();
    let v3 = transport.kernel_delta(from, &[]).await.unwrap();
    assert_eq!(v3.delta().version, 3);
    let v2 = transport
        .kernel_delta_with_proof(from, &[], true)
        .await
        .unwrap();
    assert_eq!(v2.delta().version, 2);
    let copy = dir.path().join("staged.db");
    std::fs::copy(&installed.snapshot_path, &copy).unwrap();
    std::fs::set_permissions(&copy, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    (dir, db, copy, v3, v2)
}

/// The transaction-owned seams reproduce `apply` exactly: folding and
/// certifying the same delta on a caller-owned transaction yields the same
/// generation, projection digest, timings laps and applied facts as the
/// wrapper, for both the digest-carrying and the digest-free wire versions.
#[tokio::test]
async fn kernel_v2_fold_seam_matches_apply_on_the_same_delta() {
    use super::kernel_v2_delta::{
        apply, certify_fold_in_transaction, fold_in_transaction, ApplyMode,
    };
    use super::phase_timings::PhaseTimings;
    use sqlx::Connection as _;
    let (_dir, db, copy, v3, v2) = staged_deltas(false).await;
    for trusted in [&v3, &v2] {
        let tag = if trusted.delta().version == 3 {
            "v3"
        } else {
            "v2"
        };
        let copy_a = _dir.path().join(format!("seam-wrap-{tag}.db"));
        let copy_b = _dir.path().join(format!("seam-inner-{tag}.db"));
        for path in [&copy_a, &copy_b] {
            std::fs::copy(&copy, path).unwrap();
            std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
        }
        // Wrapper path.
        let timings_wrap = PhaseTimings::default();
        let writer = crate::db::open_kernel_v2_head_writer(&copy_a)
            .await
            .unwrap();
        apply(&writer, trusted, &timings_wrap).await.unwrap();
        writer.close().await;
        // Seam path on a caller-owned transaction.
        let timings_seam = PhaseTimings::default();
        let writer = crate::db::open_kernel_v2_head_writer(&copy_b)
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(writer.write_pool()).await.unwrap();
        let folded = fold_in_transaction(&mut tx, trusted, &timings_seam, ApplyMode::Staged)
            .await
            .unwrap();
        let certified = certify_fold_in_transaction(&mut tx, trusted, folded, &timings_seam)
            .await
            .unwrap();
        assert!(certified.receipt.is_none());
        assert_eq!(certified.facts.from_act, trusted.delta().from_exclusive_act);
        assert_eq!(certified.facts.to_act, trusted.delta().head.head_act);
        assert_eq!(
            certified.facts.content_seq_to,
            trusted.delta().head.content_event_seq
        );
        assert_eq!(
            certified.facts.meta_seq_to,
            trusted.delta().head.meta_event_seq
        );
        assert_eq!(certified.facts.blob_count, trusted.delta().head.blob_count);
        assert_eq!(certified.facts.delta_sha256, trusted.delta().content_sha256);
        tx.commit().await.unwrap();
        writer.close().await;
        // Same generation, same projection digest.
        let generation_a = crate::standby::kernel_v2::verify_path(&copy_a)
            .await
            .unwrap();
        let generation_b = crate::standby::kernel_v2::verify_path(&copy_b)
            .await
            .unwrap();
        assert_eq!(generation_a, generation_b);
        assert_eq!(generation_b, trusted.delta().head.generation);
        for path in [&copy_a, &copy_b] {
            let mut conn = sqlx::SqliteConnection::connect_with(
                &sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(path)
                    .read_only(true),
            )
            .await
            .unwrap();
            let digest = crate::kernel::projection_dump::dump_on(&mut conn)
                .await
                .unwrap()
                .sha256;
            conn.close().await.unwrap();
            if let Some(expected) = &trusted.delta().head.projection_sha256 {
                assert_eq!(&digest, expected);
            }
        }
        // Same laps in the same order; the wrapper only adds begin/commit.
        let wrap_laps: Vec<&str> = timings_wrap
            .laps()
            .into_iter()
            .map(|(name, _)| name)
            .filter(|lap| *lap != "apply_begin_write" && *lap != "apply_commit")
            .collect();
        let seam_laps: Vec<&str> = timings_seam
            .laps()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(wrap_laps, seam_laps);
    }
    db.close().await;
}

/// Certification is bound to the fold: certifying with a different delta than
/// the one folded refuses, and the copy does not advance.
#[tokio::test]
async fn kernel_v2_certify_refuses_a_delta_that_does_not_match_the_fold() {
    use super::kernel_v2_delta::{certify_fold_in_transaction, fold_in_transaction, ApplyMode};
    use super::phase_timings::PhaseTimings;
    let (_dir, db, copy, v3, v2) = staged_deltas(false).await;
    let before = crate::standby::kernel_v2::verify_path(&copy).await.unwrap();
    let writer = crate::db::open_kernel_v2_head_writer(&copy).await.unwrap();
    let mut tx = crate::db::begin_write(writer.write_pool()).await.unwrap();
    let folded = fold_in_transaction(&mut tx, &v3, &PhaseTimings::default(), ApplyMode::Staged)
        .await
        .unwrap();
    let error = certify_fold_in_transaction(&mut tx, &v2, folded, &PhaseTimings::default())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("does not match the fold"),
        "{error:?}"
    );
    tx.rollback().await.unwrap();
    writer.close().await;
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&copy).await.unwrap(),
        before,
        "a mismatched certification must not advance the copy"
    );
    db.close().await;
}

/// The staged apply (no receipts, no accumulator) takes a version-3 delta with
/// no projection comparison at all.
#[tokio::test]
async fn kernel_v2_staged_apply_takes_a_version_3_delta_with_no_projection_digest() {
    use super::kernel_v2_delta::apply;
    use super::phase_timings::PhaseTimings;
    let (_dir, db, copy, v3, _) = staged_deltas(false).await;
    let writer = crate::db::open_kernel_v2_head_writer(&copy).await.unwrap();
    apply(&writer, &v3, &PhaseTimings::default()).await.unwrap();
    writer.close().await;
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&copy).await.unwrap(),
        v3.delta().head.generation
    );
    db.close().await;
}

/// The trade: version 3 skips only the projection comparison, so a hosted
/// projection the events cannot reproduce goes unnoticed by it, and the
/// version-2 delta an audit asks for finds it, with nothing committed.
#[tokio::test]
async fn kernel_v2_version_3_skips_only_the_projection_comparison_and_version_2_finds_the_divergence(
) {
    use super::kernel_v2_delta::apply;
    use super::phase_timings::PhaseTimings;
    let (dir, db, copy, v3, v2) = staged_deltas(true).await;
    let audit_copy = dir.path().join("audit.db");
    std::fs::copy(&copy, &audit_copy).unwrap();
    std::fs::set_permissions(
        &audit_copy,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    // The proof-less delta applies.
    let writer = crate::db::open_kernel_v2_head_writer(&copy).await.unwrap();
    apply(&writer, &v3, &PhaseTimings::default()).await.unwrap();
    writer.close().await;
    // The audit's delta refuses the same divergence, and the copy did not move.
    let before = crate::standby::kernel_v2::verify_path(&audit_copy)
        .await
        .unwrap();
    let writer = crate::db::open_kernel_v2_head_writer(&audit_copy)
        .await
        .unwrap();
    let error = apply(&writer, &v2, &PhaseTimings::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, crate::Error::Engine(m) if m == "kernel_v2_projection_divergence"),
        "{error:?}"
    );
    writer.close().await;
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&audit_copy)
            .await
            .unwrap(),
        before
    );
    db.close().await;
}

// ---- kernel-v2 delta wire version 2 (design record 5065900, slice 2) ----

fn reseal(value: &mut Value) {
    value.as_object_mut().unwrap().remove("content_sha256");
    let digest = crate::standby_snapshot::sha256_bytes(&serde_jcs::to_vec(&*value).unwrap());
    value["content_sha256"] = Value::String(digest);
}

async fn synthetic_db() -> crate::Db {
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
    for _ in 0..3 {
        crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    db
}

#[test]
fn kernel_v2_delta_wire_v1_fixture_from_before_the_field_still_parses() {
    let bytes = include_bytes!("testdata/kernel_v2_delta_wire_v1.json");
    let delta = super::kernel_v2_delta::KernelDelta::parse(bytes).unwrap();
    assert_eq!(delta.version, 1);
    assert!(delta.head.projection_set.is_none());
    // Re-serialising it reproduces the exact bytes: the optional field leaves
    // version 1 untouched.
    assert_eq!(delta.bytes().unwrap(), bytes);
}

#[tokio::test]
async fn kernel_v2_delta_wire_versions_round_trip_and_parse_strictly() {
    use super::kernel_v2_delta::{cut, cut_versioned, KernelDelta};
    let db = synthetic_db().await;
    let mut conn = db.pool().acquire().await.unwrap();
    let v1 = cut(&mut conn, 0, &[]).await.unwrap();
    let v1_again = cut_versioned(&mut conn, 0, &[], 1).await.unwrap();
    assert_eq!(v1.bytes().unwrap(), v1_again.bytes().unwrap());
    assert!(!String::from_utf8(v1.bytes().unwrap())
        .unwrap()
        .contains("projection_set"));
    let v2 = cut_versioned(&mut conn, 0, &[], 2).await.unwrap();
    assert_eq!(v2.version, 2);
    // Version 2 keeps the v1 digest and sections exactly, and adds the set.
    assert_eq!(v2.head.projection_sha256, v1.head.projection_sha256);
    assert_eq!(v2.head.generation, v1.head.generation);
    assert_eq!(
        serde_json::to_value(&v2.sections).unwrap(),
        serde_json::to_value(&v1.sections).unwrap()
    );
    let (_, set) = crate::kernel::projection_dump::dump_on_dual(&mut conn)
        .await
        .unwrap();
    assert_eq!(v2.head.projection_set.as_ref(), Some(&set));
    // Round trip through the canonical bytes.
    let bytes = v2.bytes().unwrap();
    let parsed = KernelDelta::parse(&bytes).unwrap();
    assert_eq!(parsed.bytes().unwrap(), bytes);
    assert_eq!(parsed.content_sha256, v2.content_sha256);
    assert_ne!(v2.content_sha256, v1.content_sha256);

    let value: Value = serde_json::from_slice(&bytes).unwrap();
    // Each negative below breaks exactly ONE rule: the helper keeps the carried
    // whole-set digest consistent with the (mutated) summaries, so the only
    // check that can refuse it is the one under test.
    let parse = |value: &Value| KernelDelta::parse(&serde_jcs::to_vec(value).unwrap());
    let with_tables = |mutate: &dyn Fn(&mut Vec<crate::kernel::projection_dump::SetTableDump>)| {
        let mut changed = value.clone();
        let mut tables: Vec<crate::kernel::projection_dump::SetTableDump> =
            serde_json::from_value(changed["head"]["projection_set"]["tables"].clone()).unwrap();
        mutate(&mut tables);
        changed["head"]["projection_set"]["sha256"] =
            json!(crate::kernel::projection_dump::set_digest(&tables).unwrap());
        changed["head"]["projection_set"]["tables"] = serde_json::to_value(&tables).unwrap();
        changed
    };
    // 1. The content digest covers the new field. A table digest is changed and
    //    the whole-set digest recomputed, so the set is self-consistent and
    //    well formed; only the stale content digest can refuse it...
    let mut covered = with_tables(&|tables| tables[0].set_sha256 = "0".repeat(64));
    assert!(
        parse(&covered).is_err(),
        "content digest must cover the set"
    );
    //    ...and once the content digest is resealed the very same document is
    //    accepted, which proves the refusal above was the content digest alone.
    reseal(&mut covered);
    assert!(parse(&covered).is_ok());
    // 2. The whole-set digest must follow from the summaries: the content is
    //    resealed, so only that check can refuse a stale one.
    let mut stale_whole = value.clone();
    stale_whole["head"]["projection_set"]["tables"][0]["set_sha256"] = json!("0".repeat(64));
    reseal(&mut stale_whole);
    assert!(parse(&stale_whole).is_err());
    // 3. Tables must be sorted by name. Reversed, with a consistent whole-set
    //    digest and a resealed content digest.
    let mut unsorted = with_tables(&|tables| tables.reverse());
    reseal(&mut unsorted);
    assert!(parse(&unsorted).is_err());
    // 4. Names must be unique: a duplicated name is sorted (non-strictly) and
    //    consistent in every digest.
    let mut duplicated = with_tables(&|tables| tables.insert(1, tables[0].clone()));
    reseal(&mut duplicated);
    assert!(parse(&duplicated).is_err());
    // 5. A malformed summary digest.
    let mut malformed = with_tables(&|tables| tables[0].schema_sha256 = "XYZ".into());
    reseal(&mut malformed);
    assert!(parse(&malformed).is_err());
    // 6. An explicit `projection_set: null` is not the absent field: it is not
    //    the canonical form, in version 2 or in version 1.
    let mut null_v2 = value.clone();
    null_v2["head"]["projection_set"] = Value::Null;
    reseal(&mut null_v2);
    assert!(parse(&null_v2).is_err());
    let mut null_v1: Value = serde_json::from_slice(&v1.bytes().unwrap()).unwrap();
    null_v1["head"]["projection_set"] = Value::Null;
    reseal(&mut null_v1);
    assert!(parse(&null_v1).is_err());
    // Version 1 with the field is refused...
    let mut v1_with_field = value.clone();
    v1_with_field["version"] = json!(1);
    reseal(&mut v1_with_field);
    assert!(KernelDelta::parse(&serde_jcs::to_vec(&v1_with_field).unwrap()).is_err());
    // ...version 2 without it is refused...
    let mut v2_without = value.clone();
    v2_without["head"]
        .as_object_mut()
        .unwrap()
        .remove("projection_set");
    reseal(&mut v2_without);
    assert!(KernelDelta::parse(&serde_jcs::to_vec(&v2_without).unwrap()).is_err());
    // ...and so is any version this build does not know.
    let mut v4 = value.clone();
    v4["version"] = json!(4);
    reseal(&mut v4);
    assert!(KernelDelta::parse(&serde_jcs::to_vec(&v4).unwrap()).is_err());
    assert!(super::kernel_v2_delta::cut_versioned(&mut conn, 0, &[], 4)
        .await
        .is_err());
    // Version 3 carries no digest: a version-2 document relabelled as 3 still
    // carries both, so it is refused.
    let mut v3_with_v1 = value.clone();
    v3_with_v1["version"] = json!(3);
    reseal(&mut v3_with_v1);
    assert!(KernelDelta::parse(&serde_jcs::to_vec(&v3_with_v1).unwrap()).is_err());
}

/// Wire version 3: no projection digest at all. Strict in both directions, and
/// the earlier versions are untouched by its existence.
#[tokio::test]
async fn kernel_v2_wire_version_3_carries_no_projection_digest() {
    use super::kernel_v2_delta::{cut, cut_versioned, KernelDelta};
    let db = synthetic_db().await;
    let mut conn = db.pool().acquire().await.unwrap();
    let v1 = cut_versioned(&mut conn, 0, &[], 1).await.unwrap();
    let v2 = cut_versioned(&mut conn, 0, &[], 2).await.unwrap();
    let v3 = cut_versioned(&mut conn, 0, &[], 3).await.unwrap();
    assert_eq!(v3.version, 3);
    assert!(v3.head.projection_sha256.is_none());
    assert!(v3.head.projection_set.is_none());
    let bytes = v3.bytes().unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("projection_sha256") && !text.contains("projection_set"));
    // Everything else is what version 2 carries: head, sections.
    assert_eq!(v3.head.generation, v2.head.generation);
    assert_eq!(
        serde_json::to_value(&v3.sections).unwrap(),
        serde_json::to_value(&v2.sections).unwrap()
    );
    let parsed = KernelDelta::parse(&bytes).unwrap();
    assert_eq!(parsed.bytes().unwrap(), bytes);
    // Versions 1 and 2 are byte-for-byte what they were.
    assert!(String::from_utf8(v2.bytes().unwrap())
        .unwrap()
        .contains("projection_sha256"));
    assert_eq!(
        v1.bytes().unwrap(),
        cut(&mut conn, 0, &[]).await.unwrap().bytes().unwrap()
    );

    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let parse = |value: &Value| KernelDelta::parse(&serde_jcs::to_vec(value).unwrap());
    // Either digest makes it something other than version 3.
    let v2_value: Value = serde_json::from_slice(&v2.bytes().unwrap()).unwrap();
    let mut with_set = value.clone();
    with_set["head"]["projection_set"] = v2_value["head"]["projection_set"].clone();
    reseal(&mut with_set);
    assert!(parse(&with_set).is_err());
    let mut with_v1 = value.clone();
    with_v1["head"]["projection_sha256"] = json!("0".repeat(64));
    reseal(&mut with_v1);
    assert!(parse(&with_v1).is_err());
    // Version 2's whole document relabelled as 3 is refused: it carries both.
    let mut relabelled = v2_value.clone();
    relabelled["version"] = json!(3);
    reseal(&mut relabelled);
    assert!(parse(&relabelled).is_err());
    // An explicit null is not the absent field: not the canonical form.
    for field in ["projection_sha256", "projection_set"] {
        let mut null = value.clone();
        null["head"][field] = Value::Null;
        reseal(&mut null);
        assert!(parse(&null).is_err(), "{field}");
    }
    // Version 3's document relabelled as 1 or 2 is refused: they need proofs.
    for version in [1, 2] {
        let mut relabelled = value.clone();
        relabelled["version"] = json!(version);
        reseal(&mut relabelled);
        assert!(parse(&relabelled).is_err(), "version {version}");
    }
    // Versions 1 and 2 still need the ordered digest, well formed.
    let mut no_v1 = v2_value.clone();
    no_v1["head"]
        .as_object_mut()
        .unwrap()
        .remove("projection_sha256");
    reseal(&mut no_v1);
    assert!(parse(&no_v1).is_err());
    let mut v1_value: Value = serde_json::from_slice(&v1.bytes().unwrap()).unwrap();
    v1_value["head"]
        .as_object_mut()
        .unwrap()
        .remove("projection_sha256");
    reseal(&mut v1_value);
    assert!(parse(&v1_value).is_err());
    let mut malformed = v2_value.clone();
    malformed["head"]["projection_sha256"] = json!("XYZ");
    reseal(&mut malformed);
    assert!(parse(&malformed).is_err());
    drop(conn);
    db.close().await;
}

/// A scripted authority: new hosted behaviour (`refuse_field: false`) or an
/// older replica that cannot read the request field (`refuse_field: true`),
/// optionally advertising version 2 in its head.
struct Negotiating {
    db: crate::Db,
    advertise: bool,
    refuse_field: bool,
    /// The head also advertises version 3.
    advertise_v3: bool,
    /// A replica that knows only versions 1 and 2: it refuses a request for 3.
    refuse_v3: bool,
    /// A misbehaving host that cuts at this version whatever was requested.
    serve_version: std::sync::Mutex<Option<u32>>,
    deltas: std::sync::Mutex<Vec<Value>>,
}
impl AuthorityActHttpClient for Negotiating {
    fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
        let db = self.db.clone();
        let (advertise, refuse_field) = (self.advertise, self.refuse_field);
        let (advertise_v3, refuse_v3) = (self.advertise_v3, self.refuse_v3);
        let serve_version = *self.serve_version.lock().unwrap();
        let args = body["params"]["arguments"].clone();
        if args["operation"] != "authority_act_head" {
            self.deltas.lock().unwrap().push(args["arguments"].clone());
        }
        Box::pin(async move {
            let inner = &args["arguments"];
            if args["operation"] != "authority_act_head"
                && refuse_field
                && inner.get("kernel_delta_version").is_some()
            {
                return Ok(serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":body["id"],"result":{"isError":true,"content":[],"structuredContent":{"error":"unknown field"}}}),
                )?);
            }
            if args["operation"] != "authority_act_head"
                && refuse_v3
                && inner["kernel_delta_version"] == 3
            {
                return Ok(serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":body["id"],"result":{"isError":true,"content":[],"structuredContent":{"error":"kernel_delta_version must be 1 or 2"}}}),
                )?);
            }
            let value = if args["operation"] == "authority_act_head" {
                let mut head = serde_json::to_value(
                    observe_authority_act_head_advertising(&db, "route-1", advertise).await?,
                )?;
                if advertise_v3 {
                    head["kernel_delta_versions"] = json!([1, 2, 3]);
                }
                head
            } else {
                let version = if let Some(forced) = serve_version {
                    forced
                } else if advertise && inner["kernel_delta_version"] == 3 {
                    3
                } else if advertise && inner["kernel_delta_version"] == 2 {
                    2
                } else {
                    1
                };
                serde_json::to_value(
                    observe_authority_act_delta_versioned(
                        &db,
                        "route-1",
                        inner["from_exclusive_act"].as_i64().unwrap(),
                        Some(
                            &serde_json::from_value::<Vec<String>>(inner["blob_inventory"].clone())
                                .unwrap(),
                        ),
                        version,
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

async fn negotiating_transport(
    db: &crate::Db,
    advertise: bool,
    refuse_field: bool,
) -> (AuthorityActTransport, Arc<Negotiating>, String) {
    scripted_transport(db, advertise, refuse_field, false, false).await
}

async fn scripted_transport(
    db: &crate::Db,
    advertise: bool,
    refuse_field: bool,
    advertise_v3: bool,
    refuse_v3: bool,
) -> (AuthorityActTransport, Arc<Negotiating>, String) {
    let head = observe_authority_act_head(db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let client = Arc::new(Negotiating {
        db: db.clone(),
        advertise,
        refuse_field,
        advertise_v3,
        refuse_v3,
        serve_version: Default::default(),
        deltas: Default::default(),
    });
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "test-token",
        client.clone(),
    )
    .unwrap();
    (transport, client, origin)
}

#[tokio::test]
async fn kernel_v2_node_requests_version_2_only_when_the_head_advertised_it() {
    let db = synthetic_db().await;
    // Not advertised (the default hosted): the field is never sent, v1 comes back.
    let (transport, client, _) = negotiating_transport(&db, false, false).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 1);
    assert!(delta.delta().head.projection_set.is_none());
    assert!(client.deltas.lock().unwrap()[0]
        .get("kernel_delta_version")
        .is_none());
    // A node that never probed the head asks for nothing either.
    let (transport, client, _) = negotiating_transport(&db, true, false).await;
    transport.kernel_delta(0, &[]).await.unwrap();
    assert!(client.deltas.lock().unwrap()[0]
        .get("kernel_delta_version")
        .is_none());
    // Advertised: version 2 is requested and served.
    let (transport, client, _) = negotiating_transport(&db, true, false).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 2);
    assert!(delta.delta().head.projection_set.is_some());
    assert_eq!(client.deltas.lock().unwrap()[0]["kernel_delta_version"], 2);
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_node_retries_once_without_the_field_and_stays_at_version_1_for_the_tick() {
    let db = synthetic_db().await;
    // An older replica behind a load balancer: the head advertises version 2
    // but the delta request carrying the field is refused.
    let (transport, client, _) = negotiating_transport(&db, true, true).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 1);
    {
        let seen = client.deltas.lock().unwrap();
        assert_eq!(seen.len(), 2, "one refused attempt, one retry");
        assert_eq!(seen[0]["kernel_delta_version"], 2);
        assert!(seen[1].get("kernel_delta_version").is_none());
    }
    // Suppressed for the rest of the tick: the next cut does not try again.
    transport.kernel_delta(0, &[]).await.unwrap();
    {
        let seen = client.deltas.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen[2].get("kernel_delta_version").is_none());
    }
    db.close().await;
}

/// The chunked route of an older host: a start request carrying the field is
/// a 400; without it, the route does not exist (404) and the MCP path serves.
struct OldChunkedHost {
    starts: std::sync::Mutex<Vec<bool>>,
}
impl AuthorityActDeltaHttp for OldChunkedHost {
    fn send(&self, request: DeltaHttpRequest) -> DeltaHttpFuture {
        let carries = request
            .json
            .as_ref()
            .is_some_and(|body| body.get("kernel_delta_version").is_some());
        self.starts.lock().unwrap().push(carries);
        Box::pin(async move {
            Ok(DeltaHttpResponse {
                status: if carries { 400 } else { 404 },
                api: None,
                content_type: None,
                etag: None,
                content_range: None,
                retry_after_secs: None,
                body: if carries {
                    br#"{"error_code":"invalid_request_body"}"#.to_vec()
                } else {
                    Vec::new()
                },
            })
        })
    }
}

#[tokio::test]
async fn kernel_v2_node_retries_a_400_from_the_chunked_route_without_the_field() {
    let db = synthetic_db().await;
    let (transport, client, _) = negotiating_transport(&db, true, false).await;
    let host = Arc::new(OldChunkedHost {
        starts: Default::default(),
    });
    let transport = transport.with_delta_http(
        host.clone(),
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(5),
        AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
    );
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 1);
    // The 400 on the field-bearing start, then a clean start (404 -> MCP).
    assert_eq!(*host.starts.lock().unwrap(), vec![true, false]);
    assert!(client.deltas.lock().unwrap()[0]
        .get("kernel_delta_version")
        .is_none());
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_node_requests_version_3_only_when_the_head_advertised_it() {
    let db = synthetic_db().await;
    // Today's hosted advertises [1, 2]: the node asks for 2 and NEVER sends 3,
    // so a host that would refuse version 3 is never asked.
    let (transport, client, _) = scripted_transport(&db, true, false, false, true).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 2);
    {
        let seen = client.deltas.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["kernel_delta_version"], 2);
    }
    // A host that advertises 3 is asked for 3 and serves the set digest alone.
    let (transport, client, _) = scripted_transport(&db, true, false, true, false).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 3);
    assert!(delta.delta().head.projection_sha256.is_none());
    assert!(delta.delta().head.projection_set.is_none());
    assert_eq!(client.deltas.lock().unwrap()[0]["kernel_delta_version"], 3);
    // An audit insists on the proof: version 2 even though 3 is advertised.
    let (transport, client, _) = scripted_transport(&db, true, false, true, false).await;
    transport.head().await.unwrap();
    let delta = transport
        .kernel_delta_with_proof(0, &[], true)
        .await
        .unwrap();
    assert_eq!(delta.delta().version, 2);
    assert!(delta.delta().head.projection_set.is_some());
    assert_eq!(client.deltas.lock().unwrap()[0]["kernel_delta_version"], 2);
    // ...and version 1 (which also carries a proof) from a host that offers
    // neither 2 nor 3 beyond the default.
    let (transport, client, _) = scripted_transport(&db, false, false, false, false).await;
    transport.head().await.unwrap();
    let delta = transport
        .kernel_delta_with_proof(0, &[], true)
        .await
        .unwrap();
    assert_eq!(delta.delta().version, 1);
    assert!(client.deltas.lock().unwrap()[0]
        .get("kernel_delta_version")
        .is_none());
    // No probe, no field (as for version 2).
    let (transport, client, _) = scripted_transport(&db, true, false, true, false).await;
    transport.kernel_delta(0, &[]).await.unwrap();
    assert!(client.deltas.lock().unwrap()[0]
        .get("kernel_delta_version")
        .is_none());
    db.close().await;
}

/// New host, old node: a head advertising `[1, 2, 3]` is still read by a node
/// that only knows 1 and 2, because it looks for 2 alone and ignores what it
/// does not know; the request it then sends (2) is served at 2.
#[tokio::test]
async fn kernel_v2_a_head_advertising_version_3_still_serves_a_node_that_asks_for_2() {
    use super::kernel_v2_delta::KernelDelta;
    let db = synthetic_db().await;
    let head = serde_json::to_value(
        observe_authority_act_head_advertising(&db, "route-1", true)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut with_3 = head.clone();
    with_3["kernel_delta_versions"] = json!([1, 2, 3]);
    // The head still parses with the extra number...
    let parsed: AuthorityActHeadResponseV1 = serde_json::from_value(with_3.clone()).unwrap();
    drop(parsed);
    // ...and the previous release's whole decision is `contains(&2)`.
    let versions: Vec<u32> =
        serde_json::from_value(with_3["kernel_delta_versions"].clone()).unwrap();
    assert!(versions.contains(&2));
    let (_transport, client, _) = scripted_transport(&db, true, false, true, false).await;
    let reply = client
        .call(
            "https://fixture.example".into(),
            "test-token".into(),
            json!({"id":1,"params":{"arguments":{
                "operation":"authority_act_delta",
                "arguments":{"from_exclusive_act":0,"blob_inventory":[],"kernel_delta_version":2}}}}),
        )
        .await
        .unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    let encoded = reply["result"]["structuredContent"]["data_base64"]
        .as_str()
        .unwrap();
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
    assert_eq!(KernelDelta::parse(&bytes).unwrap().version, 2);
    db.close().await;
}

/// Old host, new node: the host advertises 3 (a mixed fleet) but the replica
/// answering knows only 1 and 2. The node steps down to 2, not straight to 1,
/// and stays below 3 for the rest of the tick.
#[tokio::test]
async fn kernel_v2_node_steps_down_from_a_refused_version_3_to_2_then_1() {
    let db = synthetic_db().await;
    let (transport, client, _) = scripted_transport(&db, true, false, true, true).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 2);
    {
        let seen = client.deltas.lock().unwrap();
        assert_eq!(seen.len(), 2, "one refused attempt at 3, one served at 2");
        assert_eq!(seen[0]["kernel_delta_version"], 3);
        assert_eq!(seen[1]["kernel_delta_version"], 2);
    }
    transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(
        client.deltas.lock().unwrap()[2]["kernel_delta_version"],
        2,
        "3 stays suppressed"
    );
    // A replica that cannot read the field at all: 3, then 2, then none.
    let (transport, client, _) = scripted_transport(&db, true, true, true, false).await;
    transport.head().await.unwrap();
    let delta = transport.kernel_delta(0, &[]).await.unwrap();
    assert_eq!(delta.delta().version, 1);
    {
        let seen = client.deltas.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0]["kernel_delta_version"], 3);
        assert_eq!(seen[1]["kernel_delta_version"], 2);
        assert!(seen[2].get("kernel_delta_version").is_none());
    }
    db.close().await;
}

/// A chunked-route host that cuts at a fixed version whatever was requested.
struct FixedVersionChunkedHost {
    bytes: Vec<u8>,
    meta: crate::export::BinaryDeltaMeta,
}
impl FixedVersionChunkedHost {
    async fn serving(db: &crate::Db, version: u32) -> Arc<Self> {
        let root = tempfile::tempdir().unwrap();
        let (export, meta) = capture_authority_act_delta_export_versioned(
            db,
            "route-1",
            0,
            root.path(),
            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
            Some(&[]),
            version,
            None,
        )
        .await
        .unwrap();
        let bytes = std::fs::read(export.path()).unwrap();
        export.cleanup().await;
        Arc::new(Self { bytes, meta })
    }
}
impl AuthorityActDeltaHttp for FixedVersionChunkedHost {
    fn send(&self, request: DeltaHttpRequest) -> DeltaHttpFuture {
        let json = |status: u16, body: Value| DeltaHttpResponse {
            status,
            api: Some(AUTHORITY_ACT_DELTA_EXPORT_CONTRACT.into()),
            content_type: Some("application/json".into()),
            etag: None,
            content_range: None,
            retry_after_secs: None,
            body: serde_json::to_vec(&body).unwrap(),
        };
        let response = if request.method == DeltaHttpMethod::Post {
            json(
                202,
                json!({"api": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT, "export_handle": "h-1",
                       "status": "pending", "expires_at": "2099-01-01T00:00:00.000Z"}),
            )
        } else if request.method == DeltaHttpMethod::Delete {
            json(200, json!({"status": "cancelled"}))
        } else if let Some((start, end)) = request.range {
            let end = end.min(self.bytes.len() as u64 - 1);
            DeltaHttpResponse {
                status: 206,
                api: Some(AUTHORITY_ACT_DELTA_EXPORT_CONTRACT.into()),
                content_type: Some(AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE.into()),
                etag: Some(format!("\"{}\"", self.meta.outer_sha256)),
                content_range: Some(format!("bytes {start}-{end}/{}", self.bytes.len())),
                retry_after_secs: None,
                body: self.bytes[start as usize..=end as usize].to_vec(),
            }
        } else {
            json(
                200,
                json!({"export_handle": "h-1", "status": "ready",
                       "route_database_id": self.meta.route_database_id,
                       "origin_database_id": self.meta.origin_database_id,
                       "from_exclusive_act": self.meta.from_exclusive_act,
                       "to_inclusive_act": self.meta.to_inclusive_act,
                       "content_sha256": self.meta.content_sha256,
                       "outer_sha256": self.meta.outer_sha256,
                       "size_bytes": self.bytes.len(),
                       "expires_at": "2099-01-01T00:00:00.000Z"}),
            )
        };
        Box::pin(async move { Ok(response) })
    }
}

/// The version the node asked for is a ceiling on the answer, on the MCP route
/// and on the chunked one: lower is a host's deliberate fallback and stays
/// valid, higher is refused. In particular an audit (which asks for 2) cannot
/// be handed a proof-less version-3 delta it never asked for.
#[tokio::test]
async fn kernel_v2_a_response_above_the_requested_version_is_refused_on_both_routes() {
    let db = synthetic_db().await;
    // (host advertises 2, host advertises 3, audit, version it serves, wanted)
    let cases: [(bool, bool, bool, u32, Option<u32>); 8] = [
        (false, false, false, 3, None),
        (false, false, false, 2, None),
        (true, false, false, 3, None),
        (true, true, true, 3, None), // the audit asked for 2
        (true, true, false, 3, Some(3)),
        (true, true, false, 2, Some(2)),
        (true, true, false, 1, Some(1)),
        (true, true, true, 1, Some(1)),
    ];
    for (advertise, advertise_v3, audit, serves, accepted) in cases {
        // MCP route.
        let (transport, client, _) =
            scripted_transport(&db, advertise, false, advertise_v3, false).await;
        *client.serve_version.lock().unwrap() = Some(serves);
        transport.head().await.unwrap();
        let outcome = transport.kernel_delta_with_proof(0, &[], audit).await;
        // Chunked route.
        let (transport, _, _) =
            scripted_transport(&db, advertise, false, advertise_v3, false).await;
        let transport = transport.with_delta_http(
            FixedVersionChunkedHost::serving(&db, serves).await,
            std::time::Duration::from_millis(1),
            std::time::Duration::from_secs(5),
            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
        );
        transport.head().await.unwrap();
        let chunked = transport.kernel_delta_with_proof(0, &[], audit).await;
        for (route, outcome) in [("mcp", outcome), ("chunked", chunked)] {
            match (accepted, outcome) {
                (Some(version), Ok(delta)) => {
                    assert_eq!(delta.delta().version, version, "{route}");
                    assert_eq!(delta.delta().version, serves, "{route}");
                }
                (None, Err(error)) => assert!(
                    error.to_string().contains("above the requested wire version"),
                    "{route}: {error}"
                ),
                (accepted, outcome) => panic!(
                    "{route} ({advertise},{advertise_v3},{audit},{serves}): wanted {accepted:?}, got {:?}",
                    outcome.map(|d| d.delta().version)
                ),
            }
        }
    }
    // Defence in depth: even a request that allows version 3 cannot satisfy an
    // audit with it.
    let (transport, client, _) = scripted_transport(&db, true, false, true, false).await;
    *client.serve_version.lock().unwrap() = Some(3);
    transport.head().await.unwrap();
    let error = transport
        .kernel_delta_once(0, &[], Some(3), true)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("no projection proof"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_startup_rebinds_retained_copy_across_v1_only_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:startup-rebind")
            .await
            .unwrap();
    let record = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let root = dir.path().join("replica");
    let store = GenerationStore::open(&root, "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "startup-rebind").await;
    let retained = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    store.maintenance_idle().await;
    drop(store);
    db.close().await;

    // Reopen with no in-memory verification cache or hosted transport. Only
    // the observed v1 schema coordinate changes; the kernel format stays put.
    let store = GenerationStore::open(&root, "route-1", Some(origin)).unwrap();
    let mut replacement = observed();
    replacement.engine_schema_version += 1;
    let StandbyStartupOutcome::Serving(active) =
        store.activate_for_startup(&replacement).await.unwrap()
    else {
        panic!("startup must serve the compatible retained kernel copy")
    };
    assert_eq!(active.generation.id, retained.id);
    assert_eq!(active.generation.manifest, retained.manifest);
    assert_eq!(
        store.current_for_head_probe().unwrap().unwrap().id,
        retained.id
    );
    let receipt = store
        .consumer_rebind(&retained.id, &replacement)
        .unwrap()
        .expect("startup must publish rebind evidence for the replacement");
    assert_eq!(receipt.original_consumer, retained.manifest.consumer);
    assert_eq!(receipt.accepted_consumer, replacement);
    // Initial coordinates stay omitted so historical manifest IDs and receipt
    // checksums survive deserialization by this build. The accepted consumer
    // in a receipt still carries the reader coordinate, with its legacy default.
    let manifest_json = serde_json::to_value(&retained.manifest).unwrap();
    assert!(manifest_json["consumer"].get("kernel_v2_reader").is_none());
    assert!(manifest_json["kernel_v2"].get("reader_format").is_none());
    let receipt_json = serde_json::to_value(&receipt).unwrap();
    assert!(receipt_json["accepted_consumer"]
        .get("kernel_v2_reader")
        .is_none());
    let decoded: super::ConsumerRebind = serde_json::from_value(receipt_json).unwrap();
    assert_eq!(
        decoded.accepted_consumer.kernel_v2_reader,
        super::kernel_v2::KernelV2Reader::compiled()
    );
    // Reading persisted legacy evidence checks its checksum and defaulted format.
    assert_eq!(
        store.consumer_rebind(&retained.id, &replacement).unwrap(),
        Some(decoded)
    );

    let reader = crate::db::open_marked_v2_database_read_only_at(&active.generation.snapshot_path)
        .await
        .unwrap();
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
            .bind(&record)
            .fetch_one(reader.pool())
            .await
            .unwrap();
    assert!(
        present,
        "the restarted consumer can read the retained data without a FULL"
    );
    reader.close().await;
}

#[tokio::test]
async fn kernel_v2_staged_delta_after_consumer_rebind_preserves_base_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:rebound-delta")
            .await
            .unwrap();
    let initial = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = initial.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "rebound-delta").await;
    let base = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let original_manifest =
        std::fs::read(base.snapshot_path.with_file_name("manifest.json")).unwrap();
    let mut replacement = observed();
    replacement.source_sha = "a".repeat(40);
    replacement.artifact_sha256 = "b".repeat(64);
    // A release may change the v1 engine without changing the kernel format.
    replacement.engine_schema_version += 1;
    replacement.ddl_sha256 = "c".repeat(64);
    assert_ne!(replacement.source_sha, base.manifest.consumer.source_sha);
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        &origin,
        "token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    let record = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let delta = transport
        .kernel_delta(initial.head().head_act(), &[])
        .await
        .unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let unbound = store
        .prepare_kernel_delta(&base, &delta, &timestamp)
        .await
        .unwrap();
    assert!(
        store
            .publish_kernel_delta(unbound, &replacement)
            .await
            .is_err(),
        "a new consumer needs verified base acceptance before publishing"
    );
    assert_eq!(store.current_for_head_probe().unwrap().unwrap().id, base.id);
    store
        .ensure_consumer_binding(&base.id, &replacement)
        .await
        .unwrap();
    let receipt = store
        .consumer_rebind(&base.id, &replacement)
        .unwrap()
        .unwrap();
    let mut incompatible_reader = replacement.clone();
    incompatible_reader.kernel_v2_reader.reader_format += 1;
    let incompatible = store
        .prepare_kernel_delta(&base, &delta, &timestamp)
        .await
        .unwrap();
    assert!(
        store
            .publish_kernel_delta(incompatible, &incompatible_reader)
            .await
            .is_err(),
        "a prior rebind cannot authorize publication by another reader format"
    );
    assert_eq!(store.current_for_head_probe().unwrap().unwrap().id, base.id);
    let prepared = store
        .prepare_kernel_delta(&base, &delta, &timestamp)
        .await
        .unwrap();
    let next = store
        .publish_kernel_delta(prepared, &replacement)
        .await
        .unwrap();
    next.manifest
        .consumer
        .validate_observed_installed(&replacement)
        .unwrap();
    assert_eq!(next.manifest.engine, base.manifest.engine);
    assert_eq!(
        std::fs::read(base.snapshot_path.with_file_name("manifest.json")).unwrap(),
        original_manifest
    );
    assert_eq!(
        store
            .consumer_rebind(&base.id, &replacement)
            .unwrap()
            .unwrap(),
        receipt
    );
    assert!(store
        .consumer_rebind(&next.id, &replacement)
        .unwrap()
        .is_none());
    let copy = crate::db::open_marked_v2_database_read_only_at(&next.snapshot_path)
        .await
        .unwrap();
    let present: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
            .bind(&record)
            .fetch_one(copy.pool())
            .await
            .unwrap();
    assert!(
        present,
        "the replacement consumer can read the new canonical tail"
    );
    copy.close().await;
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let delta = transport
        .kernel_delta(delta.delta().head.head_act, &[])
        .await
        .unwrap();
    let prepared = store
        .prepare_kernel_delta(&next, &delta, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let latest = store
        .publish_kernel_delta(prepared, &replacement)
        .await
        .unwrap();
    latest
        .manifest
        .consumer
        .validate_observed_installed(&replacement)
        .unwrap();
    assert_eq!(
        store.current_for_head_probe().unwrap().unwrap().id,
        latest.id
    );
    db.close().await;
}

async fn working_startup_fixture() -> (
    tempfile::TempDir,
    Arc<StandbyStdioSession>,
    crate::fork::working_v2::WorkingBinding,
) {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "working-startup").await;
    let installed = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let genesis = installed
        .manifest
        .kernel_v2
        .as_ref()
        .unwrap()
        .genesis_event_id
        .clone();
    let binding = crate::fork::working_v2::WorkingBinding {
        account_id: "acct:owner".into(),
        database_id: "route-1".into(),
        origin_database_id: origin.clone(),
        history_lineage: format!("v2:{origin}:{genesis}"),
        resource_origin: "https://native.example".into(),
        install_id: None,
    };
    let session = Arc::new(session(store, origin, "acct:owner").await);
    (dir, session, binding)
}

#[tokio::test]
async fn working_startup_lease_waits_for_actual_verified_publication_then_is_immediate() {
    use crate::mcp::standby_stdio::StandbySupervisor;
    use std::{future::Future, task::Poll, time::Instant};
    let (_dir, session, binding) = working_startup_fixture().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (signal, resume) = (entered.clone(), release.clone());
    session.working_readiness_hook_for_test(move || {
        signal.notify_one();
        Ok(Some(resume.clone()))
    });
    let supervisor = StandbySupervisor::start_with_startup(session).unwrap();
    let dispatcher = supervisor.dispatcher();
    tokio::time::timeout(std::time::Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    let wait = dispatcher.initial_working_base(
        &binding,
        Instant::now() + std::time::Duration::from_secs(10),
    );
    tokio::pin!(wait);
    let first = std::future::poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await;
    assert!(
        first.is_pending(),
        "no lease before authorised readiness and publication"
    );
    release.notify_one();
    let lease = wait.await.unwrap();
    let (_, source, checkpoint, native, _, _, _) =
        lease.pin_current_source().await.unwrap().into_parts();
    assert!(binding.history_lineage.ends_with(&native.genesis_event_id));
    source.rollback().await.unwrap();
    drop(checkpoint);
    let immediate = dispatcher.initial_working_base(
        &binding,
        Instant::now() + std::time::Duration::from_secs(10),
    );
    tokio::pin!(immediate);
    assert!(
        matches!(
            std::future::poll_fn(|cx| Poll::Ready(immediate.as_mut().poll(cx))).await,
            Poll::Ready(Ok(_))
        ),
        "published lease must not wait for a refresh/recheck"
    );
    let mut mismatch = binding.clone();
    mismatch.account_id = "different-account".into();
    let refused = dispatcher.initial_working_base(
        &mismatch,
        Instant::now() + std::time::Duration::from_secs(10),
    );
    tokio::pin!(refused);
    assert!(
        matches!(
            std::future::poll_fn(|cx| Poll::Ready(refused.as_mut().poll(cx))).await,
            Poll::Ready(Err(_))
        ),
        "Serving mismatch must refuse immediately, never grant or await another scope"
    );
    drop(lease);
    tokio::time::timeout(std::time::Duration::from_secs(10), supervisor.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn working_startup_lease_terminal_readiness_refusal_cannot_issue_a_lease() {
    use crate::mcp::standby_stdio::StandbySupervisor;
    use std::{future::Future, task::Poll, time::Instant};
    let (_dir, session, binding) = working_startup_fixture().await;
    session.working_readiness_hook_for_test(|| {
        Err(crate::Error::engine(
            "actual readiness deliberately refused",
        ))
    });
    let (complete, ready) = tokio::sync::oneshot::channel();
    let supervisor = StandbySupervisor::start_with_startup_notifier(session, complete).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), ready)
        .await
        .unwrap()
        .unwrap();
    let dispatcher = supervisor.dispatcher();
    let wait = dispatcher.initial_working_base(
        &binding,
        Instant::now() + std::time::Duration::from_secs(10),
    );
    tokio::pin!(wait);
    let result = std::future::poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await;
    assert!(
        matches!(result, Poll::Ready(Err(_))),
        "terminal StatusOnly must refuse without a new wait or any lease"
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), supervisor.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn kernel_v2_incompatible_schema_or_reader_format_never_rebinds() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:rebind-boundary")
            .await
            .unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let store = GenerationStore::open(
        dir.path().join("replica"),
        "route-1",
        Some(head.head().origin_database_id().into()),
    )
    .unwrap();
    let mut replacement = observed();
    replacement.source_sha = "a".repeat(40);
    replacement.artifact_sha256 = "b".repeat(64);
    replacement.engine_schema_version += 1;
    replacement.ddl_sha256 = "c".repeat(64);
    let mut refusal_messages = Vec::new();
    for fault in [
        "schema",
        "owned-schema",
        "reader-version",
        "reader-format",
        "consumer-reader-format",
        "reader-contract",
        "platform",
    ] {
        let (snapshot, manifest_path) = stage(&store, &db, fault).await;
        let mut manifest: crate::standby_snapshot::StandbySnapshotManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let mut changed = replacement.clone();
        match fault {
            "schema" => {
                manifest.kernel_v2.as_mut().unwrap().schema_sha256 = "f".repeat(64);
                manifest.engine.ddl_sha256 = "f".repeat(64);
            }
            "owned-schema" => {
                use sqlx::Connection;
                let mut conn = sqlx::SqliteConnection::connect_with(
                    &sqlx::sqlite::SqliteConnectOptions::new().filename(&snapshot),
                )
                .await
                .unwrap();
                sqlx::query("CREATE TABLE incompatible_kernel_shape (id TEXT)")
                    .execute(&mut conn)
                    .await
                    .unwrap();
                conn.close().await.unwrap();
                let bytes = std::fs::read(&snapshot).unwrap();
                manifest.snapshot.size_bytes = bytes.len() as u64;
                manifest.snapshot.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
            }
            "reader-format" => manifest.kernel_v2.as_mut().unwrap().reader_format += 1,
            "consumer-reader-format" => changed.kernel_v2_reader.reader_format += 1,
            "reader-version" => manifest.version += 1,
            "reader-contract" => manifest.contract.push_str(".future"),
            "platform" => {
                changed.platform = crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64
            }
            _ => unreachable!(),
        }
        // Retain a structurally stored generation, as after a binary upgrade.
        // Admission normally rejects incompatible formats before installation.
        let bytes = serde_jcs::to_vec(&manifest).unwrap();
        let id = hex::encode(sha2::Sha256::digest(&bytes));
        let path = store
            .staging_dir()
            .parent()
            .unwrap()
            .join("generations")
            .join(&id);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::copy(&snapshot, path.join("snapshot.db")).unwrap();
        std::fs::write(path.join("manifest.json"), &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [path.join("snapshot.db"), path.join("manifest.json")] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        let before_snapshot = std::fs::read(path.join("snapshot.db")).unwrap();
        let before_manifest = std::fs::read(path.join("manifest.json")).unwrap();
        let error = store
            .ensure_consumer_binding(&id, &changed)
            .await
            .unwrap_err();
        assert_eq!(
            std::fs::read(path.join("snapshot.db")).unwrap(),
            before_snapshot,
            "{fault} must preserve the owned snapshot"
        );
        assert_eq!(
            std::fs::read(path.join("manifest.json")).unwrap(),
            before_manifest,
            "{fault} must preserve the owned manifest"
        );
        let expected = match fault {
            "schema" | "reader-format" => crate::standby::shapes::UNSUPPORTED,
            "consumer-reader-format" => "accepting executable has an unknown primary format",
            "owned-schema" => "kernel-v2 generation schema differs from compiled owned schema",
            "reader-version" | "reader-contract" => "unknown standby snapshot manifest contract",
            "platform" => "standby consumer rebind platform or wire mismatch",
            _ => unreachable!(),
        };
        refusal_messages.push((fault, error.to_string(), expected));
        let receipt = store
            .staging_dir()
            .parent()
            .unwrap()
            .join("heads")
            .join(format!(
                "{id}.consumer-rebind-{}.json",
                changed.artifact_sha256
            ));
        assert!(
            !receipt.exists(),
            "{fault} must not leave acceptance evidence"
        );
    }
    assert!(
        refusal_messages
            .iter()
            .all(|(_, error, expected)| error.contains(expected)),
        "{refusal_messages:?}"
    );
    db.close().await;
}

/// M1 slice 2a (plan 5b21bd7): a primary carrying the stored-visibility
/// marking objects ships a FULL with exactly the unmarked schema, and its
/// deltas carry the unmarked schema coordinate, so a receiver with no
/// knowledge of the objects installs the FULL and applies the delta.
#[tokio::test]
async fn kernel_v2_marked_primary_ships_unmarked_full_and_applicable_deltas() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let raw_schema = |path: std::path::PathBuf| async move {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true);
        let mut conn = sqlx::ConnectOptions::connect(&options).await.unwrap();
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        sqlx::Connection::close(conn).await.unwrap();
        rows
    };
    let unmarked_export = crate::export::export_connected_db(&db, None).await.unwrap();
    let unmarked_schema = raw_schema(unmarked_export.path()).await;
    unmarked_export.cleanup().await;
    let coordinate = |db: crate::Db| async move {
        let mut conn = db.pool().acquire().await.unwrap();
        super::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap()
            .schema_sha256
    };
    let unmarked_coordinate = coordinate(db.clone()).await;

    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    crate::kernel::stored_visibility::install_on(&mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        coordinate(db.clone()).await,
        unmarked_coordinate,
        "the head and delta schema coordinate ignores the exact marking objects"
    );
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id().to_owned();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "v2").await;
    assert_eq!(
        raw_schema(snapshot.clone()).await,
        unmarked_schema,
        "the shipped file is exactly the unmarked schema"
    );
    let installed = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();

    // Marked writes on the primary, then a delta to the receiver.
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
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
    let prepared = store
        .prepare_kernel_delta(&installed, &trusted, &chrono::Utc::now().to_rfc3339())
        .await
        .unwrap();
    let installed = store
        .publish_kernel_delta(prepared, &observed())
        .await
        .unwrap();
    let replica =
        crate::db::open_kernel_v2_standby_read_only(installed.snapshot_path.to_str().unwrap())
            .await
            .unwrap();
    assert_eq!(
        crate::kernel::dump_all_kernel_tables(&db).await.unwrap(),
        crate::kernel::dump_all_kernel_tables(&replica)
            .await
            .unwrap(),
        "canonical state replicates exactly"
    );
    assert_eq!(
        raw_schema(installed.snapshot_path.clone()).await,
        unmarked_schema,
        "the receiver never holds the primary's accelerators"
    );
    replica.close().await;
    db.close().await;
}
