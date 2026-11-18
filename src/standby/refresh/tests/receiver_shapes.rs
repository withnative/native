//! Exact legacy dialects are validated before a generation writer can open.
use super::*;
use std::io::Read as _;

fn producer(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/receiver-shapes")
        .join(name);
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(File::open(path).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

async fn run_v1_case(destination95: bool, head_selection: Option<i64>, cut_selection: Option<i64>) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("private-base.db");
    fs::write(&base, producer("v1-base95.sqlite.gz")).unwrap();
    let mut raw = sqlx::SqliteConnection::connect(base.to_str().unwrap())
        .await
        .unwrap();
    // Negative-path fixture only: model a physical94 destination retaining
    // the common facts/origin. This is not a migration claim about the95
    // producer's preexisting observation metadata.
    for statement in [
        "DROP INDEX idx_content_events_caller_write",
        "ALTER TABLE content_events DROP COLUMN caller_write_ordinal",
        "ALTER TABLE content_events DROP COLUMN observed_basis",
        "ALTER TABLE content_events DROP COLUMN observed_act",
        "PRAGMA user_version=94",
    ] {
        sqlx::query(statement).execute(&mut raw).await.unwrap();
    }
    assert_eq!(
        crate::db::validate_receiver_shape_on(&mut raw)
            .await
            .unwrap(),
        94
    );
    raw.close().await.unwrap();
    let source = crate::db::open_existing_database_at(&base).await.unwrap();
    let origin = crate::identity::database_id(&source).await.unwrap();
    let client = Arc::new(AlwaysFailClient {
        class: RefreshFailureClass::Network,
        calls: AtomicUsize::new(0),
    });
    let mut controller = controller_for_origin(&dir, origin, client.clone());
    controller.observed = crate::standby::generation_store::tests::observed();
    let (snapshot, manifest) =
        crate::standby::generation_store::tests::stage(&controller.store, &source, "legacy94")
            .await;
    let baseline_manifest: StandbySnapshotManifest =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let old = if destination95 {
        let path = controller.store.staging_dir().join("actual95.db");
        fs::write(&path, producer("v1-base95.sqlite.gz")).unwrap();
        let mut manifest = baseline_manifest;
        manifest.engine.schema_version = 95;
        manifest.engine.ddl_sha256 = crate::standby::shapes::V1_95.into();
        manifest.engine.source_sha = "79570567dc19b5fd1b91191d302a7a573265073f".into();
        manifest.snapshot.sha256 = hex::encode(Sha256::digest(fs::read(&path).unwrap()));
        manifest.snapshot.size_bytes = fs::metadata(&path).unwrap().len();
        let manifest_path = controller.store.staging_dir().join("actual95.json");
        fs::write(&manifest_path, manifest.canonical_json().unwrap()).unwrap();
        controller
            .store
            .install_staged(&path, &manifest_path, &controller.observed)
            .await
            .unwrap()
    } else {
        controller
            .store
            .install_staged(&snapshot, &manifest, &controller.observed)
            .await
            .unwrap()
    };
    enable_deltas(&mut controller);
    let active = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            None,
        )
        .await
        .unwrap();
    let before = fs::read(&old.snapshot_path).unwrap();
    let response: Value = serde_json::from_slice(&producer("v1-delta-response.json.gz")).unwrap();
    let inner = base64::engine::general_purpose::STANDARD
        .decode(response["data_base64"].as_str().unwrap())
        .unwrap();
    let document: Value = serde_json::from_slice(&inner).unwrap();
    let head = if destination95 && head_selection.is_none() {
        // Equal-head must not refresh a95 copy's age without a selected shape.
        serde_json::to_value(
            crate::standby::delta_transport::observe_authority_act_head(&source, "route-1")
                .await
                .unwrap(),
        )
        .unwrap()
    } else {
        json!({"contract":"native.standby-authority-act-head-response.v1","version":1,
        "route_database_id":"route-1","head":document["authority_head"]})
    };
    let early = (destination95 && head_selection != Some(95))
        || (!destination95 && head_selection == Some(95))
        || head_selection == Some(96);
    let expected_calls = if early { 1 } else { 2 };
    let advances = destination95 && head_selection == Some(95) && cut_selection == Some(95);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    controller.config.hosted_origin =
        format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let mut served = 0;
        while served < expected_calls {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, request) = read_http_request(&mut stream).await;
            if refuse_chunked_route(&mut stream, &headers).await {
                continue;
            }
            assert!(headers
                .to_ascii_lowercase()
                .contains("native-accepted-shapes:"));
            let operation = request["params"]["arguments"]["operation"]
                .as_str()
                .unwrap();
            let body = if served == 0 {
                assert_eq!(operation, "authority_act_head");
                head.clone()
            } else {
                assert_eq!(operation, "authority_act_delta");
                response.clone()
            };
            let selected = if served == 0 {
                head_selection
            } else {
                cut_selection
            };
            served += 1;
            let envelope = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,
                "result":{"isError":false,"content":[],"structuredContent":body}}))
            .unwrap();
            let selection = selected
                .map(|version| {
                    let mut shape = crate::standby::shapes::v1(95, crate::standby::shapes::V1_95)
                        .unwrap()
                        .shape();
                    if version == 94 {
                        shape = crate::standby::shapes::v1(94, crate::standby::shapes::V1_94)
                            .unwrap()
                            .shape();
                    }
                    if version == 96 {
                        shape.engine_schema = 96;
                        shape.schema_sha256 = "f".repeat(64);
                    }
                    format!(
                        "native-selected-shape: {}\r\n",
                        serde_json::to_string(&shape).unwrap()
                    )
                })
                .unwrap_or_default();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n",envelope.len(),selection).as_bytes()).await.unwrap();
            stream.write_all(&envelope).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let result = controller.refresh_delta_only().await.unwrap();
    if advances {
        assert!(
            matches!(result, StandbyDeltaOutcome::Advanced { .. }),
            "{result:?}"
        );
        assert_eq!(controller.store.receiver_writer_opens(), 1);
    } else {
        assert_eq!(
            controller.store.receiver_writer_opens(),
            0,
            "refused dialect must not open a generation writer"
        );
        assert!(
            matches!(
                result,
                StandbyDeltaOutcome::FullRefreshRequired {
                    reason: DeltaFallbackClass::HeadCompatibility
                }
            ),
            "{result:?}"
        );
        assert_eq!(controller.store.receiver_writer_opens(), 0);
        assert_eq!(fs::read(&old.snapshot_path).unwrap(), before);
    }
    server.await.unwrap();
    assert_eq!(active.generation.id, old.id);
    assert!(controller.state().unwrap().last_full_refresh_at.is_none());
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    drop(active);
    controller.store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn real95_v1_cut_without_selection_refuses_before_writer_and_keeps94() {
    run_v1_case(false, None, None).await;
}

#[tokio::test]
async fn receiver_v1_selected95_advances_only_with_coherent_head_and_cut() {
    run_v1_case(true, Some(95), Some(95)).await;
    run_v1_case(true, Some(95), None).await;
    run_v1_case(false, Some(94), Some(95)).await;
    run_v1_case(true, None, None).await;
    run_v1_case(false, Some(95), None).await;
    run_v1_case(false, Some(96), None).await;
}

#[tokio::test]
async fn real95_empty_v1_inventory_cannot_be_legacy94() {
    let response: Value =
        serde_json::from_slice(&producer("v1-empty-delta-response.json.gz")).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(response["data_base64"].as_str().unwrap())
        .unwrap();
    let validated = crate::standby::act_delta::validate_authority_act_delta(&bytes).unwrap();
    assert!(validated
        .act_cut()
        .sections()
        .iter()
        .all(|section| section.rows.is_empty()));
    let old = crate::standby::shapes::v1(94, crate::standby::shapes::V1_94).unwrap();
    let new = crate::standby::shapes::v1(95, crate::standby::shapes::V1_95).unwrap();
    assert!(
        crate::standby::shapes::check_v1_cut(validated.act_cut(), old)
            .await
            .is_err()
    );
    crate::standby::shapes::check_v1_cut(validated.act_cut(), new)
        .await
        .unwrap();
}
