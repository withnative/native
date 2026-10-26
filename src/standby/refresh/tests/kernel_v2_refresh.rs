//! Probe-only controller paths, using disposable databases and localhost HTTP.
use super::*;

async fn fixture() -> (
    tempfile::TempDir,
    StandbyRefreshController,
    crate::Db,
    String,
    Arc<AlwaysFailClient>,
) {
    let client = Arc::new(AlwaysFailClient {
        class: RefreshFailureClass::Network,
        calls: AtomicUsize::new(0),
    });
    let (directory, mut controller) = controller_with_client(client.clone());
    let (db, admin) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:fixture")
            .await
            .unwrap();
    let head = super::super::super::delta_transport::observe_authority_act_head(&db, "route-1")
        .await
        .unwrap();
    controller.runtime.origin_database_id = head.head().origin_database_id().into();
    controller.observed = crate::standby::generation_store::tests::observed();
    controller.store = GenerationStore::open(
        &controller.runtime.replica_root,
        "route-1",
        Some(controller.runtime.origin_database_id.clone()),
    )
    .unwrap();
    let (snapshot, manifest) =
        crate::standby::generation_store::tests::stage(&controller.store, &db, "v2-refresh").await;
    controller
        .store
        .install_staged(&snapshot, &manifest, &controller.observed)
        .await
        .unwrap();
    controller.delta_enabled = true;
    (directory, controller, db, admin, client)
}

#[tokio::test]
async fn auth_refusal_on_kernel_delta_never_requests_full_or_changes_serving_copy() {
    let (_directory, mut controller, db, admin, client) = fixture().await;
    let before = controller.store.current_for_head_probe().unwrap().unwrap();
    let bytes = fs::read(&before.snapshot_path).unwrap();
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    controller.config.hosted_origin =
        format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let source = db.clone();
    let server = tokio::spawn(async move {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, body) = read_http_request(&mut stream).await;
            if index == 0 {
                assert_eq!(
                    body["params"]["arguments"]["operation"],
                    "authority_act_head"
                );
                let head = super::super::super::delta_transport::observe_authority_act_head(
                    &source, "route-1",
                )
                .await
                .unwrap();
                write_json_response(&mut stream, "200 OK", &json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[],"structuredContent":head}})).await;
            } else {
                assert!(
                    headers.starts_with("POST /v1/databases/"),
                    "primary v2 delta route"
                );
                write_json_response(&mut stream, "401 Unauthorized", &json!({"error":"refused"}))
                    .await;
            }
        }
    });
    assert!(controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .is_err());
    assert_eq!(
        controller.state().unwrap().last_failure_class,
        Some(RefreshFailureClass::Authentication)
    );
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert!(controller.state().unwrap().last_full_refresh_at.is_none());
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        before.id
    );
    assert_eq!(fs::read(&before.snapshot_path).unwrap(), bytes);
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn replay_coalesces_while_active_and_discloses_post_replay_rest() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    let lock = open_private_lock(&controller.refresh_dir.join("attempt.lock")).unwrap();
    lock.try_lock_exclusive().unwrap();
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Deferred {
            reason: "refresh_in_progress"
        }
    ));
    assert!(matches!(
        controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap(),
        StandbyRefreshOutcome::Accepted { .. }
    ));
    assert!(matches!(
        controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap(),
        StandbyRefreshOutcome::Accepted { coalesced: true }
    ));
    drop(lock);
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    controller
        .defer_kernel_replay(Duration::from_secs(90))
        .unwrap();
    assert!(matches!(
        controller.refresh_once(RefreshCause::Manual).await.unwrap(),
        StandbyRefreshOutcome::Deferred {
            reason: "kernel_v2_replay_cooldown",
            ..
        }
    ));
    assert_eq!(
        controller.state().unwrap().last_deferral.as_deref(),
        Some("kernel_v2_replay_cooldown")
    );
    assert!(
        controller.state().unwrap().last_full_refresh_at.is_none(),
        "delta rest does not consume or bypass FULL cooldown"
    );
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn insufficient_disk_defers_before_delta_capture_without_spending_full_cooldown() {
    let (_directory, mut controller, db, admin, client) = fixture().await;
    let before = controller.store.current_for_head_probe().unwrap().unwrap();
    // Enough for two DB files, but NOT the separately reserved delta spool.
    controller.kernel_available_space =
        Some(2 * fs::metadata(&before.snapshot_path).unwrap().len());
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 3).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    for cause in [RefreshCause::Scheduled, RefreshCause::Manual] {
        assert!(matches!(
            controller.refresh_once(cause).await.unwrap(),
            StandbyRefreshOutcome::Deferred {
                reason: "insufficient_disk",
                ..
            }
        ));
        let state = controller.state().unwrap();
        assert_eq!(state.last_deferral.as_deref(), Some("insufficient_disk"));
        assert!(state.last_full_refresh_at.is_none());
        assert!(state.last_delta_fallback.is_none());
    }
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Deferred {
            reason: "insufficient_disk"
        }
    ));
    assert_eq!(
        sanitize_deferral("insufficient_disk"),
        Some("insufficient_disk")
    );
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        before.id
    );
    assert!(!controller.refresh_dir.join("kernel-replay.json").exists());
    assert!(!fs::read_dir(controller.store.staging_dir())
        .unwrap()
        .any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("kernel-replay-")));
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn kernel_projection_divergence_requests_full_and_retains_verified_copy() {
    let (_directory, mut controller, db, admin, client) = fixture().await;
    let before = controller.store.current_for_head_probe().unwrap().unwrap();
    let id = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Deliberately corrupt only the synthetic hosted projection, without
    // altering any coordinates. The receiver must detect the disagreement.
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut state = controller.state().unwrap();
    let previous_full = now();
    state.last_full_refresh_at = Some(previous_full.clone());
    controller.write_state(&state).unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::ProjectionDivergence
        }
    ));
    let state = controller.state().unwrap();
    // The delta-only API returns the disclosed fallback class directly. A
    // scheduled attempt retains the same diagnostic in refresh status.
    assert_eq!(state.last_full_refresh_at, Some(previous_full));
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        before.id
    );
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn kernel_blob_inventory_limit_degrades_to_disclosed_full_request() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    let mut tx = db.write_pool().begin().await.unwrap();
    for number in 0..=super::super::super::kernel_v2_delta::MAX_BLOB_INVENTORY {
        let bytes = (number as u64).to_le_bytes();
        sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
            .bind(crate::standby_snapshot::sha256_bytes(&bytes))
            .bind(bytes.as_slice())
            .bind(bytes.len() as i64)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let (snapshot, manifest) =
        crate::standby::generation_store::tests::stage(&controller.store, &db, "many-blobs").await;
    controller
        .store
        .install_staged(&snapshot, &manifest, &controller.observed)
        .await
        .unwrap();
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired {
            reason: DeltaFallbackClass::BlobInventoryLimit
        }
    ));
    assert!(controller.state().unwrap().last_full_refresh_at.is_none());
    server.await.unwrap();
    db.close().await;
}
