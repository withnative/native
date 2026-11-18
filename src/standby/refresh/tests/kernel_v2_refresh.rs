//! Probe-only controller paths, using disposable databases and localhost HTTP.
use super::*;

#[tokio::test]
async fn receiver_shape_transition_from_advanced_copy_uses_full_and_hands_off() {
    use crate::standby::shapes;
    let (_directory, mut controller, source, owner, _client) = fixture().await;
    controller.config.kernel_in_place_deltas = true;
    let old = controller.store.current_for_head_probe().unwrap().unwrap();
    let reader = controller.store.hold_serving_reader(&old.id).unwrap();
    controller
        .store
        .record_serving_reader(&old.id, &controller.observed)
        .unwrap();
    let active = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            None,
        )
        .await
        .unwrap();
    crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(source.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Advanced { .. }
    ));
    server.await.unwrap();
    assert!(controller
        .store
        .generation_head(&old.id)
        .unwrap()
        .unwrap()
        .advanced_in_place());
    shapes::tests::upgrade_fixture_to_95(&source).await;
    crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (snapshot, manifest_path) =
        crate::standby::generation_store::tests::stage(&controller.store, &source, "transition95")
            .await;
    let bytes = fs::read(snapshot).unwrap();
    let manifest: StandbySnapshotManifest =
        serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
    let mut replies = paged_replies("transition95", &bytes, &manifest);
    for reply in &mut replies {
        if let ScriptedReply::Page(page) = reply {
            page.selected_shape = Some(shapes::v2(1, shapes::V2_95).unwrap().shape());
        }
    }
    controller.client = Arc::new(ScriptedClient::new(replies));
    controller.binary_snapshot_enabled = false;
    let mut state = controller.state().unwrap();
    state.last_full_refresh_at = Some(now());
    controller.write_state(&state).unwrap();
    let (port, server) = serve_authority_act_calls(source.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let StandbyRefreshOutcome::Installed { generation, .. } = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap()
    else {
        panic!("known transition must bypass ordinary FULL cooldown once");
    };
    server.await.unwrap();
    assert_eq!(
        generation
            .manifest
            .kernel_v2
            .as_ref()
            .unwrap()
            .schema_sha256,
        shapes::V2_95
    );
    let next = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            Some(&active),
        )
        .await
        .expect("advanced94 prefix must compare and hand off to95");
    controller.store.confirm_handoff(&next).unwrap();
    assert_eq!(next.generation.id, generation.id);
    assert!(
        old.snapshot_path.exists(),
        "rollback predecessor survives transition"
    );
    drop(next);
    drop(active);
    drop(reader);
    controller.store.maintenance_idle().await;
    source.close().await;
}

pub(super) async fn fixture() -> (
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

pub(super) fn replay_record(controller: &StandbyRefreshController) -> Value {
    serde_json::from_slice(&fs::read(controller.refresh_dir.join("kernel-replay.json")).unwrap())
        .unwrap()
}

pub(super) fn phase_names(record: &Value) -> Vec<String> {
    record["last_phases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|phase| phase["phase"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn staged_kernel_delta_records_per_phase_wall_time_beside_last_wall_millis() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Advanced { .. }
    ));
    let record = replay_record(&controller);
    assert!(record["last_wall_millis"].is_u64() || record["last_wall_millis"].is_number());
    assert_eq!(record["last_outcome"], "completed_small");
    let names = phase_names(&record);
    // Every phase of the staged path is named, in execution order.
    let expected = [
        "verify_base",
        "blob_inventory",
        "fetch_delta",
        "prepare_lease_disk",
        "prepare_copy",
        "prepare_open_writer",
        "apply_begin_write",
        "apply_ingest",
        "apply_replay_projection",
        "apply_projection_digest",
        "apply_commit",
        "prepare_close_writer",
        "prepare_verify_copy",
        "prepare_rename_fsync",
        "prepare_file_sha256",
        "prepare_manifest",
        "publish_stage_files",
        "publish_verify_candidate",
        "publish_predecessor_fence",
        "publish_rename_generation",
        "publish_pointer",
        "record_synced",
    ];
    let mut cursor = names.iter();
    for want in expected {
        assert!(
            cursor.any(|name| name == want),
            "phase {want} missing or out of order in {names:?}"
        );
    }
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn failed_kernel_delta_keeps_partial_phases_and_the_one_minute_floor() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    let id = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_records SET created_at='2030-01-01T00:00:00Z' WHERE id=?")
        .bind(id)
        .execute(db.write_pool())
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::FullRefreshRequired { .. }
    ));
    let record = replay_record(&controller);
    assert_eq!(record["last_outcome"], "failed");
    // The digest ran and disagreed: the phase is recorded, the commit is not.
    assert!(phase_names(&record).contains(&"apply_projection_digest".to_owned()));
    assert!(!phase_names(&record).contains(&"apply_commit".to_owned()));
    assert!(record["last_rest_millis"].as_u64().unwrap() >= 60_000);
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn small_kernel_delta_lifts_the_one_minute_floor_but_keeps_proportional_rest() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 4).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Advanced { .. }
    ));
    let record = replay_record(&controller);
    assert_eq!(record["last_outcome"], "completed_small");
    // The rest is exactly the replay's own wall time, with no minute floor.
    assert_eq!(record["last_rest_millis"], record["last_wall_millis"]);
    assert!(record["last_rest_millis"].as_u64().unwrap() < 60_000);
    // A second small delta is not held back by the cooldown.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let past_rest = record["last_rest_millis"].as_u64().unwrap() + 50;
    tokio::time::sleep(Duration::from_millis(past_rest)).await;
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Advanced { .. }
    ));
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn large_kernel_delta_keeps_the_one_minute_floor() {
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    for _ in 0..super::super::super::kernel_v2_delta::SMALL_DELTA_MAX_EVENTS {
        crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Advanced { .. }
    ));
    let record = replay_record(&controller);
    assert_eq!(record["last_outcome"], "completed_large");
    assert!(record["last_rest_millis"].as_u64().unwrap() >= 60_000);
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_v1_only_upgrade_rebinds_without_full_download() {
    let (_directory, mut controller, db, admin, client) = fixture().await;
    let before = controller.store.current_for_head_probe().unwrap().unwrap();
    controller.observed.source_sha = "a".repeat(40);
    controller.observed.artifact_sha256 = "b".repeat(64);
    controller.observed.engine_schema_version += 1;
    controller.observed.ddl_sha256 = "c".repeat(64);
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let StandbyRefreshOutcome::Advanced { generation, .. } = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap()
    else {
        panic!("the compatible copy must advance through a staged delta")
    };
    assert!(controller
        .store
        .consumer_rebind(&before.id, &controller.observed)
        .unwrap()
        .is_some());
    generation
        .manifest
        .consumer
        .validate_observed_installed(&controller.observed)
        .unwrap();
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert!(controller.state().unwrap().last_full_refresh_at.is_none());
    assert_eq!(controller.state().unwrap().last_delta_fallback_class, None);
    server.await.unwrap();
    db.close().await;
}

/// The actual v2 transport/materialization owner emits a distinct sealed
/// handoff after BOTH supported publication routes, never through v1 observer.
#[tokio::test]
async fn native_kernel_accepted_notice_follows_actual_in_place_and_staged_publication() {
    struct Seen(std::sync::Mutex<Option<AcceptedKernelDelta>>);
    impl AcceptedKernelDeltaObserver for Seen {
        fn committed(&self, accepted: AcceptedKernelDelta) {
            assert!(self.0.lock().unwrap().replace(accepted).is_none());
        }
    }
    struct WrongLane;
    impl AcceptedDeltaObserver for WrongLane {
        fn committed(
            &self,
            _: String,
            _: crate::standby::act_materialise::TrustedAuthorityActDelta,
        ) {
            panic!("native v2 must never upcast into v1 accepted notice");
        }
    }
    for in_place in [false, true] {
        let (_directory, mut controller, db, admin, _client) = fixture().await;
        controller.config.kernel_in_place_deltas = in_place;
        let before_generation = controller.store.current_for_head_probe().unwrap().unwrap();
        let before = crate::standby::kernel_v2::verify_path(&before_generation.snapshot_path)
            .await
            .unwrap();
        let _reader = if in_place {
            let lock = controller
                .store
                .hold_serving_reader(&before_generation.id)
                .unwrap();
            controller
                .store
                .record_serving_reader(&before_generation.id, &controller.observed)
                .unwrap();
            Some(lock)
        } else {
            None
        };
        let seen = Arc::new(Seen(std::sync::Mutex::new(None)));
        let hints = RefreshHints::default();
        hints.observe_accepted_deltas(Arc::new(WrongLane));
        hints.observe_accepted_kernel_deltas(seen.clone());
        controller.set_pending_observer_for_test(hints);
        crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
        let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        assert!(matches!(
            controller.refresh_delta_only().await.unwrap(),
            StandbyDeltaOutcome::Advanced { .. }
        ));
        let published = controller.store.current_for_head_probe().unwrap().unwrap();
        let accepted = seen
            .0
            .lock()
            .unwrap()
            .take()
            .expect("genuine native publication handoff");
        assert_eq!(accepted.source(), before_generation.id);
        assert_eq!(accepted.destination(), published.id);
        assert_eq!(accepted.before(), &before);
        assert_eq!(accepted.delta().delta().from_exclusive_act, before.head_act);
        assert_eq!(
            crate::standby::kernel_v2::verify_path(&published.snapshot_path)
                .await
                .unwrap(),
            accepted.delta().delta().head.generation
        );
        assert_eq!(accepted.source() == accepted.destination(), in_place);
        server.await.unwrap();
        controller.store.maintenance_idle().await;
        db.close().await;
    }
}

/// Checkpoint verification defers without changing the accepted serving file.
/// Its begin barrier is resolved explicitly, not reported as a missing commit.
#[tokio::test]
async fn native_kernel_deferred_checkpoint_resolves_only_known_no_publication() {
    #[derive(Default)]
    struct Seen {
        begin: AtomicUsize,
        unchanged: AtomicUsize,
        unknown: AtomicUsize,
        committed: AtomicUsize,
    }
    impl AcceptedKernelDeltaObserver for Seen {
        fn begin(&self) {
            self.begin.fetch_add(1, Ordering::SeqCst);
        }
        fn no_publication(&self) {
            self.unchanged.fetch_add(1, Ordering::SeqCst);
        }
        fn finish(&self) {
            self.unknown.fetch_add(1, Ordering::SeqCst);
        }
        fn committed(&self, _: AcceptedKernelDelta) {
            self.committed.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (_directory, mut controller, db, admin, _client) = fixture().await;
    controller.config.kernel_in_place_deltas = true;
    let current = controller.store.current_for_head_probe().unwrap().unwrap();
    let before = crate::standby::kernel_v2::verify_path(&current.snapshot_path)
        .await
        .unwrap();
    let _reader = controller.store.hold_serving_reader(&current.id).unwrap();
    controller
        .store
        .record_serving_reader(&current.id, &controller.observed)
        .unwrap();
    let checkpoint_path = controller
        .store
        .staging_dir()
        .parent()
        .unwrap()
        .join("leases")
        .join(format!("{}.checkpoint", current.id));
    let checkpoint = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(checkpoint_path)
        .unwrap();
    fs2::FileExt::lock_shared(&checkpoint).unwrap();
    let seen = Arc::new(Seen::default());
    let hints = RefreshHints::default();
    hints.observe_accepted_kernel_deltas(seen.clone());
    controller.set_pending_observer_for_test(hints);
    crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (port, server) = serve_authority_act_calls(db.clone(), 2).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(matches!(
        controller.refresh_delta_only().await.unwrap(),
        StandbyDeltaOutcome::Deferred {
            reason: DEFERRED_CHECKPOINT_VERIFYING,
            ..
        }
    ));
    server.await.unwrap();
    assert_eq!(seen.begin.load(Ordering::SeqCst), 1);
    assert_eq!(seen.unchanged.load(Ordering::SeqCst), 1);
    assert_eq!(seen.unknown.load(Ordering::SeqCst), 0);
    assert_eq!(seen.committed.load(Ordering::SeqCst), 0);
    assert_eq!(
        crate::standby::kernel_v2::verify_path(&current.snapshot_path)
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        current.id
    );
    fs2::FileExt::unlock(&checkpoint).unwrap();
    controller.store.maintenance_idle().await;
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_reader_format_change_requests_full_without_changing_manifest_contract() {
    let (_directory, mut controller, db, _admin, client) = fixture().await;
    let before = controller.store.current_for_head_probe().unwrap().unwrap();
    let contract = before.manifest.contract.clone();
    controller.observed.source_sha = "a".repeat(40);
    controller.observed.artifact_sha256 = "b".repeat(64);
    controller.observed.kernel_v2_reader.reader_format += 1;
    let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    // The FULL client deliberately fails. We care that an incompatible reader
    // requests repair, never that it can continue with an old retained copy.
    assert!(controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .is_err());
    assert_eq!(
        controller.state().unwrap().last_delta_fallback_class,
        Some(DeltaFallbackClass::ConsumerChanged)
    );
    assert!(client.calls.load(Ordering::SeqCst) > 0);
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .manifest
            .contract,
        contract
    );
    assert!(controller
        .store
        .consumer_rebind(&before.id, &controller.observed)
        .is_err());
    server.await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_unreadable_reader_or_legacy_schema_fetches_and_installs_full() {
    use std::os::unix::fs::PermissionsExt;
    for kind in ["reader", "legacy-schema"] {
        let (_directory, mut controller, db, admin, _client) = fixture().await;
        controller.store.maintenance_idle().await;
        let before = controller.store.current_for_head_probe().unwrap().unwrap();
        let mut old = before.manifest.clone();
        if kind == "reader" {
            // A different retained version exercises the same equality-based
            // FULL path as a compiled reader bump, without changing the contract.
            old.kernel_v2.as_mut().unwrap().reader_format += 1;
            old.consumer.kernel_v2_reader.reader_format += 1;
        } else {
            let older = crate::standby::kernel_v2::RELEASE_PRE_WEBHOOK_SOURCE_V1_SCHEMA_SHA256;
            old.kernel_v2.as_mut().unwrap().schema_sha256 = older.into();
            old.engine.ddl_sha256 = older.into();
            assert!(serde_json::to_value(&old).unwrap()["consumer"]
                .get("kernel_v2_reader")
                .is_none());
        }
        let bytes = serde_jcs::to_vec(&old).unwrap();
        let id = hex::encode(Sha256::digest(&bytes));
        let root = controller
            .store
            .staging_dir()
            .parent()
            .unwrap()
            .to_path_buf();
        let retained = root.join("generations").join(&id);
        fs::create_dir(&retained).unwrap();
        fs::copy(&before.snapshot_path, retained.join("snapshot.db")).unwrap();
        fs::write(retained.join("manifest.json"), bytes).unwrap();
        for path in [retained.join("snapshot.db"), retained.join("manifest.json")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o500)).unwrap();
        let pointer_path = root.join("current.json");
        let mut pointer: Value = serde_json::from_slice(&fs::read(&pointer_path).unwrap()).unwrap();
        pointer["generation_id"] = json!(id);
        fs::write(pointer_path, serde_jcs::to_vec(&pointer).unwrap()).unwrap();
        assert!(controller
            .store
            .ensure_consumer_binding(&id, &controller.observed)
            .await
            .is_err());
        let record = crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
        let (snapshot, manifest_path) = crate::standby::generation_store::tests::stage(
            &controller.store,
            &db,
            "reader-repair-full",
        )
        .await;
        let bytes = fs::read(snapshot).unwrap();
        let manifest = serde_json::from_slice(&fs::read(manifest_path).unwrap()).unwrap();
        let client = Arc::new(ScriptedClient::new(paged_replies(
            "reader-repair",
            &bytes,
            &manifest,
        )));
        controller.client = client.clone();
        controller.binary_snapshot_enabled = false;
        let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
        controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
        let StandbyRefreshOutcome::Installed { generation, .. } = controller
            .refresh_once(RefreshCause::Scheduled)
            .await
            .unwrap()
        else {
            panic!("{kind} must fetch and install a FULL")
        };
        assert!(client.calls.load(Ordering::SeqCst) > 0);
        assert_eq!(generation.manifest.contract, old.contract);
        assert_eq!(
            controller
                .store
                .current_for_head_probe()
                .unwrap()
                .unwrap()
                .id,
            generation.id
        );
        let copy = crate::db::open_marked_v2_database_read_only_at(&generation.snapshot_path)
            .await
            .unwrap();
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
                .bind(record)
                .fetch_one(copy.pool())
                .await
                .unwrap();
        assert!(
            present,
            "the installed FULL contains data absent from the retained copy"
        );
        copy.close().await;
        server.await.unwrap();
        controller.store.maintenance_idle().await;
        db.close().await;
    }
}

#[tokio::test]
async fn kernel_v2_head_preserves_noninitial_reader_declaration() {
    let (_directory, mut controller, db, _admin, _client) = fixture().await;
    controller.observed.kernel_v2_reader.reader_format += 1;
    let (port, server) = serve_authority_act_calls(db.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    assert!(controller
        .revision_pause_needed("secret")
        .await
        .unwrap()
        .is_none());
    let declaration = controller.declared_consumer();
    assert_eq!(
        declaration.kernel_v2_reader,
        controller.observed.kernel_v2_reader
    );
    assert!(serde_json::to_value(declaration)
        .unwrap()
        .get("kernel_v2_reader")
        .is_some());
    server.await.unwrap();
    controller.store.maintenance_idle().await;
    db.close().await;
}

#[tokio::test]
async fn receiver_stale_episode_cannot_waive_an_unrelated_full_cooldown() {
    let (_directory, mut controller, source, _owner, client) = fixture().await;
    controller.config.full_refresh_min_interval_seconds = Some(3600);
    let current = controller.store.current_for_head_probe().unwrap().unwrap();
    let before = fs::read(&current.snapshot_path).unwrap();
    controller
        .observe_transition(
            crate::standby::shapes::v2(1, crate::standby::shapes::V2_94).unwrap(),
            crate::standby::shapes::v2(1, crate::standby::shapes::V2_95).unwrap(),
        )
        .unwrap();
    let mut state = controller.state().unwrap();
    state.last_full_refresh_at = Some(now());
    controller.write_state(&state).unwrap();
    // A later unknown head is not the94→95 transition saved above.
    let mut reply = serde_json::to_value(
        crate::standby::delta_transport::observe_authority_act_head(&source, "route-1")
            .await
            .unwrap(),
    )
    .unwrap();
    reply["head"]["generation"]["schema_sha256"] = json!("f".repeat(64));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    controller.config.hosted_origin =
        format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request(&mut stream).await;
        write_json_response(&mut stream, "200 OK", &json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[],"structuredContent":reply}})).await;
    });
    let StandbyRefreshOutcome::Deferred { reason, .. } = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap()
    else {
        panic!("ordinary FULL cooldown must remain in force");
    };
    server.await.unwrap();
    assert_eq!(reason, DEFERRED_FULL_REFRESH_INTERVAL);
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert_eq!(controller.store.receiver_writer_opens(), 0);
    assert_eq!(fs::read(&current.snapshot_path).unwrap(), before);
    controller.store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn receiver_unknown_owned_shape_goes_full_without_opening_local_writer() {
    let (_directory, mut controller, source, _owner, client) = fixture().await;
    let current = controller.store.current_for_head_probe().unwrap().unwrap();
    let before = fs::read(&current.snapshot_path).unwrap();
    let active = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            None,
        )
        .await
        .unwrap();
    let mut reply = serde_json::to_value(
        crate::standby::delta_transport::observe_authority_act_head(&source, "route-1")
            .await
            .unwrap(),
    )
    .unwrap();
    reply["head"]["generation"]["schema_sha256"] = json!("f".repeat(64));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    controller.config.hosted_origin =
        format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (headers, _) = read_http_request(&mut stream).await;
        assert!(headers
            .to_ascii_lowercase()
            .contains("native-accepted-shapes:"));
        write_json_response(&mut stream, "200 OK", &json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,"content":[],"structuredContent":reply}})).await;
    });
    assert!(controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .is_err());
    server.await.unwrap();
    assert!(
        client.calls.load(Ordering::SeqCst) > 0,
        "unknown shape must request a FULL"
    );
    assert_eq!(controller.store.receiver_writer_opens(), 0);
    assert_eq!(fs::read(&current.snapshot_path).unwrap(), before);
    assert_eq!(active.generation.id, current.id);
    assert_eq!(
        controller
            .store
            .accepted_identity_hint()
            .unwrap()
            .unwrap()
            .generation_id(),
        current.id
    );
    drop(active);
    controller.store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn receiver_selected_shape_cannot_conflict_with_real95_head_or_cut() {
    let (_directory, controller, source, _owner, _client) = fixture().await;
    crate::standby::shapes::tests::upgrade_fixture_to_95(&source).await;
    let head = serde_json::to_value(
        crate::standby::delta_transport::observe_authority_act_head(&source, "route-1")
            .await
            .unwrap(),
    )
    .unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/receiver-shapes/delta-response.json.gz");
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(File::open(path).unwrap()),
        &mut bytes,
    )
    .unwrap();
    let cut: Value = serde_json::from_slice(&bytes).unwrap();
    for kind in ["head", "cut"] {
        let reply = if kind == "head" {
            head.clone()
        } else {
            cut.clone()
        };
        let origin = if kind == "head" {
            controller.runtime.origin_database_id.clone()
        } else {
            cut["origin_database_id"].as_str().unwrap().to_owned()
        };
        let from = cut["from_exclusive_act"].as_i64().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (headers, _) = read_http_request(&mut stream).await;
                if refuse_chunked_route(&mut stream, &headers).await {
                    continue;
                }
                let selected = crate::standby::shapes::v2(1, crate::standby::shapes::V2_94)
                    .unwrap()
                    .shape();
                let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false,"structuredContent":reply}})).unwrap();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nnative-selected-shape: {}\r\n\r\n",body.len(),serde_json::to_string(&selected).unwrap()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
                break;
            }
        });
        let transport =
            AuthorityActTransport::new(&origin_url, "route-1", &origin, "secret").unwrap();
        let error = if kind == "head" {
            transport
                .head()
                .await
                .expect_err("conflicting95 head must refuse")
        } else {
            transport
                .kernel_delta(from, &[])
                .await
                .err()
                .expect("conflicting95 cut must refuse")
        };
        assert!(
            error.to_string().contains("conflicts with the actual"),
            "{error}"
        );
        server.await.unwrap();
    }
    controller.store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn receiver_transition_disk_budget_refuses_before_range_or_page_tail() {
    let (_directory, mut controller, source, _owner, _client) = fixture().await;
    controller.store.maintenance_idle().await;
    let old = controller.store.current_for_head_probe().unwrap().unwrap();
    let before = fs::read(&old.snapshot_path).unwrap();
    crate::standby::shapes::tests::upgrade_fixture_to_95(&source).await;
    let (snapshot, path) =
        crate::standby::generation_store::tests::stage(&controller.store, &source, "disk95").await;
    let bytes = fs::read(snapshot).unwrap();
    let manifest: StandbySnapshotManifest =
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut large = manifest.clone();
    large.snapshot.size_bytes = 4 * 1024 * 1024 * 1024;
    let binary = Arc::new(ScriptedBinaryClient::for_snapshot(bytes.clone(), large));
    // If the disk fence is bypassed, count the attempted request without
    // allocating the declared4GiB body or indexing beyond this small fixture.
    binary.succeed_reads.store(0, Ordering::SeqCst);
    controller.binary_client = binary.clone();
    controller.kernel_available_space = Some(0);
    let output = controller
        .store
        .staging_dir()
        .join("refused-before-ranges.db");
    let error = controller
        .download_binary_only("token".into(), &output, binary::FreshCaptureBudget::Allowed)
        .await
        .unwrap_err();
    assert_eq!(
        binary.reads.load(Ordering::SeqCst),
        0,
        "metadata refusal must precede every range GET"
    );
    assert!(
        error.source.to_string().contains("transition_disk_budget"),
        "{error:?}"
    );
    assert!(!controller
        .refresh_dir
        .join("binary-resume.partial.db")
        .exists());
    assert!(!output.exists());
    let mut oversized = manifest.clone();
    oversized.snapshot.size_bytes = 9 * 1024 * 1024 * 1024;
    controller.kernel_available_space = Some(u64::MAX);
    assert!(controller
        .transition_transfer_budget(&oversized, oversized.snapshot.size_bytes)
        .is_err());
    controller.kernel_available_space = Some(0);
    let mut pages = paged_replies("disk95", &bytes, &manifest);
    for page in &mut pages {
        if let ScriptedReply::Page(page) = page {
            page.selected_shape = Some(
                crate::standby::shapes::v2(1, crate::standby::shapes::V2_95)
                    .unwrap()
                    .shape(),
            );
        }
    }
    let pages = Arc::new(ScriptedClient::new(pages));
    controller.client = pages.clone();
    let manifest_path = controller
        .store
        .staging_dir()
        .join("refused-before-page-tail.json");
    let error = controller
        .download_and_install(
            "http://fixture/mcp/route%2D1",
            "secret".into(),
            &output,
            &manifest_path,
        )
        .await
        .unwrap_err();
    assert!(
        error.source.to_string().contains("transition_disk_budget"),
        "{error:?}"
    );
    assert_eq!(
        pages.calls.load(Ordering::SeqCst),
        1,
        "legacy transport permits only its bounded metadata page before refusal"
    );
    assert_eq!(fs::metadata(&output).unwrap().len(), 0);
    assert_eq!(fs::read(&old.snapshot_path).unwrap(), before);
    assert_eq!(
        controller
            .store
            .current_for_head_probe()
            .unwrap()
            .unwrap()
            .id,
        old.id
    );
    assert_eq!(controller.store.receiver_writer_opens(), 0);
    controller.store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn receiver_full_budget_allows_ordinary94_and_recovers_unknown_pointer_honestly() {
    let (_directory, mut controller, source, owner, _client) = fixture().await;
    controller.store.maintenance_idle().await;
    let old94 = controller.store.current_for_head_probe().unwrap().unwrap();
    let original94 = fs::read(&old94.snapshot_path).unwrap();
    crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (snapshot, path) =
        crate::standby::generation_store::tests::stage(&controller.store, &source, "ordinary94")
            .await;
    let bytes = fs::read(&snapshot).unwrap();
    let manifest: StandbySnapshotManifest =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let binary = Arc::new(ScriptedBinaryClient::for_snapshot(bytes, manifest));
    controller.binary_client = binary;
    controller.binary_snapshot_enabled = true;
    controller.kernel_available_space = Some(u64::MAX);
    controller.delta_enabled = false;
    let (port, server) = serve_authority_act_calls(source.clone(), 1).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller.refresh_once(RefreshCause::Manual).await.unwrap();
    assert!(
        matches!(outcome, StandbyRefreshOutcome::Installed { .. }),
        "{outcome:?}"
    );
    server.await.unwrap();
    assert!(controller.state().unwrap().last_full_refresh_at.is_some());
    assert_eq!(fs::read(&old94.snapshot_path).unwrap(), original94);
    let rollback94 = controller.store.current_for_head_probe().unwrap().unwrap();
    let rollback_bytes = fs::read(&rollback94.snapshot_path).unwrap();
    assert!(!controller
        .refresh_dir
        .join("shape-transition.json")
        .exists());
    controller.store.maintenance_idle().await;
    crate::standby::shapes::tests::upgrade_fixture_to_95(&source).await;
    let (snapshot, path) =
        crate::standby::generation_store::tests::stage(&controller.store, &source, "fallback95")
            .await;
    let accepted95 = controller
        .store
        .install_staged(&snapshot, &path, &controller.observed)
        .await
        .unwrap();
    let active = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            None,
        )
        .await
        .unwrap();
    controller.store.confirm_handoff(&active).unwrap();
    controller.kernel_available_space = Some(0);
    assert!(
        controller
            .transition_transfer_budget(
                &accepted95.manifest,
                accepted95.manifest.snapshot.size_bytes
            )
            .is_err(),
        "same95 FULL still retains the94 rollback pin"
    );
    controller.kernel_available_space = Some(u64::MAX);
    let pin = controller
        .store
        .staging_dir()
        .parent()
        .unwrap()
        .join("shape-rollback-pins.json");
    let pin_before = fs::read(&pin).unwrap();
    controller.store.maintenance_idle().await;
    // A future binary's declaration is unreadable to A. Its rows are never
    // trusted here; the actual verified95 fallback keeps serving separately.
    let mut future = accepted95.manifest.clone();
    // NKV2's envelope engine schema is always zero; unknown reader identity
    // lives in its kernel coordinates and the future executable declaration.
    future.engine.ddl_sha256 = "f".repeat(64);
    future.consumer.engine_schema_version = 96;
    future.consumer.ddl_sha256 = "f".repeat(64);
    future.kernel_v2.as_mut().unwrap().schema_sha256 = "f".repeat(64);
    future.kernel_v2.as_mut().unwrap().reader_format = 96;
    future.consumer.kernel_v2_reader.schema_sha256 = "f".repeat(64);
    future.consumer.kernel_v2_reader.reader_format = 96;
    assert!(future.validate().is_err());
    future.validate_other_revision_for_replacement().unwrap();
    let raw = serde_jcs::to_vec(&future).unwrap();
    let id = hex::encode(Sha256::digest(&raw));
    let accepted = controller
        .store
        .staging_dir()
        .parent()
        .unwrap()
        .to_path_buf();
    let directory = accepted.join("generations").join(&id);
    fs::create_dir(&directory).unwrap();
    fs::copy(&accepted95.snapshot_path, directory.join("snapshot.db")).unwrap();
    fs::write(directory.join("manifest.json"), raw).unwrap();
    use std::os::unix::fs::PermissionsExt;
    for file in ["snapshot.db", "manifest.json"] {
        fs::set_permissions(directory.join(file), fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let pointer = accepted.join("current.json");
    let mut unknown: Value = serde_json::from_slice(&fs::read(&pointer).unwrap()).unwrap();
    unknown["generation_id"] = json!(id);
    unknown["snapshot_sha256"] = json!(future.snapshot.sha256);
    fs::write(&pointer, serde_jcs::to_vec(&unknown).unwrap()).unwrap();
    assert!(controller.store.current_for_head_probe().is_err());
    crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (snapshot, path) = crate::standby::generation_store::tests::stage(
        &controller.store,
        &source,
        "recover-known95",
    )
    .await;
    let bytes = fs::read(&snapshot).unwrap();
    let manifest: StandbySnapshotManifest =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let prior = controller.store.full_predecessor_scratch_bytes().unwrap();
    assert!(prior >= fs::metadata(&accepted95.snapshot_path).unwrap().len());
    let peak = manifest.snapshot.size_bytes * 5 + prior + 16 * 1024 * 1024;
    controller.kernel_available_space = Some(peak - 1);
    assert!(
        controller
            .transition_transfer_budget(&manifest, manifest.snapshot.size_bytes)
            .is_err(),
        "unreadable pointer cannot erase fallback scratch allocation"
    );
    controller.kernel_available_space = Some(u64::MAX);
    let binary = Arc::new(ScriptedBinaryClient::for_snapshot(bytes, manifest));
    controller.binary_client = binary;
    let downloaded = controller.store.staging_dir().join("known95-downloaded.db");
    let manifest = controller
        .download_binary_only(
            "secret".into(),
            &downloaded,
            binary::FreshCaptureBudget::Allowed,
        )
        .await
        .unwrap();
    let output_manifest = controller
        .store
        .staging_dir()
        .join("known95-downloaded.json");
    let (generation, _) = controller
        .install_downloaded_snapshot(manifest, &downloaded, &output_manifest)
        .await
        .unwrap();
    let next = controller
        .store
        .activate_accepted(
            &controller.store.accepted_identity_hint().unwrap().unwrap(),
            &controller.observed,
            Some(&active),
        )
        .await
        .unwrap();
    controller.store.confirm_handoff(&next).unwrap();
    assert_eq!(next.generation.id, generation.id);
    assert_eq!(fs::read(&pin).unwrap(), pin_before);
    assert_eq!(fs::read(&rollback94.snapshot_path).unwrap(), rollback_bytes);
    controller.store.maintenance_idle().await;
    // Malformed pointer recovery is the existing supervised startup path. The
    // size sample stays conservative before that path restores a valid pointer.
    fs::write(&pointer, b"{broken").unwrap();
    assert!(controller
        .transition_transfer_budget(
            &next.generation.manifest,
            next.generation.manifest.snapshot.size_bytes
        )
        .unwrap()
        .is_some());
    let crate::standby::StandbyStartupOutcome::Serving(recovered) = controller
        .store
        .activate_for_startup(&controller.observed)
        .await
        .unwrap()
    else {
        panic!("verified fallback must survive unreadable pointer")
    };
    assert_eq!(
        recovered
            .generation
            .manifest
            .kernel_v2
            .as_ref()
            .unwrap()
            .schema_sha256,
        crate::standby::shapes::V2_95
    );
    assert_eq!(fs::read(&pin).unwrap(), pin_before);
    drop(recovered);
    drop(next);
    drop(active);
    controller.store.maintenance_idle().await;
    source.close().await;
}
