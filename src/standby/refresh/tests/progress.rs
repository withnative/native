use super::super::transfer_progress::{TransferPause, BYTE_UPDATE_INTERVAL};
use super::*;

fn pause(
    controller: &StandbyRefreshController,
    stage: StandbyTransferStage,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered, receiver) = std::sync::mpsc::channel();
    let (sender, resume) = std::sync::mpsc::channel();
    *controller.transfer_pause.lock().unwrap() = Some(TransferPause {
        stage,
        entered,
        resume,
    });
    (receiver, sender)
}

async fn entered(receiver: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(20)).unwrap())
        .await
        .unwrap();
}

async fn observe(
    provider: &super::super::super::StandbyStatusProvider,
    stage: StandbyTransferStage,
    completed: u64,
    total: u64,
    accepted: &str,
    success: &Option<String>,
) {
    let status = provider.status().await;
    assert_eq!(status.refresh.refresh_active, Some(true));
    assert_eq!(
        status.accepted_generation.as_ref().unwrap().generation_id,
        accepted
    );
    assert_eq!(&status.refresh.last_success_at, success);
    let progress = status.refresh.transfer_progress.unwrap();
    assert_eq!(progress.stage, stage);
    assert_eq!(progress.activity, StandbyTransferActivity::Active);
    assert_eq!(progress.bytes_completed, Some(completed));
    assert_eq!(progress.bytes_total, Some(total));
    assert_eq!(progress.bytes_remaining, Some(total - completed));
    let json = serde_json::to_string(&progress).unwrap();
    for secret in [
        "secret",
        "12345678-1234-1234-1234-1234567890ab",
        "snapshot.db",
        "resume successor",
        "bearer",
    ] {
        assert!(
            !json.contains(secret),
            "progress must contain only closed tokens, time and counts"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_progress_uses_durable_ranges_and_keeps_freshness_until_publication() {
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let ((base, base_manifest), (bytes, manifest)) = resume_snapshots(&db).await;
    let total = bytes.len() as u64;
    let chunks = bytes.len().div_ceil(1024 * 1024);
    assert!((2..=7).contains(&chunks));
    let directory = tempfile::tempdir().unwrap();
    let fake = Arc::new(ScriptedBinaryClient::for_snapshot(base, base_manifest));
    let controller = Arc::new(resume_test_controller(
        &directory,
        origin.clone(),
        fake.clone(),
    ));
    controller.refresh_once(RefreshCause::Manual).await.unwrap();
    controller.store.maintenance_idle().await;
    let super::super::super::StandbyStartupOutcome::Serving(active) = controller
        .store
        .activate_for_startup(&controller.observed)
        .await
        .unwrap()
    else {
        panic!("base must serve")
    };
    let provider = super::super::super::StandbyStatusProvider::for_serving(
        controller.runtime.clone(),
        controller.store.clone(),
        controller.observed.clone(),
        &active,
        true,
        true,
    );
    let before = provider.status().await;
    let accepted = before.accepted_generation.unwrap();
    let success = before.refresh.last_success_at;
    *fake.bytes.lock().unwrap() = bytes;
    *fake.manifest.lock().unwrap() = manifest;
    let (control, mut requests) = concurrent::RangeReadControl::new();
    *fake.range_control.lock().unwrap() = Some(control.clone());
    let (capture_entered, capture_resume) = pause(&controller, StandbyTransferStage::Capture);
    let worker = controller.clone();
    let task = tokio::spawn(async move { worker.refresh_once(RefreshCause::Manual).await });
    entered(capture_entered).await;
    let capture = provider.status().await;
    assert_eq!(capture.refresh.last_success_at, success);
    let capture = capture.refresh.transfer_progress.unwrap();
    assert_eq!(capture.stage, StandbyTransferStage::Capture);
    assert_eq!(capture.activity, StandbyTransferActivity::Active);
    assert_eq!(capture.bytes_total, None);
    capture_resume.send(()).unwrap();
    for _ in 0..chunks.min(4) {
        concurrent::started(&mut requests).await;
    }
    observe(
        &provider,
        StandbyTransferStage::Download,
        0,
        total,
        &accepted.generation_id,
        &success,
    )
    .await;
    let primary_before_bytes = fs::read(controller.state_path()).unwrap();
    let advisory_path = controller.refresh_dir.join("transfer-progress.json");
    let advisory = fs::read(&advisory_path).unwrap();
    let mut value: Value = serde_json::from_slice(&advisory).unwrap();
    value["progress"]["updated_at"] = json!("2020-01-01T00:00:00Z");
    fs::write(&advisory_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        provider
            .status()
            .await
            .refresh
            .transfer_progress
            .unwrap()
            .activity,
        StandbyTransferActivity::Stale
    );
    value["progress"]["bytes_completed"] = json!(total + 1);
    fs::write(&advisory_path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        provider.status().await.refresh.diagnostics,
        super::super::super::StandbyRefreshDiagnosticsState::Unavailable
    );
    // Refuse impossible advisory counters without losing durable cooldown state.
    assert!(controller.state().unwrap().last_full_refresh_at.is_some());
    assert_eq!(
        fs::read(controller.state_path()).unwrap(),
        primary_before_bytes
    );
    fs::write(&advisory_path, advisory).unwrap();
    tokio::time::sleep(BYTE_UPDATE_INTERVAL + Duration::from_millis(50)).await;
    control.release(0);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if controller
                .state()
                .unwrap()
                .transfer_progress
                .unwrap()
                .bytes_completed
                == Some(1024 * 1024)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fs::read(controller.state_path()).unwrap(),
        primary_before_bytes,
        "byte observations never replace durable scheduling state"
    );
    observe(
        &provider,
        StandbyTransferStage::Download,
        1024 * 1024,
        total,
        &accepted.generation_id,
        &success,
    )
    .await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let stopped = provider.status().await;
    assert_eq!(stopped.refresh.refresh_active, Some(false));
    let progress = stopped.refresh.transfer_progress.unwrap();
    assert_eq!(progress.activity, StandbyTransferActivity::Interrupted);
    assert_eq!(progress.bytes_completed, Some(1024 * 1024));
    assert!(progress.retained_for_resume);
    assert_eq!(
        stopped.accepted_generation.unwrap().captured_at,
        accepted.captured_at
    );
    assert_eq!(stopped.refresh.last_success_at, success);
    assert_eq!(
        fake.cancels.load(Ordering::SeqCst),
        1,
        "only the consumed base export was cancelled"
    );
    drop(controller);

    let controller = Arc::new(resume_test_controller(&directory, origin, fake.clone()));
    let super::super::super::StandbyStartupOutcome::Serving(restarted) = controller
        .store
        .activate_for_startup(&controller.observed)
        .await
        .unwrap()
    else {
        panic!("the accepted base must survive restart")
    };
    let provider = super::super::super::StandbyStatusProvider::for_serving(
        controller.runtime.clone(),
        controller.store.clone(),
        controller.observed.clone(),
        &restarted,
        true,
        true,
    );
    let (resume_control, _resume_requests) = concurrent::RangeReadControl::new();
    for chunk in 0..chunks {
        resume_control.release(chunk);
    }
    *fake.range_control.lock().unwrap() = Some(resume_control);
    let (download_entered, download_resume) = pause(&controller, StandbyTransferStage::Download);
    let reads_before = fake.reads.load(Ordering::SeqCst);
    let worker = controller.clone();
    let task = tokio::spawn(async move { worker.refresh_once(RefreshCause::Manual).await });
    entered(download_entered).await;
    observe(
        &provider,
        StandbyTransferStage::Download,
        1024 * 1024,
        total,
        &accepted.generation_id,
        &success,
    )
    .await;
    let (verification_entered, verification_resume) =
        pause(&controller, StandbyTransferStage::Verification);
    download_resume.send(()).unwrap();
    entered(verification_entered).await;
    observe(
        &provider,
        StandbyTransferStage::Verification,
        total,
        total,
        &accepted.generation_id,
        &success,
    )
    .await;
    let (publication_entered, publication_resume) =
        pause(&controller, StandbyTransferStage::Publication);
    verification_resume.send(()).unwrap();
    entered(publication_entered).await;
    observe(
        &provider,
        StandbyTransferStage::Publication,
        total,
        total,
        &accepted.generation_id,
        &success,
    )
    .await;
    publication_resume.send(()).unwrap();
    let StandbyRefreshOutcome::Installed { generation, .. } = task.await.unwrap().unwrap() else {
        panic!("resume must publish")
    };
    assert_ne!(generation.id, accepted.generation_id);
    assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fake.reads.load(Ordering::SeqCst) - reads_before, chunks - 1);
    let done = provider.status().await;
    assert_eq!(
        done.accepted_generation.unwrap().generation_id,
        generation.id
    );
    assert_eq!(done.refresh.refresh_active, Some(false));
    let progress = done.refresh.transfer_progress.unwrap();
    assert_eq!(progress.stage, StandbyTransferStage::Following);
    assert_eq!(progress.activity, StandbyTransferActivity::Inactive);
    assert_eq!(progress.bytes_total, None);
    assert!(!progress.retained_for_resume);
    db.close().await;
}

#[test]
fn state_readers_reject_impossible_progress_and_accept_older_state() {
    let directory = tempfile::tempdir().unwrap();
    let controller = controller_for_origin(
        &directory,
        "ndb_00000000000000000000000000000000".into(),
        Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        }),
    );
    let mut state = StandbyRefreshState::default();
    let root = &controller.runtime.replica_root;
    let path = root.join("refresh/state.json");
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy.as_object_mut().unwrap().remove("transfer_progress");
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert!(matches!(
        observe_refresh_state(root),
        RefreshStateObservation::Available(_)
    ));
    assert_eq!(controller.state().unwrap().transfer_progress, None);
    legacy["refresh_active"] = json!(true);
    fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let RefreshStateObservation::Available(older) = observe_refresh_state(root) else {
        panic!("older active state remains readable")
    };
    assert!(!older.refresh_active);
    assert!(older.transfer_progress.is_none());
    let good = StandbyTransferProgress {
        stage: StandbyTransferStage::Download,
        activity: StandbyTransferActivity::Inactive,
        updated_at: now(),
        bytes_completed: Some(4),
        bytes_remaining: Some(6),
        bytes_total: Some(10),
        retained_for_resume: true,
    };
    for (completed, remaining, total) in
        [(11, 0, 10), (4, 7, 10), (0, 0, 0), (0, u64::MAX, u64::MAX)]
    {
        let mut progress = good.clone();
        progress.bytes_completed = Some(completed);
        progress.bytes_remaining = Some(remaining);
        progress.bytes_total = Some(total);
        state.transfer_progress = Some(progress);
        fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(
            observe_refresh_state(root),
            RefreshStateObservation::Unavailable
        ));
        assert!(controller.state().is_err());
    }
    state.transfer_progress = Some(good);
    state.refresh_active = true;
    state.transfer_progress.as_mut().unwrap().activity = StandbyTransferActivity::Active;
    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let RefreshStateObservation::Available(observed) = observe_refresh_state(root) else {
        panic!("valid interrupted state")
    };
    assert!(!observed.refresh_active);
    assert_eq!(
        observed.transfer_progress.unwrap().activity,
        StandbyTransferActivity::Interrupted
    );
    fs::create_dir(root.join("refresh/attempt.lock")).unwrap();
    assert!(
        matches!(
            observe_refresh_state(root),
            RefreshStateObservation::Unavailable
        ),
        "an unreadable owner must not be reported inactive or active"
    );
    fs::remove_dir(root.join("refresh/attempt.lock")).unwrap();
    let mut progress = StandbyTransferProgress {
        stage: StandbyTransferStage::Capture,
        activity: StandbyTransferActivity::Active,
        updated_at: "2020-01-01T00:00:00Z".into(),
        bytes_completed: None,
        bytes_remaining: None,
        bytes_total: None,
        retained_for_resume: true,
    };
    assert_eq!(
        progress.clone().observed(Some(chrono::Utc::now())).activity,
        StandbyTransferActivity::Stale
    );
    progress.updated_at = "2099-01-01T00:00:00Z".into();
    assert_eq!(
        progress.observed(Some(chrono::Utc::now())).activity,
        StandbyTransferActivity::Stale
    );
}
