use super::*;
use transfer_repr::SnapshotTransfer;

#[tokio::test]
async fn pending_gzip_restart_keeps_protocol_and_renews_credentials() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    let fake = gzip::client(&bytes, &manifest);
    *fake.poll_mode.lock().unwrap() = ResumePollMode::Pending;
    let dir = tempfile::tempdir().unwrap();
    let controller =
        resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
    let refresh = controller.refresh_dir.clone();
    let binding = controller.resume_binding();
    let target = dir.path().join("interrupted.db");
    let attempt = tokio::spawn(async move {
        controller
            .download_binary_only(
                "obsolete".into(),
                &target,
                binary::FreshCaptureBudget::Allowed,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(20), async {
        while fake.polls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());
    let pending = transfer_repr::load_pending_transfer(&refresh, &binding)
        .unwrap()
        .unwrap();
    assert_eq!(pending.transfer, SnapshotTransfer::GzipV1 { level: 1 });
    assert_eq!(pending.pending.origin, binding.origin);
    assert!(
        !refresh.join("binary-pending.json").exists(),
        "new pending is one authoritative record"
    );
    assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
    *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
    let controller =
        resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
    fs::write(&controller.config.credential_file, b"renewed").unwrap();
    let target = dir.path().join("resumed.db");
    controller
        .download_binary_only(
            "obsolete".into(),
            &target,
            binary::FreshCaptureBudget::ReuseOnly,
        )
        .await
        .unwrap();
    assert_eq!(fs::read(target).unwrap(), bytes);
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fake.poll_bearers.lock().unwrap().last().unwrap(), "renewed");
    assert!(fake
        .read_bearers
        .lock()
        .unwrap()
        .iter()
        .all(|token| token == "renewed"));
    db.close().await;
}

fn entropy(len: usize) -> Vec<u8> {
    let mut seed = 0x1745_ef32_19ab_cdef_u64;
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

#[tokio::test]
async fn gzip_out_of_order_abort_resumes_missing_encoded_ranges_inside_production_cooldown() {
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let (base, base_manifest) = snapshot_fixture(&db).await;
    let (port, server, _) =
        chunked::serve_host(db.clone(), chunked::HostRoute::CaptureTooLarge).await;
    let host = format!("http://127.0.0.1:{port}");
    let dir = tempfile::tempdir().unwrap();
    let fake = gzip::client(&base, &base_manifest);
    let mut controller = resume_test_controller(&dir, origin.clone(), fake.clone());
    controller.config.hosted_origin = host.clone();
    controller.refresh_once(RefreshCause::Manual).await.unwrap();
    // Installation maintenance shares attempt.lock with the next refresh.
    controller.store.maintenance_idle().await;
    let accepted = controller.state().unwrap();
    let data = entropy(5 * 1024 * 1024);
    sqlx::query("INSERT INTO blobs (id, bytes, size_bytes, storage_tier, created_at) VALUES ('gzip-padding', ?1, ?2, 'inline', '2026-10-17T00:00:00Z')")
        .bind(&data).bind(data.len() as i64).execute(db.write_pool()).await.unwrap();
    crate::store::append(
        &db,
        crate::store::AppendSpec {
            record_id: uuid::Uuid::new_v4().to_string(),
            event_type: "record.created".into(),
            payload: json!({"type":"Document","kind":"note","name":"gzip successor"}),
            actor: None,
        },
    )
    .await
    .unwrap();
    let (grown, manifest) = snapshot_fixture(&db).await;
    let encoded = gzip::encode(&grown);
    let count = encoded.len().div_ceil(1024 * 1024);
    assert!((5..=7).contains(&count));
    *fake.bytes.lock().unwrap() = encoded.clone();
    *fake.manifest.lock().unwrap() = manifest.clone();
    enable_deltas(&mut controller);
    let (control, mut started) = concurrent::RangeReadControl::new();
    *fake.range_control.lock().unwrap() = Some(control.clone());
    let refresh = controller.refresh_dir.clone();
    let binding = controller.resume_binding();
    let attempt = tokio::spawn(async move { controller.refresh_once(RefreshCause::Manual).await });
    concurrent::initial_four(&mut started, &control).await;
    control.release(2);
    assert_eq!(
        concurrent::started(&mut started).await.offset,
        4 * 1024 * 1024
    );
    // The coordinator only refills after the out-of-order range is fsynced
    // and ledgered. Network progress therefore describes durable wire bytes.
    let saved = binary_resume::load_resume_ledger(&refresh, &binding)
        .unwrap()
        .unwrap();
    assert_eq!(saved.size_bytes, grown.len() as u64);
    assert_eq!(saved.manifest.as_ref().unwrap(), &manifest);
    assert_eq!(saved.range_size(), encoded.len() as u64);
    assert_eq!(saved.completed.len(), 1);
    assert_eq!(saved.completed[0].offset, 2 * 1024 * 1024);
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());
    control.assert_dropped();
    assert_eq!(
        fake.cancels.load(Ordering::SeqCst),
        1,
        "only the accepted base was canceled"
    );
    let mut controller = resume_test_controller(&dir, origin, fake.clone());
    controller.config.hosted_origin = host;
    controller.config.full_refresh_min_interval_seconds = Some(3600);
    enable_deltas(&mut controller);
    let interrupted = controller.state().unwrap();
    assert_eq!(interrupted.last_success_at, accepted.last_success_at);
    assert_eq!(
        interrupted.snapshot_captured_at,
        accepted.snapshot_captured_at
    );
    let full_started = interrupted.last_full_refresh_at.clone();
    let progress = interrupted.transfer_progress.unwrap();
    assert!(!matches!(
        progress.activity,
        StandbyTransferActivity::Active
    ));
    assert_eq!(progress.bytes_total, Some(encoded.len() as u64));
    assert_eq!(progress.bytes_completed, Some(1024 * 1024));
    fs::write(&controller.config.credential_file, b"rotated").unwrap();
    let (next, mut requests) = concurrent::RangeReadControl::new();
    for index in 0..7 {
        next.release(index);
    }
    *fake.range_control.lock().unwrap() = Some(next.clone());
    let reads_before = fake.reads.load(Ordering::SeqCst);
    let polls_before = fake.polls.load(Ordering::SeqCst);
    let outcome = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let outcome = controller
                .refresh_once(RefreshCause::Scheduled)
                .await
                .unwrap();
            if !matches!(outcome, StandbyRefreshOutcome::Accepted { .. }) {
                break outcome;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let StandbyRefreshOutcome::Installed { generation, .. } = outcome else {
        panic!("live gzip must resume inside cooldown");
    };
    assert_eq!(fs::read(generation.snapshot_path).unwrap(), grown);
    assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fake.reads.load(Ordering::SeqCst) - reads_before, count - 1);
    assert!(fake.polls.load(Ordering::SeqCst) >= polls_before + 2);
    assert_eq!(
        controller.state().unwrap().last_full_refresh_at,
        full_started
    );
    assert_eq!(
        controller.state().unwrap().last_delta_fallback_class,
        Some(DeltaFallbackClass::DeltaTooLarge)
    );
    let mut offsets = Vec::new();
    while let Ok(request) = requests.try_recv() {
        assert_eq!(request.bearer, "rotated");
        offsets.push(request.offset);
    }
    offsets.sort_unstable();
    assert_eq!(
        offsets,
        (0..count)
            .filter(|index| *index != 2)
            .map(|index| index as u64 * 1024 * 1024)
            .collect::<Vec<_>>()
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    controller.store.maintenance_idle().await;
    db.close().await;
}

#[tokio::test]
async fn gzip_handle_loss_spends_only_allowed_replacement_budget() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    let dir = tempfile::tempdir().unwrap();
    let fake = gzip::client(&bytes, &manifest);
    let controller =
        resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
    gzip::seed_complete(&controller, &fake, &manifest);
    *fake.poll_mode.lock().unwrap() = ResumePollMode::Gone;
    let failure = controller
        .download_binary_only(
            "obsolete".into(),
            &dir.path().join("refused.db"),
            binary::FreshCaptureBudget::ReuseOnly,
        )
        .await
        .unwrap_err();
    assert_eq!(failure.class, RefreshFailureClass::Throttled);
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
    assert!(!controller.refresh_dir.join("binary-resume.json").exists());
    *fake.poll_mode.lock().unwrap() = ResumePollMode::Ready;
    let target = dir.path().join("replacement.db");
    controller
        .download_binary_only(
            "obsolete".into(),
            &target,
            binary::FreshCaptureBudget::Allowed,
        )
        .await
        .unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(target).unwrap(), bytes);
    db.close().await;
}
