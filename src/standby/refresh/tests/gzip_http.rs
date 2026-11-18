use super::*;
use transfer_repr::SnapshotTransfer;

#[tokio::test]
async fn receiver_first_full_space_covers_both_real_copies_without_a_pin_margin() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    let first_peak = manifest.snapshot.size_bytes * 3 + 16 * 1024 * 1024;
    for ample in [false, true] {
        let fixture = acquisition_fixture(bytes.clone(), manifest.clone());
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let mut controller = controller(&dir, manifest.origin_database_id.clone(), port);
        assert_eq!(
            controller.store.full_predecessor_scratch_bytes().unwrap(),
            0
        );
        // Identity wireD plus decoded stagingD and owned publicationD. No
        // previous generation exists to incur a generic pin's late margin.
        controller.kernel_available_space = Some(if ample { first_peak } else { first_peak - 1 });
        let snapshot = controller.store.staging_dir().join("first-full.db");
        let result = controller
            .download_binary_and_install(
                "secret".into(),
                &snapshot,
                &controller.store.staging_dir().join("first-full.json"),
                binary::FreshCaptureBudget::Allowed,
                &mut AttemptProgress::new(RefreshCause::Scheduled),
            )
            .await;
        if ample {
            let (generation, _) = result.unwrap();
            assert_eq!(fs::read(generation.snapshot_path).unwrap(), bytes);
            assert!(controller.store.accepted_identity_hint().unwrap().is_some());
            assert!(!fixture.ranges.lock().unwrap().is_empty());
        } else {
            let error = result.unwrap_err();
            assert!(
                error.source.to_string().contains("transition_disk_budget"),
                "{error:?}"
            );
            assert!(
                fixture.ranges.lock().unwrap().is_empty(),
                "refuse before the body transfer"
            );
            assert!(!snapshot.exists());
            assert!(controller.store.accepted_identity_hint().unwrap().is_none());
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        controller.store.maintenance_idle().await;
    }
    db.close().await;
}

#[tokio::test]
async fn receiver_legacy94_full_rejects_contradictory_poll_and_range_selection() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    for fault in [
        BinaryWireFault::WrongPollSelection,
        BinaryWireFault::WrongRangeSelection,
    ] {
        let mut fixture = acquisition_fixture(bytes.clone(), manifest.clone());
        fixture.fault = fault;
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(&dir, manifest.origin_database_id.clone(), port);
        if matches!(fault, BinaryWireFault::WrongPollSelection) {
            // A retained94 Ready identity must constrain even a later Pending
            // poll. It has no selected header in the old protocol.
            let ledger = binary_resume::new_ready_ledger(
                &controller.resume_binding(),
                BINARY_TEST_HANDLE.into(),
                manifest.snapshot.size_bytes,
                manifest.snapshot.sha256.clone(),
                manifest.clone(),
                now(),
            );
            binary_resume::prepare_partial_file(&controller.refresh_dir, bytes.len() as u64)
                .unwrap();
            binary_resume::save_resume_ledger(&controller.refresh_dir, &ledger).unwrap();
            let result = controller.probe_binary_resume().await;
            assert!(
                result.is_err(),
                "a95 poll selection cannot replace a bound94 export"
            );
            assert_eq!(result.err().unwrap().class, RefreshFailureClass::Protocol);
            assert_eq!(fixture.starts.load(Ordering::SeqCst), 0);
        } else {
            let error = controller
                .download_binary_only(
                    "secret".into(),
                    &dir.path().join("contradictory.db"),
                    binary::FreshCaptureBudget::Allowed,
                )
                .await
                .unwrap_err();
            assert_eq!(error.class, RefreshFailureClass::Protocol);
            assert!(!fixture.ranges.lock().unwrap().is_empty());
        }
        assert!(controller.store.accepted_identity_hint().unwrap().is_none());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    db.close().await;
}

#[tokio::test]
async fn receiver_missing_gzip_route_consumes_one_transition_capture_start() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    // The fixture serves only the original identity route: the preferred
    // gzip POST returns a bare404 before one real capture starts.
    let fixture = acquisition_fixture(bytes, manifest.clone());
    let (port, server) = serve_binary_fixture(fixture.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let controller = controller(&dir, manifest.origin_database_id.clone(), port);
    controller
        .observe_transition(
            super::super::super::shapes::v1(94, super::super::super::shapes::V1_94).unwrap(),
            super::super::super::shapes::v1(95, super::super::super::shapes::V1_95).unwrap(),
        )
        .unwrap();
    let mut progress = AttemptProgress::new(RefreshCause::Scheduled);
    progress.transition = true;
    controller
        .download_binary_and_install(
            "secret".into(),
            &controller.store.staging_dir().join("one-start.db"),
            &controller.store.staging_dir().join("one-start.json"),
            binary::FreshCaptureBudget::Allowed,
            &mut progress,
        )
        .await
        .unwrap();
    let episode: Value = serde_json::from_slice(
        &fs::read(controller.refresh_dir.join("shape-transition.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(episode["attempts"], 1);
    assert_eq!(fixture.starts.load(Ordering::SeqCst), 1);
    assert!(progress.full_started_at.is_some());
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    controller.store.maintenance_idle().await;
    db.close().await;
}

fn controller(dir: &tempfile::TempDir, origin: String, port: u16) -> StandbyRefreshController {
    let mut controller = controller_for_origin(
        dir,
        origin,
        Arc::new(AlwaysFailClient {
            class: RefreshFailureClass::Protocol,
            calls: AtomicUsize::new(0),
        }),
    );
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    controller.binary_snapshot_enabled = true;
    controller.delta_enabled = false;
    controller
}

#[tokio::test]
async fn gzip_http_download_admits_decoded_sqlite_and_refuses_wire_drift() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    for (fault, expected) in [
        (BinaryWireFault::None, None),
        (
            BinaryWireFault::ContentRange,
            Some(RefreshFailureClass::DownloadIntegrity),
        ),
        (
            BinaryWireFault::Etag,
            Some(RefreshFailureClass::DownloadIntegrity),
        ),
        (
            BinaryWireFault::HeaderLength,
            Some(RefreshFailureClass::DownloadIntegrity),
        ),
        (
            BinaryWireFault::MediaType,
            Some(RefreshFailureClass::DownloadIntegrity),
        ),
        (
            BinaryWireFault::ContentEncoding,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::WrongApi,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::WrongHandle,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::UnknownLevel,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::UnknownEncoding,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::WrongApiHeader,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::MissingEncoded,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::InvalidPollJson,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::FailedPoll,
            Some(RefreshFailureClass::Protocol),
        ),
        (
            BinaryWireFault::Unauthorized,
            Some(RefreshFailureClass::Authentication),
        ),
        (
            BinaryWireFault::ShortBody,
            Some(RefreshFailureClass::Network),
        ),
    ] {
        let mut fixture = acquisition_fixture(gzip::encode(&bytes), manifest.clone());
        fixture.transfer = SnapshotTransfer::GzipV1 { level: 1 };
        fixture.authority = Some(db.clone());
        fixture.fault = fault;
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(&dir, manifest.origin_database_id.clone(), port);
        let result = controller.refresh_once(RefreshCause::Manual).await;
        if let Some(class) = expected {
            assert!(result.is_err());
            let state = controller.state().unwrap();
            assert_eq!(state.last_failure_class, Some(class));
            assert!(state.last_success_at.is_none());
            assert!(state.snapshot_captured_at.is_none());
            assert!(!state.refresh_active);
            let retained = matches!(
                class,
                RefreshFailureClass::Network | RefreshFailureClass::Authentication
            );
            assert_eq!(
                controller.refresh_dir.join("binary-resume.json").exists(),
                retained
            );
            if matches!(fault, BinaryWireFault::ShortBody) {
                assert_eq!(fixture.ranges.lock().unwrap().len(), 3);
            }
        } else {
            let StandbyRefreshOutcome::Installed { generation, .. } = result.unwrap() else {
                panic!("v2 must publish admitted decoded SQLite");
            };
            assert_eq!(fs::read(generation.snapshot_path).unwrap(), bytes);
        }
        assert_eq!(fixture.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.legacy_starts.load(Ordering::SeqCst),
            0,
            "no identity capture as a refusal workaround"
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    db.close().await;
}

#[tokio::test]
async fn gzip_http_corrupt_streams_reach_decode_and_never_advance_freshness() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    let encoded = gzip::encode(&bytes);
    let mut footer = encoded.clone();
    let last = footer.len() - 1;
    footer[last] ^= 0xff;
    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"trailing");
    let mut empty_member = encoded.clone();
    empty_member.extend_from_slice(&gzip::encode(&[]));
    let mut member = encoded.clone();
    member.extend_from_slice(&gzip::encode(b"another member"));
    for damaged in [
        encoded[..encoded.len() / 2].to_vec(),
        footer,
        trailing,
        empty_member,
        member,
    ] {
        // The fixture's ready encoded digest and ETag describe these damaged
        // bytes exactly: an earlier hash/header refusal cannot mask decoding.
        let mut fixture = acquisition_fixture(damaged, manifest.clone());
        fixture.transfer = SnapshotTransfer::GzipV1 { level: 1 };
        fixture.authority = Some(db.clone());
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(&dir, manifest.origin_database_id.clone(), port);
        let failure = controller
            .refresh_once_with_receipt(RefreshCause::Manual)
            .await
            .unwrap_err();
        assert_eq!(
            failure.receipt.class,
            RefreshFailureClass::DownloadIntegrity
        );
        assert!(!fixture.ranges.lock().unwrap().is_empty());
        let state = controller.state().unwrap();
        assert!(state.last_success_at.is_none());
        assert!(state.snapshot_captured_at.is_none());
        assert!(!controller.refresh_dir.join("binary-resume.json").exists());
        assert!(!controller
            .refresh_dir
            .join("binary-decoded.stage.db")
            .exists());
        assert_eq!(fixture.legacy_starts.load(Ordering::SeqCst), 0);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    db.close().await;
}

#[tokio::test]
async fn structured_start_refusals_never_start_identity_compatibility_capture() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    for fault in [
        BinaryWireFault::StartContract,
        BinaryWireFault::StartStructured404,
    ] {
        let mut fixture = acquisition_fixture(gzip::encode(&bytes), manifest.clone());
        fixture.transfer = SnapshotTransfer::GzipV1 { level: 1 };
        fixture.authority = Some(db.clone());
        fixture.fault = fault;
        let (port, server) = serve_binary_fixture(fixture.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let controller = controller(&dir, manifest.origin_database_id.clone(), port);
        assert!(controller.refresh_once(RefreshCause::Manual).await.is_err());
        assert_eq!(
            controller.state().unwrap().last_failure_class,
            Some(RefreshFailureClass::Protocol)
        );
        assert_eq!(fixture.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.legacy_starts.load(Ordering::SeqCst), 0);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    db.close().await;
}
