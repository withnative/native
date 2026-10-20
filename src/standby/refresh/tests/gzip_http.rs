use super::*;
use transfer_repr::SnapshotTransfer;

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
