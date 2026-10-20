use super::*;
use transfer_repr::SnapshotTransfer;

pub(super) fn encode(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(1));
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

pub(super) fn client(
    bytes: &[u8],
    manifest: &StandbySnapshotManifest,
) -> Arc<ScriptedBinaryClient> {
    let fake = Arc::new(ScriptedBinaryClient::for_snapshot(
        encode(bytes),
        manifest.clone(),
    ));
    *fake.transfer.lock().unwrap() = SnapshotTransfer::GzipV1 { level: 1 };
    fake
}

pub(super) fn seed_complete(
    controller: &StandbyRefreshController,
    fake: &ScriptedBinaryClient,
    manifest: &StandbySnapshotManifest,
) {
    let bytes = fake.bytes.lock().unwrap();
    let binding = controller.resume_binding();
    let mut ledger = binary_resume::new_ready_ledger(
        &binding,
        ScriptedBinaryClient::handle_for(1),
        manifest.snapshot.size_bytes,
        manifest.snapshot.sha256.clone(),
        manifest.clone(),
        now(),
    );
    ledger.set_encoded(binary_resume::EncodedResume {
        route_api: transfer_repr::GZIP_EXPORT_API.into(),
        transfer: SnapshotTransfer::GzipV1 { level: 1 },
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&*bytes)),
    });
    binary_resume::prepare_partial_file(&controller.refresh_dir, bytes.len() as u64).unwrap();
    for (index, bytes) in bytes.chunks(1024 * 1024).enumerate() {
        let offset = index as u64 * 1024 * 1024;
        let sha =
            binary_resume::write_range_and_hash(&controller.refresh_dir, offset, bytes).unwrap();
        binary_resume::record_completed_range(&mut ledger, offset, bytes.len() as u64, sha)
            .unwrap();
    }
    binary_resume::save_resume_ledger(&controller.refresh_dir, &ledger).unwrap();
}

#[tokio::test]
async fn missing_gzip_ready_identity_cannot_be_read_as_legacy_v1() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    for field in ["encoded", "manifest"] {
        let dir = tempfile::tempdir().unwrap();
        let fake = client(&bytes, &manifest);
        let controller =
            resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
        seed_complete(&controller, &fake, &manifest);
        let path = controller.refresh_dir.join("binary-resume.json");
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["contract"], "native.standby-binary-resume.v2");
        saved.as_object_mut().unwrap().remove(field);
        binary_resume::write_fixed_json(
            &controller.refresh_dir,
            &controller.refresh_dir.join("binary-resume.json.tmp"),
            &path,
            &serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
        let target = dir.path().join("refused.db");
        let failure = controller
            .download_binary_only(
                "obsolete".into(),
                &target,
                binary::FreshCaptureBudget::ReuseOnly,
            )
            .await
            .unwrap_err();
        assert_eq!(
            failure.class,
            if field == "encoded" {
                RefreshFailureClass::Throttled
            } else {
                RefreshFailureClass::DownloadIntegrity
            }
        );
        assert_eq!(
            fake.polls.load(Ordering::SeqCst),
            usize::from(field == "manifest")
        );
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
        assert_eq!(fake.reads.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
        assert!(!target.exists());
    }
    db.close().await;
}

#[tokio::test]
async fn gzip_coordinator_decodes_then_uses_unchanged_generation_admission() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    let dir = tempfile::tempdir().unwrap();
    let fake = client(&bytes, &manifest);
    let controller =
        resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
    let StandbyRefreshOutcome::Installed { generation, .. } =
        controller.refresh_once(RefreshCause::Manual).await.unwrap()
    else {
        panic!("must admit decoded SQLite");
    };
    assert_eq!(fs::read(generation.snapshot_path).unwrap(), bytes);
    assert_eq!(
        controller.state().unwrap().transfer_progress.unwrap().stage,
        StandbyTransferStage::Following
    );
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    assert!(!controller.refresh_dir.join("binary-resume.json").exists());
    db.close().await;
}

#[tokio::test]
async fn fully_cached_gzip_requires_authorized_repoll_and_refuses_all_identity_drift() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (bytes, manifest) = snapshot_fixture(&db).await;
    for mode in [
        ResumePollMode::Auth,
        ResumePollMode::ChangedEncodedSha,
        ResumePollMode::ChangedEncodedSize,
        ResumePollMode::ChangedSha,
        ResumePollMode::ChangedDecodedSize,
        ResumePollMode::ChangedManifest,
        ResumePollMode::Pending,
        ResumePollMode::Ready,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fake = client(&bytes, &manifest);
        let controller =
            resume_test_controller(&dir, manifest.origin_database_id.clone(), fake.clone());
        seed_complete(&controller, &fake, &manifest);
        *fake.poll_mode.lock().unwrap() = mode;
        fs::write(&controller.config.credential_file, b"renewed").unwrap();
        let target = dir.path().join("decoded.db");
        let result = controller
            .download_binary_only(
                "obsolete".into(),
                &target,
                binary::FreshCaptureBudget::ReuseOnly,
            )
            .await;
        assert_eq!(fake.polls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.poll_bearers.lock().unwrap().as_slice(), &["renewed"]);
        assert_eq!(
            fake.reads.load(Ordering::SeqCst),
            0,
            "complete cache must not issue a range"
        );
        assert_eq!(
            fake.starts.load(Ordering::SeqCst),
            0,
            "no fresh capture on refusal"
        );
        match mode {
            ResumePollMode::Ready => {
                result.unwrap();
                assert_eq!(fs::read(target).unwrap(), bytes);
            }
            ResumePollMode::Auth => {
                assert_eq!(
                    result.unwrap_err().class,
                    RefreshFailureClass::Authentication
                );
                assert!(controller.refresh_dir.join("binary-resume.json").exists());
                assert_eq!(fake.cancels.load(Ordering::SeqCst), 0);
            }
            _ => {
                assert_eq!(
                    result.unwrap_err().class,
                    if mode == ResumePollMode::Pending {
                        RefreshFailureClass::Protocol
                    } else {
                        RefreshFailureClass::DownloadIntegrity
                    }
                );
                assert!(!controller.refresh_dir.join("binary-resume.json").exists());
            }
        }
    }
    db.close().await;
}
