use super::tests::{observed, stage};
use super::*;
use tracing::instrument::WithSubscriber;

pub(super) async fn capture<T>(work: impl std::future::Future<Output = T>) -> (T, String) {
    let logs = test_diagnostics::Capture::default();
    let value = work.with_subscriber(logs.subscriber()).await;
    (value, logs.output())
}

fn suite_runs(logs: &str) -> usize {
    logs.lines()
        .filter(|line| line.contains("standby suite started"))
        .count()
}

pub(super) async fn fixture() -> (
    tempfile::TempDir,
    crate::Db,
    GenerationStore,
    Box<ActivatedGeneration>,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "first").await;
    store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let StandbyStartupOutcome::Serving(active) =
        store.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("device startup must serve");
    };
    (dir, db, store, active)
}

#[tokio::test]
async fn device_checks_accept_without_conformance_or_awareness() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let (path, manifest_path) = stage(&store, &db, "device").await;
    let manifest = read_canonical_manifest(&manifest_path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
        false,
    ))
    .await;
    result.unwrap();
    assert_eq!(suite_runs(&logs), 0, "no conformance suite on device");
    assert!(
        logs.contains("standby phase finished phase=\"sqlite-quick-check-foreign-keys\""),
        "quick_check is the device damage predicate"
    );
    assert!(!logs.contains("rebuild-and-diff"), "no historical rebuild");
    assert!(
        !logs.contains("awareness-projections"),
        "no awareness rebuild"
    );
    assert!(
        verify_snapshot_contents(&path, &manifest, None, &store.staging_dir(), false)
            .await
            .is_ok()
    );
    db.close().await;
}

#[tokio::test]
async fn quick_check_damage_refuses_with_matching_digest() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let (path, manifest_path) = stage(&store, &db, "damaged").await;
    let mut manifest = read_canonical_manifest(&manifest_path).unwrap();
    // Clobber a whole non-header page: size is unchanged so byte identity
    // passes after re-signing, but the btree walk must fail.
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() > 8192, "fixture must span several pages");
    for byte in &mut bytes[4096..8192] {
        *byte = 0;
    }
    fs::write(&path, &bytes).unwrap();
    manifest.snapshot.size_bytes = bytes.len() as u64;
    manifest.snapshot.sha256 = sha256_file(&path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
        false,
    ))
    .await;
    let error = result.unwrap_err().to_string();
    assert!(
        !error.contains("byte identity mismatch"),
        "digest matches: {error}"
    );
    assert!(!error.contains("route/origin"), "binding intact: {error}");
    assert_eq!(suite_runs(&logs), 0, "refusal needs no conformance suite");
    db.close().await;
}

#[tokio::test]
async fn deliberate_audit_runs_deep_checks_and_catches_projection_drift() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let (outcome, logs) = capture(store.audit_current(&observed())).await;
    let outcome = outcome.unwrap();
    assert_eq!(outcome.generation_id, active.generation.id);
    assert!(outcome.passed, "deep audit passes a valid copy");
    assert_eq!(
        suite_runs(&logs),
        1,
        "the deliberate audit runs the deep suite"
    );
    // Stable projection drift with a freshly matching digest passes device
    // byte identity but must fail the deep verifier (conformance rebuild).
    let (path, manifest_path) = stage(&store, &db, "drift").await;
    let mut manifest = read_canonical_manifest(&manifest_path).unwrap();
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET name='projection drift' WHERE id='native:root'")
        .execute(&mut raw)
        .await
        .unwrap();
    raw.close().await.unwrap();
    manifest.snapshot.size_bytes = fs::metadata(&path).unwrap().len();
    manifest.snapshot.sha256 = sha256_file(&path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents_deep(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
        false,
    ))
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("conformance failed"));
    assert_eq!(suite_runs(&logs), 1);
    db.close().await;
}

#[tokio::test]
async fn reader_predecessor_hit_fallback_and_cold_start_are_distinct() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &observed(), Some(&active))).await;
    assert_eq!(result.unwrap().id, id);
    assert_eq!(
        suite_runs(&logs),
        0,
        "predecessor re-check runs no conformance suite"
    );
    assert!(logs.contains("phase=\"byte-manifest-consumer-identity\""));

    // No predecessor witness: the device verifier runs instead.
    let (result, logs) = capture(store.verify_reader_predecessor(&id, &observed(), None)).await;
    result.unwrap();
    assert_eq!(suite_runs(&logs), 0, "fallback stays device-only");

    crate::store::create_record(
        &db,
        serde_json::json!({"type":"Document", "kind":"note", "name":"successor"}),
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &db, "second").await;
    // Acquisition stays device-only even with a live reader.
    let (result, logs) = capture(store.install_staged(&snapshot, &manifest, &observed())).await;
    let installed = result.unwrap();
    assert_eq!(suite_runs(&logs), 0, "admission runs no conformance suite");
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (result, logs) = capture(store.activate_accepted(&hint, &observed(), Some(&active))).await;
    let next = result.unwrap();
    assert_eq!(next.generation.id, installed.id);
    assert_eq!(suite_runs(&logs), 0, "activation runs no conformance suite");
    assert!(
        logs.contains("phase=\"successor-fence\""),
        "pair comparison is always independent"
    );

    // Cold startup verifies current, without rechecking an older retained item.
    let (result, logs) = capture(store.activate_for_startup(&observed())).await;
    let StandbyStartupOutcome::Serving(cold) = result.unwrap() else {
        panic!("cold startup");
    };
    assert_eq!(cold.generation.id, installed.id);
    assert_eq!(suite_runs(&logs), 0);
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("standby phase finished phase=\"startup-generation\""))
            .count(),
        1,
        "{logs}"
    );
    db.close().await;
}

#[tokio::test]
async fn consumer_format_mismatch_refuses_without_suite() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    for mismatch in 2..5 {
        let mut changed = observed();
        match mismatch {
            0 => changed.source_sha = "d".repeat(40),
            1 => changed.artifact_sha256 = "d".repeat(64),
            2 => changed.engine_schema_version += 1,
            3 => changed.ddl_sha256 = "d".repeat(64),
            4 => changed.platform = crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64,
            _ => unreachable!(),
        }
        let (result, logs) =
            capture(store.verify_reader_predecessor(&id, &changed, Some(&active))).await;
        assert!(result.is_err(), "binding mismatch {mismatch} must refuse");
        assert_eq!(suite_runs(&logs), 0);
    }
    db.close().await;
}

#[tokio::test]
async fn advanced_predecessor_hit_still_validates_consumer_binding() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    // Mark the copy advanced in place without touching its bytes: the
    // checkpoint digest no longer applies, but binding must still hold.
    let head_act = active.generation.manifest.head_act.unwrap_or_default();
    let captured_at = active.generation.manifest.captured_at.clone();
    let mut head = store
        .record_synced(&active.generation, head_act, &captured_at)
        .unwrap();
    head.materialization = StandbyGenerationMaterialization::Delta;
    store.write_generation_head(&head).unwrap();
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &observed(), Some(&active))).await;
    result.unwrap();
    assert!(logs.contains("phase=\"manifest-consumer-identity\""));
    let mut changed = observed();
    changed.ddl_sha256 = "d".repeat(64);
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &changed, Some(&active))).await;
    assert!(
        result.is_err(),
        "advanced copy must still refuse consumer mismatch"
    );
    assert_eq!(suite_runs(&logs), 0);
    // A compatible binary swap does take the consistent-copy device path,
    // even though the normal predecessor hit above is deliberately cheaper.
    let mut replacement = observed();
    replacement.source_sha = "d".repeat(40);
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &replacement, Some(&active))).await;
    result.unwrap();
    assert!(logs.contains("phase=\"advanced-consistent-copy\""));
    assert_eq!(suite_runs(&logs), 0);
    assert!(store.consumer_rebind(&id, &replacement).unwrap().is_some());
    db.close().await;
}

#[tokio::test]
async fn reader_hit_rehashes_bytes_and_rejects_manifest_config_and_consumer_tamper() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = &active.generation.id;
    let path = &active.generation.snapshot_path;
    let bytes = fs::read(path).unwrap();
    for grow in [false, true] {
        let mut changed = bytes.clone();
        if grow {
            changed.push(0);
        } else {
            changed[100] ^= 1;
        }
        set_mode(path, 0o600).unwrap();
        fs::write(path, changed).unwrap();
        set_mode(path, 0o400).unwrap();
        let (result, logs) =
            capture(store.verify_reader_predecessor(id, &observed(), Some(&active))).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("byte identity mismatch"));
        assert_eq!(
            suite_runs(&logs),
            0,
            "bad bytes honestly refuse before admission"
        );
    }
    set_mode(path, 0o600).unwrap();
    fs::write(path, bytes).unwrap();
    set_mode(path, 0o400).unwrap();
    let manifest_path = path.parent().unwrap().join("manifest.json");
    let canonical = fs::read(&manifest_path).unwrap();
    for changed in [[canonical.as_slice(), b"\n"].concat(), {
        let mut m = active.generation.manifest.clone();
        m.captured_at = "2026-10-03T00:00:00Z".into();
        m.canonical_json().unwrap()
    }] {
        set_mode(&manifest_path, 0o600).unwrap();
        fs::write(&manifest_path, changed).unwrap();
        set_mode(&manifest_path, 0o400).unwrap();
        assert!(store
            .verify_reader_predecessor(id, &observed(), Some(&active))
            .await
            .is_err());
    }
    set_mode(&manifest_path, 0o600).unwrap();
    fs::write(&manifest_path, canonical).unwrap();
    set_mode(&manifest_path, 0o400).unwrap();
    for route in [true, false] {
        let mut changed = store.clone();
        if route {
            changed.expected_route_id = "wrong-route".into();
        } else {
            changed.expected_origin_id = Some("wrong-origin".into());
        }
        assert!(changed
            .verify_reader_predecessor(id, &observed(), Some(&active))
            .await
            .is_err());
    }
    for mismatch in 2..5 {
        let mut changed = observed();
        match mismatch {
            0 => changed.source_sha = "d".repeat(40),
            1 => changed.artifact_sha256 = "d".repeat(64),
            2 => changed.engine_schema_version += 1,
            3 => changed.ddl_sha256 = "d".repeat(64),
            4 => changed.platform = crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64,
            _ => unreachable!(),
        }
        assert!(store
            .verify_reader_predecessor(id, &changed, Some(&active))
            .await
            .is_err());
    }
    // Restoration permits the same predecessor; no error is ever converted to hit.
    let (result, logs) =
        capture(store.verify_reader_predecessor(id, &observed(), Some(&active))).await;
    result.unwrap();
    assert_eq!(suite_runs(&logs), 0);
    db.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_after_byte_validation_verifies_nothing() {
    use std::future::Future;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let consumer = observed();
    let flag = Arc::new(AtomicBool::new(false));
    let mut work = Box::pin(verify_snapshot_contents(
        &active.generation.snapshot_path,
        &active.generation.manifest,
        Some(&consumer),
        &store.root,
        false,
    ));
    let (result, logs) = capture(futures::future::poll_fn(|cx| {
        let polled = with_verification_cancellation(flag.clone(), || work.as_mut().poll(cx));
        if polled.is_pending() {
            flag.store(true, Ordering::Release);
        }
        polled
    }))
    .await;
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert!(logs.lines().any(
        |line| line.contains("phase=\"byte-manifest-consumer-identity\"")
            && line.contains("ok=true")
    ));
    assert!(!logs.contains("phase=\"awareness-projections\""));
    assert!(!logs.contains("standby suite started"));
    // A cancelled predecessor re-check still observes cancellation.
    let mut reuse =
        Box::pin(store.verify_reader_predecessor(&active.generation.id, &consumer, Some(&active)));
    let (result, logs) = capture(futures::future::poll_fn(|cx| {
        with_verification_cancellation(flag.clone(), || reuse.as_mut().poll(cx))
    }))
    .await;
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert_eq!(suite_runs(&logs), 0);
    flag.store(false, Ordering::Release);
    let (result, logs) =
        capture(store.verify_reader_predecessor(&active.generation.id, &observed(), Some(&active)))
            .await;
    result.unwrap();
    assert_eq!(suite_runs(&logs), 0, "uncancelled predecessor still hits");
    db.close().await;
}

#[tokio::test]
async fn startup_and_bounded_retention_leave_priors_unverified() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, first) = fixture().await;
    let mut latest = first.generation.clone();
    for ordinal in 0..2 {
        crate::store::create_record(
            &db,
            serde_json::json!({
                "type":"Document", "kind":"note", "name":format!("next-{ordinal}")
            }),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, &format!("next-{ordinal}")).await;
        latest = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
    }
    // Older corruption must neither delay nor prevent a healthy current.
    set_mode(&first.generation.snapshot_path, 0o600).unwrap();
    fs::write(&first.generation.snapshot_path, b"corrupt prior").unwrap();
    set_mode(&first.generation.snapshot_path, 0o400).unwrap();
    let (result, logs) = capture(store.activate_for_startup(&observed())).await;
    let StandbyStartupOutcome::Serving(active) = result.unwrap() else {
        panic!("current must serve")
    };
    assert_eq!(active.generation.id, latest.id);
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("standby phase finished phase=\"startup-generation\""))
            .count(),
        1,
        "{logs}"
    );
    for phase in [
        "startup-lock",
        "startup-cleanup",
        "startup-rebind",
        "startup-selection",
        "startup-prune",
    ] {
        assert!(
            logs.lines()
                .any(|line| line.contains(&format!("phase=\"{phase}\""))
                    && line.contains("elapsed_ms=")),
            "{phase}: {logs}"
        );
    }
    let (result, logs) = capture(store.prune_retention(&observed())).await;
    assert!(result.unwrap().is_empty());
    assert!(
        !logs.contains("startup-generation"),
        "no excess means no database checks"
    );
    assert!(first.generation.snapshot_path.exists());
    db.close().await;
}

#[tokio::test]
async fn retention_never_deletes_a_generation_that_fails_verification() {
    let (_dir, db, store, first) = fixture().await;
    for ordinal in 0..3 {
        crate::store::create_record(
            &db,
            serde_json::json!({
                "type":"Document", "kind":"note", "name":format!("retained-{ordinal}")
            }),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, &format!("retained-{ordinal}")).await;
        store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
    }
    drop(first._lease);
    let path = first.generation.snapshot_path;
    let original = fs::read(&path).unwrap();
    set_mode(&path, 0o600).unwrap();
    fs::write(&path, b"unverified corruption").unwrap();
    set_mode(&path, 0o400).unwrap();
    store.prune_retention(&observed()).await.unwrap();
    assert!(path.exists());
    assert_eq!(store.generation_ids().unwrap().len(), 4);
    // It becomes eligible only after an actual successful device check.
    set_mode(&path, 0o600).unwrap();
    fs::write(&path, original).unwrap();
    set_mode(&path, 0o400).unwrap();
    store.prune_retention(&observed()).await.unwrap();
    assert!(!path.exists());
    assert_eq!(store.generation_ids().unwrap().len(), 3);
    db.close().await;
}

#[tokio::test]
async fn retention_freshly_checks_floor_despite_a_matching_cached_verdict() {
    let (_dir, db, store, first) = fixture().await;
    let oldest = first.generation.snapshot_path.clone();
    drop(first);
    let mut priors = Vec::new();
    for ordinal in 0..3 {
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document", "kind":"note", "name":format!("floor-{ordinal}")}),
        ).await.unwrap();
        let (snapshot, manifest) = stage(&store, &db, &format!("floor-{ordinal}")).await;
        priors.push(
            store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap(),
        );
    }
    let damaged = &priors[1]; // Newest prior, ahead of two good older copies.
    let mut bytes = fs::read(&damaged.snapshot_path).unwrap();
    bytes[4096..8192].fill(0);
    set_mode(&damaged.snapshot_path, 0o600).unwrap();
    fs::write(&damaged.snapshot_path, bytes).unwrap();
    set_mode(&damaged.snapshot_path, 0o400).unwrap();
    // Model a metadata-stamp collision: retain a positive observation matching
    // these stamps even though the bytes have changed. The device check must
    // override it before this prior can count toward the deletion floor.
    store.remember_verification(
        &damaged.id,
        &observed(),
        store.status_stamp(&damaged.id, &observed()).ok(),
        true,
    );
    assert_eq!(
        store.cached_verification(&damaged.id, &observed()),
        Some(true)
    );
    store.prune_retention(&observed()).await.unwrap();
    assert_eq!(
        store.cached_verification(&damaged.id, &observed()),
        Some(false)
    );
    assert!(
        oldest.exists(),
        "a corrupt floor prior must not cost a good older copy"
    );
    assert_eq!(store.generation_ids().unwrap().len(), 4);
    db.close().await;
}

#[tokio::test]
async fn status_uses_cached_checks_and_discloses_invalidation() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = &active.generation.id;
    // Repeated status must do no database verification, even through a clone.
    let clone = store.clone();
    let (_, logs) = capture(async {
        for _ in 0..3 {
            let status = clone.inspect_status(&observed()).await;
            assert!(status.current.is_some());
            assert_eq!(status.unverified_candidate_count, 0);
        }
    })
    .await;
    assert!(!logs.contains("standby phase"), "{logs}");
    // Another process has no transferable serving proof or status cache.
    let cold = GenerationStore::open(
        store.root.parent().unwrap(),
        "route-1",
        store.expected_origin_id.clone(),
    )
    .unwrap();
    let status = cold.inspect_status(&observed()).await;
    assert_eq!(
        status.current_provenance,
        GenerationProvenanceStatus::Unverified
    );
    assert_eq!(status.unverified_candidate_count, 1);
    assert_eq!(status.unusable_candidate_count, 0);
    // A failed check is a negative cached observation; an ordinary file change
    // first invalidates, rather than silently retaining a healthy verdict.
    let path = &active.generation.snapshot_path;
    set_mode(path, 0o600).unwrap();
    fs::write(path, b"corrupt after activation").unwrap();
    set_mode(path, 0o400).unwrap();
    let status = store.inspect_status(&observed()).await;
    assert!(status.current.is_none());
    assert_eq!(status.unverified_candidate_count, 1);
    assert_eq!(status.unusable_candidate_count, 0);
    assert!(store
        .verify_generation_for_startup(id, &observed())
        .await
        .is_err());
    let (status, logs) = capture(store.inspect_status(&observed())).await;
    assert_eq!(
        status.current_provenance,
        GenerationProvenanceStatus::Invalid
    );
    assert_eq!(status.unusable_candidate_count, 1);
    assert_eq!(status.unverified_candidate_count, 0);
    assert!(!logs.contains("standby phase"));
    db.close().await;
}

#[tokio::test]
async fn status_invalidates_on_pointer_head_and_consumer_changes() {
    let (_dir, db, store, active) = fixture().await;
    let generation = &active.generation;
    let pointer_path = store.root.join("current.json");
    let pointer = fs::read(&pointer_path).unwrap();
    // Even rewriting the same descriptor invalidates the prior observation.
    fs::write(&pointer_path, &pointer).unwrap();
    assert_eq!(
        store
            .inspect_status(&observed())
            .await
            .unverified_candidate_count,
        1
    );
    store
        .verify_generation_for_startup(&generation.id, &observed())
        .await
        .unwrap();
    assert!(store.inspect_status(&observed()).await.current.is_some());
    let mut consumer = observed();
    consumer.artifact_sha256 = "f".repeat(64);
    assert!(store.inspect_status(&consumer).await.current.is_none());
    store
        .ensure_consumer_binding(&generation.id, &consumer)
        .await
        .unwrap();
    assert!(store.inspect_status(&consumer).await.current.is_some());
    // A new sync timestamp alone does not change the verified database.
    store
        .record_synced(
            generation,
            generation.manifest.head_act.unwrap(),
            &generation.manifest.captured_at,
        )
        .unwrap();
    // Creating a head changes its shape from checkpoint-only to recorded.
    store
        .verify_generation_for_startup(&generation.id, &observed())
        .await
        .unwrap();
    store
        .record_synced(
            generation,
            generation.manifest.head_act.unwrap(),
            "2026-10-15T00:00:00Z",
        )
        .unwrap();
    assert!(store.inspect_status(&observed()).await.current.is_some());
    store.require_full_refresh(generation).unwrap();
    // Model an admission completion racing a later refresh/audit marker. Its
    // checkpoint verdict cannot be attached to the changed generation.
    store.cache_completed_verification(&generation.id, &observed(), true);
    let status = store.inspect_status(&observed()).await;
    assert!(status.current.is_none());
    assert_eq!(status.unverified_candidate_count, 1);
    db.close().await;
}

#[tokio::test]
async fn status_observes_time_after_reading_the_reported_sync() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let runtime = super::super::StandbyRuntimeConfig {
        replica_root: store.root.parent().unwrap().to_path_buf(),
        hosted_route_database_id: "route-1".into(),
        origin_database_id: store.expected_origin_id.clone().unwrap(),
    };
    let provider = super::super::StandbyStatusProvider::for_serving(
        runtime,
        store.clone(),
        observed(),
        &active,
        true,
        true,
    );
    let generation = active.generation.clone();
    let updater = store.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let updating = barrier.clone();
    let writer = std::thread::spawn(move || {
        updating.wait();
        for _ in 0..20 {
            updater
                .record_synced(
                    &generation,
                    generation.manifest.head_act.unwrap(),
                    &chrono::Utc::now().to_rfc3339(),
                )
                .unwrap();
        }
    });
    barrier.wait();
    let (_, logs) = capture(async {
        for _ in 0..3 {
            let status = provider.status().await;
            if let Some(synced_at) = status.serving_generation.unwrap().synced_at {
                let observed = chrono::DateTime::parse_from_rfc3339(&status.observed_at).unwrap();
                let synced = chrono::DateTime::parse_from_rfc3339(&synced_at).unwrap();
                assert!(observed >= synced);
            }
            assert_ne!(
                status.freshness.state,
                super::super::StandbyFreshnessState::Unavailable
            );
        }
    })
    .await;
    writer.join().unwrap();
    assert!(!logs.contains("standby phase"));
    db.close().await;
}

#[tokio::test]
async fn transient_verification_failures_remain_unverified() {
    let (_dir, db, store, active) = fixture().await;
    let id = &active.generation.id;
    let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let error = with_verification_cancellation(cancellation, || {
        futures::executor::block_on(store.verify_generation_for_startup(id, &observed()))
    })
    .unwrap_err();
    assert!(audit_infrastructure_error(&error));
    let status = store.inspect_status(&observed()).await;
    assert_eq!(
        status.current_provenance,
        GenerationProvenanceStatus::Unverified
    );
    assert_eq!(status.unusable_candidate_count, 0);

    // Advanced copies require a consistent private verification copy. An
    // immutable checkpoint does not use scratch on the device-check path.
    let writer = store
        .open_head_writer(&active.generation)
        .await
        .unwrap()
        .unwrap();
    writer.close().await;
    store
        .verify_generation_for_startup(id, &observed())
        .await
        .unwrap();
    assert!(store.inspect_status(&observed()).await.current.is_some());
    // The advanced bytes are healthy but verification scratch is unavailable.
    let staging = store.staging_dir();
    let saved = staging.with_file_name("saved-staging");
    fs::rename(&staging, &saved).unwrap();
    fs::write(&staging, b"not a scratch directory").unwrap();
    let error = store
        .verify_generation_for_startup(id, &observed())
        .await
        .unwrap_err();
    assert!(audit_infrastructure_error(&error), "{error}");
    let status = store.inspect_status(&observed()).await;
    assert_eq!(status.unusable_candidate_count, 0);
    assert_eq!(status.unverified_candidate_count, 1);
    fs::remove_file(staging).unwrap();
    fs::rename(saved, store.staging_dir()).unwrap();
    db.close().await;
}

#[tokio::test]
async fn startup_with_excess_generations_defers_checks_and_background_fills_priors() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, staging, first) = fixture().await;
    let oldest = first.generation.clone();
    drop(first);
    let mut generations = vec![oldest.clone()];
    for ordinal in 1..4 {
        crate::store::create_record(
            &db,
            serde_json::json!({
                "type":"Document", "kind":"note", "name":format!("background-{ordinal}")
            }),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&staging, &db, &format!("background-{ordinal}")).await;
        generations.push(
            staging
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap(),
        );
    }
    // A fresh node has no cached observations of any prior.
    let store = GenerationStore::open(
        staging.root.parent().unwrap(),
        "route-1",
        staging.expected_origin_id.clone(),
    )
    .unwrap();
    let (startup, logs) = capture(store.activate_for_startup(&observed())).await;
    let StandbyStartupOutcome::Serving(active) = startup.unwrap() else {
        panic!("serve current")
    };
    assert_eq!(active.generation.id, generations[3].id);
    assert_eq!(store.generation_ids().unwrap().len(), 4);
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("standby phase finished phase=\"startup-generation\""))
            .count(),
        1,
        "{logs}"
    );
    assert_eq!(
        store
            .inspect_status(&observed())
            .await
            .unverified_candidate_count,
        3
    );

    // Ordinary refresh diagnostics are present; unchecked priors alone must
    // not degrade the serving node.
    let refresh = store.root.parent().unwrap().join("refresh");
    create_private_directory(&refresh).unwrap();
    let state = refresh.join("state.json");
    fs::write(
        &state,
        serde_json::to_vec(&super::super::StandbyRefreshState::default()).unwrap(),
    )
    .unwrap();
    set_mode(&state, 0o600).unwrap();
    let provider = super::super::StandbyStatusProvider::for_serving(
        super::super::StandbyRuntimeConfig {
            replica_root: store.root.parent().unwrap().to_path_buf(),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: store.expected_origin_id.clone().unwrap(),
        },
        store.clone(),
        observed(),
        &active,
        true,
        true,
    );
    let status = provider.status().await;
    assert!(!status.degraded, "{:?}", status.degraded_reasons);
    assert_eq!(status.unverified_candidate_count, 3);

    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let resume = std::sync::Arc::new(tokio::sync::Notify::new());
    *store.verification_pause.lock().unwrap() = Some((entered.clone(), resume.clone()));
    store.schedule_maintenance(&observed());
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .unwrap();
    // Background verification is pinned, but promotion/refresh coordination is free.
    let promotion = OpenOptions::new()
        .read(true)
        .write(true)
        .open(store.root.join("promotion.lock"))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&promotion).unwrap();
    drop(promotion);
    let attempt = super::super::refresh::open_private_lock(&refresh.join("attempt.lock")).unwrap();
    attempt.try_lock_exclusive().unwrap();
    drop(attempt); // Prior checks never hold refresh coordination.
                   // Change bytes between the verifier's before/after observations. Even a
                   // successful check of the new consistent copy must not issue the old stamp.
    let changed = &generations[2].snapshot_path;
    let bytes = fs::read(changed).unwrap();
    set_mode(changed, 0o600).unwrap();
    fs::write(changed, bytes).unwrap();
    set_mode(changed, 0o400).unwrap();
    resume.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(60), store.maintenance_idle())
        .await
        .unwrap();
    let status = store.inspect_status(&observed()).await;
    assert_eq!(status.unverified_candidate_count, 1);
    assert_eq!(status.unusable_candidate_count, 0);
    assert_eq!(store.generation_ids().unwrap().len(), 4);
    assert!(oldest.snapshot_path.exists());

    // A later stable pass fills that prior and safely converges retention.
    store.schedule_maintenance(&observed());
    tokio::time::timeout(std::time::Duration::from_secs(60), store.maintenance_idle())
        .await
        .unwrap();
    let status = store.inspect_status(&observed()).await;
    assert!(status.current.is_some());
    assert_eq!(status.retained_generation_ids.len(), 3);
    assert_eq!(status.unverified_candidate_count, 0);
    assert_eq!(store.generation_ids().unwrap().len(), 3);
    assert!(!oldest.snapshot_path.exists());
    // Rewriting current invalidates current only; verified priors remain known.
    let pointer = store.root.join("current.json");
    fs::write(&pointer, fs::read(&pointer).unwrap()).unwrap();
    let status = store.inspect_status(&observed()).await;
    assert_eq!(status.unverified_candidate_count, 1);
    assert_eq!(status.retained_generation_ids.len(), 2);
    db.close().await;
}

#[tokio::test]
async fn missing_current_recovers_newest_and_all_corrupt_candidates_are_status_only() {
    let (_dir, db, store, first) = fixture().await;
    crate::store::create_record(
        &db,
        serde_json::json!({"type":"Document", "kind":"note", "name":"newest"}),
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &db, "newest-fallback").await;
    let newest = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    fs::remove_file(store.root.join("current.json")).unwrap();
    let StandbyStartupOutcome::Serving(active) =
        store.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("missing current must recover newest usable")
    };
    assert_eq!(active.generation.id, newest.id);
    assert_eq!(
        active.startup_reason,
        Some(StandbyStartupReason::CurrentMissing)
    );
    drop(active);
    for path in [&first.generation.snapshot_path, &newest.snapshot_path] {
        set_mode(path, 0o600).unwrap();
        fs::write(path, b"corrupt retained generation").unwrap();
        set_mode(path, 0o400).unwrap();
    }
    let StandbyStartupOutcome::StatusOnly(status) =
        store.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("no usable candidates must remain status-only")
    };
    assert_eq!(status.candidate_count, 2);
    assert_eq!(status.unusable_candidate_count, 2);
    assert_eq!(status.reason, "no_usable_generation");
    db.close().await;
}
