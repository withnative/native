use super::tests::{observed, stage};
use super::*;
use tracing::instrument::WithSubscriber;

async fn capture<T>(work: impl std::future::Future<Output = T>) -> (T, String) {
    let logs = test_diagnostics::Capture::default();
    let value = work.with_subscriber(logs.subscriber()).await;
    (value, logs.output())
}

fn full_runs(logs: &str) -> usize {
    logs.lines()
        .filter(|line| line.contains("standby suite started"))
        .count()
}

async fn fixture() -> (
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
        panic!("full startup must serve");
    };
    assert!(active.full_proof.is_some());
    (dir, db, store, active)
}

#[tokio::test]
async fn proof_issuance_requires_complete_success_and_observed_consumer() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::awareness::set_preference(
        &mut tx,
        "acct:proof",
        "message:proof",
        crate::awareness::PreferenceAction::FlagAttention,
        None,
        0,
        "proof-preference",
        "proof fixture",
        &mut act,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (path, manifest_path) = stage(&store, &db, "proof").await;
    let mut manifest = read_canonical_manifest(&manifest_path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
    ))
    .await;
    let proof = result.unwrap().unwrap();
    assert_eq!(proof.profile, crate::conformance::ConformanceProfile::Full);
    assert_eq!(proof.consumer, observed());
    let checks = logs
        .lines()
        .filter(|line| line.contains("standby check finished"))
        .collect::<Vec<_>>();
    let names = checks
        .iter()
        .map(|line| {
            line.split("check=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "required-tables",
            "event-log-shape",
            "meta-event-log-shape",
            "command-event-log-shapes",
            "derivation-request-shape",
            "home-contract",
            "rebuild-and-diff",
            "rebuild-and-diff-meta",
            "rebuild-and-diff-policy",
            "rebuild-and-diff-relationship",
            "rebuild-and-diff-control",
            "rebuild-and-diff-derivation",
            "provenance-state",
            "authorization-revision-state",
            "grant-revision-state",
            "authorization-policy-state",
            "control-event-log-state",
            "policy-event-log-state",
            "relationship-event-log-state",
            "portable-identity-state",
            "storage-portability-policy-state",
        ]
    );
    assert!(checks.iter().all(|line| line.contains("ok=true")));
    assert!(logs.contains("standby phase finished phase=\"awareness-projections\""));
    assert!(
        verify_snapshot_contents(&path, &manifest, None, &store.staging_dir())
            .await
            .unwrap()
            .is_none()
    );

    // A failure in the final awareness phase, after all 21 checks succeeded,
    // still returns no proof. Scratch allocation is part of complete success.
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &dir.path().join("absent"),
    ))
    .await;
    assert!(result.is_err());
    assert_eq!(full_runs(&logs), 1);
    assert!(logs
        .lines()
        .any(|line| line.contains("phase=\"awareness-projections\"") && line.contains("ok=false")));

    // Real awareness history is retained, but a stable projection mutation
    // passes the 21 observational checks and must fail the external rebuild.
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query("UPDATE message_preferences SET muted=1 WHERE subject_account_id='acct:proof'")
            .execute(&mut raw)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    raw.close().await.unwrap();
    manifest.snapshot.size_bytes = fs::metadata(&path).unwrap().len();
    manifest.snapshot.sha256 = sha256_file(&path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
    ))
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("awareness projection drift"));
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("standby check finished") && line.contains("ok=true"))
            .count(),
        21
    );

    // Stable projection drift with a freshly matching digest is not proof.
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE message_preferences SET muted=0 WHERE subject_account_id='acct:proof'")
        .execute(&mut raw)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET name='projection drift' WHERE id='native:root'")
        .execute(&mut raw)
        .await
        .unwrap();
    raw.close().await.unwrap();
    manifest.snapshot.size_bytes = fs::metadata(&path).unwrap().len();
    manifest.snapshot.sha256 = sha256_file(&path).unwrap();
    let (result, logs) = capture(verify_snapshot_contents(
        &path,
        &manifest,
        Some(&observed()),
        &store.staging_dir(),
    ))
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("conformance failed"));
    assert_eq!(full_runs(&logs), 1);
    assert!(!logs.contains("phase=\"awareness-projections\""));
    db.close().await;
}

#[tokio::test]
async fn reader_predecessor_hit_absent_fallback_and_cold_start_are_distinct() {
    let (_dir, db, store, mut active) = fixture().await;
    let id = active.generation.id.clone();
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &observed(), Some(&active))).await;
    assert_eq!(result.unwrap().id, id);
    assert_eq!(
        full_runs(&logs),
        0,
        "same-process predecessor witness must hit"
    );
    assert!(logs.contains("phase=\"byte-manifest-consumer-identity\""));

    let proof = active.full_proof.take();
    let (result, logs) =
        capture(store.verify_reader_predecessor(&id, &observed(), Some(&active))).await;
    result.unwrap();
    assert_eq!(full_runs(&logs), 1, "no witness must complete FULL");
    assert!(
        active.full_proof.is_none(),
        "a predecessor read must not populate an active cache"
    );
    active.full_proof = proof;

    crate::store::create_record(
        &db,
        serde_json::json!({"type":"Document", "kind":"note", "name":"successor"}),
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &db, "second").await;
    // Acquisition is a separate FULL path even with a live reader witness.
    let (result, logs) = capture(store.install_staged(&snapshot, &manifest, &observed())).await;
    let installed = result.unwrap();
    assert_eq!(
        full_runs(&logs),
        2,
        "helper candidate and predecessor stay FULL"
    );
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (result, logs) = capture(store.activate_accepted(&hint, &observed(), Some(&active))).await;
    let next = result.unwrap();
    assert_eq!(next.generation.id, installed.id);
    assert!(next.full_proof.is_some());
    assert_eq!(
        full_runs(&logs),
        1,
        "new candidate FULL, own predecessor reused"
    );
    assert!(
        logs.contains("phase=\"successor-fence\""),
        "pair comparison is always independent"
    );

    // Cold startup has no witness parameter and rechecks every retained item,
    // even while this fixture still holds old reader proofs in memory.
    let (result, logs) = capture(store.activate_for_startup(&observed())).await;
    let StandbyStartupOutcome::Serving(cold) = result.unwrap() else {
        panic!("cold startup");
    };
    assert_eq!(cold.generation.id, installed.id);
    assert_eq!(full_runs(&logs), 2);
    db.close().await;
}

#[tokio::test]
async fn reader_proof_binding_and_full_profile_mismatch_take_full_fallback() {
    let (_dir, db, store, mut active) = fixture().await;
    let id = active.generation.id.clone();
    let consumer = active.full_proof.as_ref().unwrap().consumer.clone();
    let canonical = active
        .full_proof
        .as_ref()
        .unwrap()
        .canonical_manifest
        .clone();
    for mismatch in 0..8 {
        let proof = active.full_proof.as_mut().unwrap();
        match mismatch {
            0 => proof.consumer.source_sha = "d".repeat(40),
            1 => proof.consumer.artifact_sha256 = "d".repeat(64),
            2 => proof.consumer.engine_schema_version += 1,
            3 => proof.consumer.ddl_sha256 = "d".repeat(64),
            4 => {
                proof.consumer.platform =
                    crate::standby_snapshot::StandbyConsumerPlatform::MacosArm64
            }
            5 => proof.profile = crate::conformance::ConformanceProfile::Core,
            6 => proof.canonical_manifest.push(b' '),
            7 => proof.generation_id = "d".repeat(64),
            _ => unreachable!(),
        }
        let (result, logs) =
            capture(store.verify_reader_predecessor(&id, &observed(), Some(&active))).await;
        result.unwrap();
        assert_eq!(
            full_runs(&logs),
            1,
            "binding mismatch {mismatch} must complete FULL"
        );
        // Restore the original issuer's bindings without another verifier run;
        // the predecessor fallback itself never replaces the active witness.
        let proof = active.full_proof.as_mut().unwrap();
        proof.consumer = consumer.clone();
        proof.canonical_manifest = canonical.clone();
        proof.generation_id = id.clone();
        proof.profile = crate::conformance::ConformanceProfile::Full;
    }
    db.close().await;
}

#[tokio::test]
async fn reader_hit_rehashes_bytes_and_rejects_manifest_config_and_consumer_tamper() {
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
            full_runs(&logs),
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
    for mismatch in 0..5 {
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
    // Restoration permits the same witness; no error is ever converted to hit.
    let (result, logs) =
        capture(store.verify_reader_predecessor(id, &observed(), Some(&active))).await;
    result.unwrap();
    assert_eq!(full_runs(&logs), 0);
    db.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_after_byte_validation_returns_no_full_proof() {
    use std::future::Future;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let (_dir, db, store, active) = fixture().await;
    let flag = Arc::new(AtomicBool::new(false));
    let mut work = Box::pin(verify_snapshot_contents(
        &active.generation.snapshot_path,
        &active.generation.manifest,
        Some(&active.full_proof.as_ref().unwrap().consumer),
        &store.root,
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
    assert!(
        active.full_proof.is_some(),
        "only the old successful witness remains"
    );
    // A previously issued valid proof must still observe cancellation on reuse.
    let mut reuse = Box::pin(store.verify_reader_predecessor(
        &active.generation.id,
        &active.full_proof.as_ref().unwrap().consumer,
        Some(&active),
    ));
    let (result, logs) = capture(futures::future::poll_fn(|cx| {
        with_verification_cancellation(flag.clone(), || reuse.as_mut().poll(cx))
    }))
    .await;
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert_eq!(full_runs(&logs), 0);
    flag.store(false, Ordering::Release);
    let (result, logs) =
        capture(store.verify_reader_predecessor(&active.generation.id, &observed(), Some(&active)))
            .await;
    result.unwrap();
    assert_eq!(full_runs(&logs), 0, "uncancelled valid proof still hits");
    db.close().await;
}
