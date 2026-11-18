//! Routine paths stay cheap: single-flight verification, the cheap handoff of
//! a generation this process built, and retention sweeps that do not redo
//! unchanged or repeatedly failing work.
use super::device_verification_tests::{capture, fixture};
use super::tests::{observed, stage};
use super::*;

fn count(logs: &str, needle: &str) -> usize {
    logs.lines().filter(|line| line.contains(needle)).count()
}

fn heavy_checks(logs: &str) -> usize {
    [
        "startup-generation-verify",
        "sqlite-quick-check-foreign-keys",
    ]
    .iter()
    .map(|needle| count(logs, needle))
    .sum()
}

async fn install_next(store: &GenerationStore, db: &crate::Db, name: &str) -> InstalledGeneration {
    crate::store::create_record(
        db,
        serde_json::json!({"type":"Document", "kind":"note", "name":name}),
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(store, db, name).await;
    store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap()
}

fn rewrite(path: &Path, bytes: &[u8]) {
    set_mode(path, 0o600).unwrap();
    fs::write(path, bytes).unwrap();
    set_mode(path, 0o400).unwrap();
}

#[tokio::test]
async fn concurrent_verifications_of_one_generation_run_once() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    store.invalidate_verification(&id, &observed());
    let consumer = observed();
    let (results, logs) = capture(async {
        tokio::join!(
            store.verify_generation_for_startup(&id, &consumer, "test"),
            store.verify_generation_for_startup(&id, &consumer, "test"),
        )
    })
    .await;
    results.0.unwrap();
    results.1.unwrap();
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    assert_eq!(count(&logs, "shared with a concurrent pass"), 1, "{logs}");
    assert_eq!(store.cached_verification(&id, &observed()), Some(true));

    // A refusal is never shared: a changed copy takes its own pass and fails.
    let bytes = fs::read(&active.generation.snapshot_path).unwrap();
    let mut damaged = bytes.clone();
    for byte in &mut damaged[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&active.generation.snapshot_path, &damaged);
    let consumer = observed();
    let (results, logs) = capture(async {
        tokio::join!(
            store.verify_generation_for_startup(&id, &consumer, "test"),
            store.verify_generation_for_startup(&id, &consumer, "test"),
        )
    })
    .await;
    assert!(results.0.is_err() && results.1.is_err());
    assert_eq!(count(&logs, "shared with a concurrent pass"), 0, "{logs}");
    db.close().await;
}

#[tokio::test]
async fn fresh_build_hands_off_on_cheap_checks_and_defers_the_heavy_ones() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let installed = install_next(&store, &db, "fresh").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (result, logs) =
        capture(store.activate_accepted_fast(&hint, &observed(), Some(&active))).await;
    let (next, deferred) = result.unwrap();
    assert_eq!(next.generation.id, installed.id);
    assert_eq!(
        heavy_checks(&logs),
        0,
        "no heavy phase in the handoff: {logs}"
    );
    assert_eq!(count(&logs, "byte-manifest-consumer-identity"), 0, "{logs}");
    let deferred = deferred.expect("the heavy phases are deferred, not dropped");
    assert_eq!(deferred.generation_id(), installed.id);

    let (result, logs) = capture(deferred.run()).await;
    result.unwrap();
    assert!(
        count(&logs, "phase=\"sqlite-quick-check-foreign-keys\"") >= 1,
        "{logs}"
    );
    assert_eq!(count(&logs, "phase=\"successor-fence\""), 0, "{logs}");
    db.close().await;
}

#[tokio::test]
async fn only_a_generation_built_here_and_unchanged_takes_the_cheap_route() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (dir, db, store, active) = fixture().await;
    let installed = install_next(&store, &db, "elsewhere").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();

    // A store that did not build it (another process, a restart) has no
    // receipt: the full handoff runs, heavy phases included, nothing deferred.
    let origin = crate::identity::database_id(&db).await.unwrap();
    let other = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let (result, logs) =
        capture(other.activate_accepted_fast(&hint, &observed(), Some(&active))).await;
    let (_, deferred) = result.unwrap();
    assert!(deferred.is_none());
    assert!(heavy_checks(&logs) >= 2, "{logs}");

    // A copy changed after it was built loses the cheap route and is refused
    // by the full checks, as before.
    let damaged_installed = install_next(&store, &db, "changed").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let mut bytes = fs::read(&damaged_installed.snapshot_path).unwrap();
    for byte in &mut bytes[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&damaged_installed.snapshot_path, &bytes);
    let (result, _) =
        capture(store.activate_accepted_fast(&hint, &observed(), Some(&active))).await;
    assert!(result.is_err());
    assert_ne!(installed.id, damaged_installed.id);
    db.close().await;
}

#[tokio::test]
async fn background_failure_is_a_verdict_and_success_is_not() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let installed = install_next(&store, &db, "background").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (_next, deferred) = store
        .activate_accepted_fast(&hint, &observed(), Some(&active))
        .await
        .unwrap();
    let mut run = deferred.unwrap().start_background();
    let verdict = wait_for_verdict(&mut run).await;
    assert_eq!(verdict, DeferredHandoffVerdict::Passed);

    // Same again, but the copy is damaged behind the cheap handoff.
    let installed2 = install_next(&store, &db, "background-damaged").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (_next, deferred) = store
        .activate_accepted_fast(
            &hint,
            &observed(),
            Some(&installed_as_active(&store, &installed).await),
        )
        .await
        .unwrap();
    let mut bytes = fs::read(&installed2.snapshot_path).unwrap();
    for byte in &mut bytes[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&installed2.snapshot_path, &bytes);
    let mut run = deferred.unwrap().start_background();
    assert_eq!(
        wait_for_verdict(&mut run).await,
        DeferredHandoffVerdict::Failed
    );
    assert_eq!(
        store.cached_verification(&installed2.id, &observed()),
        Some(false)
    );
    db.close().await;
}

async fn installed_as_active(
    store: &GenerationStore,
    generation: &InstalledGeneration,
) -> ActivatedGeneration {
    ActivatedGeneration {
        generation: generation.clone(),
        startup_reason: None,
        retained_generation_ids: Vec::new(),
        retention_warnings: Vec::new(),
        _lease: store.acquire_serving_lease(&generation.id).unwrap(),
    }
}

async fn wait_for_verdict(run: &mut DeferredHandoffRun) -> DeferredHandoffVerdict {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            if let Some(verdict) = run.try_verdict() {
                return verdict;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("deferred verdict")
}

#[tokio::test]
async fn sweeps_skip_unchanged_verified_priors_and_recheck_after_a_change() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, _active) = fixture().await;
    install_next(&store, &db, "second").await;
    let third = install_next(&store, &db, "third").await;
    assert_eq!(store.generation_ids().unwrap().len(), 3);
    let (_, logs) = capture(async {
        for _ in 0..3 {
            store.maintain_generations(&observed(), true).await.unwrap();
        }
    })
    .await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        0,
        "{logs}"
    );

    // Touch an older prior (same bytes): its inputs changed, so it is
    // re-verified once, then skipped again.
    let prior = store
        .generation_ids()
        .unwrap()
        .into_iter()
        .find(|id| *id != third.id && store.cached_verification(id, &observed()) == Some(true))
        .unwrap();
    let path = store
        .root
        .join("generations")
        .join(&prior)
        .join("snapshot.db");
    rewrite(&path, &fs::read(&path).unwrap());
    let (_, logs) = capture(async {
        for _ in 0..3 {
            store.maintain_generations(&observed(), true).await.unwrap();
        }
    })
    .await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    assert_eq!(store.generation_ids().unwrap().len(), 3);
    db.close().await;
}

#[tokio::test]
async fn a_repeat_failing_generation_is_not_recopied_every_sweep_or_deleted() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, _active) = fixture().await;
    let oldest = store.generation_ids().unwrap().remove(0);
    install_next(&store, &db, "second").await;
    install_next(&store, &db, "third").await;
    install_next(&store, &db, "fourth").await;
    assert_eq!(
        store.generation_ids().unwrap().len(),
        4,
        "more than three: excess"
    );
    let path = store
        .root
        .join("generations")
        .join(&oldest)
        .join("snapshot.db");
    let original = fs::read(&path).unwrap();
    let mut damaged = original.clone();
    for byte in &mut damaged[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&path, &damaged);

    let (_, logs) = capture(async {
        for _ in 0..5 {
            store.maintain_generations(&observed(), true).await.unwrap();
        }
    })
    .await;
    // Only the first sweep spends a check on it; the two good priors and the
    // current were observed unchanged, so no rescan and no deletion.
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    assert_eq!(
        store.generation_ids().unwrap().len(),
        4,
        "kept, not deleted"
    );
    assert!(path.exists());

    // Restoring the bytes is a change: it is checked again, and may then go
    // through ordinary retention like any verified surplus copy.
    rewrite(&path, &original);
    let (_, logs) = capture(store.maintain_generations(&observed(), true)).await;
    assert!(
        count(&logs, "phase=\"startup-generation-verify\"") >= 1,
        "{logs}"
    );
    db.close().await;
}

#[tokio::test]
async fn backoff_holds_only_for_unchanged_inputs_and_logs_once() {
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    let consumer = serde_jcs::to_vec(&observed()).unwrap();
    let stamp = store.status_stamp(&id, &observed()).unwrap();
    let backoff = &store.retention_backoff;
    assert!(!backoff.holds(&id, &consumer, &stamp));
    assert!(
        backoff.record_failure(&id, &consumer, stamp.clone()),
        "first failure is logged"
    );
    assert!(
        !backoff.record_failure(&id, &consumer, stamp.clone()),
        "later ones are not"
    );
    assert!(backoff.holds(&id, &consumer, &stamp));
    let path = &active.generation.snapshot_path;
    rewrite(path, &fs::read(path).unwrap());
    let changed = store.status_stamp(&id, &observed()).unwrap();
    assert!(
        !backoff.holds(&id, &consumer, &changed),
        "a changed copy is retried at once"
    );
    backoff.expire_all();
    assert!(
        !backoff.holds(&id, &consumer, &stamp),
        "and the backoff expires"
    );
    db.close().await;
}

#[tokio::test]
async fn retention_backoff_count_clamps_and_restores() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    let consumer = serde_jcs::to_vec(&observed()).unwrap();
    let stamp = store.status_stamp(&id, &observed()).unwrap();
    let backoff = &store.retention_backoff;
    // Far past the point where the delay caps, the count stops at the largest
    // value a restart accepts, so the 6 h backoff survives a process restart.
    for _ in 0..verification_flight::BACKOFF_MAX_FAILURES + 10 {
        backoff.record_failure(&id, &consumer, stamp.clone());
    }
    let (_, failures, retry_at) = backoff.entry(&id, &consumer).unwrap();
    assert_eq!(failures, verification_flight::BACKOFF_MAX_FAILURES);
    // A fresh table restores the clamped verdict and still holds it.
    backoff.clear(&id, &consumer);
    backoff.restore(&id, &consumer, stamp.clone(), failures, retry_at);
    assert!(backoff.holds(&id, &consumer, &stamp));
    db.close().await;
}

#[tokio::test]
async fn prune_keeps_live_and_misshapen_sidecars_and_drops_only_gone_ids() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let heads = store.root.join("heads");
    // A validly named sidecar for a generation that never existed is pruned;
    // misshapen names are never candidates, whatever they contain.
    let gone = "f".repeat(64);
    let gone_path = heads.join(format!("{gone}.retention-backoff.json"));
    fs::write(&gone_path, b"{}").unwrap();
    let junk = heads.join("not-an-id.retention-backoff.json");
    fs::write(&junk, b"{}").unwrap();
    let tmp = heads.join(".retention-backoff-orphan.tmp");
    fs::write(&tmp, b"{}").unwrap();
    // A sidecar for the live serving copy is kept even with valid content.
    let live_path = heads.join(format!("{}.retention-backoff.json", active.generation.id));
    fs::write(&live_path, b"{}").unwrap();
    store.maintain_generations(&observed(), true).await.unwrap();
    assert!(!gone_path.exists(), "a gone id is pruned");
    assert!(junk.exists(), "a non-id name is never matched");
    assert!(tmp.exists(), "a temp leftover is never matched");
    assert!(live_path.exists(), "a live id keeps its file");
    db.close().await;
}

/// Two branches of one origin: `served` (generation A, which holds the row
/// "served branch") and a fork that never saw it, with a generation B built on
/// the fork. B is individually valid but does not preserve A's row.
struct Branches {
    _dir: tempfile::TempDir,
    store: GenerationStore,
    active: Box<ActivatedGeneration>,
    b: InstalledGeneration,
    dbs: (crate::Db, crate::Db),
}

async fn branches() -> Branches {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store =
        GenerationStore::open(root.join("replica"), "route-1", Some(origin.clone())).unwrap();
    let export = crate::export::export_connected_db(&db, None).await.unwrap();
    let fork_path = root.join("fork.db");
    fs::copy(export.path(), &fork_path).unwrap();
    export.cleanup().await;
    let fork = crate::open_existing_database(fork_path.to_str().unwrap())
        .await
        .unwrap();
    crate::store::create_record(
        &db,
        serde_json::json!({"type":"Document","kind":"note","name":"served branch"}),
    )
    .await
    .unwrap();
    let (snapshot, manifest) = stage(&store, &db, "served").await;
    store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let StandbyStartupOutcome::Serving(active) =
        store.activate_for_startup(&observed()).await.unwrap()
    else {
        panic!("startup")
    };
    let donor = GenerationStore::open(root.join("donor"), "route-1", Some(origin)).unwrap();
    let mut built = Vec::new();
    for name in ["fork one"] {
        crate::store::create_record(
            &fork,
            serde_json::json!({"type":"Document","kind":"note","name":name}),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&donor, &fork, name.replace(' ', "-").as_str()).await;
        built.push(
            donor
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap(),
        );
    }
    let b = built.pop().unwrap();
    Branches {
        _dir: dir,
        store,
        active,
        b,
        dbs: (db, fork),
    }
}

impl Branches {
    /// Publish a donor generation into the served store as if the refresh
    /// controller had just built and verified it there, and point at it.
    async fn publish_as_fresh(&self, generation: &InstalledGeneration) -> AcceptedGenerationHint {
        let destination = self.store.root.join("generations").join(&generation.id);
        fs::create_dir(&destination).unwrap();
        fs::copy(&generation.snapshot_path, destination.join("snapshot.db")).unwrap();
        fs::write(
            destination.join("manifest.json"),
            generation.manifest.canonical_json().unwrap(),
        )
        .unwrap();
        set_mode(&destination.join("snapshot.db"), 0o400).unwrap();
        set_mode(&destination.join("manifest.json"), 0o400).unwrap();
        set_mode(&destination, 0o500).unwrap();
        self.store
            .write_pointer(&CurrentPointer {
                contract: POINTER_CONTRACT.into(),
                version: 1,
                generation_id: generation.id.clone(),
                snapshot_sha256: generation.manifest.snapshot.sha256.clone(),
            })
            .unwrap();
        self.store
            .verify_generation_for_startup(&generation.id, &observed(), "test")
            .await
            .unwrap();
        self.store
            .fresh_builds
            .note(&generation.id, serde_jcs::to_vec(&observed()).unwrap());
        self.store.accepted_identity_hint().unwrap().unwrap()
    }
}

#[tokio::test]
async fn a_failed_fence_refuses_the_candidate_keeps_serving_and_marks_it_for_repair() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let fixture = branches().await;
    let store = &fixture.store;
    let hint = fixture.publish_as_fresh(&fixture.b).await;
    // B is a verified fresh build, so the cheap route applies; its fence
    // against the served A still runs first, and refuses.
    let error = store
        .activate_accepted_fast(&hint, &observed(), Some(&fixture.active))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not preserve"), "{error}");
    assert!(
        store
            .generation_head(&fixture.b.id)
            .unwrap()
            .unwrap()
            .full_refresh_required
    );
    assert!(!store
        .generation_head(&fixture.active.generation.id)
        .unwrap()
        .is_some_and(|head| head.full_refresh_required));
    // A retry is refused the same way: the fence does not depend on state
    // this process remembers.
    let error = store
        .activate_accepted_fast(&hint, &observed(), Some(&fixture.active))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not preserve"), "{error}");
    drop(fixture.dbs);
}

#[tokio::test]
async fn an_undetermined_result_is_not_a_verdict_or_a_repair() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let installed = install_next(&store, &db, "undetermined").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (_next, deferred) = store
        .activate_accepted_fast(&hint, &observed(), Some(&active))
        .await
        .unwrap();
    // Shutdown-style cancellation: no verdict, nothing marked for repair.
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut run =
        with_verification_cancellation(cancelled, || deferred.unwrap().start_background());
    assert_eq!(
        wait_for_verdict(&mut run).await,
        DeferredHandoffVerdict::Undetermined
    );
    assert!(!store
        .generation_head(&installed.id)
        .unwrap()
        .is_some_and(|head| head.full_refresh_required));
    db.close().await;
}

#[tokio::test]
async fn a_cached_failure_is_retried_when_its_backoff_expires() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, _active) = fixture().await;
    let oldest = store.generation_ids().unwrap().remove(0);
    install_next(&store, &db, "second").await;
    install_next(&store, &db, "third").await;
    install_next(&store, &db, "fourth").await;
    let path = store
        .root
        .join("generations")
        .join(&oldest)
        .join("snapshot.db");
    let mut damaged = fs::read(&path).unwrap();
    for byte in &mut damaged[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&path, &damaged);
    let (_, logs) = capture(async {
        store.maintain_generations(&observed(), true).await.unwrap();
        store.maintain_generations(&observed(), true).await.unwrap();
    })
    .await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    assert_eq!(store.cached_verification(&oldest, &observed()), Some(false));
    // Expire both backoff layers: the in-memory entry and the sidecar beside
    // the heads that carries the same window across processes.
    store.retention_backoff.expire_all();
    let sidecar = store
        .root
        .join("heads")
        .join(format!("{oldest}.retention-backoff.json"));
    let _ = fs::remove_file(&sidecar);
    let (_, logs) = capture(store.maintain_generations(&observed(), true)).await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "retried: {logs}"
    );
    assert_eq!(store.generation_ids().unwrap().len(), 4, "still kept");
    db.close().await;
}

#[tokio::test]
async fn only_a_definite_verdict_starts_the_retention_backoff() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    let consumer = serde_jcs::to_vec(&observed()).unwrap();
    let stamp = store.status_stamp(&id, &observed()).unwrap();
    let io = Error::Io(std::io::Error::other("lock unavailable"));
    let (_, logs) = capture(async {
        store.settle_prior_failure(&id, &consumer, Some(stamp.clone()), &io);
    })
    .await;
    assert!(!store.retention_backoff.holds(&id, &consumer, &stamp));
    assert_eq!(
        count(&logs, "could not complete; retrying next sweep"),
        1,
        "{logs}"
    );
    assert_eq!(count(&logs, "fails verification"), 0, "{logs}");

    let verdict = Error::engine("standby snapshot byte identity mismatch");
    let (_, logs) = capture(async {
        store.settle_prior_failure(&id, &consumer, Some(stamp.clone()), &verdict);
    })
    .await;
    assert!(store.retention_backoff.holds(&id, &consumer, &stamp));
    assert_eq!(count(&logs, "fails verification"), 1, "{logs}");
    db.close().await;
}

#[tokio::test]
async fn advanced_serving_copy_second_sweep_runs_no_full_pass() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    // A delta advances the serving copy in place, invalidating its
    // in-memory observation...
    let writer = store
        .open_head_writer(&active.generation)
        .await
        .unwrap()
        .unwrap();
    writer.close().await;
    assert_eq!(
        store.cached_verification(&active.generation.id, &observed()),
        None
    );
    // ...the first sweep re-establishes the verdict...
    store.maintain_generations(&observed(), true).await.unwrap();
    assert_eq!(
        store.cached_verification(&active.generation.id, &observed()),
        Some(true)
    );
    // ...and the next sweep spends no full device pass on it.
    let (_, logs) = capture(store.maintain_generations(&observed(), true)).await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        0,
        "{logs}"
    );
    db.close().await;
}

#[tokio::test]
async fn failing_prior_is_checked_once_per_backoff_window_across_restart() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (dir, db, store, active) = fixture().await;
    // Installing moves the pointer, so damage the demoted prior: the
    // serving copy keeps its own recovery path.
    install_next(&store, &db, "second").await;
    let damaged = active.generation.id.clone();
    let path = active.generation.snapshot_path.clone();
    let mut bytes = fs::read(&path).unwrap();
    for byte in &mut bytes[4096..8192] {
        *byte ^= 0xff;
    }
    rewrite(&path, &bytes);

    // The first sweep spends the one full check and arms the backoff, in
    // memory and in the sidecar beside the heads.
    let (_, logs) = capture(store.maintain_generations(&observed(), true)).await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    let sidecar = store
        .root
        .join("heads")
        .join(format!("{damaged}.retention-backoff.json"));
    assert!(sidecar.exists(), "the backoff survives a process restart");

    // A simulated restart (a new store over the same directory) re-verifies
    // the serving copy once, but does not re-copy and re-check the failing
    // prior inside its backoff window.
    let origin = crate::identity::database_id(&db).await.unwrap();
    let store2 =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let (_, logs) = capture(store2.maintain_generations(&observed(), true)).await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    assert_eq!(store2.generation_ids().unwrap().len(), 2);
    assert!(path.exists(), "kept, not deleted");

    // A corrupt sidecar reads as no verdict, never fatal: the copy is
    // checked again at the next sweep.
    store2.retention_backoff.expire_all();
    fs::write(&sidecar, b"not json").unwrap();
    let (_, logs) = capture(store2.maintain_generations(&observed(), true)).await;
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    db.close().await;
}

/// The serving copy advanced in place by a real kernel-v2 delta with a
/// qualifying at-rest record takes the trusting recheck instead of a full
/// device pass; anything short of trust falls back to exactly one full pass.
/// Needs a genuine v2 copy with an audited receipt chain, so it only runs
/// with the v2-kernel-probe feature.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn v2_advanced_serving_copy_rechecks_cheap_and_light_refusal_falls_back() {
    use crate::standby::refresh::{audited_and_recorded, Setup};
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;

    // Case 1: a qualifying copy. A fresh process over the same directory
    // runs no full phases and records TrustedAtRest, not a full verdict.
    let s: Setup = audited_and_recorded().await;
    let id = s.current().id.clone();
    assert!(s.current().manifest.kernel_v2.is_some());
    let store2 = s.restarted_store();
    assert_eq!(store2.cached_verification_trusting(&id, s.observed()), None);
    let (_, logs) = capture(store2.maintain_generations(s.observed(), true)).await;
    assert!(
        !logs.contains("phase=\"startup-generation-verify\""),
        "no full pass: {logs}"
    );
    assert!(
        logs.lines()
            .any(|line| line.contains("phase=\"startup-generation-trusted\"")
                && line.contains("reason=\"maintenance_recheck\"")
                && line.contains("ok=true")),
        "the trusted pass ran and is labelled: {logs}"
    );
    assert_eq!(
        store2.cached_verification_trusting(&id, s.observed()),
        Some(true)
    );
    // A TrustedAtRest stamp is not a full verdict: retention and every other
    // non-trusting decision keep the strict view.
    assert_eq!(store2.cached_verification(&id, s.observed()), None);

    // A second recheck within the window does no work at all.
    let (_, logs) = capture(store2.maintain_generations(s.observed(), true)).await;
    assert!(!logs.contains("startup-generation-verify"), "{logs}");
    assert!(!logs.contains("startup-generation-trusted"), "{logs}");
    s.finish().await;

    // Case 2: no record, a failed record, or a damage flag. Each runs
    // exactly one full pass, labelled with the maintenance reason.
    type Damage = (&'static str, Box<dyn Fn(&Setup)>);
    let cases: Vec<Damage> = vec![
        (
            "no at-rest record",
            Box::new(|s: &Setup| s.store().remove_at_rest(&s.current().id)),
        ),
        (
            "a failed at-rest record",
            Box::new(|s: &Setup| {
                s.store().remove_at_rest(&s.current().id);
                s.store()
                    .write_at_rest_failed(&s.current().id, chrono::Utc::now())
                    .unwrap();
            }),
        ),
        (
            "a damage flag on the sidecar",
            Box::new(|s: &Setup| {
                let mut head = s.store().generation_head(&s.current().id).unwrap().unwrap();
                head.full_refresh_required = true;
                // Write the flag without the failed-record side effect of the
                // repair helper, so the sidecar alone is what blocks trust.
                s.store().write_head_for_test(&head);
            }),
        ),
    ];
    for (name, damage) in cases {
        let s: Setup = audited_and_recorded().await;
        damage(&s);
        let id = s.current().id.clone();
        let store = s.restarted_store();
        assert_eq!(store.cached_verification_trusting(&id, s.observed()), None);
        let (_, logs) = capture(store.maintain_generations(s.observed(), true)).await;
        assert_eq!(
            count(&logs, "phase=\"startup-generation-verify\""),
            1,
            "{name}: {logs}"
        );
        assert!(
            logs.contains("reason=\"maintenance_recheck\""),
            "{name}: the full pass is labelled: {logs}"
        );
        assert!(
            !logs
                .lines()
                .any(|line| line.contains("phase=\"startup-generation-trusted\"")
                    && line.contains("ok=true")),
            "{name}: nothing trusted: {logs}"
        );
        s.finish().await;
    }
}

#[tokio::test]
async fn cheap_handoff_background_pass_runs_exactly_once() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let installed = install_next(&store, &db, "fresh").await;
    let hint = store.accepted_identity_hint().unwrap().unwrap();
    let (next, deferred) = store
        .activate_accepted_fast(&hint, &observed(), Some(&active))
        .await
        .unwrap();
    assert_eq!(next.generation.id, installed.id);
    let (verdict, logs) = capture(async {
        let mut run = deferred
            .expect("a cheap handoff defers the heavy phases")
            .start_background();
        wait_for_verdict(&mut run).await
    })
    .await;
    assert_eq!(verdict, DeferredHandoffVerdict::Passed);
    assert_eq!(
        count(&logs, "phase=\"startup-generation-verify\""),
        1,
        "{logs}"
    );
    db.close().await;
}

#[tokio::test]
async fn a_full_pass_logs_its_reason_and_counts_toward_status() {
    let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
    let (_dir, db, store, active) = fixture().await;
    let id = active.generation.id.clone();
    store.invalidate_verification(&id, &observed());
    let (before_passes, before_ms) = super::verification_stats();
    let (result, logs) =
        capture(store.verify_generation_for_startup(&id, &observed(), "handoff")).await;
    result.unwrap();
    let line = logs
        .lines()
        .find(|line| {
            line.contains("phase=\"startup-generation-verify\"")
                && line.contains("reason=\"handoff\"")
        })
        .expect("a finished pass logs its reason")
        .to_owned();
    let logged_ms: u64 = line
        .split("elapsed_ms=")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let (after_passes, after_ms) = super::verification_stats();
    // Tolerant on purpose: the counters are process-global and other tests
    // run full verifications in parallel, so another pass can land between
    // the two snapshots — a concurrent pass can even mask a missing increment
    // here. This stays a smoke check; exactness would need process-wide
    // serialization of every verification.
    assert!(
        after_passes > before_passes,
        "passes {before_passes} -> {after_passes}"
    );
    // This pass's own logged time must have reached the total. Millisecond
    // truncation can legitimately log 0 on a fast machine, so there is no
    // lower bound on `logged_ms` itself — only that the total grew by at
    // least what this pass reported.
    assert!(
        after_ms >= before_ms + logged_ms,
        "total ms {before_ms} -> {after_ms}, this pass logged {logged_ms}ms: {line}"
    );
    db.close().await;
}
