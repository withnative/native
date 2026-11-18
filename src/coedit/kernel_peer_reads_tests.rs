//! Source candidate only until separately compiled/executed by root.
//! CURRENT_OWNED_SQL-only runtime coverage remains explicit accepted debt.
use super::*;
use crate::{events::KERNEL_ROOT_ID, kernel};
use serde_json::{json, Value};
use yrs::{
    updates::decoder::Decode, Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update,
};

struct World {
    db: Db,
    admin: String,
    member: String,
    home: String,
    caller: Caller,
}
async fn world() -> World {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "N2 admin", "acct:n2admin")
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let manifest: Value = serde_json::from_str(crate::meta::kind::CORE_KIND_MANIFEST_JSON).unwrap();
    let mut rows = Vec::new();
    for typ in ["Document", "WorkItem"] {
        rows.push((
            "vocabularies",
            json!({"id":format!("voc:kind:{typ}"),"name":format!("kind:{typ}")}),
        ));
        for entry in manifest["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["type"] == typ)
        {
            rows.push(("vocabulary_values", json!({"id":entry["value_id"],"vocabulary_id":format!("voc:kind:{typ}"),"value":entry["token"],"status":"active","gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null})));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "n2-native-fixture".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-28T00:00:00Z".into(),
            snapshot: json!({}),
        })
        .collect::<Vec<_>>();
    kernel::v1_state::import_state_batch_as(&db, &host, &rows)
        .await
        .unwrap();
    let member = kernel::create_principal(&db, "account", "N2 member", "acct:n2member", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&member, "edit")]), &admin)
        .await
        .unwrap();
    World {
        db,
        admin,
        member,
        home,
        caller: Caller::authenticated("acct:n2member")
            .with_channel(crate::provenance::Channel::Web),
    }
}
async fn record(w: &World, typ: &str, kind: &str) -> String {
    kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":typ,"v1_kind":kind,"title":"N2 body"}).to_string(),
        &w.home,
    )
    .await
    .unwrap()
}
async fn open(w: &World, id: &str, mode: PeerKind) -> (SessionPeer, Opened) {
    open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id.into(),
            mode,
            resume_peer: None,
        },
    )
    .await
    .unwrap()
}
fn update(opened: &Opened, text: &str) -> Vec<u8> {
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    doc.transact_mut()
        .apply_update(Update::decode_v1(&opened.sync).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    doc.get_or_insert_text("body")
        .insert(&mut doc.transact_mut(), 0, text);
    let delta = doc.transact().encode_diff_v1(&before);
    delta
}
fn text(bytes: &[u8]) -> String {
    let doc = Doc::new();
    doc.transact_mut()
        .apply_update(Update::decode_v1(bytes).unwrap())
        .unwrap();
    let body = doc.get_or_insert_text("body").get_string(&doc.transact());
    body
}
fn jobs(db: &Db) -> usize {
    lock(&db_sessions(db).kernel_lifecycle.serial).accepted_jobs
}
fn assert_no_work(probe: &TestProbe) {
    assert_eq!(probe.clones.load(Ordering::SeqCst), 0);
    assert_eq!(probe.launches.load(Ordering::SeqCst), 0);
    assert_eq!(probe.checkouts.load(Ordering::SeqCst), 0);
    assert_eq!(probe.acquisitions.load(Ordering::SeqCst), 0);
}
fn request(
    peer: &SessionPeer,
    caller: &Caller,
    probe: Option<Arc<TestProbe>>,
) -> OwnedPeerReadRequest {
    let (origin, db, owner) = PeerOrigin::capture(peer, caller).unwrap();
    OwnedPeerReadRequest {
        origin,
        db,
        owner,
        caller: caller.clone(),
        request: PeerReadRequest::Sync {
            state_vector: vec![],
        },
        probe,
    }
}
// Use the actual existing slot and scopes, but retain the JoinHandle so the
// test can destroy the OWNER rather than merely losing its result observer.
fn destroyable(request: OwnedPeerReadRequest) -> tokio::task::JoinHandle<Result<PeerReadReply>> {
    let slot = reserve_job_slot(&request.db).unwrap();
    tokio::spawn(OWNED_JOB_SLOT.scope(slot, N2_PEER_SCOPE.scope((), run_owned(request))))
}

async fn dispose_retained(db: &Db) {
    dispose_retained_with_handle(db, None).await;
}
async fn dispose_retained_with_handle(db: &Db, expected: Option<usize>) {
    let entries = {
        let mut retained = lock(&RETAINED_PEER_READS);
        let (ours, other): (Vec<_>, Vec<_>) =
            std::mem::take(&mut *retained).into_iter().partition(|e| {
                let o = match e {
                    RetainedPeerRead::CheckoutNativeUnknown { ownership, .. }
                    | RetainedPeerRead::OwnedConnectionUnknown { ownership, .. } => ownership,
                };
                o.db.same_handle(db)
            });
        *retained = other;
        ours
    };
    for entry in entries {
        match entry {
            RetainedPeerRead::OwnedConnectionUnknown {
                mut lease,
                ownership,
                ..
            } => {
                // External panic-safe worker fixture was released before this.
                {
                    let mut h = lease.lock_handle().await.unwrap();
                    if let Some(expected) = expected {
                        assert_eq!(h.as_raw_handle().as_ptr() as usize, expected);
                    }
                    h.remove_progress_handler();
                }
                SqliteTransactionManager::rollback(&mut *lease)
                    .await
                    .unwrap();
                {
                    let mut h = lease.lock_handle().await.unwrap();
                    assert_ne!(
                        unsafe {
                            libsqlite3_sys::sqlite3_get_autocommit(h.as_raw_handle().as_ptr())
                        },
                        0
                    );
                }
                assert_eq!(SqliteTransactionManager::get_transaction_depth(&lease), 0);
                drop(lease); // Actual clean lease BEFORE ops/gate and slot.
                drop(ownership);
            }
            RetainedPeerRead::CheckoutNativeUnknown { ownership, .. } => {
                // Test teardown only: no physical-drain/recovery assertion.
                drop(ownership);
            }
        }
    }
}
async fn finish(w: World, peers: Vec<SessionPeer>) {
    dispose_retained(&w.db).await;
    let owner = db_sessions(&w.db);
    for peer in &peers {
        peer.inner.left.store(true, Ordering::Release);
    }
    let rooms = lock(&owner.records).values().cloned().collect::<Vec<_>>();
    for room in rooms {
        close_locked(&mut room.state());
    }
    lock(&owner.records).clear();
    drop(peers);
    assert_eq!(lock(&owner.kernel_lifecycle.serial).accepted_jobs, 0);
    w.db.close().await;
    lock(&SERVICE).remove(&session_key(&w.db));
}

#[tokio::test]
async fn actual_caller_apply_and_mode_preserving_sync_document_task_epic() {
    let w = world().await;
    let mut peers = Vec::new();
    for (typ, kind) in [
        ("Document", "note"),
        ("WorkItem", "task"),
        ("WorkItem", "epic"),
    ] {
        let id = record(&w, typ, kind).await;
        let (edit, opened) = open(&w, &id, PeerKind::Edit).await;
        let (view, _) = open(&w, &id, PeerKind::View).await;
        let delta = update(&opened, "café 東京");
        let before = kernel::body_history_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .len();
        let ack = apply_as(&edit, &w.caller, "real-native", &delta)
            .await
            .unwrap();
        assert_eq!(ack.update_id, "real-native");
        assert_eq!(
            text(&sync_as(&view, &w.caller, &[]).await.unwrap()),
            "café 東京"
        );
        {
            let state = edit.inner.session.state();
            let snapshot = state.registry.version_snapshot(&state.session).unwrap();
            assert_eq!(snapshot.contributors().len(), 1);
            assert_eq!(snapshot.contributors()[0].principal, w.member);
            assert_eq!(snapshot.contributors()[0].channel.as_deref(), Some("web"));
            assert!(snapshot.contributors()[0].app.is_none());
        }
        assert_eq!(
            kernel::body_history_as(&w.db, &w.admin, &id)
                .await
                .unwrap()
                .len(),
            before
        );
        assert!(apply_as(&view, &w.caller, "no-view-write", &delta)
            .await
            .is_err());
        peers.extend([edit, view]);
    }
    finish(w, peers).await;
}

#[tokio::test]
async fn raw_envelope_refuses_oversize_before_clone_reserve_spawn() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
    let probe = TestProbe::new(None);
    let before = jobs(&w.db);
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            assert_eq!(
                apply_as(&peer, &w.caller, "", &vec![0; 64 * 1024 + 1])
                    .await
                    .unwrap_err()
                    .code,
                RefusalCode::TooLarge
            );
            assert_eq!(
                apply_as(
                    &peer,
                    &w.caller,
                    &"i".repeat(64 * 1024 + 1),
                    &vec![0; 64 * 1024]
                )
                .await
                .unwrap_err()
                .code,
                RefusalCode::TooLarge
            );
            assert_eq!(
                sync_as(&peer, &w.caller, &vec![0; 128 * 1024 + 1])
                    .await
                    .unwrap_err()
                    .code,
                RefusalCode::TooLarge
            );
        })
        .await;
    assert_no_work(&probe);
    assert_eq!(jobs(&w.db), before);
    assert!(apply_bytes_fit(64 * 1024, 64 * 1024));
    assert!(apply_bytes_fit(128 * 1024, 0));
    assert!(!apply_bytes_fit(usize::MAX, 1));
    assert!(!apply_bytes_fit(0, 64 * 1024 + 1));
    // Boundary bytes pass RAW validation; their decoder refusal is genuine.
    let boundary = TestProbe::new(None);
    TEST_PROBE
        .scope(Arc::clone(&boundary), async {
            assert_ne!(
                sync_as(&peer, &w.caller, &vec![0xff; 128 * 1024])
                    .await
                    .unwrap_err()
                    .code,
                RefusalCode::TooLarge
            );
        })
        .await;
    assert_eq!(boundary.clones.load(Ordering::SeqCst), 1);
    assert_eq!(boundary.launches.load(Ordering::SeqCst), 1);
    let delta = update(&opened, "exact-raw-envelope");
    let id_at_boundary = "i".repeat(MAX_NATIVE_PEER_REQUEST_BYTES - delta.len());
    let ack = apply_as(&peer, &w.caller, &id_at_boundary, &delta)
        .await
        .unwrap();
    assert_eq!(
        ack.update_id.len() + delta.len(),
        MAX_NATIVE_PEER_REQUEST_BYTES
    );
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn queued_revoke_precedes_first_native_snapshot() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let ops = Arc::clone(&peer.inner.session.ops).lock_owned().await;
    let queued = test_gate(&w.db, super::super::TestStage::OpsQueued, false);
    let p = SessionPeer {
        inner: Arc::clone(&peer.inner),
    };
    let caller = w.caller.clone();
    let task = tokio::spawn(async move { sync_as(&p, &caller, &[]).await });
    queued.entered.notified().await;
    kernel::replace_home_policy(&w.db, &w.admin, &w.home, &[])
        .await
        .unwrap();
    queued.release.notify_one();
    drop(ops);
    assert!(task.await.unwrap().is_err());
    assert_eq!(peer.inner.session.state().epoch(), 0);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn overlapping_post_t2_revoke_preserves_snapshot_contract() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
    let delta = update(&opened, "snapshot-admitted");
    let probe = TestProbe::new(Some(TestStage::Facts));
    let p = SessionPeer {
        inner: Arc::clone(&peer.inner),
    };
    let caller = w.caller.clone();
    let used = Arc::clone(&probe);
    let task = tokio::spawn(async move {
        TEST_PROBE
            .scope(used, apply_as(&p, &caller, "t2", &delta))
            .await
    });
    probe.entered.notified().await;
    // Real native policy transaction is independent of room ops.
    kernel::replace_home_policy(&w.db, &w.admin, &w.home, &[])
        .await
        .unwrap();
    probe.resume.notify_one();
    task.await.unwrap().unwrap();
    {
        let state = peer.inner.session.state();
        assert_eq!(
            state.registry.live_body(&state.session).unwrap(),
            "snapshot-admitted"
        );
    }
    assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn original_principal_app_handle_and_peer_incarnation_are_immutable() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let impostor = Caller::authenticated("acct:n2admin");
    assert!(sync_as(&peer, &impostor, &[]).await.is_err());
    let app =
        crate::mcp::app_attribution::AppAttribution::new("missing.app", "1", "no-install").unwrap();
    assert!(
        sync_as(&peer, &w.caller.clone().with_host_asserted_app(app), &[])
            .await
            .is_err()
    );
    let (replacement, resumed) = open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id,
            mode: PeerKind::Edit,
            resume_peer: Some(peer.inner.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(resumed.resumed);
    assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
    finish(w, vec![peer, replacement]).await;
}

#[tokio::test]
async fn same_snapshot_facts_do_not_hydrate_target_body() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let observed = kernel_v2::observe_body(&id, true);
    let caller = w
        .caller
        .clone()
        .with_run_context(Some("n2-actual-run".into()), None);
    let (fresh, opened) = open(&w, &id, PeerKind::Edit).await;
    let delta = update(&opened, "run");
    apply_as(&fresh, &caller, "run-context", &delta)
        .await
        .unwrap();
    sync_as(&peer, &w.caller, &[]).await.unwrap();
    assert!(observed.stages().is_empty());
    {
        let state = fresh.inner.session.state();
        let snap = state.registry.version_snapshot(&state.session).unwrap();
        assert_eq!(
            snap.contributors()[0].run_key.as_deref(),
            Some("n2-actual-run")
        );
    }
    finish(w, vec![peer, fresh]).await;
}

#[tokio::test]
async fn registry_refusal_and_replay_preserve_state_and_authorship() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
    assert!(apply_as(&peer, &w.caller, "bad", &[0xff]).await.is_err());
    assert_eq!(peer.inner.session.state().epoch(), 0);
    let delta = update(&opened, "only-once");
    apply_as(&peer, &w.caller, "first", &delta).await.unwrap();
    let before = peer.inner.session.state().epoch();
    let relayed = w
        .caller
        .clone()
        .with_run_context(Some("must-not-credit-replay".into()), None);
    apply_as(&peer, &relayed, "again", &delta).await.unwrap();
    {
        let state = peer.inner.session.state();
        assert_eq!(state.epoch(), before);
        assert_ne!(
            state.peers[&peer.inner.peer].caller.run_key(),
            Some("must-not-credit-replay")
        );
        assert_eq!(
            state
                .registry
                .version_snapshot(&state.session)
                .unwrap()
                .contributors()
                .len(),
            1
        );
    }
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn ordinary_checkout_reuses_and_establishes_capacity_with_existing_hooks() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let held = w.db.pool().acquire().await.unwrap();
    let probe = TestProbe::new(None);
    TEST_PROBE
        .scope(Arc::clone(&probe), sync_as(&peer, &w.caller, &[]))
        .await
        .unwrap();
    assert!(
        w.db.pool().size() >= 2,
        "ordinary checkout can establish spare capacity"
    );
    assert_eq!(probe.checkouts.load(Ordering::SeqCst), 1);
    assert_eq!(probe.acquisitions.load(Ordering::SeqCst), 1);
    drop(held);
    sync_as(&peer, &w.caller, &[]).await.unwrap();
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn normal_checkout_failure_is_not_physical_drain_evidence() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    w.db.pool().close().await;
    assert_eq!(
        sync_as(&peer, &w.caller, &[]).await.unwrap_err().code,
        RefusalCode::Unavailable
    );
    assert!(!*db_sessions(&w.db).kernel_quarantine.borrow());
    assert_eq!(jobs(&w.db), 0);
    assert_eq!(peer.inner.session.state().epoch(), 0);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn checkout_owner_loss_retains_terminal_native_fence_without_lease() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(w.db.pool().acquire().await.unwrap());
    }
    let req = request(&peer, &w.caller, None);
    // Prepare actual native ownership, then poll real ordinary checkout Pending.
    let gate = acquire_read_gate(&w.db, &req.owner).await.unwrap();
    let ops = acquire_peer_ops(&peer.inner.session).await.unwrap();
    let slot = reserve_job_slot(&w.db).unwrap();
    let ownership = PeerReadOwnership {
        db: req.db,
        owner: req.owner,
        room: Arc::clone(&peer.inner.session),
        origin: req.origin,
        request: req.request,
        caller: req.caller,
        _ops: ops,
        _gate: gate,
        slot,
        probe: None,
    };
    let mut read = PeerReadGuard::new(ownership);
    {
        let future = read.checkout();
        tokio::pin!(future);
        assert!(futures::poll!(future.as_mut()).is_pending());
    }
    drop(read); // Actual owner, not observer. No returned lease can be named.
    let owner = db_sessions(&w.db);
    assert!(*owner.kernel_quarantine.borrow());
    assert_eq!(jobs(&w.db), 1);
    assert!(peer.inner.session.ops.try_lock().is_err());
    {
        let retained = lock(&RETAINED_PEER_READS);
        assert!(retained.iter().any(|e| matches!(e, RetainedPeerRead::CheckoutNativeUnknown { ownership, .. } if ownership.db.same_handle(&w.db))));
    }
    assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
    assert!(matches!(
        kernel_lifecycle::seal_kernel_retirement(&w.db).observe(),
        super::super::super::KernelRetirementState::Uncertain { .. }
    ));
    drop(held);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn post_checkout_begin_read_rollback_owner_loss_retains_original_lease() {
    for stage in [TestStage::LeaseReady, TestStage::Begun, TestStage::Settling] {
        let w = world().await;
        let id = record(&w, "Document", "note").await;
        let (peer, _) = open(&w, &id, PeerKind::Edit).await;
        let worker = WorkerBarrier::new();
        let release = ReleaseWorker(Arc::clone(&worker));
        let mut probe = TestProbe::new(None);
        Arc::get_mut(&mut probe).unwrap().worker = Some((stage, Arc::clone(&worker)));
        let owner = destroyable(request(&peer, &w.caller, Some(probe)));
        worker.entered.notified().await; // Actual SQLite VM callback, not pre-poll checkpoint.
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        assert!(*db_sessions(&w.db).kernel_quarantine.borrow());
        assert_eq!(jobs(&w.db), 1);
        assert!(peer.inner.session.ops.try_lock().is_err());
        let expected = worker.handle.load(Ordering::SeqCst);
        assert_ne!(expected, 0);
        // The retained ORIGINAL lease is checked after releasing its blocked worker.
        drop(release);
        {
            let mut entries = lock(&RETAINED_PEER_READS);
            let entry = entries.iter_mut().find(|e| matches!(e, RetainedPeerRead::OwnedConnectionUnknown { ownership, .. } if ownership.db.same_handle(&w.db))).unwrap();
            // Do not await while holding the retained-list lock. Same-handle check
            // happens in controlled cleanup below, using the recorded handle.
            assert!(matches!(
                entry,
                RetainedPeerRead::OwnedConnectionUnknown { .. }
            ));
        }
        dispose_retained_with_handle(&w.db, Some(expected)).await;
        assert_eq!(jobs(&w.db), 0);
        finish(w, vec![peer]).await;
    }
}

#[tokio::test]
async fn settlement_ack_and_read_disposal_precede_t3() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(w.db.pool().acquire().await.unwrap());
    }
    let probe = TestProbe::new(Some(TestStage::Settled));
    let owner = destroyable(request(&peer, &w.caller, Some(Arc::clone(&probe))));
    probe.entered.notified().await;
    assert!(peer.inner.session.ops.try_lock().is_err());
    // Real unrelated read checkout succeeds; the N2 read lease already disposed.
    let lease = w.db.pool().acquire().await.unwrap();
    drop(lease);
    kernel_lifecycle::seal_kernel_retirement(&w.db);
    probe.resume.notify_one();
    let result = owner.await.unwrap().unwrap();
    assert!(matches!(result, PeerReadReply::Sync(Err(_))));
    assert_eq!(peer.inner.session.state().epoch(), 0);
    drop(held);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn lost_result_observer_does_not_erase_accepted_dirty_state() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
    let probe = TestProbe::new(Some(TestStage::Facts));
    let p = SessionPeer {
        inner: Arc::clone(&peer.inner),
    };
    let caller = w.caller.clone();
    let delta = update(&opened, "owned-after-observer");
    let used = Arc::clone(&probe);
    let observer = tokio::spawn(async move {
        TEST_PROBE
            .scope(used, apply_as(&p, &caller, "lost", &delta))
            .await
    });
    probe.entered.notified().await;
    observer.abort();
    assert!(observer.await.unwrap_err().is_cancelled());
    probe.resume.notify_one();
    assert_eq!(
        text(&sync_as(&peer, &w.caller, &[]).await.unwrap()),
        "owned-after-observer"
    );
    assert!(peer.inner.session.state().dirty());
    assert!(kernel::body_history_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .is_empty());
    finish(w, vec![peer]).await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn real_ambient_and_owned_scopes_refuse_before_clone_reserve_or_spawn() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let probe = TestProbe::new(None);
    let before = jobs(&w.db);
    let reads = [("records", "id")];
    let ran = std::cell::Cell::new(false);
    crate::mcp::kernel_v2::with_native_peer_sql_read_session_for_test(
        &w.db,
        &w.member,
        &reads,
        async {
            TEST_PROBE
                .scope(Arc::clone(&probe), async {
                    ran.set(true);
                    assert!(apply_as(&peer, &w.caller, "", &[]).await.is_err());
                    assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
                })
                .await;
            Ok(())
        },
    )
    .await
    .unwrap();
    assert!(ran.get());
    assert_eq!(jobs(&w.db), before);
    assert_no_work(&probe);
    let db = w.db.clone();
    let p = SessionPeer {
        inner: Arc::clone(&peer.inner),
    };
    let caller = w.caller.clone();
    let used = Arc::clone(&probe);
    owned_result(db, async move {
        TEST_PROBE
            .scope(used, async {
                assert!(sync_as(&p, &caller, &[]).await.is_err());
                assert!(apply_as(&p, &caller, "", &[]).await.is_err());
            })
            .await;
        Ok(())
    })
    .await
    .unwrap();
    assert_no_work(&probe);
    N2_PEER_SCOPE
        .scope((), async {
            assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
        })
        .await;
    require_ingress().unwrap(); // Actual SQL/scope ownership no longer present.
    sync_as(&peer, &w.caller, &[]).await.unwrap();
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn actual_native_roster_loss_refuses_next_operation() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    for members in [vec!["acct:n2admin", "acct:n2member"], vec!["acct:n2admin"]] {
        let members = members.into_iter().map(str::to_owned).collect();
        kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async move {
            // SAFETY: complete authoritative synthetic portable-account roster;
            // real native reconciler appends/projects its membership event.
            Ok(unsafe {
                kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                    "acct:n2admin".into(),
                    members,
                )
            })
        })
        .await
        .unwrap();
    }
    assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
    assert_eq!(peer.inner.session.state().epoch(), 0);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn existing_job_capacity_refuses_without_new_worker_or_checkout() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let seats = hold_job_slots_for_test(&w.db, MAX_OWNED_KERNEL_JOBS_PER_DATABASE);
    let before = jobs(&w.db);
    let probe = TestProbe::new(None);
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
        })
        .await;
    assert_eq!(jobs(&w.db), before);
    assert_eq!(probe.launches.load(Ordering::SeqCst), 0);
    assert_eq!(probe.checkouts.load(Ordering::SeqCst), 0);
    drop(seats);
    sync_as(&peer, &w.caller, &[]).await.unwrap();
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn map_loss_after_t2_refuses_without_registry_effect() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let probe = TestProbe::new(Some(TestStage::Facts));
    let job = destroyable(request(&peer, &w.caller, Some(Arc::clone(&probe))));
    probe.entered.notified().await;
    let owner = db_sessions(&w.db);
    let original = lock(&owner.records).remove(&id).unwrap();
    probe.resume.notify_one();
    assert!(matches!(
        job.await.unwrap().unwrap(),
        PeerReadReply::Sync(Err(_))
    ));
    lock(&owner.records).insert(id, original);
    assert_eq!(peer.inner.session.state().epoch(), 0);
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn actual_begin_error_retains_the_returned_original_lease() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let mut worker = WorkerBarrier::new();
    Arc::get_mut(&mut worker).unwrap().interrupt = true;
    let release = ReleaseWorker(Arc::clone(&worker));
    let mut probe = TestProbe::new(None);
    Arc::get_mut(&mut probe).unwrap().worker = Some((TestStage::LeaseReady, Arc::clone(&worker)));
    let owner = destroyable(request(&peer, &w.caller, Some(probe)));
    worker.entered.notified().await; // Real BEGIN VM, not an injected Err result.
    drop(release); // Progress handler returns false; actual SQLite BEGIN fails.
    assert!(owner.await.unwrap().is_err());
    assert!(*db_sessions(&w.db).kernel_quarantine.borrow());
    assert_eq!(jobs(&w.db), 1);
    dispose_retained_with_handle(&w.db, Some(worker.handle.load(Ordering::SeqCst))).await;
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn owner_panic_after_begin_retains_concrete_read_state() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let req = request(&peer, &w.caller, None);
    let gate = acquire_read_gate(&w.db, &req.owner).await.unwrap();
    let ops = acquire_peer_ops(&peer.inner.session).await.unwrap();
    let slot = reserve_job_slot(&w.db).unwrap();
    let ownership = PeerReadOwnership {
        db: req.db,
        owner: req.owner,
        room: Arc::clone(&peer.inner.session),
        origin: req.origin,
        request: req.request,
        caller: req.caller,
        _ops: ops,
        _gate: gate,
        slot,
        probe: None,
    };
    let mut read = PeerReadGuard::new(ownership);
    read.checkout().await.unwrap();
    read.begin_deferred().await.unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _actual_read_owner = read;
        panic!("intentional N2 owner panic with actual begun read");
    }));
    assert!(result.is_err());
    assert_eq!(jobs(&w.db), 1);
    assert!(*db_sessions(&w.db).kernel_quarantine.borrow());
    assert!(peer.inner.session.ops.try_lock().is_err());
    finish(w, vec![peer]).await;
}

#[tokio::test]
async fn actual_cleanup_scope_refuses_before_clone_reserve_or_spawn() {
    let w = world().await;
    let id = record(&w, "Document", "note").await;
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let witness = kernel_lifecycle::seal_kernel_retirement(&w.db);
    let probe = TestProbe::new(None);
    let before = jobs(&w.db);
    assert!(OWNED_JOB_SLOT.try_with(|_| ()).is_err());
    kernel_lifecycle::with_cleanup_scope_for_peer_ingress_test(&witness, async {
        assert!(kernel_lifecycle::current_cleanup().is_some());
        assert!(OWNED_JOB_SLOT.try_with(|_| ()).is_err());
        TEST_PROBE
            .scope(Arc::clone(&probe), async {
                assert!(apply_as(&peer, &w.caller, "", &[]).await.is_err());
                assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
            })
            .await;
    })
    .await;
    assert!(kernel_lifecycle::current_cleanup().is_none());
    assert_no_work(&probe);
    assert_eq!(jobs(&w.db), before);
    // Actual cleanup-scope refusal, NOT an owned cleanup-driver proof.
    finish(w, vec![peer]).await;
}

// try_lock is observation of actual locks ONLY, never ingress authority.
fn dirty_callback_locks_free(owner: &DbSessions, room: &LiveSession) -> bool {
    owner.kernel_lifecycle.serial.try_lock().is_ok()
        && room.state.try_lock().is_ok()
        && owner.records.try_lock().is_ok()
}

struct InspectingDirtyLease {
    owner: Arc<DbSessions>,
    room: Arc<LiveSession>,
    observed: std::sync::mpsc::SyncSender<bool>,
}
impl Drop for InspectingDirtyLease {
    fn drop(&mut self) {
        let available = dirty_callback_locks_free(&self.owner, &self.room);
        if available {
            // Real lock-taking native inspection, skipped on old failing source
            // so a regression records false rather than wedging an executor.
            let _jobs = lock(&self.owner.kernel_lifecycle.serial).accepted_jobs;
            let _epoch = self.room.state().epoch();
        }
        let _ = self.observed.try_send(available);
    }
}

#[tokio::test]
async fn dirty_hook_reentry_revalidates_actual_seal_and_quarantine() {
    for seal in [true, false] {
        let w = world().await;
        let id = record(&w, "Document", "note").await;
        let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
        let delta = update(&opened, "must refuse after hook");
        let owner = db_sessions(&w.db);
        let room = Arc::clone(&peer.inner.session);
        let (send, observed) = std::sync::mpsc::sync_channel(1);
        let hook = kernel_lifecycle::test_admission_hook(
            &w.db,
            kernel_lifecycle::AdmissionKind::Dirty,
            Arc::new(move |db| {
                let available = dirty_callback_locks_free(&owner, &room);
                if available {
                    if seal {
                        let witness = kernel_lifecycle::seal_kernel_retirement(db);
                        let _actual_retirement_state = witness.observe();
                    } else {
                        quarantine_storage(db, "actual-dirty-hook");
                    }
                }
                let _ = send.try_send(available);
                Some(Box::new(()) as Box<dyn Send>)
            }),
        );
        let answer = tokio::time::timeout(
            Duration::from_secs(5),
            apply_as(&peer, &w.caller, "hook", &delta),
        )
        .await
        .unwrap();
        assert!(
            observed.try_recv().unwrap(),
            "hook ran with a native lock held"
        );
        assert!(answer.is_err());
        {
            let state = peer.inner.session.state();
            assert_eq!(state.epoch(), 0);
            assert!(!state.dirty());
            assert!(state.dirty_admission.is_none());
            assert!(state
                .registry
                .version_snapshot(&state.session)
                .unwrap()
                .contributors()
                .is_empty());
        }
        drop(hook);
        finish(w, vec![peer]).await;
    }
}

#[tokio::test]
async fn unused_dirty_lease_drop_reenters_after_final_locks_release() {
    for case in ["malformed", "replay", "accepted"] {
        let w = world().await;
        let id = record(&w, "Document", "note").await;
        let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
        let delta = update(&opened, "retained accepted basis");
        if case == "replay" {
            apply_as(&peer, &w.caller, "first", &delta).await.unwrap();
        }
        let before = peer.inner.session.state().epoch();
        let owner = db_sessions(&w.db);
        let room = Arc::clone(&peer.inner.session);
        let (send, observed) = std::sync::mpsc::sync_channel(1);
        let hook = kernel_lifecycle::test_admission_hook(
            &w.db,
            kernel_lifecycle::AdmissionKind::Dirty,
            Arc::new(move |_| {
                Some(Box::new(InspectingDirtyLease {
                    owner: Arc::clone(&owner),
                    room: Arc::clone(&room),
                    observed: send.clone(),
                }) as Box<dyn Send>)
            }),
        );
        let bytes = if case == "malformed" {
            &[0xff][..]
        } else {
            &delta[..]
        };
        let answer = tokio::time::timeout(
            Duration::from_secs(5),
            apply_as(&peer, &w.caller, "lease", bytes),
        )
        .await
        .unwrap();
        if case == "malformed" {
            assert!(answer.is_err());
        } else {
            answer.unwrap();
        }
        if case == "accepted" {
            assert!(matches!(
                observed.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            assert!(peer.inner.session.state().epoch() > before);
            // The accepted lease was retained. Teardown releases it outside
            // State too; this test is not a change to historical close_locked.
            let retained = peer.inner.session.state().dirty_admission.take();
            assert!(retained.is_some());
            drop(retained);
        } else {
            assert_eq!(peer.inner.session.state().epoch(), before);
            assert!(peer.inner.session.state().dirty_admission.is_none());
        }
        assert!(
            observed.try_recv().unwrap(),
            "unused lease dropped under native locks"
        );
        drop(hook);
        finish(w, vec![peer]).await;
    }
}

// Current native app enforcement only. The ancestor fixture explicitly trusts
// synthetic import/frozen activation/catalog/cookie setup; not a hosted proof.
async fn adopted_app_world() -> (
    Arc<crate::v1_import::NativePeerAdoptedAppFixture>,
    World,
    String,
) {
    let fixture = crate::v1_import::native_peer_adopted_app_fixture_for_test().await;
    let home = kernel::create_home(
        &fixture.db,
        KERNEL_ROOT_ID,
        Some(&[(&fixture.principal, "edit")]),
        &fixture.administrator,
    )
    .await
    .unwrap();
    // No native SQL authority facts or late importer writes. Ordinary supported
    // creation makes an ordinary Document note, admitted by existing policy.
    let id = kernel::create_json_as(
        &fixture.db,
        &fixture.administrator,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Native app target"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let w = World {
        db: fixture.db.clone(),
        admin: fixture.administrator.clone(),
        member: fixture.principal.clone(),
        home,
        caller: fixture
            .adopted_caller
            .clone()
            .with_channel(crate::provenance::Channel::Web),
    };
    (fixture, w, id)
}

#[tokio::test]
async fn adopted_app_current_native_apply_sync_and_stale_removed_controls() {
    let (fixture, w, id) = adopted_app_world().await;
    assert_ne!(fixture.staged_generation, fixture.adopted_generation);
    // STALE after adoption, not an operation while install was still staged.
    assert!(
        kernel_v2::revalidate(&w.db, &fixture.staged_caller, &id, PeerKind::Edit)
            .await
            .is_err()
    );
    let (edit, opened) = open(&w, &id, PeerKind::Edit).await;
    let (view, _) = open(&w, &id, PeerKind::View).await;
    let mut probe = TestProbe::new(None);
    Arc::get_mut(&mut probe).unwrap().fixture_owner = Some(Arc::clone(&fixture));
    let caller = w
        .caller
        .clone()
        .with_run_context(Some("native-app-run".into()), None);
    let delta = update(&opened, "actual adopted native app");
    let before = kernel::body_history_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .len();
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            apply_as(&edit, &caller, "adopted", &delta).await.unwrap();
            assert_eq!(
                text(&sync_as(&view, &w.caller, &[]).await.unwrap()),
                "actual adopted native app"
            );
        })
        .await;
    {
        let state = edit.inner.session.state();
        let snapshot = state.registry.version_snapshot(&state.session).unwrap();
        assert_eq!(snapshot.contributors().len(), 1);
        let author = &snapshot.contributors()[0];
        assert_eq!(author.principal, fixture.principal);
        assert_eq!(author.run_key.as_deref(), Some("native-app-run"));
        assert_eq!(author.channel.as_deref(), Some("web"));
        let app = author.app.as_ref().unwrap();
        assert_eq!(app.package, fixture.pin.package);
        assert_eq!(app.version, fixture.pin.version);
        assert_eq!(app.install_event_id, fixture.adopted_generation);
    }
    assert_eq!(
        kernel::body_history_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .len(),
        before
    );
    let epoch = edit.inner.session.state().epoch();
    kernel::app_installs::remove_as(
        &w.db,
        &fixture.principal,
        &fixture.pin.package,
        &fixture.adopted_generation,
    )
    .await
    .unwrap();
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            assert!(sync_as(&view, &w.caller, &[]).await.is_err());
            assert!(apply_as(&edit, &caller, "removed", &delta).await.is_err());
        })
        .await;
    assert_eq!(edit.inner.session.state().epoch(), epoch);
    assert!(kernel::read_record_as(&w.db, &fixture.principal, &id)
        .await
        .unwrap()
        .is_some());
    finish(w, vec![edit, view]).await;
    drop(probe); // Original leases/guards/slots and Db closed BEFORE TempDir.
    drop(fixture);
}

#[tokio::test]
async fn adopted_app_current_source_view_loss_refuses_without_mutation() {
    let (fixture, w, id) = adopted_app_world().await;
    let (peer, opened) = open(&w, &id, PeerKind::Edit).await;
    let mut probe = TestProbe::new(None);
    Arc::get_mut(&mut probe).unwrap().fixture_owner = Some(Arc::clone(&fixture));
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            sync_as(&peer, &w.caller, &[]).await.unwrap();
        })
        .await;
    let private = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &fixture.administrator)
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &fixture.administrator, &fixture.source_id, &private)
        .await
        .unwrap();
    // Target still visible: this refusal comes from current app source checks.
    assert!(kernel::read_record_as(&w.db, &fixture.principal, &id)
        .await
        .unwrap()
        .is_some());
    assert!(
        kernel::read_record_as(&w.db, &fixture.principal, &fixture.source_id)
            .await
            .unwrap()
            .is_none()
    );
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            assert!(sync_as(&peer, &w.caller, &[]).await.is_err());
            assert!(apply_as(
                &peer,
                &w.caller,
                "hidden-source",
                &update(&opened, "refused")
            )
            .await
            .is_err());
        })
        .await;
    assert_eq!(peer.inner.session.state().epoch(), 0);
    finish(w, vec![peer]).await;
    drop(probe); // Settle original leases/guards/slot and close Db first.
    drop(fixture);
}

#[tokio::test]
async fn app_fixture_directory_is_owned_through_pending_and_quarantined_read() {
    let (fixture, w, id) = adopted_app_world().await;
    let weak = Arc::downgrade(&fixture);
    let (peer, _) = open(&w, &id, PeerKind::Edit).await;
    let worker = WorkerBarrier::new();
    let release = ReleaseWorker(Arc::clone(&worker));
    let mut probe = TestProbe::new(None);
    {
        let p = Arc::get_mut(&mut probe).unwrap();
        p.fixture_owner = Some(Arc::clone(&fixture));
        p.worker = Some((TestStage::Begun, Arc::clone(&worker)));
    }
    let owner = destroyable(request(&peer, &w.caller, Some(probe)));
    drop(fixture);
    worker.entered.notified().await; // Actual blocked SQL worker, no sleep oracle.
    assert!(weak.upgrade().is_some()); // Only owned request/probe holds directory.
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert!(*db_sessions(&w.db).kernel_quarantine.borrow());
    assert!(peer.inner.session.ops.try_lock().is_err());
    assert_eq!(jobs(&w.db), 1);
    let teardown_owner = weak
        .upgrade()
        .expect("quarantine must retain actual directory owner");
    assert_eq!(Arc::strong_count(&teardown_owner), 2); // This owner + actual retained probe.
    let original = worker.handle.load(Ordering::SeqCst);
    assert_ne!(original, 0);
    drop(release);
    dispose_retained_with_handle(&w.db, Some(original)).await;
    assert_eq!(Arc::strong_count(&teardown_owner), 1);
    finish(w, vec![peer]).await; // Db close while TempDir owner is still held.
    drop(teardown_owner);
    assert!(weak.upgrade().is_none());
}

// A successful explicit cut may have reserved its independent post-commit
// recheck. Observe actual native job release before the unchanged teardown;
// this never settles SQL, clears quarantine, or disposes a retained graph.
async fn m1_wait_for_owned_jobs_before_finish(w: &World) {
    let owner = db_sessions(&w.db);
    let mut changed = owner.kernel_lifecycle.changed.subscribe();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = { lock(&owner.kernel_lifecycle.serial).accepted_jobs != 0 };
            if !pending {
                assert!(
                    !*owner.kernel_quarantine.borrow(),
                    "successful M1 teardown encountered native quarantine"
                );
                return;
            }
            changed.changed().await.expect("native job watch closed");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("native jobs remained before finish: {}", jobs(&w.db)));
}

struct M1GateRelease(Arc<TestGate>);
impl Drop for M1GateRelease {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}

// M1: actual native admission on the existing synthetic-import trust fixture.
// No shipping Spaces/host permission is inferred from these private operations.
async fn two_app_world() -> (
    Arc<crate::v1_import::NativePeerTwoAdoptedAppsFixture>,
    World,
    World,
    String,
    Arc<TestProbe>,
) {
    let fixture = crate::v1_import::native_peer_two_adopted_apps_fixture_for_test().await;
    let f = &fixture.owner;
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.principal, "edit"), (&fixture.second_principal, "edit")]),
        &f.administrator,
    )
    .await
    .unwrap();
    let a = World {
        db: f.db.clone(),
        admin: f.administrator.clone(),
        member: f.principal.clone(),
        home: home.clone(),
        caller: f
            .adopted_caller
            .clone()
            .with_channel(crate::provenance::Channel::Web),
    };
    let b = World {
        db: f.db.clone(),
        admin: f.administrator.clone(),
        member: fixture.second_principal.clone(),
        home,
        caller: fixture
            .second_adopted_caller
            .clone()
            .with_channel(crate::provenance::Channel::Web),
    };
    let id = record(&a, "Document", "note").await;
    let mut probe = TestProbe::new(None);
    Arc::get_mut(&mut probe).unwrap().fixture_owner = Some(Arc::clone(f));
    Arc::get_mut(&mut probe).unwrap().fixture_registration = Some(Box::new(
        register_writer_fixture_owner_for_test(&f.db, Arc::clone(f)),
    ));
    (fixture, a, b, id, probe)
}
async fn mixed_dirty(
    a: &World,
    b: &World,
    id: &str,
    probe: &Arc<TestProbe>,
) -> (Arc<SessionPeer>, Arc<SessionPeer>, String) {
    let (pa, oa) = open(a, id, PeerKind::Edit).await;
    let (pb, ob) = open(b, id, PeerKind::Edit).await;
    TEST_PROBE
        .scope(Arc::clone(probe), async {
            apply_as(&pa, &a.caller, "A", &update(&oa, "from A"))
                .await
                .unwrap();
            apply_as(&pb, &b.caller, "B-last", &update(&ob, "from B"))
                .await
                .unwrap();
        })
        .await;
    let body = {
        let s = pa.inner.session.state();
        assert!(s.dirty());
        let snapshot = s.registry.version_snapshot(&s.session).unwrap();
        assert_eq!(snapshot.last_accepted().unwrap().principal, b.member);
        assert_eq!(snapshot.contributors().len(), 2);
        snapshot.body().to_owned()
    };
    (Arc::new(pa), Arc::new(pb), body)
}
async fn assert_initiator_action(db: &Db, version: &Versioned, principal: &str, generation: &str) {
    let (actor, act, payload): (String, i64, String) =
        sqlx::query_as("SELECT actor,act,payload FROM content_events WHERE id=?")
            .bind(&version.event_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(actor, principal);
    let body: Value = serde_json::from_str(&payload).unwrap();
    assert!(body["coedit"].is_object());
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT seq,type,id FROM content_events WHERE act=? ORDER BY seq")
            .bind(act)
            .fetch_all(db.pool())
            .await
            .unwrap();
    let start = rows
        .iter()
        .position(|(_, t, _)| t == "kernel.app_action_started.v1")
        .unwrap();
    let own = rows
        .iter()
        .position(|(_, _, id)| id == &version.event_id)
        .unwrap();
    let finish = rows
        .iter()
        .position(|(_, t, _)| t == "kernel.app_action_recorded.v1")
        .unwrap();
    assert!(start < own && own < finish);
    assert_eq!(
        rows.iter()
            .filter(|(_, t, _)| t == "kernel.app_action_started.v1")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|(_, t, _)| t == "kernel.body_set.v1")
            .count(),
        1
    );
    let (account, install, operation, outputs): (String,String,String,String) = sqlx::query_as(
        "SELECT principal,install_generation,operation,outputs_json FROM kernel_app_actions WHERE event_id=?")
        .bind(&rows[finish].2).fetch_one(db.pool()).await.unwrap();
    assert_eq!(account, principal);
    assert_eq!(install, generation);
    assert_eq!(operation, "update_record");
    let outputs: Vec<Value> = serde_json::from_str(&outputs).unwrap();
    assert!(outputs
        .iter()
        .any(|v| v["event_id"] == version.event_id && v["event_seq"] == rows[own].0));
    assert_eq!(
        version.proof.body_event_id.as_deref(),
        Some(version.event_id.as_str())
    );
    assert_eq!(version.proof.body_event_seq, Some(rows[own].0));
}
#[tokio::test]
async fn explicit_requester_a_persists_b_last_and_reverse() {
    for reverse in [false, true] {
        let (f, a, b, id, probe) = two_app_world().await;
        let (a, b, generation) = if reverse {
            (b, a, f.second_adopted_generation.clone())
        } else {
            (a, b, f.owner.adopted_generation.clone())
        };
        let (pa, pb, body) = mixed_dirty(&a, &b, &id, &probe).await;
        let before = kernel::body_history_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .len();
        let version = TEST_PROBE
            .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            kernel::body_history_as(&a.db, &a.admin, &id)
                .await
                .unwrap()
                .len(),
            before + 1
        );
        assert_eq!(
            kernel::read_record_as(&a.db, &a.admin, &id)
                .await
                .unwrap()
                .unwrap()
                .body
                .as_deref(),
            Some(body.as_str())
        );
        assert_eq!(version.contributors.len(), 2);
        assert!(version
            .contributors
            .iter()
            .any(|c| c.app.as_ref().unwrap().install_event_id == f.owner.adopted_generation));
        assert!(version
            .contributors
            .iter()
            .any(|c| c.app.as_ref().unwrap().install_event_id == f.second_adopted_generation));
        assert_initiator_action(&a.db, &version, &a.member, &generation).await;
        assert!(!pa.inner.session.state().dirty());
        m1_wait_for_owned_jobs_before_finish(&a).await;
        finish(
            a,
            vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
        )
        .await;
        drop(b);
        drop(probe);
        drop(f);
    }
}
#[tokio::test]
async fn explicit_revoked_requester_never_falls_back_to_valid_peer() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, _) = mixed_dirty(&a, &b, &id, &probe).await;
    let history_before = kernel::body_history_as(&a.db, &a.admin, &id)
        .await
        .unwrap()
        .len();
    let lane = Arc::clone(&db_sessions(&a.db).kernel_lane)
        .lock_owned()
        .await;
    let queued = test_gate(&a.db, super::super::TestStage::LaneQueued, false);
    let _release = M1GateRelease(Arc::clone(&queued));
    let operation = {
        let pa = pa.clone();
        let caller = a.caller.clone();
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { TEST_PROBE.scope(probe, version_as(&pa, &caller)).await })
    };
    tokio::time::timeout(Duration::from_secs(2), queued.entered.notified())
        .await
        .unwrap();
    kernel::app_installs::remove_as(
        &a.db,
        &a.member,
        &f.owner.pin.package,
        &f.owner.adopted_generation,
    )
    .await
    .unwrap();
    queued.release.notify_one();
    drop(lane);
    assert!(operation.await.unwrap().is_err());
    assert!(pa.inner.session.state().dirty());
    assert!(kernel::read_record_as(&a.db, &b.member, &id)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        kernel::body_history_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .len(),
        history_before
    );
    finish(
        a,
        vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
    )
    .await;
    drop(b);
    drop(probe);
    drop(f);
}
#[tokio::test]
async fn explicit_peer_incarnation_and_app_identity_change_refuse() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, _) = mixed_dirty(&a, &b, &id, &probe).await;
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            assert!(version_as(&pa, &f.owner.staged_caller).await.is_err());
            assert!(version_as(&pa, &b.caller).await.is_err());
        })
        .await;
    let (replacement, _) = open_for_test(
        &a.db,
        &a.caller,
        OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(pa.inner.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(TEST_PROBE
        .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
        .await
        .is_err());
    assert!(replacement.inner.session.state().dirty());
    finish(
        a,
        vec![
            Arc::try_unwrap(pa).unwrap(),
            Arc::try_unwrap(pb).unwrap(),
            replacement,
        ],
    )
    .await;
    drop(b);
    drop(probe);
    drop(f);
}
#[tokio::test]
async fn explicit_ambient_claim_consistency_and_absent_dispatch_app_admission() {
    for ambient in [false, true] {
        let (f, a, b, id, probe) = two_app_world().await;
        let (pa, pb, _) = mixed_dirty(&a, &b, &id, &probe).await;
        let args = json!({"id":id});
        // Independently constructed ordinary account request, never an app
        // Caller with a removed claim. Ambient Some may not attach an app.
        let actual_nonapp = Caller::authenticated("account-a");
        let (nonapp_peer, _) = open_for_test(
            &a.db,
            &actual_nonapp,
            OpenRequest {
                record_id: id.clone(),
                mode: PeerKind::Edit,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        let app_on_nonapp = crate::provenance::ProvenanceDispatch::from_caller(
            &a.caller,
            "update_record",
            &args,
            None,
        );
        assert!(app_on_nonapp
            .scope(TEST_PROBE.scope(Arc::clone(&probe), version_as(&nonapp_peer, &actual_nonapp),))
            .await
            .is_err());
        let foreign = crate::provenance::ProvenanceDispatch::from_caller(
            &b.caller,
            "update_record",
            &args,
            None,
        );
        assert!(foreign
            .scope(TEST_PROBE.scope(Arc::clone(&probe), version_as(&pa, &a.caller)))
            .await
            .is_err());
        let same = crate::provenance::ProvenanceDispatch::from_caller(
            &a.caller,
            "update_record",
            &args,
            None,
        );
        let result = if ambient {
            same.scope(TEST_PROBE.scope(Arc::clone(&probe), version_as(&pa, &a.caller)))
                .await
        } else {
            TEST_PROBE
                .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
                .await
        };
        let version = result.unwrap().unwrap();
        assert_initiator_action(&a.db, &version, &a.member, &f.owner.adopted_generation).await;
        m1_wait_for_owned_jobs_before_finish(&a).await;
        finish(
            a,
            vec![
                Arc::try_unwrap(pa).unwrap(),
                Arc::try_unwrap(pb).unwrap(),
                nonapp_peer,
            ],
        )
        .await;
        drop(b);
        drop(probe);
        drop(f);
    }
}
#[tokio::test]
async fn explicit_clean_current_admission_creates_no_effect() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, _) = open(&a, &id, PeerKind::Edit).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(a.db.pool())
        .await
        .unwrap();
    assert!(TEST_PROBE
        .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
        .await
        .unwrap()
        .is_none());
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(a.db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    kernel::app_installs::remove_as(
        &a.db,
        &a.member,
        &f.owner.pin.package,
        &f.owner.adopted_generation,
    )
    .await
    .unwrap();
    assert!(TEST_PROBE
        .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
        .await
        .is_err());
    finish(a, vec![pa]).await;
    drop(b);
    drop(probe);
    drop(f);
}
#[tokio::test]
async fn explicit_current_contributor_revocation_blocks_original_requester() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, _) = mixed_dirty(&a, &b, &id, &probe).await;
    let history_before = kernel::body_history_as(&a.db, &a.admin, &id)
        .await
        .unwrap()
        .len();
    let actions_before: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_actions")
        .fetch_one(a.db.pool())
        .await
        .unwrap();
    kernel::app_installs::remove_as(
        &a.db,
        &b.member,
        &f.second_pin.package,
        &f.second_adopted_generation,
    )
    .await
    .unwrap();
    assert!(TEST_PROBE
        .scope(Arc::clone(&probe), version_as(&pa, &a.caller))
        .await
        .is_err());
    assert!(pa.inner.session.state().dirty());
    assert_eq!(
        kernel::body_history_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .len(),
        history_before
    );
    let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_actions")
        .fetch_one(a.db.pool())
        .await
        .unwrap();
    assert_eq!(actions, actions_before);
    finish(
        a,
        vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
    )
    .await;
    drop(b);
    drop(probe);
    drop(f);
}
#[tokio::test]
async fn explicit_dirty_lease_drops_after_known_install_outside_native_locks() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, oa) = open(&a, &id, PeerKind::Edit).await;
    let (sender, receiver) = std::sync::mpsc::channel();
    struct Guard {
        room: std::sync::Weak<LiveSession>,
        sender: std::sync::mpsc::Sender<bool>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let available = self.room.upgrade().is_some_and(|room| {
                let state = room.state.try_lock();
                state.as_ref().is_ok_and(|s| !s.dirty())
                    && room
                        .owner
                        .upgrade()
                        .is_some_and(|o| o.kernel_lifecycle.serial.try_lock().is_ok())
            });
            let _ = self.sender.send(available);
        }
    }
    let weak = Arc::downgrade(&pa.inner.session);
    let hook = kernel_lifecycle::test_admission_hook(
        &a.db,
        kernel_lifecycle::AdmissionKind::Dirty,
        Arc::new(move |_| {
            Some(Box::new(Guard {
                room: weak.clone(),
                sender: sender.clone(),
            }))
        }),
    );
    TEST_PROBE
        .scope(Arc::clone(&probe), async {
            apply_as(
                &pa,
                &a.caller,
                "dirty-lease",
                &update(&oa, "owned dirty lease"),
            )
            .await
            .unwrap();
            assert!(receiver.try_recv().is_err());
            version_as(&pa, &a.caller).await.unwrap().unwrap();
        })
        .await;
    assert!(receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap());
    drop(hook);
    m1_wait_for_owned_jobs_before_finish(&a).await;
    finish(a, vec![pa]).await;
    drop(b);
    drop(probe);
    drop(f);
}
#[tokio::test]
async fn explicit_lost_commit_ack_and_quarantine_retain_fixture_owner() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, body) = mixed_dirty(&a, &b, &id, &probe).await;
    let weak = Arc::downgrade(&f.owner);
    let gate = test_gate(&a.db, super::super::TestStage::AfterDurability, true);
    let _release = M1GateRelease(Arc::clone(&gate));
    let operation = {
        let pa = pa.clone();
        let caller = a.caller.clone();
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { TEST_PROBE.scope(probe, version_as(&pa, &caller)).await })
    };
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    drop(f);
    drop(probe);
    drop(b);
    gate.release.notify_one();
    assert!(operation.await.unwrap().is_err());
    assert!(weak.upgrade().is_some());
    assert!(*db_sessions(&a.db).kernel_quarantine.borrow());
    assert!(pa.inner.session.ops.try_lock().is_err());
    assert!(pa.inner.session.state().dirty());
    assert_eq!(
        kernel::read_record_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some(body.as_str())
    );
    let teardown = weak.upgrade().unwrap();
    dispose_settled_quarantine_for_test(&a.db).await;
    finish(
        a,
        vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
    )
    .await;
    drop(teardown);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn explicit_known_commit_seal_before_install_retains_dirty_native_graph() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, body) = mixed_dirty(&a, &b, &id, &probe).await;
    let gate = test_gate(&a.db, super::super::TestStage::BeforeCommit, false);
    let _release = M1GateRelease(Arc::clone(&gate));
    let operation = {
        let pa = Arc::clone(&pa);
        let caller = a.caller.clone();
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { TEST_PROBE.scope(probe, version_as(&pa, &caller)).await })
    };
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    let _witness = kernel_lifecycle::seal_kernel_retirement(&a.db);
    gate.release.notify_one();
    let error = operation.await.unwrap().unwrap_err();
    assert!(error
        .to_string()
        .contains("committed but native installation is retained"));
    assert!(pa.inner.session.state().dirty());
    assert!(pa.inner.session.ops.try_lock().is_err());
    assert!(*db_sessions(&a.db).kernel_quarantine.borrow());
    assert_eq!(
        kernel::read_record_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some(body.as_str())
    );
    let retained = {
        let mut all = lock(&RETAINED_EXPLICIT_INSTALLS);
        let (ours, other): (Vec<_>, Vec<_>) = std::mem::take(&mut *all)
            .into_iter()
            .partition(|entry| entry.owner.db.same_handle(&a.db));
        *all = other;
        ours
    };
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].snapshot.body(), body);
    assert!(retained[0].base.proof.body_event_id.is_some());
    // Known commit has ALREADY disposed its actual lease. Test teardown drops
    // native guards/slot only; this neither rolls back nor unseals/reconciles it.
    drop(retained);
    finish(
        a,
        vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
    )
    .await;
    drop(b);
    drop(probe);
    drop(f);
}

#[tokio::test]
async fn explicit_response_cancellation_keeps_original_initiator_through_commit() {
    let (f, a, b, id, probe) = two_app_world().await;
    let (pa, pb, body) = mixed_dirty(&a, &b, &id, &probe).await;
    let gate = test_gate(&a.db, super::super::TestStage::BeforeCommit, false);
    struct Release(Arc<TestGate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release.notify_one();
        }
    }
    let _release = Release(Arc::clone(&gate));
    let mut events = pa.subscribe();
    let owner = db_sessions(&a.db);
    let mut changed = owner.kernel_lifecycle.changed.subscribe();
    let response = {
        let pa = Arc::clone(&pa);
        let caller = a.caller.clone();
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { TEST_PROBE.scope(probe, version_as(&pa, &caller)).await })
    };
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    assert!(events.try_recv().is_err());
    response.abort();
    assert!(response.await.unwrap_err().is_cancelled());
    gate.release.notify_one();
    let version = match tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .unwrap()
        .unwrap()
    {
        SessionEvent::Versioned(version) => version,
        other => panic!("unexpected event before explicit commit: {other:?}"),
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let pending = { lock(&owner.kernel_lifecycle.serial).accepted_jobs != 0 };
            if !pending {
                break;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&a.db, &a.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some(body.as_str())
    );
    assert_initiator_action(&a.db, &version, &a.member, &f.owner.adopted_generation).await;
    assert!(!pa.inner.session.state().dirty());
    finish(
        a,
        vec![Arc::try_unwrap(pa).unwrap(), Arc::try_unwrap(pb).unwrap()],
    )
    .await;
    drop(b);
    drop(probe);
    drop(f);
}
