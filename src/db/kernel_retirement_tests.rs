//! Inactive L2 native candidates. No execution until qualified L1 is stacked and
//! root releases Rust. Real native authorization/transactions and physical pools.
use super::*;
use crate::coedit::live::{kernel_writes, OpenRequest, Opened, SessionPeer};
use crate::coedit::PeerKind;
use crate::{events::KERNEL_ROOT_ID, kernel, mcp::Caller};
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};

// The ONLY installation sites. Existing verified factories return their owned
// fresh handle straight into the private consuming installer, before publication.
async fn create_registered(path: &str) -> (Db, String) {
    let (db, admin) = kernel::create_v2_database(path, "account", "Admin", "acct:retirement-admin")
        .await
        .unwrap();
    (install_verified_owned(db).unwrap(), admin)
}
async fn open_registered(path: &Path) -> Db {
    install_verified_owned(
        kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .unwrap(),
    )
    .unwrap()
}
async fn open_registered_readonly(path: &Path) -> Db {
    install_verified_owned(open_marked_v2_database_read_only_at(path).await.unwrap()).unwrap()
}
fn coordinator(witness: &BodyRetirementWitness) -> Arc<Coordinator> {
    match &witness.future {
        BodyRetirement::Kernel(coordinator) => coordinator.clone(),
        BodyRetirement::Legacy(_) => panic!("fixture was not explicitly registered"),
    }
}
fn physical_gate(coordinator: &Coordinator, panic: bool) -> Arc<PhysicalCheckpoint> {
    let gate = Arc::new(PhysicalCheckpoint {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        panic,
    });
    *coordinator.physical_checkpoint.lock().unwrap() = Some(gate.clone());
    gate
}
async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    // Timeout only fails a proof; it never establishes an ordering or ACK.
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("retirement fixture made no progress")
}

struct World {
    db: Db,
    admin: String,
    editor: String,
    home: String,
    record: String,
    caller: Caller,
}
async fn world() -> World {
    let (db, admin) = create_registered(":memory:").await;
    let editor =
        kernel::create_principal(&db, "account", "Editor", "acct:retirement-editor", &admin)
            .await
            .unwrap();
    let package = crate::v2_standard::document4_package();
    let identity = kernel::install_package_as(&db, &admin, &package)
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
    let home = kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&editor, "edit")]),
        &admin,
    )
    .await
    .unwrap();
    let record = kernel::create_json_as(
        &db,
        &admin,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        r#"{"title":"Retirement proof"}"#,
        &home,
    )
    .await
    .unwrap();
    World {
        db,
        admin,
        editor,
        home,
        record,
        caller: Caller::authenticated("acct:retirement-editor"),
    }
}
async fn open_editor(world: &World) -> (SessionPeer, Opened) {
    kernel_writes::open_for_test(
        &world.db,
        &world.caller,
        OpenRequest {
            record_id: world.record.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap()
}
async fn dirty(peer: &SessionPeer, opened: &Opened) {
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    let sync = peer.sync(&[]).await.unwrap();
    doc.transact_mut()
        .apply_update(Update::decode_v1(&sync).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    let text = doc.get_or_insert_text("body");
    let end = text.get_string(&doc.transact()).len() as u32;
    text.insert(&mut doc.transact_mut(), end, "retained retirement text");
    let update = doc.transact().encode_diff_v1(&before);
    peer.apply("retirement-proof", &update).await.unwrap();
}
async fn body_events(db: &Db, record: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.body_set.v1'",
    )
    .bind(record)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn verified_test_factories_alone_install_marker_and_reject_shared_or_stopped_handle() {
    let (db, _) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:unregistered")
        .await
        .unwrap();
    assert!(db.kernel_lifecycle.is_none());
    let other = db.clone();
    assert!(install_verified_owned(db).is_err());
    assert!(other.kernel_lifecycle.is_none());
    other.close().await;
    let (db, _) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:stopped")
        .await
        .unwrap();
    db.body_jobs.stop_submission();
    assert!(install_verified_owned(db).is_err());
    let (db, _) = create_registered(":memory:").await;
    assert!(db.kernel_lifecycle.is_some());
    let clone = db.clone();
    let same = install_verified_owned(clone).unwrap();
    assert!(same.same_handle(&db));
    assert!(bounded(db.fence_body_retirement().drain()).await);
}

#[tokio::test]
async fn accepted_reservation_without_spawn_is_pending_and_never_pool_ack() {
    let (db, _) = create_registered(":memory:").await;
    let accepted = kernel_writes::hold_job_slots_for_test(&db, 1);
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    assert!(matches!(
        coordinator.observe(),
        Observation::Kernel(KernelRetirementState::Pending {
            accepted_jobs: 1,
            ..
        })
    ));
    assert!(!witness.retirement_complete());
    assert!(!db.pool().is_closed() && !db.write_pool().is_closed());
    assert!(kernel_writes::owned_result(db.clone(), async { Ok(()) })
        .await
        .is_err());
    drop(accepted);
    assert!(bounded(witness.drain()).await);
    assert!(witness.retirement_complete());
    assert!(!live::release_idle_database(&db));
}

#[tokio::test]
async fn retirement_seal_refuses_accepted_seed_before_sql_and_keeps_original_owner() {
    let world = world().await;
    let gate =
        kernel_writes::test_gate(&world.db, kernel_writes::TestStage::SeedBeforeFence, false);
    let opening = {
        let db = world.db.clone();
        let caller = world.caller.clone();
        let record = world.record.clone();
        tokio::spawn(async move {
            kernel_writes::open_for_test(
                &db,
                &caller,
                OpenRequest {
                    record_id: record,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
        })
    };
    bounded(gate.entered.notified()).await;
    let witness = world.db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    assert!(matches!(
        coordinator.observe(),
        Observation::Kernel(KernelRetirementState::Pending { .. })
    ));
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    gate.release.notify_one();
    assert!(bounded(opening).await.unwrap().is_err());
    assert!(kernel_writes::base_for_test(&world.db, &world.record).is_none());
    assert_eq!(body_events(&world.db, &world.record).await, 0);
    assert!(bounded(witness.drain()).await);
    assert!(!live::release_idle_database(&world.db));
}

#[tokio::test]
async fn native_policy_blocked_sealed_retirement_retains_custody_without_restore_bypass() {
    let world = world().await;
    let (peer, opened) = open_editor(&world).await;
    dirty(&peer, &opened).await;
    kernel::replace_home_policy(
        &world.db,
        &world.admin,
        &world.home,
        &[(&world.admin, "manage")],
    )
    .await
    .unwrap();
    let witness = world.db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let seal = coordinator.seal_id();
    assert!(!bounded(witness.drain()).await);
    let observation = bounded(async {
        loop {
            match coordinator.observe() {
                Observation::Kernel(KernelRetirementState::Pending { .. }) => {
                    tokio::task::yield_now().await
                }
                settled => break settled,
            }
        }
    })
    .await;
    assert!(matches!(
        observation,
        Observation::Kernel(KernelRetirementState::RetainedBlocked { .. })
    ));
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    assert!(!world.db.pool().is_closed() && !world.db.write_pool().is_closed());
    assert_eq!(
        kernel_writes::live_text_for_test(&world.db, &world.record).as_deref(),
        Some("retained retirement text")
    );
    assert_eq!(body_events(&world.db, &world.record).await, 0);
    // Ordinary policy writes cannot restore rights after the terminal seal.
    // This is an intentional availability boundary, never a test SQL bypass.
    assert!(kernel::replace_home_policy(
        &world.db,
        &world.admin,
        &world.home,
        &[(&world.admin, "manage"), (&world.editor, "edit")]
    )
    .await
    .is_err());
    let retry = world.db.fence_body_retirement();
    assert!(retry.future.ptr_eq(&witness.future));
    assert_eq!(coordinator.seal_id(), seal);
    assert!(!bounded(retry.drain()).await);
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    assert!(coordinator.lock().retained.is_some());
}

#[tokio::test]
async fn external_fleet_barrier_recovers_same_seal_and_retains_real_lease_through_cut() {
    use crate::mcp::{DeploymentAdmission, DeploymentMutationBarrier, OperationAccess};
    let world = world().await;
    let (peer, opened) = open_editor(&world).await;
    dirty(&peer, &opened).await;
    let barrier = DeploymentMutationBarrier::default();
    let hook_barrier = barrier.clone();
    // Root-approved L1 test-only keyed RAII shim, installed by L1 before stack.
    // No global hook, synthetic readiness flag, policy mutation or seal bypass.
    let _hook = live::test_kernel_fleet_admission(
        &world.db,
        Arc::new(move |_| {
            match hook_barrier.admit(
                &crate::DeploymentReadOnlyOperation::server("l2_fleet_retirement_proof"),
                OperationAccess::Mutation,
            ) {
                Ok(DeploymentAdmission::Writable(lease)) => Some(Box::new(lease) as Box<dyn Send>),
                _ => None,
            }
        }),
    );
    let frozen = barrier.freeze().await;
    let witness = world.db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let seal = coordinator.seal_id();
    assert!(!bounded(witness.drain()).await);
    assert!(!world.db.pool().is_closed() && !world.db.write_pool().is_closed());
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    assert_eq!(body_events(&world.db, &world.record).await, 0);
    drop(frozen); // Real external authority restoration, outside sealed storage.
    let cut_gate =
        kernel_writes::test_gate(&world.db, kernel_writes::TestStage::BeforeCommit, false);
    let closing = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drain().await })
    };
    bounded(cut_gate.entered.notified()).await;
    let second_freeze = barrier.freeze();
    tokio::pin!(second_freeze);
    assert!(
        futures::poll!(second_freeze.as_mut()).is_pending(),
        "actual cut must retain the fleet lease"
    );
    assert_eq!(coordinator.seal_id(), seal);
    cut_gate.release.notify_one();
    assert!(bounded(closing).await.unwrap());
    let freeze = bounded(second_freeze).await;
    assert_eq!(coordinator.observe(), Observation::Complete);
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 1);
    assert_eq!(coordinator.seal_id(), seal);
    drop(freeze);
}

#[tokio::test]
async fn raw_uncertain_transaction_without_room_prevents_retirement_and_reopen_writes() {
    let (db, _) = create_registered(":memory:").await;
    let gate = kernel_writes::test_gate(&db, kernel_writes::TestStage::AfterDurability, true);
    let writing = {
        let db = db.clone();
        kernel_writes::owned_result(db.clone(), async move {
            let mut tx = kernel_writes::KernelTransaction::begin(&db, (), |_, _| {}).await?;
            sqlx::query("CREATE TEMP TABLE retirement_uncertain_owner(value INTEGER)")
                .execute(&mut *tx.parts().0)
                .await?;
            tx.commit().await
        })
    };
    tokio::pin!(writing);
    assert!(futures::poll!(writing.as_mut()).is_pending());
    bounded(gate.entered.notified()).await;
    gate.release.notify_one();
    assert!(bounded(writing).await.is_err());
    assert_eq!(kernel_writes::retained_transactions_for_test(&db), 1);
    let witness = db.fence_body_retirement();
    assert!(!bounded(witness.drain()).await);
    let coordinator = coordinator(&witness);
    assert!(matches!(
        coordinator.observe(),
        Observation::Kernel(KernelRetirementState::Uncertain { .. })
    ));
    assert!(!db.pool().is_closed() && !db.write_pool().is_closed());
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    let reopened = open_registered(db.path()).await;
    assert!(
        kernel_writes::owned_result(reopened.clone(), async { Ok(()) })
            .await
            .is_err()
    );
    assert!(!bounded(reopened.fence_body_retirement().drain()).await);
    // Actual uncertain tx/slot/handle custody is retained. No test disposes it.
}

#[tokio::test]
async fn kernel_quiescence_and_body_readiness_are_independent_conjuncts() {
    let (db, _) = create_registered(":memory:").await;
    let ticket = db.register_body_job().unwrap();
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    assert_eq!(coordinator.observe(), Observation::BodyUnresolved);
    let mut observing = Box::pin(witness.drain());
    assert!(futures::poll!(observing.as_mut()).is_pending());
    assert!(!db.pool().is_closed());
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    drop(observing);
    ticket.no_physical_started().unwrap();
    assert!(bounded(witness.drain()).await);
}

#[tokio::test]
async fn cancelled_and_repeated_observers_share_original_cut_and_physical_future() {
    let world = world().await;
    let (peer, opened) = open_editor(&world).await;
    dirty(&peer, &opened).await;
    let cut_gate =
        kernel_writes::test_gate(&world.db, kernel_writes::TestStage::BeforeCommit, false);
    let witness = world.db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let physical = physical_gate(&coordinator, false);
    let first = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drain().await })
    };
    bounded(cut_gate.entered.notified()).await;
    first.abort();
    let _ = first.await;
    assert!(!world.db.pool().is_closed());
    let second = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drain().await })
    };
    let third = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drain().await })
    };
    cut_gate.release.notify_one();
    bounded(physical.entered.notified()).await;
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 1);
    assert_eq!(body_events(&world.db, &world.record).await, 1);
    assert!(!witness.retirement_complete());
    physical.release.notify_one();
    assert!(bounded(second).await.unwrap());
    assert!(bounded(third).await.unwrap());
    assert_eq!(coordinator.observe(), Observation::Complete);
    {
        let state = coordinator.lock();
        assert!(state.retained.is_none() && state.physical.is_none());
    }
}

#[tokio::test]
async fn physical_ack_requires_each_actual_pool_checkout_to_return() {
    for kind in ["read", "write", "governed", "capture"] {
        let (db, _) = create_registered(":memory:").await;
        let pool = match kind {
            "read" => db.read_pool.clone(),
            "write" => db.write_pool.clone(),
            "governed" => db.governed_pool.clone(),
            _ => {
                // Real separate pool materialized before fencing, not a fake
                // readiness bit. This handle is non-enrolled; no driver change.
                let pool = SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(db.write_pool.connect_options().as_ref().clone())
                    .await
                    .unwrap();
                db.capture_pool.set(pool.clone()).unwrap();
                pool
            }
        };
        let connection = pool.acquire().await.unwrap();
        let witness = db.fence_body_retirement();
        let coordinator = coordinator(&witness);
        let mut observing = Box::pin(witness.drain());
        assert!(futures::poll!(observing.as_mut()).is_pending());
        assert!(!witness.retirement_complete());
        assert!(pool.size() > 0);
        assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 1);
        drop(observing); // original Shared, not SQLx close state, stays retained.
        assert!(coordinator.lock().physical.is_some());
        drop(connection);
        assert!(bounded(witness.drain()).await);
        assert!(pool.is_closed() && pool.size() == 0);
        assert!(witness.retirement_complete());
    }
}

#[tokio::test]
async fn same_storage_independent_readonly_handle_and_clones_have_distinct_pool_ack() {
    let (db, _) = create_registered(":memory:").await;
    let reopened = open_registered(db.path()).await;
    let readonly = open_registered_readonly(db.path()).await;
    let clone = db.clone();
    assert!(clone.same_handle(&db));
    assert!(!reopened.same_handle(&db) && !readonly.same_handle(&db));
    let held = readonly.pool().acquire().await.unwrap();
    let first = db.fence_body_retirement();
    let second = reopened.fence_body_retirement();
    let third = readonly.fence_body_retirement();
    assert_eq!(
        coordinator(&first).seal_id(),
        coordinator(&second).seal_id()
    );
    assert_eq!(coordinator(&first).seal_id(), coordinator(&third).seal_id());
    assert!(bounded(first.drain()).await && bounded(second.drain()).await);
    assert!(first.retirement_complete() && !third.retirement_complete());
    let mut close_readonly = Box::pin(third.drain());
    assert!(futures::poll!(close_readonly.as_mut()).is_pending());
    drop(close_readonly);
    assert!(!third.retirement_complete());
    drop(held);
    assert!(bounded(third.drain()).await);
    assert!(!live::release_idle_database(&db));
    // Unregistered same-key open cannot evade supported storage-wide seal.
    let raw = kernel::open_marked_v2_database(db.path().to_str().unwrap())
        .await
        .unwrap();
    assert!(raw.kernel_lifecycle.is_none());
    assert!(kernel_writes::owned_result(raw.clone(), async { Ok(()) })
        .await
        .is_err());
    raw.close().await;
}

#[tokio::test]
async fn acknowledged_clean_completion_releases_new_handle_and_future_cycles() {
    let (db, _) = create_registered(":memory:").await;
    let weak_cache = Arc::downgrade(&db.body_retirement);
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let weak_coordinator = Arc::downgrade(&coordinator);
    assert!(bounded(witness.drain()).await);
    {
        let state = coordinator.lock();
        assert!(state.retained.is_none() && state.physical.is_none());
    }
    let seal = coordinator.seal_id();
    assert_eq!(coordinator.observe(), Observation::Complete);
    assert_eq!(coordinator.seal_id(), seal);
    drop(coordinator);
    drop(witness);
    drop(db);
    assert!(
        weak_cache.upgrade().is_none(),
        "new acknowledged cache must not retain its own Db"
    );
    assert!(weak_coordinator.upgrade().is_none());
}

#[test]
fn no_runtime_fence_retains_pools_then_later_observer_drives_original_future() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (db, _) = runtime.block_on(create_registered(":memory:"));
    drop(runtime);
    let weak_cache = Arc::downgrade(&db.body_retirement);
    db.close_in_background();
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    assert!(!db.pool().is_closed() && !db.write_pool().is_closed());
    assert!(!witness.retirement_complete());
    assert!(!coordinator.lock().background_running);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(runtime.block_on(bounded(witness.drain())));
    drop(coordinator);
    drop(witness);
    drop(db);
    drop(runtime);
    assert!(weak_cache.upgrade().is_none());
}

#[test]
fn entered_stopped_runtime_background_rejection_returns_and_retains_original_custody() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (db, _) = runtime.block_on(create_registered(":memory:"));
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let seal = coordinator.seal_id();
    let handle = runtime.handle().clone();
    drop(runtime); // Actual runtime shutdown; retained Handle still enters.
    let (returned, received) = std::sync::mpsc::sync_channel(1);
    let worker_db = db.clone();
    let worker = std::thread::spawn(move || {
        let _entered = handle.enter();
        worker_db.close_in_background();
        returned.send(()).unwrap();
    });
    // Only a failure bound. Runtime shutdown, not a sleep, establishes rejection.
    received
        .recv_timeout(Duration::from_secs(10))
        .expect("stopped-runtime spawn must not deadlock background close");
    worker.join().unwrap();
    assert_eq!(coordinator.observe(), Observation::Uncertain);
    assert!(!witness.retirement_complete());
    assert!(!db.pool().is_closed() && !db.write_pool().is_closed());
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 0);
    {
        let state = coordinator.lock();
        assert!(!state.background_running && state.background.is_none());
        assert_eq!(state.background_generation, 1);
        assert!(state.retained.is_some() && state.physical.is_none());
        assert!(state.acknowledged.is_none());
    }
    assert_eq!(coordinator.seal_id(), seal);
    let retry = db.fence_body_retirement();
    assert!(retry.future.ptr_eq(&witness.future));
    match &retry.future {
        BodyRetirement::Kernel(original) => assert!(Arc::ptr_eq(&coordinator, original)),
        BodyRetirement::Legacy(_) => panic!("registered retry lost coordinator"),
    }
    // Original unresolved custody stays retained; no replacement/disposal/ACK.
}

#[test]
fn background_completion_before_handle_publication_cannot_revive_slot_or_task_cycle() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (db, _) = runtime.block_on(create_registered(":memory:"));
    let weak_cache = Arc::downgrade(&db.body_retirement);
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let weak_coordinator = Arc::downgrade(&coordinator);
    let (entered, spawned) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::sync_channel(1);
    *coordinator.background_publication.lock().unwrap() =
        Some(Arc::new(BackgroundPublicationCheckpoint {
            entered,
            release: Mutex::new(released),
        }));
    let handle = runtime.handle().clone();
    let worker_db = db.clone();
    let (returned, received) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _entered = handle.enter();
        worker_db.close_in_background();
        returned.send(()).unwrap();
    });
    spawned
        .recv_timeout(Duration::from_secs(10))
        .expect("spawn must reach pre-publication checkpoint");
    runtime.block_on(bounded(async {
        while {
            let state = coordinator.lock();
            state.background_running
        } {
            tokio::task::yield_now().await;
        }
    }));
    // The task's terminal guard ran while its JoinHandle was still local to
    // start_background. The task itself established actual physical ACK.
    assert!(witness.retirement_complete());
    assert_eq!(coordinator.observe(), Observation::Complete);
    {
        let state = coordinator.lock();
        assert!(state.background.is_none());
        assert_eq!(state.background_generation, 1);
        assert!(state.retained.is_none() && state.physical.is_none());
    }
    // A repeated observer while the old handle awaits publication must coalesce.
    {
        let _entered = runtime.enter();
        db.close_in_background();
    }
    assert_eq!(coordinator.lock().background_generation, 1);
    release.send(()).unwrap();
    received
        .recv_timeout(Duration::from_secs(10))
        .expect("completed attempt must discard its unpublished handle");
    worker.join().unwrap();
    {
        let state = coordinator.lock();
        assert!(!state.background_running && state.background.is_none());
    }
    assert!(!coordinator.uncertain.load(Ordering::Acquire));
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 1);
    drop(coordinator);
    drop(witness);
    drop(db);
    drop(runtime);
    assert!(weak_cache.upgrade().is_none());
    assert!(weak_coordinator.upgrade().is_none());
}

#[tokio::test]
async fn background_observers_coalesce_and_release_task_handle_cycle_after_ack() {
    let (db, _) = create_registered(":memory:").await;
    let witness = db.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let gate = physical_gate(&coordinator, false);
    let weak_cache = Arc::downgrade(&db.body_retirement);
    db.close_in_background();
    bounded(gate.entered.notified()).await;
    for _ in 0..8 {
        db.close_in_background();
    }
    assert_eq!(coordinator.physical_starts.load(Ordering::SeqCst), 1);
    gate.release.notify_one();
    assert!(bounded(witness.drain()).await);
    bounded(async {
        while {
            let state = coordinator.lock();
            state.background_running
        } {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(coordinator.lock().background.is_none());
    drop(coordinator);
    drop(witness);
    drop(db);
    assert!(weak_cache.upgrade().is_none());
}

#[tokio::test]
async fn physical_panic_and_background_abort_never_ack_or_lose_original_custody() {
    let (db, _) = create_registered(":memory:").await;
    let witness = db.fence_body_retirement();
    let panic_coordinator = coordinator(&witness);
    let gate = physical_gate(&panic_coordinator, true);
    let observing = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drain().await })
    };
    bounded(gate.entered.notified()).await;
    gate.release.notify_one();
    assert!(!bounded(observing).await.unwrap());
    assert_eq!(panic_coordinator.observe(), Observation::Uncertain);
    assert!(panic_coordinator.lock().retained.is_some());
    assert!(!witness.retirement_complete());

    let (other, _) = create_registered(":memory:").await;
    let witness = other.fence_body_retirement();
    let coordinator = coordinator(&witness);
    let gate = physical_gate(&coordinator, false);
    other.close_in_background();
    bounded(gate.entered.notified()).await;
    coordinator.lock().background.as_ref().unwrap().abort();
    bounded(async {
        while {
            let state = coordinator.lock();
            state.background_running
        } {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(coordinator.observe(), Observation::Uncertain);
    {
        let state = coordinator.lock();
        assert!(state.retained.is_some() && state.physical.is_some());
    }
    assert!(!witness.retirement_complete());
    // No retry/disposal/unseal is used to turn panic/abort into an ACK.
}

#[tokio::test]
async fn none_marker_preserves_v1_background_fence_and_ordinary_kernel_reopen() {
    let v1 = crate::create_database(":memory:").await.unwrap();
    assert!(v1.kernel_lifecycle.is_none());
    v1.close_in_background();
    assert!(v1.pool().is_closed() && v1.write_pool().is_closed());
    assert!(bounded(v1.fence_body_retirement().drain()).await);
    let (db, admin) =
        kernel::create_v2_database(":memory:", "account", "Admin", "acct:ordinary-none")
            .await
            .unwrap();
    assert!(db.kernel_lifecycle.is_none());
    let path = db.path().to_path_buf();
    let principal =
        kernel::create_principal(&db, "account", "Ordinary", "acct:ordinary-second", &admin)
            .await
            .unwrap();
    assert!(!principal.is_empty());
    db.close().await;
    let reopened = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    assert!(reopened.kernel_lifecycle.is_none());
    assert!(
        kernel_writes::owned_result(reopened.clone(), async { Ok(()) })
            .await
            .is_ok()
    );
    reopened.close().await;
}

/// The background alias verifier is retained by the SAME physical retirement
/// future as other readers. Cancelling a drain observer cannot acknowledge or
/// abandon the verifier while its original physical connection is still held.
#[tokio::test]
async fn demand_root_alias_worker_survives_retirement_observer_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_registered(dir.path().join("alias-retirement.db").to_str().unwrap()).await;
    let release = kernel::demand_root_aliases::Check::pause_close(&db).await;
    let witness = db.fence_body_retirement();
    let observer_witness = witness.clone();
    let observer = tokio::spawn(async move { observer_witness.drain().await });
    bounded(db.demand_root_aliases.stop_entered.notified()).await;
    assert!(!observer.is_finished());
    assert!(!witness.retirement_complete());
    observer.abort();
    let _ = observer.await;
    assert!(!witness.retirement_complete());
    release.notify_one();
    assert!(bounded(witness.drain()).await);
    assert!(witness.retirement_complete());
}
