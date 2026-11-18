//! L1 candidate proofs. Source-only until root authorizes Rust qualification.
use super::*;

#[tokio::test]
async fn registration_pin_and_idle_release_linearize_without_detaching_owner() {
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let gate = pin_gate(&db, PinStage::Registration);
    let worker_db = db.clone();
    let registering = std::thread::spawn(move || register_kernel_lifecycle(&worker_db));
    gate.entered.wait(); // Real lookup has pinned owner; ledger not yet written.
    let owner = existing_db_sessions(&db).unwrap();
    assert!(lock(&owner.kernel_lifecycle.serial).registered.is_empty());
    assert!(!release_idle_database(&db));
    gate.release.wait();
    let registration = registering.join().unwrap();
    assert!(Arc::ptr_eq(&registration._owner, &owner));
    drop(owner);
    // Even dropping the marker cannot erase registered participation.
    drop(registration);
    assert!(!release_idle_database(&db));
    let witness = seal_kernel_retirement(&db);
    assert_eq!(witness.observe(), KernelRetirementState::Quiescent);
    assert!(!release_idle_database(&db));
}

#[tokio::test]
async fn registered_marker_and_reopened_handle_share_exact_terminal_seal() {
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    crate::kernel::prepare_v2_database(&db).await.unwrap();
    let registration = register_kernel_lifecycle(&db);
    assert!(!release_idle_database(&db));
    let reopened = crate::kernel::open_v2_database(db.path().to_str().unwrap())
        .await
        .unwrap();
    let other = register_kernel_lifecycle(&reopened);
    assert_ne!(db.handle_id(), reopened.handle_id());
    assert!(Arc::ptr_eq(&registration._owner, &other._owner));
    let first = seal_kernel_retirement(&db);
    let second = seal_kernel_retirement(&reopened);
    assert_eq!(first.seal_id(), second.seal_id());
    assert!(Arc::ptr_eq(&first.purpose.owner, &registration._owner));
    assert!(Arc::ptr_eq(&second.purpose.owner, &registration._owner));
    assert_eq!(first.observe(), KernelRetirementState::Quiescent);
    assert_eq!(second.observe(), KernelRetirementState::Quiescent);
    assert!(kernel_writes::ensure_available(&reopened).is_err());
    assert!(!release_idle_database(&reopened));
}

#[tokio::test]
async fn no_room_reservation_pin_precedes_idle_release_and_seal_accounting() {
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let gate = pin_gate(&db, PinStage::Reservation);
    let worker_db = db.clone();
    let reserving =
        std::thread::spawn(move || kernel_writes::hold_job_slots_for_test(&worker_db, 1));
    gate.entered.wait(); // Arc pinned, before accepted-before-spawn count.
    assert!(!release_idle_database(&db));
    gate.release.wait();
    let reservation = reserving.join().unwrap();
    assert!(!release_idle_database(&db));
    let registration = register_kernel_lifecycle(&db);
    let witness = seal_kernel_retirement(&db);
    assert!(Arc::ptr_eq(&registration._owner, &witness.purpose.owner));
    assert_eq!(
        witness.observe(),
        KernelRetirementState::Pending {
            accepted_jobs: 1,
            cleanup_running: false
        }
    );
    drop(reservation);
    assert_eq!(witness.observe(), KernelRetirementState::Quiescent);
}

use crate::{events::KERNEL_ROOT_ID, kernel, mcp::Caller};
use serde_json::{json, Value};
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};

#[derive(Clone)]
struct World {
    db: crate::db::Db,
    admin: String,
    caller: Caller,
}
async fn world() -> World {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
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
            .filter(|row| row["type"] == typ)
        {
            rows.push(("vocabulary_values", json!({"id":entry["value_id"], "vocabulary_id":format!("voc:kind:{typ}"), "value":entry["token"], "status":"active", "gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null})));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "kernel-coedit-proof".into(),
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
    let v1_tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('records','vocabularies','vocabulary_values')").fetch_one(db.pool()).await.unwrap();
    assert_eq!(v1_tables, 0);
    World {
        db,
        admin,
        caller: Caller::authenticated("acct:admin"),
    }
}
async fn record(w: &World, typ: &str, kind: &str, body: Option<&str>) -> String {
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":typ,"v1_kind":kind,"title":"Foundation"}).to_string(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    if let Some(body) = body {
        let revision = kernel::read_record_as(&w.db, &w.admin, &id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::set_body_as(&w.db, &w.admin, &id, body, revision)
            .await
            .unwrap();
    }
    id
}

async fn room(w: &World, id: &str) -> (SessionPeer, Opened) {
    kernel_writes::open_for_test(
        &w.db,
        &w.caller,
        OpenRequest {
            record_id: id.into(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap()
}

async fn peer_update(peer: &SessionPeer, opened: &Opened, text: &str) -> Vec<u8> {
    let mut options =
        Options::with_client_id(yrs::ClientID::new(u64::from(opened.doc_client_ids[0])));
    options.offset_kind = OffsetKind::Bytes;
    let doc = Doc::with_options(options);
    let sync = peer.sync(&[]).await.unwrap();
    doc.transact_mut()
        .apply_update(Update::decode_v1(&sync).unwrap())
        .unwrap();
    let before = doc.transact().state_vector();
    let body = doc.get_or_insert_text("body");
    let end = body.get_string(&doc.transact()).len() as u32;
    body.insert(&mut doc.transact_mut(), end, text);
    let update = doc.transact().encode_diff_v1(&before);
    update
}

async fn append_peer(peer: &SessionPeer, opened: &Opened, text: &str) {
    let update = peer_update(peer, opened, text).await;
    peer.apply("writer-proof", &update).await.unwrap();
}

async fn update(w: &World, args: Value) -> crate::Result<Value> {
    call(w, "update_record", args).await
}
async fn call(w: &World, name: &str, args: Value) -> crate::Result<Value> {
    let mut tools = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    tools
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(w.db.clone()),
            w.caller.clone(),
            name,
            args,
        )
        .await
}

async fn stored_body(w: &World, id: &str) -> String {
    kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default()
}

fn target(w: &World, id: &str) -> Target {
    Target::new(&w.db, existing_session(&w.db, id).unwrap())
}
async fn flush(w: &World, id: &str) -> Outcome {
    finalize(
        w.db.clone(),
        target(w, id),
        Intent::Flush,
        "lifecycle proof".into(),
        None,
    )
    .await
}
async fn body_events(w: &World, id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.body_set.v1'",
    )
    .bind(id)
    .fetch_one(w.db.pool())
    .await
    .unwrap()
}
async fn observed(
    witness: &KernelRetirementWitness,
    predicate: impl Fn(&KernelRetirementState) -> bool,
) -> KernelRetirementState {
    let mut changed = witness.purpose.owner.kernel_lifecycle.changed.subscribe();
    loop {
        let state = witness.observe();
        if predicate(&state) {
            return state;
        }
        changed.changed().await.unwrap();
    }
}
async fn policy_world() -> (World, World, String, String, String, String) {
    let admin = world().await;
    let alice = kernel::create_principal(&admin.db, "account", "Alice", "acct:alice", &admin.admin)
        .await
        .unwrap();
    let bob = kernel::create_principal(&admin.db, "account", "Bob", "acct:bob", &admin.admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &admin.db,
        KERNEL_ROOT_ID,
        Some(&[(&alice, "edit"), (&bob, "edit")]),
        &admin.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_json_as(
        &admin.db,
        &admin.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Policy custody"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let revision = kernel::read_record_as(&admin.db, &admin.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&admin.db, &admin.admin, &id, "seed", revision)
        .await
        .unwrap();
    let a = World {
        caller: Caller::authenticated("acct:alice"),
        ..admin.clone()
    };
    let b = World {
        caller: Caller::authenticated("acct:bob"),
        ..admin.clone()
    };
    (a, b, id, home, alice, bob)
}

#[tokio::test]
async fn cut_actor_revocation_uses_only_another_current_native_actor() {
    let (alice, bob, id, home, a, b) = policy_world().await;
    let (peer, opened) = room(&alice, &id).await;
    let (other, _) = room(&bob, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    kernel::replace_home_policy(
        &alice.db,
        &alice.admin,
        &home,
        &[(&a, "view"), (&b, "edit")],
    )
    .await
    .unwrap();
    assert!(matches!(flush(&alice, &id).await, Outcome::Versioned(_)));
    let actor: String = sqlx::query_scalar("SELECT actor FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(alice.db.pool()).await.unwrap();
    assert_eq!(actor, b);
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(&id).fetch_one(alice.db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["coedit"]["contributors"][0]["principal"], a);
    other.leave().await;
    peer.leave().await;
}

#[tokio::test]
async fn no_eligible_actor_retains_dirty_text_without_service_recovery() {
    let (alice, _, id, home, a, _) = policy_world().await;
    let (peer, opened) = room(&alice, &id).await;
    append_peer(&peer, &opened, " dirty").await;
    let before = body_events(&alice, &id).await;
    kernel::replace_home_policy(&alice.db, &alice.admin, &home, &[(&a, "view")])
        .await
        .unwrap();
    match flush(&alice, &id).await {
        Outcome::RetainedBlocked { basis, .. } => assert!(basis.dirty),
        other => panic!("{other:?}"),
    }
    assert_eq!(body_events(&alice, &id).await, before);
    assert_eq!(
        kernel_writes::live_text_for_test(&alice.db, &id).as_deref(),
        Some("seed dirty")
    );
    // Restore through a real policy event BEFORE a terminal seal; no test unseal.
    kernel::replace_home_policy(&alice.db, &alice.admin, &home, &[(&a, "edit")])
        .await
        .unwrap();
    assert!(matches!(flush(&alice, &id).await, Outcome::Versioned(_)));
    assert_eq!(body_events(&alice, &id).await, before + 1);
    peer.leave().await;
}

#[tokio::test]
async fn revoked_pending_member_blocks_without_reattribution() {
    let (alice, bob, id, _, a, _) = policy_world().await;
    async fn roster(db: &Db, actor: &str, members: &[&str]) {
        kernel::hosted_identity::reconcile_hosted_caller(db, |_| async {
            // SAFETY: complete test host catalogue, never request input. The
            // real native reconciliation API appends/projects the actual roster.
            Ok(unsafe {
                kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                    actor.into(),
                    members.iter().map(|m| (*m).into()).collect(),
                )
            })
        })
        .await
        .unwrap();
    }
    roster(
        &alice.db,
        "acct:admin",
        &["acct:admin", "acct:alice", "acct:bob"],
    )
    .await;
    let (peer, opened) = room(&alice, &id).await;
    let (other, _) = room(&bob, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let before = body_events(&alice, &id).await;
    roster(&alice.db, "acct:admin", &["acct:admin", "acct:bob"]).await;
    assert!(matches!(
        flush(&bob, &id).await,
        Outcome::RetainedBlocked { .. }
    ));
    assert_eq!(body_events(&alice, &id).await, before);
    let room = existing_session(&alice.db, &id).unwrap();
    let state = room.state();
    assert!(state.dirty());
    let snapshot = state.registry.version_snapshot(&state.session).unwrap();
    assert_eq!(snapshot.body(), "seed retained");
    assert_eq!(snapshot.contributors()[0].principal, a);
    drop(state);
    // Real installed-app positive/mixed/revoked proofs remain explicit debt;
    // this case uses genuine membership authority, never fabricated app rows.
    drop(other);
    drop(peer);
}

#[tokio::test]
async fn known_rollback_retains_dirty_snapshot_contributors_and_database_lease() {
    let w = world().await;
    let dir = tempfile::tempdir().unwrap();
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    let dirty_store = store.clone();
    let _hook = test_admission_hook(
        &w.db,
        AdmissionKind::Dirty,
        Arc::new(move |_| {
            dirty_store
                .admit("rollback")
                .unwrap()
                .map(|lease| Box::new(lease) as Box<dyn Send>)
        }),
    );
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let target = target(&w, &id);
    let snapshot = {
        let state = target.room.state();
        state.registry.version_snapshot(&state.session).unwrap()
    };
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::BeforeCommit, true);
    let worker = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { flush(&w, &id).await })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    assert!(matches!(
        worker.await.unwrap(),
        Outcome::RetainedBlocked { .. }
    ));
    assert_eq!(stored_body(&w, &id).await, "seed");
    {
        let state = target.room.state();
        let retained = state.registry.version_snapshot(&state.session).unwrap();
        assert_eq!(retained.body(), snapshot.body());
        assert_eq!(retained.contributors(), snapshot.contributors());
        assert_eq!(retained.span_map(), snapshot.span_map());
        assert!(state.dirty());
        assert!(state.dirty_admission.is_some());
    }
    assert!(matches!(flush(&w, &id).await, Outcome::Versioned(_)));
    peer.leave().await;
}

#[tokio::test]
async fn shutdown_response_drop_does_not_cancel_final_cut_or_custody() {
    for stage in [
        kernel_writes::TestStage::BeforeCommit,
        kernel_writes::TestStage::AfterDurability,
    ] {
        let w = world().await;
        let _registration = register_kernel_lifecycle(&w.db);
        let id = record(&w, "Document", "note", Some("seed")).await;
        let (peer, opened) = room(&w, &id).await;
        append_peer(&peer, &opened, " durable").await;
        let mut events = peer.subscribe();
        let witness = seal_kernel_retirement(&w.db);
        let gate = kernel_writes::test_gate(&w.db, stage, false);
        let observer = {
            let witness = witness.clone();
            tokio::spawn(async move { witness.drive_once().await })
        };
        gate.entered.notified().await;
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        assert!(matches!(
            witness.observe(),
            KernelRetirementState::Pending {
                cleanup_running: true,
                ..
            }
        ));
        gate.release.notify_one();
        assert!(matches!(
            events.recv().await.unwrap(),
            SessionEvent::Versioned(_)
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            SessionEvent::Closed { peer: None, .. }
        ));
        assert_eq!(
            observed(&witness, |s| matches!(s, KernelRetirementState::Quiescent)).await,
            KernelRetirementState::Quiescent
        );
        assert_eq!(stored_body(&w, &id).await, "seed durable");
        assert!(peer.sync(&[]).await.is_err());
    }
}

#[tokio::test]
async fn cleanup_slot_is_released_before_quiescence_and_observers_coalesce() {
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " final").await;
    let before = body_events(&w, &id).await;
    let witness = seal_kernel_retirement(&w.db);
    let gate = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LifecyclePassFinished,
        false,
    );
    let first = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drive_once().await })
    };
    gate.entered.notified().await;
    // All rooms have closed, but the cleanup job still owns its admission slot.
    assert!(lock(&witness.purpose.owner.records).is_empty());
    assert_eq!(
        witness.observe(),
        KernelRetirementState::Pending {
            accepted_jobs: 1,
            cleanup_running: true
        }
    );
    let second = witness.drive_once();
    tokio::pin!(second);
    assert!(futures::poll!(second.as_mut()).is_pending());
    assert_eq!(
        lock(&witness.purpose.owner.kernel_lifecycle.serial).accepted_jobs,
        1
    );
    gate.release.notify_one();
    assert_eq!(first.await.unwrap(), KernelRetirementState::Quiescent);
    assert_eq!(second.await, KernelRetirementState::Quiescent);
    assert_eq!(body_events(&w, &id).await, before + 1);
    assert!(peer.sync(&[]).await.is_err());
}

#[tokio::test]
async fn lifecycle_capacity_refusal_keeps_original_custody_and_other_keys_capacity() {
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let held = kernel_writes::hold_job_slots_for_test(&w.db, 8);
    let witness = seal_kernel_retirement(&w.db);
    assert_eq!(
        witness.drive_once().await,
        KernelRetirementState::Pending {
            accepted_jobs: 8,
            cleanup_running: false
        }
    );
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed retained")
    );
    let other = world().await;
    let other_id = record(&other, "Document", "note", Some("other")).await;
    update(&other, json!({"id":other_id,"body_append":" available"}))
        .await
        .unwrap();
    assert_eq!(stored_body(&other, &other_id).await, "other available");
    drop(held);
    assert!(matches!(
        witness.observe(),
        KernelRetirementState::RetainedBlocked {
            reason: KernelBlockedReason::Capacity,
            ..
        }
    ));
    assert_eq!(witness.drive_once().await, KernelRetirementState::Quiescent);
    assert_eq!(stored_body(&w, &id).await, "seed retained");
    drop(peer);
}

#[tokio::test]
async fn old_room_lifecycle_intent_cannot_cut_or_close_replacement_room() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let old = target(&w, &id);
    let gate = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LifecycleBeforeAcquire,
        false,
    );
    let worker = {
        let db = w.db.clone();
        let old = old.clone();
        tokio::spawn(
            async move { finalize(db, old, Intent::Shutdown, "old target".into(), None).await },
        )
    };
    gate.entered.notified().await;
    let ops = old.room.ops.lock().await;
    assert!(!old.room.state().dirty());
    close_session(&old.room, CloseReason::Superseded);
    drop(ops);
    let (replacement, _) = room(&w, &id).await;
    let current = target(&w, &id);
    assert!(!Arc::ptr_eq(&old.room, &current.room));
    assert_ne!(old.session, current.session);
    let before = body_events(&w, &id).await;
    gate.release.notify_one();
    assert!(matches!(
        worker.await.unwrap(),
        Outcome::RetainedBlocked { .. }
    ));
    assert!(Arc::ptr_eq(
        &existing_session(&w.db, &id).unwrap(),
        &current.room
    ));
    assert!(replacement.sync(&[]).await.is_ok());
    assert_eq!(body_events(&w, &id).await, before);
    drop(peer);
    replacement.leave().await;
}

#[tokio::test]
async fn scoped_freeze_drains_only_after_authorized_known_commit() {
    let w = world().await;
    let dir = tempfile::tempdir().unwrap();
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    let hook_store = store.clone();
    let _hook = test_admission_hook(
        &w.db,
        AdmissionKind::Dirty,
        Arc::new(move |_| {
            hook_store
                .admit("scoped")
                .unwrap()
                .map(|lease| Box::new(lease) as Box<dyn Send>)
        }),
    );
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " accepted").await;
    let rejected = peer_update(&peer, &opened, " rejected").await;
    let freezer = {
        let store = store.clone();
        tokio::spawn(async move { store.freeze("scoped").await })
    };
    // The persisted intent is the predicate; yielding only lets its task run.
    while !store.is_frozen("scoped").unwrap() {
        tokio::task::yield_now().await;
    }
    assert!(!freezer.is_finished());
    assert!(peer.apply("after-intent", &rejected).await.is_err());
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let cut = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { flush(&w, &id).await })
    };
    gate.entered.notified().await;
    assert!(!freezer.is_finished()); // Durable SQL alone has not drained custody.
    assert!(existing_session(&w.db, &id)
        .unwrap()
        .state()
        .dirty_admission
        .is_some());
    gate.release.notify_one();
    assert!(matches!(cut.await.unwrap(), Outcome::Versioned(_)));
    freezer.await.unwrap().unwrap();
    assert_eq!(stored_body(&w, &id).await, "seed accepted");
    peer.leave().await;
}

#[tokio::test]
async fn fleet_freeze_refuses_cut_without_begin_and_keeps_custody() {
    use crate::mcp::{DeploymentAdmission, DeploymentMutationBarrier, OperationAccess};
    let w = world().await;
    let barrier = DeploymentMutationBarrier::default();
    let hook_barrier = barrier.for_fleet();
    let _hook = crate::coedit::live::test_kernel_fleet_admission(
        &w.db,
        Arc::new(move |_| {
            match hook_barrier.admit(
                &crate::error::DeploymentReadOnlyOperation::server("update_record"),
                OperationAccess::Mutation,
            ) {
                Ok(DeploymentAdmission::Writable(lease)) => Some(Box::new(lease) as Box<dyn Send>),
                Ok(DeploymentAdmission::FrozenRead) | Err(_) => None,
            }
        }),
    );
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let before = body_events(&w, &id).await;
    let freeze = barrier.freeze().await;
    let db = w.db.clone();
    let exact = target(&w, &id);
    // Instrument INSIDE the owned job: acquisition counters are task-local and
    // must not be assumed to cross a spawned result-owner boundary.
    let (outcome, acquisitions) = kernel_writes::owned_result(w.db.clone(), async move {
        Ok(
            crate::db::with_write_pool_acquisition_counter(finalize_in_owner(
                db,
                exact,
                Intent::Flush,
                "fleet refusal".into(),
                None,
            ))
            .await,
        )
    })
    .await
    .unwrap();
    assert!(outcome.is_err());
    assert_eq!(acquisitions, 0);
    assert_eq!(body_events(&w, &id).await, before);
    assert!(existing_session(&w.db, &id).unwrap().state().dirty());
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed retained")
    );
    drop(freeze);
    assert!(matches!(flush(&w, &id).await, Outcome::Versioned(_)));
    peer.leave().await;
}

#[tokio::test]
async fn retirement_seal_refuses_already_queued_writer_open_and_peer_without_seed() {
    use kernel_writes::{KernelBodyWrite, KernelWriteMode};
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let unopened = record(&w, "Document", "note", Some("unopened")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " accepted").await;
    let bytes = peer_update(&peer, &opened, " rejected").await;
    let held = KernelBodyWrite::acquire(&w.db, &w.caller, Some(&id), KernelWriteMode::RouteBody)
        .await
        .unwrap();
    let writer_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let writer = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { update(&w, json!({"id":id,"body_append":" rejected"})).await })
    };
    writer_gate.entered.notified().await;
    let opener_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let opener = {
        let w = w.clone();
        let id = unopened.clone();
        tokio::spawn(async move {
            kernel_writes::open_for_test(
                &w.db,
                &w.caller,
                OpenRequest {
                    record_id: id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
        })
    };
    opener_gate.entered.notified().await;
    let peer_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::OpsQueued, false);
    let apply = tokio::spawn(async move {
        let result = peer.apply("sealed-no-ack", &bytes).await;
        (peer, result)
    });
    peer_gate.entered.notified().await;
    let witness = seal_kernel_retirement(&w.db);
    writer_gate.release.notify_one();
    opener_gate.release.notify_one();
    peer_gate.release.notify_one();
    assert!(writer.await.unwrap().is_err());
    assert!(opener.await.unwrap().is_err());
    let (peer, result) = apply.await.unwrap();
    assert!(result.is_err());
    assert!(kernel_writes::base_for_test(&w.db, &unopened).is_none());
    assert_eq!(stored_body(&w, &unopened).await, "unopened");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed accepted")
    );
    // All three waiters refused while the original exact ops guard was held.
    drop(held);
    assert_eq!(witness.drive_once().await, KernelRetirementState::Quiescent);
    assert_eq!(stored_body(&w, &id).await, "seed accepted");
    assert!(peer.sync(&[]).await.is_err());
}

#[tokio::test]
async fn queued_recheck_and_grace_waiters_exit_on_quarantine() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " durable but uncertain").await;
    let target = target(&w, &id);
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, true);
    // Commit schedules a coalesced recheck BEFORE AfterDurability; observe its
    // real Pending ops wait even if that worker runs before the cut gate wakes.
    let recheck_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::OpsQueued, false);
    let cut = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { flush(&w, &id).await })
    };
    gate.entered.notified().await;
    schedule_recheck(w.db.clone(), target.room.clone());
    tokio::time::timeout(Duration::from_secs(30), recheck_gate.entered.notified())
        .await
        .expect("coalesced recheck must reach an actual Pending ops wait");
    for _ in 0..100 {
        schedule_recheck(w.db.clone(), target.room.clone());
    }
    let owner = db_sessions(&w.db);
    assert_eq!(lock(&owner.kernel_lifecycle.rechecks).len(), 1);
    let grace_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::LaneQueued, false);
    let grace = {
        let db = w.db.clone();
        let target = target.clone();
        tokio::spawn(async move {
            finalize(db, target, Intent::GraceExpire, "queued grace".into(), None).await
        })
    };
    grace_gate.entered.notified().await;
    gate.release.notify_one();
    assert!(matches!(cut.await.unwrap(), Outcome::Uncertain { .. }));
    recheck_gate.release.notify_one();
    grace_gate.release.notify_one();
    assert!(matches!(grace.await.unwrap(), Outcome::Uncertain { .. }));
    let mut changed_rx = owner.kernel_lifecycle.changed.subscribe();
    loop {
        let jobs = lock(&owner.kernel_lifecycle.serial).accepted_jobs;
        let rechecks = lock(&owner.kernel_lifecycle.rechecks).len();
        if jobs == 1 && rechecks == 0 {
            break;
        }
        changed_rx.changed().await.unwrap();
    }
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 1);
    assert!(peer.sync(&[]).await.is_err());
    assert!(peer.recheck_access(&w.caller).await.is_err());
    // This test injected uncertainty AFTER known depth-zero commit. Dispose only
    // that settled test resource; product quarantine remains permanently armed.
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    drop(peer);
}

#[tokio::test]
async fn quarantined_closed_room_is_unresolved_not_clean_in_kernel_drain_report() {
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    let gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, true);
    let cut = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move { flush(&w, &id).await })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    assert!(matches!(cut.await.unwrap(), Outcome::Uncertain { .. }));
    assert!(existing_session(&w.db, &id).unwrap().state().closed);
    let witness = seal_kernel_retirement(&w.db);
    assert!(matches!(
        witness.observe(),
        KernelRetirementState::Uncertain { .. }
    ));
    assert!(matches!(
        witness.drive_once().await,
        KernelRetirementState::Uncertain { .. }
    ));
    kernel_writes::dispose_settled_quarantine_for_test(&w.db).await;
    assert!(matches!(
        witness.observe(),
        KernelRetirementState::Uncertain { .. }
    ));
    drop(peer);

    let empty = world().await;
    let _registration = register_kernel_lifecycle(&empty.db);
    let gate = kernel_writes::test_gate(&empty.db, kernel_writes::TestStage::AfterDurability, true);
    let worker = {
        let db = empty.db.clone();
        tokio::spawn(async move {
            let inner_db = db.clone();
            kernel_writes::owned_result(db, async move {
                let tx = kernel_writes::KernelTransaction::begin(&inner_db, (), |_, _| {}).await?;
                tx.commit().await
            })
            .await
        })
    };
    gate.entered.notified().await;
    gate.release.notify_one();
    assert!(worker.await.unwrap().is_err());
    assert!(lock(&db_sessions(&empty.db).records).is_empty());
    let witness = seal_kernel_retirement(&empty.db);
    assert!(matches!(
        witness.observe(),
        KernelRetirementState::Uncertain { .. }
    ));
    kernel_writes::dispose_settled_quarantine_for_test(&empty.db).await;
    assert!(matches!(
        witness.observe(),
        KernelRetirementState::Uncertain { .. }
    ));
}

#[tokio::test]
async fn grace_expiry_rechecks_join_and_dirty_epoch_under_owned_ops() {
    let w = world().await;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    let target = target(&w, &id);
    fn detach_for_expiry(target: &Target) {
        let mut state = target.room.state();
        let peers = state.peers.keys().cloned().collect::<Vec<_>>();
        let session = state.session.clone();
        for peer in peers {
            state.peers.remove(&peer);
            state.registry.remove_peer(&session, &peer);
        }
        // Exact expiry precondition; no real-time delay is used as an oracle.
        state.grace_until = Some(Instant::now());
    }
    detach_for_expiry(&target);
    let gate = kernel_writes::test_gate(
        &w.db,
        kernel_writes::TestStage::LifecycleBeforeAcquire,
        false,
    );
    let expiry = {
        let db = w.db.clone();
        let target = target.clone();
        tokio::spawn(async move {
            finalize(db, target, Intent::GraceExpire, "expiry".into(), None).await
        })
    };
    gate.entered.notified().await;
    let (joined, opened) = room(&w, &id).await;
    gate.release.notify_one();
    assert!(matches!(expiry.await.unwrap(), Outcome::Active));
    append_peer(&joined, &opened, " grace").await;
    detach_for_expiry(&target);
    assert!(matches!(
        finalize(
            w.db.clone(),
            target.clone(),
            Intent::GraceExpire,
            "expiry wins".into(),
            None
        )
        .await,
        Outcome::Versioned(_)
    ));
    assert!(target.room.state().closed);
    assert_eq!(stored_body(&w, &id).await, "seed grace");
    let (next, _) = room(&w, &id).await;
    assert_ne!(
        target.session,
        existing_session(&w.db, &id).unwrap().state().session
    );
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &id).as_deref(),
        Some("seed grace")
    );
    drop(peer);
    drop(joined);
    next.leave().await;
}

#[tokio::test]
async fn shutdown_cut_and_close_hold_one_exact_owner_until_durability() {
    use kernel_writes::{KernelBodyWrite, KernelWriteMode};
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " final").await;
    let exact = target(&w, &id);
    let held = KernelBodyWrite::acquire(&w.db, &w.caller, Some(&id), KernelWriteMode::RouteBody)
        .await
        .unwrap();
    let join_gate = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::OpsQueued, false);
    let join = {
        let w = w.clone();
        let id = id.clone();
        tokio::spawn(async move {
            kernel_writes::open_for_test(
                &w.db,
                &w.caller,
                OpenRequest {
                    record_id: id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
        })
    };
    join_gate.entered.notified().await;
    let mut events = peer.subscribe();
    let mut witness = seal_kernel_retirement(&w.db);
    witness.intent = Intent::Shutdown;
    join_gate.release.notify_one();
    assert!(join.await.unwrap().is_err()); // Does not need retained ops released.
    let durable = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::AfterDurability, false);
    let driver = {
        let witness = witness.clone();
        tokio::spawn(async move { witness.drive_once().await })
    };
    drop(held);
    durable.entered.notified().await;
    assert_eq!(stored_body(&w, &id).await, "seed final");
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(!exact.room.state().closed);
    assert!(exact.room.state().dirty());
    // The cut owns the SAME ops guard through postcommit install/drain/close.
    assert!(exact.room.ops.try_lock().is_err());
    durable.release.notify_one();
    let version = match events.recv().await.unwrap() {
        SessionEvent::Versioned(v) => v,
        e => panic!("{e:?}"),
    };
    assert!(matches!(
        events.recv().await.unwrap(),
        SessionEvent::Closed {
            peer: None,
            reason: CloseReason::ServerShutdown
        }
    ));
    assert_eq!(driver.await.unwrap(), KernelRetirementState::Quiescent);
    let body_id: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(body_id, version.event_id);
    assert!(exact.room.state().closed);
    assert!(peer.sync(&[]).await.is_err());
}

#[tokio::test]
async fn policy_blocked_scoped_freeze_keeps_dirty_lease_and_unresolved_custody() {
    let (w, _, id, home, actor, _) = policy_world().await;
    let dir = tempfile::tempdir().unwrap();
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    let hook_store = store.clone();
    let _hook = test_admission_hook(
        &w.db,
        AdmissionKind::Dirty,
        Arc::new(move |_| {
            hook_store
                .admit("blocked")
                .unwrap()
                .map(|lease| Box::new(lease) as Box<dyn Send>)
        }),
    );
    let (peer, opened) = room(&w, &id).await;
    append_peer(&peer, &opened, " retained").await;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&actor, "view")])
        .await
        .unwrap();
    let freezer = {
        let store = store.clone();
        tokio::spawn(async move { store.freeze("blocked").await })
    };
    while !store.is_frozen("blocked").unwrap() {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        flush(&w, &id).await,
        Outcome::RetainedBlocked { .. }
    ));
    let target = target(&w, &id);
    assert!(target.room.state().dirty_admission.is_some());
    assert!(target.room.state().dirty());
    assert!(!freezer.is_finished());
    assert_eq!(stored_body(&w, &id).await, "seed");
    // Cancelling observation never thaws the real persisted intent or custody.
    freezer.abort();
    assert!(freezer.await.unwrap_err().is_cancelled());
    assert!(store.is_frozen("blocked").unwrap());
    assert!(target.room.state().dirty_admission.is_some());
    drop(peer);
}

#[tokio::test]
async fn panicking_cleanup_is_terminal_uncertainty_not_quiescence() {
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let witness = seal_kernel_retirement(&w.db);
    let owner = witness.purpose.owner.clone();
    {
        let mut ledger = lock(&owner.kernel_lifecycle.serial);
        ledger.cleanup_running = true;
        ledger.cleanup_generation += 1;
    }
    let mut purpose = witness.purpose.clone();
    purpose.generation = lock(&owner.kernel_lifecycle.serial).cleanup_generation;
    let db = w.db.clone();
    let (receiver,) = with_cleanup(purpose, async {
        (kernel_writes::start_owned_with(w.db.clone(), move || {
            let guard = DriveGuard {
                db,
                owner,
                finished: false,
            };
            async move {
                let _guard = guard;
                panic!("deterministic cleanup panic before SQL");
                #[allow(unreachable_code)]
                Ok::<(), crate::Error>(())
            }
        })
        .unwrap(),)
    })
    .await;
    assert!(receiver.await.is_err());
    let state = observed(&witness, |s| {
        matches!(s, KernelRetirementState::Uncertain { .. })
    })
    .await;
    assert!(
        matches!(state, KernelRetirementState::Uncertain { operation_ids } if !operation_ids.is_empty())
    );
    assert!(kernel_writes::ensure_available(&w.db).is_err());
    assert_eq!(
        lock(&witness.purpose.owner.kernel_lifecycle.serial).accepted_jobs,
        0
    );
    assert!(!release_idle_database(&w.db));
}

#[tokio::test]
async fn last_room_unregister_cannot_detach_dropped_marker_registration() {
    let w = world().await;
    let registration = register_kernel_lifecycle(&w.db);
    let seal_id = registration._owner.kernel_lifecycle.seal_id;
    let id = record(&w, "Document", "note", Some("seed")).await;
    let (peer, _) = room(&w, &id).await;
    drop(registration);
    let room = existing_session(&w.db, &id).unwrap();
    let ops = room.ops.lock().await;
    close_session(&room, CloseReason::Left);
    drop(ops);
    drop(room);
    drop(peer);
    // Do not hold an extra owner Arc across unregister: the old automatic
    // strong-count-only path could detach this registered owner.
    assert!(existing_db_sessions(&w.db).is_some());
    let witness = seal_kernel_retirement(&w.db);
    assert_eq!(witness.seal_id(), seal_id);
    assert_eq!(witness.observe(), KernelRetirementState::Quiescent);
    assert!(!release_idle_database(&w.db));
}

// Exercise the ordinary owned opener with its SQL counter INSIDE the result
// owner. The gate notification is emitted only after exclusive acquisition was
// actually polled Pending, after winning the mutation lane.
async fn queued_exclusive_seed_refuses_while_shared_reader_is_retained(quarantine: bool) {
    let w = world().await;
    let _registration = register_kernel_lifecycle(&w.db);
    let dirty_id = record(&w, "Document", "note", Some("seed")).await;
    let unopened = record(&w, "Document", "note", Some("unopened")).await;
    let (peer, opened) = room(&w, &dirty_id).await;
    append_peer(&peer, &opened, " retained").await;
    let before = body_events(&w, &unopened).await;
    let owner = db_sessions(&w.db);
    let reader = Arc::clone(&owner.open_gate).read_owned().await;
    let queued = kernel_writes::test_gate(&w.db, kernel_writes::TestStage::SeedGateQueued, false);
    let opener = {
        let w = w.clone();
        let unopened = unopened.clone();
        tokio::spawn(async move {
            let db = w.db.clone();
            kernel_writes::owned_result(w.db, async move {
                Ok(crate::db::with_write_pool_acquisition_counter(open_backend(
                    &db,
                    &w.caller,
                    OpenRequest {
                        record_id: unopened,
                        mode: PeerKind::Edit,
                        resume_peer: None,
                    },
                    SessionBackend::KernelV2,
                ))
                .await)
            })
            .await
        })
    };
    queued.entered.notified().await;
    assert!(owner.kernel_lane.try_lock().is_err());
    assert_eq!(lock(&owner.kernel_lifecycle.serial).accepted_jobs, 1);
    let witness = if quarantine {
        kernel_writes::quarantine_storage(&w.db, "exclusive-seed-test-uncertainty");
        None // Seal must not mask the independently tested quarantine wake.
    } else {
        Some(seal_kernel_retirement(&w.db))
    };
    queued.release.notify_one();
    let (result, acquisitions) = opener.await.unwrap().unwrap();
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains(if quarantine { "quarantin" } else { "seal" }),
        "{error}"
    );
    assert_eq!(
        acquisitions, 0,
        "refusal precedes any seed write-pool acquisition"
    );
    assert_eq!(lock(&owner.kernel_lifecycle.serial).accepted_jobs, 0);
    assert!(owner.kernel_lane.try_lock().is_ok());
    assert!(owner.open_gate.try_write().is_err()); // Reader STILL held.
    assert!(kernel_writes::base_for_test(&w.db, &unopened).is_none());
    assert_eq!(body_events(&w, &unopened).await, before);
    assert_eq!(stored_body(&w, &unopened).await, "unopened");
    assert_eq!(
        kernel_writes::live_text_for_test(&w.db, &dirty_id).as_deref(),
        Some("seed retained")
    );
    assert!(existing_session(&w.db, &dirty_id).unwrap().state().dirty());
    assert_eq!(kernel_writes::retained_transactions_for_test(&w.db), 0);
    let witness = witness.unwrap_or_else(|| seal_kernel_retirement(&w.db));
    if quarantine {
        assert!(matches!(
            witness.observe(),
            KernelRetirementState::Uncertain { .. }
        ));
    } else {
        assert_eq!(
            witness.observe(),
            KernelRetirementState::Pending {
                accepted_jobs: 0,
                cleanup_running: false
            }
        );
    }
    // No Quiescent: dirty room is separate custody even though seed settled.
    drop(reader);
    drop(peer);
}

#[tokio::test]
async fn exclusive_seed_gate_waiter_refuses_terminal_seal_with_reader_still_held() {
    queued_exclusive_seed_refuses_while_shared_reader_is_retained(false).await;
}

#[tokio::test]
async fn exclusive_seed_gate_waiter_refuses_quarantine_with_reader_still_held() {
    queued_exclusive_seed_refuses_while_shared_reader_is_retained(true).await;
}
