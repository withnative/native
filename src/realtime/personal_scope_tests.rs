use super::*;
use crate::identity::hosted::{HostedMembershipRole, HostedMembershipSource};

async fn fixture() -> (
    tempfile::TempDir,
    Db,
    Arc<RealtimeHub>,
    String,
    HostedMembershipArrival,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("scope.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let arrival = HostedMembershipArrival::new(
        HostedMembershipRole::Owner,
        HostedMembershipSource::Personal,
        crate::store::now_iso(),
    )
    .unwrap();
    let account = crate::identity::hosted::resolve_account_identity_with_arrival(
        &db,
        "alice@example.com",
        "catalog-alice",
        &arrival,
    )
    .await
    .unwrap();
    let (db, hub) = RealtimeHub::attach(db, None).await.unwrap();
    (dir, db, hub, account, arrival)
}
fn identity(arrival: &HostedMembershipArrival) -> PersonalAlphaRegistryIdentity<'_> {
    PersonalAlphaRegistryIdentity {
        email: "alice@example.com",
        catalog_user_id: "catalog-alice",
        arrival,
        public_principal: None,
    }
}
async fn order(db: &Db, account: &str, key: &str) {
    use crate::control::{self, AlphaTabOrderPayload, ControlEventPayload, NewControlEvent};
    control::append_control_event(
        db,
        NewControlEvent::authored(
            key,
            control::alpha_tab_order_aggregate_id(account),
            account,
            None,
            "scope fixture",
            ControlEventPayload::AlphaTabOrderSet(AlphaTabOrderPayload {
                account_id: account.into(),
                tab_order: vec!["agents".into()],
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn personal_alpha_registry_slot_provisional_same_handle_and_matched_retirement() {
    let (_dir, db, hub, account, arrival) = fixture().await;
    assert!(hub.bind_personal_alpha_registry(&db, &account).is_err());
    assert_eq!(hub.current_db().unwrap().handle_id(), db.handle_id());
    hub.refresh_scheduler_handle(&db);
    let scope = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    hub.refresh_scheduler_handle(&db.clone());
    assert!(scope.check_current().is_ok());
    assert!(scope
        .stage_initial(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_some());
    hub.retire_scheduler_handle(&db);
    assert!(scope.check_current().is_err());
    assert!(hub.current_db().is_none());
    hub.refresh_scheduler_handle(&db);
    assert!(
        scope.check_current().is_err(),
        "reaccept must not revive old marker"
    );
    let fresh = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    assert!(fresh.check_current().is_ok());
    hub.terminalize();
    hub.refresh_scheduler_handle(&db);
    assert!(fresh.check_current().is_err());
    assert!(hub.bind_personal_alpha_registry(&db, &account).is_err());
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_rejected_staged_pool_never_moves_captured_authority() {
    let (dir, db, hub, account, arrival) = fixture().await;
    hub.refresh_scheduler_handle(&db);
    let scope = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    let staged = crate::open_existing_database(dir.path().join("scope.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let (staged, _) = RealtimeHub::attach(staged, Some(hub.clone()))
        .await
        .unwrap();
    assert!(hub.bind_personal_alpha_registry(&staged, &account).is_err());
    hub.retire_scheduler_handle(&staged); // exact router rejected-close behavior
    staged.close().await;
    assert!(scope.check_current().is_ok());
    assert_eq!(hub.current_db().unwrap().handle_id(), db.handle_id());
    assert!(scope
        .stage_initial(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_some());
    assert!(
        hub.inbox_invalidation_vector().await.is_err(),
        "staged hub pool really closed"
    );
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_unknown_known_baselines_quiet_recovery_and_read_only_identity() {
    let (_dir, db, hub, account, arrival) = fixture().await;
    hub.refresh_scheduler_handle(&db);
    let scope = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    sqlx::query("ALTER TABLE alpha_tab_orders RENAME TO unavailable_orders")
        .execute(db.write_pool())
        .await
        .unwrap();
    let unknown = scope.observe(identity(&arrival)).await.unwrap();
    assert!(unknown.fingerprint.is_none());
    let prompt = scope.stage_initial(unknown).unwrap().unwrap();
    assert_eq!(prompt.event_name(), "alpha-registry");
    assert_eq!(
        prompt.data(),
        r#"{"version":"native.alpha-registry-invalidation.v1"}"#
    );
    assert!(scope.baseline.lock().unwrap().fingerprint.is_none());
    sqlx::query("ALTER TABLE unavailable_orders RENAME TO alpha_tab_orders")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_some());
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_none());
    order(&db, "foreign-account", "foreign-order").await;
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_none());
    sqlx::query("ALTER TABLE alpha_tab_orders RENAME TO unavailable_orders")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_none());
    assert!(scope.baseline.lock().unwrap().fingerprint.is_some());
    sqlx::query("ALTER TABLE unavailable_orders RENAME TO alpha_tab_orders")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_none());
    order(&db, &account, "personal-order").await;
    // No unrelated wake required: direct quiet retry sees durable state.
    assert!(scope
        .stage_update(scope.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_some());
    let mut writer = db.write_pool().begin().await.unwrap();
    sqlx::query("UPDATE alpha_tab_orders SET updated_at=updated_at")
        .execute(&mut *writer)
        .await
        .unwrap();
    let observed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        scope.observe(identity(&arrival)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(scope.stage_update(observed).unwrap().is_none());
    writer.rollback().await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(scope
        .observe(PersonalAlphaRegistryIdentity {
            email: "missing@example.com",
            catalog_user_id: "missing",
            arrival: &arrival,
            public_principal: None
        })
        .await
        .is_err());
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "read-only identity must never provision");
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_same_portable_restore_final_fence_and_old_retirement() {
    let (dir, db, hub, account, arrival) = fixture().await;
    hub.refresh_scheduler_handle(&db);
    let old = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    let before_publish = old.observe(identity(&arrival)).await.unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(db.write_pool())
        .await
        .unwrap();
    let restored_path = dir.path().join("restored.sqlite");
    std::fs::copy(db.path(), &restored_path).unwrap();
    let restored = crate::open_existing_database(restored_path.to_str().unwrap())
        .await
        .unwrap();
    order(&restored, &account, "restored-order").await;
    let (restored, _) = RealtimeHub::attach(restored, Some(hub.clone()))
        .await
        .unwrap();
    hub.refresh_scheduler_handle(&restored);
    assert!(old.stage_initial(before_publish).is_err());
    assert!(
        old.baseline.lock().unwrap().fingerprint.is_none(),
        "failed final fence cannot advance baseline"
    );
    assert!(hub.bind_personal_alpha_registry(&db, &account).is_err());
    let fresh = hub
        .bind_personal_alpha_registry(&restored, &account)
        .unwrap();
    hub.retire_scheduler_handle(&db);
    db.close().await;
    assert!(fresh.check_current().is_ok());
    assert_eq!(hub.current_db().unwrap().handle_id(), restored.handle_id());
    assert!(fresh
        .stage_initial(fresh.observe(identity(&arrival)).await.unwrap())
        .unwrap()
        .is_some());
    let other_scope = hub
        .bind_personal_alpha_registry(&restored, &account)
        .unwrap();
    assert!(fresh
        .stage_update(other_scope.observe(identity(&arrival)).await.unwrap())
        .is_err());
    restored.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_replacement_during_real_projection_fetch_discards_observation() {
    let (dir, db, hub, account, arrival) = fixture().await;
    hub.refresh_scheduler_handle(&db);
    let scope = Arc::new(hub.bind_personal_alpha_registry(&db, &account).unwrap());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let reading = scope.clone();
    let gate = (entered.clone(), release.clone());
    let reader = tokio::spawn(super::super::personal_registry::BETWEEN_TABLES.scope(
        gate,
        async move { reading.observe(identity(&arrival)).await },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let replacement =
        crate::open_existing_database(dir.path().join("scope.sqlite").to_str().unwrap())
            .await
            .unwrap();
    let (replacement, _) = RealtimeHub::attach(replacement, Some(hub.clone()))
        .await
        .unwrap();
    hub.refresh_scheduler_handle(&replacement);
    release.notify_one();
    assert!(reader.await.unwrap().is_err());
    assert!(scope.baseline.lock().unwrap().fingerprint.is_none());
    assert!(scope.check_current().is_err());
    db.close().await;
    replacement.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_closed_captured_pool_refuses_final_stage() {
    let (_dir, db, hub, account, arrival) = fixture().await;
    hub.refresh_scheduler_handle(&db);
    let scope = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    let observed = scope.observe(identity(&arrival)).await.unwrap();
    db.close().await;
    assert!(scope.stage_initial(observed).is_err());
    assert!(scope.baseline.lock().unwrap().fingerprint.is_none());
    assert!(hub.bind_personal_alpha_registry(&db, &account).is_err());
}

#[tokio::test]
async fn personal_alpha_registry_account_rebinding_during_projection_refuses_observation() {
    let (_dir, db, hub, account, arrival) = fixture().await;
    crate::identity::hosted::resolve_account_identity_with_arrival(
        &db,
        "bob@example.com",
        "catalog-bob",
        &arrival,
    )
    .await
    .unwrap();
    hub.refresh_scheduler_handle(&db);
    let scope = Arc::new(hub.bind_personal_alpha_registry(&db, &account).unwrap());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let reading = scope.clone();
    let gate = (entered.clone(), release.clone());
    let reader = tokio::spawn(super::super::personal_registry::BETWEEN_TABLES.scope(
        gate,
        async move { reading.observe(identity(&arrival)).await },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    sqlx::query("UPDATE bindings SET is_canonical=0, record_id=(SELECT record_id FROM bindings WHERE system='email' AND identifier='bob@example.com') WHERE system='email' AND identifier='alice@example.com'")
        .execute(db.write_pool()).await.unwrap();
    release.notify_one();
    assert!(reader.await.unwrap().is_err());
    assert!(
        scope.check_current().is_ok(),
        "handle remained current; identity moved"
    );
    assert!(scope.baseline.lock().unwrap().fingerprint.is_none());
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_scope_final_identity_rebind_refuses_without_baseline() {
    let (_dir, db, hub, account, arrival) = fixture().await;
    crate::identity::hosted::resolve_account_identity_with_arrival(
        &db,
        "bob@example.com",
        "catalog-bob",
        &arrival,
    )
    .await
    .unwrap();
    hub.refresh_scheduler_handle(&db);
    let scope = hub.bind_personal_alpha_registry(&db, &account).unwrap();
    let observed = scope.observe(identity(&arrival)).await.unwrap();
    // A held serialized writer must not prevent this read-only fence.
    let tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        scope.recheck_identity_read_only(identity(&arrival)),
    )
    .await
    .unwrap()
    .unwrap();
    tx.rollback().await.unwrap();
    let before: (String, i64) = sqlx::query_as("SELECT record_id,is_canonical FROM bindings WHERE system='email' AND identifier='alice@example.com'")
        .fetch_one(db.pool()).await.unwrap();
    sqlx::query("UPDATE bindings SET is_canonical=0, record_id=(SELECT record_id FROM bindings WHERE system='email' AND identifier='bob@example.com') WHERE system='email' AND identifier='alice@example.com'")
        .execute(db.write_pool()).await.unwrap();
    assert!(
        scope.check_current().is_ok(),
        "same accepted physical handle"
    );
    assert!(scope
        .recheck_identity_read_only(identity(&arrival))
        .await
        .is_err());
    assert!(!scope.baseline.lock().unwrap().initial_staged);
    assert!(scope.baseline.lock().unwrap().fingerprint.is_none());
    sqlx::query("UPDATE bindings SET record_id=?,is_canonical=? WHERE system='email' AND identifier='alice@example.com'")
        .bind(before.0).bind(before.1).execute(db.write_pool()).await.unwrap();
    scope
        .recheck_identity_read_only(identity(&arrival))
        .await
        .unwrap();
    assert!(
        scope.stage_initial(observed).unwrap().is_some(),
        "refused final fence did not consume initial baseline"
    );
    db.close().await;
}
