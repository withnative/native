//! M2 subscribe-mode tool tests (task `61e11ad`, design `ee12faf` §2.2).
//!
//! Connection tokens are minted directly on the hub registry — the SSE
//! layer's mint-and-announce job, unwired until `e7d2c04` lands. The tool
//! layer resolves them exactly as it will production tokens.

use native_ce::authorization::Capability;
use native_ce::mcp::tools::live_scheduler::NeedScheduler;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::need_subscriptions::{
    AccessHook, ConnectionToken, NeedClosedReason, NeedSinkFrame, SubscriptionId, SurfaceBinding,
    MAX_SUBSCRIPTIONS_PER_CONNECTION, SINK_CAPACITY,
};
use native_ce::realtime::RealtimeHub;
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::alpha_tabs::{
    adopt_fixture_artifact, adopted_live_fixture, adopted_with_package, call_as, clock_declaration,
    configure_preview_launch, grant, live_read_args, live_task, revoke_all, sql_need, ALICE,
    ARTIFACT_A, BEA,
};

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    // `install` is crate-private; `attach` with no retained hub installs.
    let (db, _hub) = RealtimeHub::attach(db, None).await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
}

fn hub_token(db: &Db, account: &str, database: &str) -> String {
    let hub = RealtimeHub::for_database(db).expect("hub installed");
    let token = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_connection(account, database, true);
    token.to_hex()
}

fn subscription_count(db: &Db, token_hex: &str) -> usize {
    let hub = RealtimeHub::for_database(db).expect("hub installed");
    let token = ConnectionToken::from_hex(token_hex).unwrap();
    let count = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .connection_subscription_count(&token);
    count
}

fn subscribe_args(event: &str, stream: &str) -> Value {
    json!({
        "action": "live_read",
        "package": "agent.attention-cockpit",
        "expected_install_event_id": event,
        "subscribe": {"stream": stream},
    })
}

async fn unsub(registry: &ToolRegistry, db: &Db, stream: &str, sub: &str) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "live_unsubscribe", "stream": stream, "subscription": sub}),
    )
    .await
    .unwrap()
}

async fn on_request_search(
    registry: &ToolRegistry,
    db: &Db,
    verified: &str,
    extra: Value,
) -> native_ce::Result<Value> {
    let mut args = json!({
        "action": "live_read",
        "package": "agent.attention-cockpit",
        "expected_install_event_id": verified,
        "need": "records.search.v1",
        "params": {"query": "Visible", "limit": 5},
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args,
    )
    .await
}

#[tokio::test]
async fn subscribe_returns_subscription_and_resync_is_unchanged() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    assert_eq!(first["subscription"]["time_dependent"], false);
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert_eq!(subscription_count(&db, &stream), 1);
    let digest = first["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let resync = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.attention-cockpit",
            "expected_install_event_id": verified,
            "subscribe": {"stream": stream},
            "if_revision": digest,
        }),
    )
    .await
    .unwrap();
    assert_eq!(resync["unchanged"], true);
    assert!(resync.get("input").is_none());
    assert!(resync["subscription"]["id"].is_string());
}

#[tokio::test]
async fn subscribe_reports_time_dependent_for_clock_needs() {
    // M1 slice 1: `subscription.time_dependent` reflects the declared
    // snapshot needs — true when an evaluated need uses `now_ms()`.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let read = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    assert_eq!(read["time_dependent"], true);
    assert!(read["as_of_ms"].is_number());
    assert_eq!(read["subscription"]["time_dependent"], true);
    assert!(read["subscription"]["id"].is_string());
    assert_eq!(subscription_count(&db, &stream), 1);
}

#[tokio::test]
async fn clock_probe_replays_stored_bind_and_keeps_quiet_baseline() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    let hub = RealtimeHub::for_database(&db).unwrap();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let id = SubscriptionId::from_wire(first["subscription"]["id"].as_str().unwrap());
    let initial_clock = first["input"]["sql"]["lane.clock"]["now_ms_ms"]
        .as_i64()
        .unwrap();
    {
        let needs = hub.need_registry().lock().unwrap();
        let state = needs.subscription_state(&token, &id).unwrap();
        assert_eq!(
            state.clock_bindings.as_ref().unwrap()["lane.clock"],
            initial_clock
        );
        assert_eq!(needs.probe_clock_eligible_count(), 1);
    }
    let fence = hub.inbox_invalidation_vector().await.unwrap().content;
    native_ce::realtime::wait_until_published_for_tests(&db, fence).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut scheduler = NeedScheduler::new(hub.clone());
    scheduler.probe_clock_once_for_tests().await;
    let (attempts, mismatches, _) = hub.need_clock_probe_totals_for_tests();
    assert_eq!(attempts, 1);
    assert_eq!(mismatches, 0);
    assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 0);
    // A queued/in-flight push is excluded: its old digest can differ while
    // ordinary scheduling is still responsible for the delivery.
    {
        let mut needs = hub.need_registry().lock().unwrap();
        needs.enqueue_dirty(&token, &id, true);
        assert_eq!(needs.probe_clock_eligible_count(), 0);
    }
    scheduler.probe_clock_once_for_tests().await;
    let (attempts, mismatches, suppressed) = hub.need_clock_probe_totals_for_tests();
    assert_eq!((attempts, mismatches, suppressed[0]), (1, 0, 1));
}

#[tokio::test]
async fn clock_probe_detects_lost_content_push_at_held_statement_clock() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "live_read", "package": "agent.clock",
            "expected_install_event_id": event, "subscribe": {"stream": stream}}),
    )
    .await
    .unwrap();
    let hub = RealtimeHub::for_database(&db).unwrap();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let id = SubscriptionId::from_wire(first["subscription"]["id"].as_str().unwrap());
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-0000000000b3",
        "Clock probe visible mismatch",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-0000000000b3",
        ALICE,
        Capability::View,
    )
    .await;
    let fence = hub.inbox_invalidation_vector().await.unwrap().content;
    native_ce::realtime::wait_until_published_for_tests(&db, fence).await;
    {
        let mut needs = hub.need_registry().lock().unwrap();
        assert!(needs.pop_dirty(&token).is_some());
        needs.clear_dirty(&token, &id).unwrap();
        needs.finish_rerun(&token, &id);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut scheduler = NeedScheduler::new(hub.clone());
    scheduler.probe_clock_once_for_tests().await;
    let (attempts, mismatches, _) = hub.need_clock_probe_totals_for_tests();
    assert_eq!((attempts, mismatches), (1, 1));
    assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 1);
}

#[tokio::test]
async fn activity_sql_subscriptions_are_reported_outside_both_probe_denominators() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let hub = RealtimeHub::for_database(&db).unwrap();
    for (package, sql, time_dependent) in [
        (
            "agent.activity-free",
            "SELECT activity_id FROM agent_activity ORDER BY activity_id LIMIT 4",
            false,
        ),
        (
            "agent.activity-clock",
            "SELECT claim_id FROM agent_activity_claims WHERE now_ms() > 0 ORDER BY claim_id LIMIT 4",
            true,
        ),
    ] {
        let event = adopted_with_package(
            &registry,
            &db,
            ALICE,
            package,
            json!({"needs": ["attention.query.v1", sql_need("lane.activity", "Activity", sql)],
                "effects": []}),
        )
        .await;
        let read = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            json!({"action":"live_read", "package":package,
                "expected_install_event_id":event, "subscribe":{"stream":stream}}),
        )
        .await
        .unwrap();
        assert_eq!(read["subscription"]["time_dependent"], time_dependent);
        let token = ConnectionToken::from_hex(&stream).unwrap();
        let id = SubscriptionId::from_wire(read["subscription"]["id"].as_str().unwrap());
        let needs = hub.need_registry().lock().unwrap();
        assert!(!needs.subscription_state(&token, &id).unwrap().clock_replay_safe);
    }
    let needs = hub.need_registry().lock().unwrap();
    assert_eq!(needs.probe_activity_excluded_count(), 2);
    assert_eq!(needs.probe_eligible_count(), 0);
    assert_eq!(needs.probe_clock_eligible_count(), 0);
}

#[tokio::test]
async fn missed_delivery_probe_detects_and_requeues_a_visible_digest_change() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let hub = RealtimeHub::for_database(&db).unwrap();
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let id = SubscriptionId::from_wire(first["subscription"]["id"].as_str().unwrap());
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-0000000000a3",
        "Visible probe mismatch",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-0000000000a3",
        ALICE,
        Capability::View,
    )
    .await;
    let fence = hub.inbox_invalidation_vector().await.unwrap().content;
    native_ce::realtime::wait_until_published_for_tests(&db, fence).await;
    // Deliberately lose the queued push work, leaving an active clean
    // subscription with an old baseline. This models the failure the
    // out-of-band probe is meant to detect, without depending on timing.
    {
        let mut needs = hub.need_registry().lock().unwrap();
        assert!(needs.pop_dirty(&token).is_some());
        needs.clear_dirty(&token, &id).unwrap();
        needs.finish_rerun(&token, &id);
        assert_eq!(needs.dirty_len(&token), 0);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut scheduler = NeedScheduler::new(hub.clone());
    scheduler.probe_once_for_tests().await;
    assert_eq!(hub.need_probe_totals_for_tests(), (1, 1, 0));
    assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 1);
}

#[tokio::test]
async fn scheduler_clock_rerun_is_quiet_then_row_change_delivers_with_stamp() {
    // M1 slice 1 (review repair): a forced re-run with no row change is
    // quiet even on a clock-bearing subscription — the digest excludes the
    // stamp — while a later visible row change delivers a frame carrying
    // that evaluation's stamp.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    // Forced re-run, no data change: digest holds, nothing is sent.
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(sink.try_recv().is_err());
    // A new visible open task moves the attention lane's rows.
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000020",
        "Visible clock",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000020",
        ALICE,
        Capability::View,
    )
    .await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Need(need) = frame else {
        panic!("visible row change must deliver a need frame");
    };
    assert_eq!(need.delivery, 1);
    assert!(need.result.is_some());
    need.as_of_ms
        .expect("row-change frame carries its evaluation stamp");
}

#[tokio::test]
async fn clock_tick_with_no_row_change_is_quiet() {
    // M1 slice 2: a due clock tick re-runs through the ordinary digest
    // gate, so a tick with unchanged rows sends no frame — same quiet
    // path as a content wake, driven by `mark_due_clock_ticks`.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    // Jump this subscription's own timer to due without any write, then
    // drain: the re-run must stay frame-less.
    let hub = RealtimeHub::for_database(&db).unwrap();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let due = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .subscription_state(&token, &SubscriptionId::from_wire(&id))
        .unwrap()
        .next_clock_at
        .unwrap();
    assert_eq!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_due_clock_ticks(due),
        1
    );
    drain_once(&db).await;
    assert!(sink.try_recv().is_err());
    let audit = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .clock_due_audit(tokio::time::Instant::now());
    assert_eq!(audit.due_periods, 1);
    assert_eq!(audit.covered_periods, 1);
    assert_eq!(audit.covering_evaluations, 1);
    assert_eq!(audit.pending_periods, 0);
}

#[tokio::test]
async fn clock_tick_delivers_a_row_that_becomes_eligible_without_a_write() {
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let record_id = "f3d00000-0000-4000-8000-000000000021";
    live_task(&registry, &db, record_id, "Future clock row", "open").await;
    grant(&db, record_id, ALICE, Capability::View).await;
    // The declaration is fixed before subscribe. Leave room for parallel
    // test load so the first read still precedes the cutoff.
    let cutoff = chrono::Utc::now().timestamp_millis() + 10_000;
    let sql = format!(
        "SELECT id, name FROM records WHERE deleted_at IS NULL AND id = '{record_id}' AND now_ms() >= {cutoff} ORDER BY id LIMIT 40"
    );
    let declaration = json!({
        "needs": ["attention.query.v1", sql_need("lane.future", "Future", &sql)],
        "effects": [],
    });
    let event = adopted_with_package(&registry, &db, ALICE, "agent.future", declaration).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.future",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["subscription"]["time_dependent"], true);
    assert_eq!(first["input"]["sql"]["lane.future"]["row_count"], 0);
    let mut sink = test_sink(&db, &stream);
    while chrono::Utc::now().timestamp_millis() < cutoff {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Simulate this subscription's timer reaching its due time. No content
    // write occurs after the baseline; the row changes solely with time.
    let hub = RealtimeHub::for_database(&db).unwrap();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let due = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .subscription_state(
            &token,
            &SubscriptionId::from_wire(first["subscription"]["id"].as_str().unwrap()),
        )
        .unwrap()
        .next_clock_at
        .unwrap();
    assert_eq!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_due_clock_ticks(due),
        1
    );
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Need(need) = frame else {
        panic!("clock-only eligibility must deliver");
    };
    assert_eq!(need.delivery, 1);
    assert_eq!(
        need.result.as_ref().unwrap()["input"]["sql"]["lane.future"]["row_count"],
        1
    );
    assert!(need.as_of_ms.is_some());
}

#[tokio::test]
async fn unchanged_resync_carries_no_fresh_stamp() {
    // M1 slice 1 (review repair): an `if_revision`-equal resync freshly
    // evaluates but suppresses the unchanged body and new stamp; the held
    // rows remain valid, and the subscription flag remains true.
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    let event =
        adopted_with_package(&registry, &db, ALICE, "agent.clock", clock_declaration()).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
        }),
    )
    .await
    .unwrap();
    let digest = first["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let resync = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.clock",
            "expected_install_event_id": event,
            "subscribe": {"stream": stream},
            "if_revision": digest,
        }),
    )
    .await
    .unwrap();
    assert_eq!(resync["unchanged"], true);
    assert!(resync.get("input").is_none());
    assert!(resync.get("as_of_ms").is_none());
    assert!(resync["subscription"]["id"].is_string());
    assert_eq!(resync["subscription"]["time_dependent"], true);
}

#[tokio::test]
async fn visible_change_is_never_unchanged() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let digest = first["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000001",
        "Visible new",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000001",
        ALICE,
        Capability::View,
    )
    .await;
    let second = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.attention-cockpit",
            "expected_install_event_id": verified,
            "if_revision": digest,
        }),
    )
    .await
    .unwrap();
    assert!(second.get("unchanged").is_none());
    assert_ne!(
        second["revision"]["revision_digest"].as_str().unwrap(),
        digest
    );
}

#[tokio::test]
async fn unknown_token_refuses_subscribe_but_read_succeeds() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let cross_account = hub_token(&db, BEA, &database);
    let cross_database = hub_token(&db, ALICE, "another-database");
    let closed = hub_token(&db, ALICE, &database);
    RealtimeHub::for_database(&db)
        .expect("hub installed")
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .remove_connection(&ConnectionToken::from_hex(&closed).unwrap());
    for stream in [
        "0".repeat(32),
        "not-a-token".to_string(),
        cross_account,
        cross_database,
        closed,
    ] {
        let read = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            subscribe_args(&verified, &stream),
        )
        .await
        .unwrap();
        assert_eq!(read["subscribe_refused"], "stream_unknown");
        assert!(read.get("subscription").is_none());
        assert!(read["revision"]["revision_digest"].is_string());
    }
    // The plain read is unaffected.
    let plain = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(plain.get("subscribe_refused").is_none());
    let mut resync = subscribe_args(&verified, &"0".repeat(32));
    resync["if_revision"] = plain["revision"]["revision_digest"].clone();
    let unchanged = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        resync,
    )
    .await
    .unwrap();
    assert_eq!(unchanged["unchanged"], true);
    assert_eq!(unchanged["subscribe_refused"], "stream_unknown");
    assert!(unchanged.get("subscription").is_none());
}

#[tokio::test]
async fn unsubscribe_is_scoped_and_idempotent() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let first_stream = hub_token(&db, ALICE, &database);
    let second_stream = hub_token(&db, ALICE, &database);
    let subscribed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &first_stream),
    )
    .await
    .unwrap();
    let id = subscribed["subscription"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Another connection's id: success with no effect.
    assert_eq!(
        unsub(&registry, &db, &second_stream, &id).await["unsubscribed"],
        true
    );
    assert_eq!(subscription_count(&db, &first_stream), 1);
    // Own id: removed; repeat and unknown ids stay success.
    assert_eq!(
        unsub(&registry, &db, &first_stream, &id).await["unsubscribed"],
        true
    );
    assert_eq!(subscription_count(&db, &first_stream), 0);
    assert_eq!(
        unsub(&registry, &db, &first_stream, &id).await["unsubscribed"],
        true
    );
    assert_eq!(
        unsub(&registry, &db, &first_stream, &"0".repeat(32)).await["unsubscribed"],
        true
    );
    assert_eq!(
        unsub(&registry, &db, "not-a-token", &id).await["unsubscribed"],
        true
    );
}

#[tokio::test]
async fn on_request_need_refuses_subscribe_and_if_revision() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    assert!(on_request_search(
        &registry,
        &db,
        &verified,
        json!({"subscribe": {"stream": stream}})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("invalid_params"));
    assert!(
        on_request_search(&registry, &db, &verified, json!({"if_revision": "abc"}))
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid_params")
    );
}

fn test_sink(db: &Db, token_hex: &str) -> tokio::sync::mpsc::Receiver<NeedSinkFrame> {
    let hub = RealtimeHub::for_database(db).expect("hub installed");
    let token = ConnectionToken::from_hex(token_hex).unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
    hub.need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_sink(&token, sender);
    receiver
}

fn mark_forcing(db: &Db, token_hex: &str, id: &str) {
    let hub = RealtimeHub::for_database(db).expect("hub installed");
    let token = ConnectionToken::from_hex(token_hex).unwrap();
    hub.need_registry()
        .lock()
        .expect("need registry poisoned")
        .enqueue_dirty(&token, &SubscriptionId::from_wire(id), true);
}

async fn drain_once(db: &Db) {
    let hub = RealtimeHub::for_database(db).expect("hub installed");
    NeedScheduler::new(hub).drain().await;
}

#[tokio::test]
async fn graph_keyed_visible_link_hints_one_variant_hidden_link_is_quiet() {
    const SEED1: &str = "f3d00000-0000-4000-8000-0000000000b1";
    const SEED2: &str = "f3d00000-0000-4000-8000-0000000000b2";
    const HIDDEN: &str = "f3d00000-0000-4000-8000-0000000000b3";
    const VISIBLE: &str = "f3d00000-0000-4000-8000-0000000000b4";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    for (id, name) in [
        (SEED1, "Seed one"),
        (SEED2, "Seed two"),
        (HIDDEN, "Hidden neighbour"),
        (VISIBLE, "Visible neighbour"),
    ] {
        live_task(&registry, &db, id, name, "open").await;
    }
    for id in [SEED1, SEED2, VISIBLE] {
        grant(&db, id, ALICE, Capability::View).await;
    }
    revoke_all(&db, HIDDEN).await;
    let seeds_sql = format!(
        "SELECT id, name FROM records WHERE id IN ('{SEED1}','{SEED2}') ORDER BY id LIMIT 9"
    );
    let neighbours_sql = "SELECT r.id, r.name FROM records r JOIN links l ON ((l.source_id = ?1 AND l.target_id = r.id) OR (l.target_id = ?1 AND l.source_id = r.id)) WHERE r.deleted_at IS NULL AND r.id != ?1 ORDER BY r.id LIMIT 48";
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.graph-frontier",
        json!({
            "needs": [sql_need("graph.seeds", "Seeds", &seeds_sql),
                {"need":"sql.snapshot.v1", "key":"graph.neighbours", "label":"Neighbours",
                 "sql": neighbours_sql, "params":[{"name":"seed_id","type":"text","max_len":128}]}],
            "effects": []
        }),
    )
    .await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action":"live_read", "package":"agent.graph-frontier",
            "expected_install_event_id":event, "subscribe":{"stream":stream}
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let sub_id = SubscriptionId::from_wire(&id);
    let mut sink = test_sink(&db, &stream);
    let read = |seed: &str| {
        json!({"action":"live_read", "package":"agent.graph-frontier",
        "expected_install_event_id":event, "need":"graph.neighbours",
        "params":{"seed_id":seed}, "watch":{"stream":stream,"subscription":id}})
    };
    let seed1 = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(SEED1),
    )
    .await
    .unwrap();
    let seed2 = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(SEED2),
    )
    .await
    .unwrap();
    assert!(seed1["keyed_freshness"]["variant"].is_string());
    assert!(seed2["keyed_freshness"]["variant"].is_string());
    let retained = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert!(retained.keyed.variants().all(
        |variant| variant.relations.contains("records") && variant.relations.contains("links")
    ));
    let initial_rows = seed1["result"]["rows"].clone();
    let initial_revision = seed1["revision"]["revision_digest"].clone();
    // A link to an invisible endpoint leaves the viewer's bytes unchanged.
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action":"add", "source_id":SEED1, "target_id":HIDDEN,
            "relationship":"relates_to"
        }),
    )
    .await
    .unwrap();
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let hidden_again = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(SEED1),
    )
    .await
    .unwrap();
    assert_eq!(hidden_again["result"]["rows"], initial_rows);
    assert_eq!(
        hidden_again["revision"]["revision_digest"],
        initial_revision
    );
    assert!(
        sink.try_recv().is_err(),
        "hidden link cannot produce a hint"
    );
    let state = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert_eq!(state.delivery, 0);
    // Visible edge changes seed2 only, so only its opaque variant is sent.
    call_as(
        &registry,
        &db,
        Caller::local(),
        "manage_links",
        json!({
            "action":"add", "source_id":SEED2, "target_id":VISIBLE,
            "relationship":"relates_to"
        }),
    )
    .await
    .unwrap();
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let NeedSinkFrame::Keyed(hint) = sink.try_recv().expect("visible keyed hint") else {
        panic!("keyed frame expected")
    };
    assert_eq!(hint.key, seed2["keyed_freshness"]["variant"]);
    assert_eq!(hint.delivery, 1);
    let fresh = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(SEED2),
    )
    .await
    .unwrap();
    assert_eq!(hint.at_revision, fresh["revision"]["revision_digest"]);
    assert_ne!(fresh["result"]["rows"], seed2["result"]["rows"]);
    assert!(sink.try_recv().is_err(), "seed1 must not hint");
    // Bounded session state: the 33rd distinct params value evicts one
    // variant, reports the degraded key, and the evicted seed remains a
    // correct pull read when opened again.
    let mut overflow = Value::Null;
    for index in 0..31 {
        overflow = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            read(&format!("unknown-seed-{index}")),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        overflow["keyed_freshness"]["evicted"],
        json!(["graph.neighbours"])
    );
    let reopened = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(SEED1),
    )
    .await
    .unwrap();
    assert_eq!(reopened["result"]["rows"], initial_rows);
}

/// Production Folders SQL, extracted from the fixture single-source so the
/// keyed test binds the exact declared statements (not a reduced copy).
/// Precedent: `alpha_tabs.rs` already `include_str!`s experiments bundles.
const FOLDERS_FIXTURE: &str = include_str!("../../experiments/demo-shell/fixtures/folders-sql.mjs");

fn folders_fixture_sql(name: &str) -> String {
    let marker = format!("export const {name} = `");
    let body = FOLDERS_FIXTURE
        .find(&marker)
        .unwrap_or_else(|| panic!("folders fixture lacks {name}"));
    let start = body + marker.len();
    let end = FOLDERS_FIXTURE[start..]
        .find('`')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("folders fixture {name} is unterminated"));
    FOLDERS_FIXTURE[start..end].to_string()
}

/// Folders `folders.children` keyed freshness (first Folders slice).
///
/// Two folder variants under one snapshot pin: a post-subscription
/// hidden-only write burst (revoked child plus archiving it, across both
/// declared tables) leaves rows, revision, stored fingerprints, outbox and
/// delivery counter untouched, while a visible child write hints only the
/// affected folder with `at_revision` equal to the governed re-read digest.
/// The 33rd variant exercises the eviction/pull fallback and disable closes
/// the pin. `browse.children` is a separate package and is not covered here.
#[tokio::test]
async fn folders_children_visible_result_only_hints_affected_folder() {
    const FOLDER_A: &str = "f7d00000-0000-4000-8000-0000000000a1";
    const FOLDER_B: &str = "f7d00000-0000-4000-8000-0000000000a2";
    const KID_A: &str = "f7d00000-0000-4000-8000-0000000000b1";
    const KID_B: &str = "f7d00000-0000-4000-8000-0000000000b2";
    const HIDDEN_KID: &str = "f7d00000-0000-4000-8000-0000000000c1";
    const VISIBLE_KID: &str = "f7d00000-0000-4000-8000-0000000000c2";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    async fn folder(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"id": id, "type": "Collection", "kind": "folder",
                    "name": name, "body": name,
                    "reason": "Folders keyed freshness fixture."}),
            )
            .await
            .unwrap();
    }
    async fn kid(registry: &ToolRegistry, db: &Db, id: &str, name: &str, home: &str) {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"id": id, "type": "Document", "kind": "note",
                    "name": name, "body": name, "home_id": home,
                    "reason": "Folders keyed freshness fixture."}),
            )
            .await
            .unwrap();
    }
    folder(&registry, &db, FOLDER_A, "Folder A").await;
    folder(&registry, &db, FOLDER_B, "Folder B").await;
    kid(&registry, &db, KID_A, "Kid A", FOLDER_A).await;
    kid(&registry, &db, KID_B, "Kid B", FOLDER_B).await;
    for id in [FOLDER_A, FOLDER_B, KID_A, KID_B] {
        grant(&db, id, ALICE, Capability::View).await;
    }
    let roots_sql = folders_fixture_sql("FOLDERS_ROOTS_SQL");
    let children_sql = folders_fixture_sql("FOLDERS_CHILDREN_SQL");
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.folders",
        json!({
            "needs": [sql_need("folders.roots", "Roots", &roots_sql),
                {"need":"sql.snapshot.v1", "key":"folders.children", "label":"Children",
                 "sql": children_sql, "params":[{"name":"folder_id","type":"text","max_len":128}]}],
            "effects": []
        }),
    )
    .await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action":"live_read", "package":"agent.folders",
            "expected_install_event_id":event, "subscribe":{"stream":stream}
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let sub_id = SubscriptionId::from_wire(&id);
    let mut sink = test_sink(&db, &stream);
    let read = |folder: &str| {
        json!({"action":"live_read", "package":"agent.folders",
        "expected_install_event_id":event, "need":"folders.children",
        "params":{"folder_id":folder}, "watch":{"stream":stream,"subscription":id}})
    };
    let kids_a = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    let kids_b = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_B),
    )
    .await
    .unwrap();
    assert!(kids_a["keyed_freshness"]["variant"].is_string());
    assert!(kids_b["keyed_freshness"]["variant"].is_string());
    assert_ne!(
        kids_a["keyed_freshness"]["variant"],
        kids_b["keyed_freshness"]["variant"]
    );
    let retained = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert_eq!(retained.keyed.variants_for("folders.children").count(), 2);
    for variant in retained.keyed.variants_for("folders.children") {
        assert_eq!(
            variant.relations,
            std::collections::BTreeSet::from(["facet_values".to_string(), "records".to_string()])
        );
    }
    let digest_of = |read: &Value| {
        read["keyed_freshness"]["variant"]
            .as_str()
            .unwrap()
            .strip_prefix("folders.children:")
            .unwrap()
            .to_string()
    };
    let digest_a = digest_of(&kids_a);
    let digest_b = digest_of(&kids_b);
    let stored_revision = |digest: &str| {
        RealtimeHub::for_database(&db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed
            .revision("folders.children", digest)
            .unwrap()
            .to_string()
    };
    let initial_rows = kids_a["result"]["rows"].clone();
    let initial_revision = kids_a["revision"]["revision_digest"].clone();
    let fp_a_before = stored_revision(&digest_a);
    let fp_b_before = stored_revision(&digest_b);
    let keyed_dirty = || {
        RealtimeHub::for_database(&db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed_dirty
    };
    // Causal pump barrier: await tail-pump publication of everything
    // committed so far (durable `content_events.seq` high-water) before a
    // forced drain reads scheduler state. Bounded fail-closed wait on the
    // existing hidden seam — never a sleep, and delivery never depends on
    // it. Without this, a forced drain can retain a Content trigger with
    // keyed_dirty false and skip the keyed comparison
    // (`live_scheduler.rs` reruns keyed only when the snapshot wake is
    // forcing or keyed_dirty), so the `try_recv` below is timing-sensitive.
    let await_published = |label: &'static str| {
        let db = &db;
        async move {
            let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                native_ce::realtime::wait_until_published_for_tests(db, seq),
            )
            .await
            .unwrap_or_else(|_| panic!("{label}: pump did not publish seq {seq}"));
        }
    };
    // Settle the admission catch-up: silent when nothing changed, and the
    // scheduler consumes the pass (clean baseline for the vacuity guard).
    // Publish first: a backlog publishing between this drain and the
    // !keyed_dirty baseline (or after it) would violate the clean-settle
    // premise the vacuity guard rests on.
    await_published("admission catch-up").await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(
        sink.try_recv().is_err(),
        "admission catch-up must be silent"
    );
    assert!(!keyed_dirty());
    // Post-subscription hidden burst across both tables the key declares: a
    // revoked child (records) plus archiving it (facet_values, via the
    // governed archive path since `archived` is engine-reserved). Both stay
    // invisible to Alice, so rows, revision, stored fingerprints, outbox and
    // the delivery counter must not move.
    kid(&registry, &db, HIDDEN_KID, "Hidden kid", FOLDER_A).await;
    revoke_all(&db, HIDDEN_KID).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "archive_record",
            json!({"id": HIDDEN_KID, "reason": "Hidden archive burst."}),
        )
        .await
        .unwrap();
    // Publication must precede the guard: the async tail pump (not the
    // writes) schedules the keyed comparison, so assert only after it has
    // observably published the burst.
    await_published("hidden burst").await;
    // Vacuity guard: the hidden burst must actually schedule keyed
    // comparisons (intersect the table prefilter) before the drain.
    assert!(
        keyed_dirty(),
        "hidden burst must schedule keyed comparisons"
    );
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let hidden_again = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    assert_eq!(hidden_again["result"]["rows"], initial_rows);
    assert_eq!(
        hidden_again["revision"]["revision_digest"],
        initial_revision
    );
    assert_eq!(stored_revision(&digest_a), fp_a_before);
    assert_eq!(stored_revision(&digest_b), fp_b_before);
    assert!(
        sink.try_recv().is_err(),
        "hidden write cannot produce a hint"
    );
    let state = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert_eq!(state.delivery, 0);
    // Visible child lands in folder B only: exactly one hint names B's
    // opaque variant and its revision matches the governed re-read.
    kid(&registry, &db, VISIBLE_KID, "Visible kid", FOLDER_B).await;
    grant(&db, VISIBLE_KID, ALICE, Capability::View).await;
    // Same publication barrier as the hidden burst: without it the forced
    // drain can keep a Content trigger with keyed_dirty false, skip the
    // keyed comparison, and leave the sink empty on a loaded runner.
    await_published("visible kid").await;
    assert!(
        keyed_dirty(),
        "visible write must schedule keyed comparisons"
    );
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let NeedSinkFrame::Keyed(hint) = sink.try_recv().expect("visible keyed hint") else {
        panic!("keyed frame expected")
    };
    assert_eq!(hint.key, kids_b["keyed_freshness"]["variant"]);
    assert_eq!(hint.delivery, 1);
    let fresh = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_B),
    )
    .await
    .unwrap();
    assert_eq!(hint.at_revision, fresh["revision"]["revision_digest"]);
    assert_ne!(fresh["result"]["rows"], kids_b["result"]["rows"]);
    assert!(sink.try_recv().is_err(), "folder A must not hint");
    // Bounded session state per declared key: the 33rd distinct folder
    // evicts one variant, reports the degraded key, and the evicted folder
    // remains a correct pull read when opened again.
    let mut overflow = Value::Null;
    for index in 0..31 {
        overflow = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            read(&format!("unknown-folder-{index}")),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        overflow["keyed_freshness"]["evicted"],
        json!(["folders.children"])
    );
    let reopened = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    assert_eq!(reopened["result"]["rows"], initial_rows);
    // Disable closes the pin: hints stop and the subscription is gone.
    call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.folders",
            "expected_install_event_id": event,
            "reason": "Pause the tab for the closure test.",
        }),
    )
    .await
    .unwrap();
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

/// Keyset-paged `folders.children` for the per-page revision proof below.
///
/// The shipped Folders children statement, extended with a keyset predicate
/// over its own `ORDER BY name ASC, id ASC LIMIT 200`: `?2`/`?3` are the
/// last delivered `(name, id)`, both required, and empty strings start the
/// chain. No new keyed key: the declared key stays `folders.children`.
fn paged_children_sql() -> String {
    let base = folders_fixture_sql("FOLDERS_CHILDREN_SQL");
    let order = "ORDER BY name ASC, id ASC LIMIT 200";
    assert_eq!(
        base.matches(order).count(),
        1,
        "shipped children SQL order changed"
    );
    base.replace(
        order,
        &format!("AND (name > ?2 OR (name = ?2 AND id > ?3)) {order}"),
    )
}

const PAGED_PACKAGE: &str = "agent.folders-paged";
const PAGED_KEY: &str = "folders.children";
const PAGED_FOLDER: &str = "f7e00000-0000-4000-8000-0000000000f1";
const PAGED_OTHER_FOLDER: &str = "f7e00000-0000-4000-8000-0000000000f2";
const PAGED_OTHER_KID: &str = "f7e00000-0000-4000-8000-0000000000f3";
const PAGED_PAGE_SIZE: usize = 200;
/// 1,071 children, 21 of them hidden from ALICE, leaving 1,050 visible:
/// more than `query_sql`'s own 1,000-row cap, so six keyset pages.
const PAGED_CHILDREN: usize = 1_071;

/// Ids run opposite to indices, so within a name pair the higher index
/// sorts first and only the `(name, id)` tie-break decides the order.
fn paged_child_id(index: usize) -> String {
    format!("c1d00000-0000-4000-8000-{:012}", 9_999 - index)
}

/// Names pair indices `(2k - 1, 2k)`. With the hidden rule below this puts
/// the two halves of a pair on either side of every initial page boundary
/// (asserted in the test, not assumed), so each next-page cursor is a
/// `(name, id)` whose name continues on the following page.
fn paged_child_name(index: usize) -> String {
    format!("Child {:04}", index.div_ceil(2))
}

fn paged_child_hidden(index: usize) -> bool {
    index % 51 == 7
}

type KeysetCursor = (String, String);

struct KeysetPage {
    after: KeysetCursor,
    variant: Option<String>,
    revision: String,
    rows: Vec<KeysetCursor>,
}

fn paged_params(after: &KeysetCursor) -> Value {
    json!({"folder_id": PAGED_FOLDER, "after_name": after.0, "after_id": after.1})
}

/// The full keyed variant identity, derived with the production helpers the
/// read path uses: key plus the canonical digest of the complete params.
fn paged_variant(after: &KeysetCursor) -> String {
    native_ce::keyed_freshness::variant_handle(
        PAGED_KEY,
        &native_ce::need_subscriptions::params_digest(Some(&paged_params(after))),
    )
}

/// No frame-visible key or column may carry a sequence (task `a5804e8`):
/// not in results, cursors, revisions or keyed freshness.
fn assert_no_sequence_fields(value: &Value, path: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                assert!(
                    !key.to_ascii_lowercase().contains("seq"),
                    "{path}.{key} exposes a sequence"
                );
                assert_no_sequence_fields(child, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_sequence_fields(item, path);
            }
        }
        _ => {}
    }
}

/// One governed on-request page, optionally watched on the snapshot
/// subscription. Each page is its own read under ALICE's authority at the
/// moment it runs; nothing ties it to any other page's state.
async fn read_keyset_page(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    watch: Option<(&str, &str)>,
    after: &KeysetCursor,
) -> KeysetPage {
    let mut args = json!({
        "action": "live_read", "package": PAGED_PACKAGE,
        "expected_install_event_id": event, "need": PAGED_KEY,
        "params": paged_params(after),
    });
    if let Some((stream, subscription)) = watch {
        args["watch"] = json!({"stream": stream, "subscription": subscription});
    }
    let read = call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap();
    assert_no_sequence_fields(&read, "read");
    assert_eq!(read["need"], PAGED_KEY);
    assert_eq!(
        read["params"],
        paged_params(after),
        "the read echoes its complete cursor params"
    );
    for column in read["result"]["columns"].as_array().unwrap() {
        let name = column
            .as_str()
            .or_else(|| column["name"].as_str())
            .unwrap_or_default();
        assert!(!name.contains("seq"), "column {name} exposes a sequence");
    }
    let rows: Vec<KeysetCursor> = read["result"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_string(),
                row["id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(rows.len() <= PAGED_PAGE_SIZE);
    assert_eq!(read["result"]["row_count"], json!(rows.len()));
    assert_eq!(read["result"]["truncated"], false);
    let variant = watch.map(|_| {
        assert_eq!(
            read["keyed_freshness"]["evicted"],
            json!([]),
            "the chain stays inside the 32-variant bound"
        );
        let variant = read["keyed_freshness"]["variant"]
            .as_str()
            .expect("watched keyed read returns its variant")
            .to_string();
        assert_eq!(
            variant,
            paged_variant(after),
            "the variant is the key plus the canonical digest of the full params"
        );
        variant
    });
    KeysetPage {
        after: after.clone(),
        variant,
        revision: read["revision"]["revision_digest"]
            .as_str()
            .expect("keyed page carries its own revision")
            .to_string(),
        rows,
    }
}

/// Page to completion from `after`, watching every page. A short page ends
/// the chain. Every page is recorded in `tracked` as variant -> (cursor,
/// revision), the host-side record a package would hold.
async fn read_keyset_chain(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    watch: (&str, &str),
    mut after: KeysetCursor,
    tracked: &mut std::collections::BTreeMap<String, (KeysetCursor, String)>,
) -> Vec<KeysetPage> {
    let mut pages = Vec::new();
    loop {
        let page = read_keyset_page(registry, db, event, Some(watch), &after).await;
        tracked.insert(
            page.variant.clone().unwrap(),
            (after.clone(), page.revision.clone()),
        );
        let short = page.rows.len() < PAGED_PAGE_SIZE;
        if let Some(last) = page.rows.last() {
            after = last.clone();
        }
        pages.push(page);
        if short {
            return pages;
        }
        assert!(pages.len() <= 12, "chain must stay bounded");
    }
}

/// The recovery rule under test: keep the pages before the earliest moved
/// page, re-read that page at its unchanged cursor, and page on from its
/// new last key.
async fn rechain_keyset_from(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    watch: (&str, &str),
    chain: &mut Vec<KeysetPage>,
    from: usize,
    tracked: &mut std::collections::BTreeMap<String, (KeysetCursor, String)>,
) {
    let after = chain[from].after.clone();
    chain.truncate(from);
    chain.extend(read_keyset_chain(registry, db, event, watch, after, tracked).await);
}

/// The held set a package would have if it re-read only the moved pages
/// and kept every other page as held: the tempting shortcut the test shows
/// to be wrong when boundaries shift.
async fn naive_keyset_refresh(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    chain: &[KeysetPage],
    moved: &[usize],
) -> Vec<KeysetCursor> {
    let mut rows = Vec::new();
    for (index, page) in chain.iter().enumerate() {
        if moved.contains(&index) {
            rows.extend(
                read_keyset_page(registry, db, event, None, &page.after)
                    .await
                    .rows,
            );
        } else {
            rows.extend(page.rows.iter().cloned());
        }
    }
    rows
}

fn moved_in_chain(
    chain: &[KeysetPage],
    changed: &std::collections::BTreeSet<String>,
) -> Vec<usize> {
    chain
        .iter()
        .enumerate()
        .filter(|(_, page)| changed.contains(page.variant.as_ref().unwrap()))
        .map(|(index, _)| index)
        .collect()
}

fn flatten_keyset(chain: &[KeysetPage]) -> Vec<KeysetCursor> {
    chain
        .iter()
        .flat_map(|page| page.rows.iter().cloned())
        .collect()
}

/// Wait for the tail pump to publish everything committed so far, the same
/// fail-closed barrier as the Folders keyed test above. Never a sleep.
async fn await_paged_published(db: &Db, label: &str) {
    let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        native_ce::realtime::wait_until_published_for_tests(db, seq),
    )
    .await
    .unwrap_or_else(|_| panic!("{label}: pump did not publish seq {seq}"));
}

/// Force one scheduler pass, then hold the hints to the governed truth:
/// re-read every tracked variant (unwatched) and require that the hinted
/// set is exactly the set whose visible result moved, that each hint's
/// `at_revision` equals that re-read, and that the retained fingerprint
/// carries the full identity (key, complete params, canonical params
/// digest) and the re-read revision. Returns the changed variants;
/// `tracked` is updated.
#[allow(clippy::too_many_arguments)]
async fn drain_and_match_keyed_hints(
    registry: &ToolRegistry,
    db: &Db,
    event: &str,
    stream: &str,
    id: &str,
    sink: &mut tokio::sync::mpsc::Receiver<NeedSinkFrame>,
    tracked: &mut std::collections::BTreeMap<String, (KeysetCursor, String)>,
    label: &str,
) -> std::collections::BTreeSet<String> {
    await_paged_published(db, label).await;
    mark_forcing(db, stream, id);
    drain_once(db).await;
    let mut hinted = std::collections::BTreeMap::new();
    while let Ok(frame) = sink.try_recv() {
        let NeedSinkFrame::Keyed(hint) = frame else {
            panic!("{label}: only keyed hints are expected");
        };
        assert_eq!(hint.subscription, id);
        assert_no_sequence_fields(&serde_json::to_value(&hint).unwrap(), "hint");
        assert!(
            hinted.insert(hint.key.clone(), hint.at_revision).is_none(),
            "{label}: one hint per variant per pass"
        );
    }
    let token = ConnectionToken::from_hex(stream).unwrap();
    let sub_id = SubscriptionId::from_wire(id);
    let mut changed = std::collections::BTreeSet::new();
    for (variant, (after, known)) in tracked.iter_mut() {
        let fresh = read_keyset_page(registry, db, event, None, after).await;
        let params = paged_params(after);
        let params_digest = native_ce::need_subscriptions::params_digest(Some(&params));
        assert_eq!(
            *variant,
            native_ce::keyed_freshness::variant_handle(PAGED_KEY, &params_digest)
        );
        let retained = RealtimeHub::for_database(db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed
            .variants_for(PAGED_KEY)
            .find(|fingerprint| fingerprint.params_digest == params_digest)
            .cloned()
            .unwrap_or_else(|| panic!("{label}: {variant} is retained"));
        assert_eq!(retained.key, PAGED_KEY);
        assert_eq!(
            retained.params, params,
            "{label}: retained params are the complete cursor"
        );
        assert_eq!(
            retained.revision, fresh.revision,
            "{label}: retained fingerprint for {variant} matches the governed re-read"
        );
        if fresh.revision != *known {
            assert_eq!(
                hinted.get(variant),
                Some(&fresh.revision),
                "{label}: hint for {variant} names the governed re-read"
            );
            changed.insert(variant.clone());
            *known = fresh.revision;
        }
    }
    assert_eq!(
        hinted
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        changed,
        "{label}: hints name exactly the variants whose visible result moved"
    );
    changed
}

/// Per-page keyed revision evidence for keyset paging past 1,000 rows
/// (task `232e8f5`, design `f7088a0` S1), through the existing
/// `folders.children` key, watch and scheduler: no new key, engine API or
/// snapshot semantics.
///
/// What this proves, and what it does not:
/// - Each page is a separate governed on-request read that echoes its
///   complete cursor params, has the canonical variant identity (key plus
///   params digest) and its own `revision_digest` over that page's
///   viewer-visible rows. Pages are read at different moments under the
///   authority current at each read; the chain is **not** a snapshot of
///   one instant, and no digest here anchors another page's data.
/// - Name pairs straddle every initial page boundary, so each next-page
///   cursor relies on the `(name, id)` tie-break.
/// - A write hints exactly the variants whose visible result moved, each
///   with `at_revision` equal to the governed re-read; hidden and unrelated
///   writes move nothing.
/// - A hint says *which page moved*, not how the chain shifted. After a
///   rename across a boundary, a deletion of a cursor row, an insert or a
///   visibility loss, re-reading only the moved pages loses or repeats rows
///   at the boundaries (shown here each time). Re-reading from the earliest
///   moved page and re-chaining from its new last key restores an exact-once
///   set, so that rule is evidence rather than advice.
/// - No sequence appears in any result, cursor, revision or hint.
///   Eviction past 32 variants is covered by
///   `folders_children_visible_result_only_hints_affected_folder`; this
///   proof stays inside the bound and asserts nothing was evicted.
#[tokio::test]
async fn folders_children_keyset_pages_carry_per_page_keyed_revisions() {
    use native_ce::store::{append_batch, create_record as create_raw_record, AppendSpec};
    use std::collections::{BTreeMap, BTreeSet};
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    // Children inherit their folder's policy boundary, so seeding costs
    // two grants, one batched append per 250 children and one explicit
    // empty policy per hidden child, rather than a tool call per record.
    for (folder, name) in [
        (PAGED_FOLDER, "Paged folder"),
        (PAGED_OTHER_FOLDER, "Other folder"),
    ] {
        create_raw_record(
            &db,
            json!({"id": folder, "type": "Collection", "kind": "folder", "name": name}),
        )
        .await
        .unwrap();
        grant(&db, folder, ALICE, Capability::View).await;
    }
    append_batch(
        &db,
        vec![AppendSpec {
            record_id: PAGED_OTHER_KID.to_string(),
            event_type: "record.created".into(),
            payload: json!({"type": "Document", "kind": "note", "name": "Other kid",
                "body": "Other kid", "home_id": PAGED_OTHER_FOLDER}),
            actor: None,
        }],
    )
    .await
    .unwrap();
    // Out of order, so only ORDER BY can order them.
    let order: Vec<usize> = (0..PAGED_CHILDREN)
        .map(|step| (step * 7919) % PAGED_CHILDREN)
        .collect();
    for chunk in order.chunks(250) {
        let specs = chunk
            .iter()
            .map(|index| AppendSpec {
                record_id: paged_child_id(*index),
                event_type: "record.created".into(),
                payload: json!({"type": "Document", "kind": "note",
                    "name": paged_child_name(*index), "body": "Paged child",
                    "home_id": PAGED_FOLDER}),
                actor: None,
            })
            .collect();
        append_batch(&db, specs).await.unwrap();
    }
    for index in (0..PAGED_CHILDREN).filter(|index| paged_child_hidden(*index)) {
        revoke_all(&db, &paged_child_id(index)).await;
    }
    let mut expected: Vec<KeysetCursor> = (0..PAGED_CHILDREN)
        .filter(|index| !paged_child_hidden(*index))
        .map(|index| (paged_child_name(index), paged_child_id(index)))
        .collect();
    expected.sort();
    assert_eq!(expected.len(), 1_050);

    let roots_sql = folders_fixture_sql("FOLDERS_ROOTS_SQL");
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        PAGED_PACKAGE,
        json!({
            "needs": [sql_need("folders.roots", "Roots", &roots_sql),
                {"need": "sql.snapshot.v1", "key": PAGED_KEY,
                 "label": "Children, in keyset pages of 200", "sql": paged_children_sql(),
                 "params": [{"name": "folder_id", "type": "text", "max_len": 128},
                            {"name": "after_name", "type": "text", "max_len": 256},
                            {"name": "after_id", "type": "text", "max_len": 128}]}],
            "effects": []
        }),
    )
    .await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read", "package": PAGED_PACKAGE,
            "expected_install_event_id": event, "subscribe": {"stream": stream}
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    let watch = (stream.as_str(), id.as_str());
    let start: KeysetCursor = (String::new(), String::new());
    let mut tracked: BTreeMap<String, (KeysetCursor, String)> = BTreeMap::new();

    // 1. Initial chain: six pages, deterministic, every visible child once,
    //    each page its own variant and revision, with a name pair split
    //    across every page boundary.
    let mut chain =
        read_keyset_chain(&registry, &db, &event, watch, start.clone(), &mut tracked).await;
    assert_eq!(
        chain.iter().map(|page| page.rows.len()).collect::<Vec<_>>(),
        vec![200, 200, 200, 200, 200, 50]
    );
    assert_eq!(
        flatten_keyset(&chain),
        expected,
        "every visible child once, in (name, id) order, no gaps"
    );
    for boundary in chain.windows(2) {
        let last = boundary[0].rows.last().unwrap();
        let next = boundary[1].rows.first().unwrap();
        assert_eq!(&boundary[1].after, last, "the cursor is the last row held");
        assert_eq!(last.0, next.0, "a name pair straddles the boundary");
        assert!(last.1 < next.1, "the id tie-break orders it");
    }
    assert_eq!(tracked.len(), 6, "one keyed variant per page");
    assert_eq!(
        chain
            .iter()
            .map(|page| page.revision.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        6,
        "each page carries its own revision"
    );
    let again = read_keyset_chain(&registry, &db, &event, watch, start.clone(), &mut tracked).await;
    assert_eq!(
        tracked.len(),
        6,
        "the same state pages to the same variants"
    );
    for (before, after) in chain.iter().zip(&again) {
        assert_eq!(before.rows, after.rows);
        assert_eq!(before.revision, after.revision);
        assert_eq!(before.variant, after.variant);
    }
    await_paged_published(&db, "admission").await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(
        sink.try_recv().is_err(),
        "admission catch-up must be silent"
    );

    // 2. Hidden and unrelated writes: a hidden child renamed, a hidden child
    //    inserted into the paged folder, and a visible child of another
    //    folder renamed. No page moves and nothing is hinted.
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({"id": paged_child_id(7), "name": "Child 0000 hidden rename",
                "reason": "Hidden rename inside the paged folder."}),
        )
        .await
        .unwrap();
    let hidden_insert = "c1d00000-0000-4000-8000-b00000000001";
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({"id": hidden_insert, "type": "Document", "kind": "note",
                "name": "Child 0000 hidden insert", "body": "Hidden", "home_id": PAGED_FOLDER,
                "reason": "Hidden insert inside the paged folder."}),
        )
        .await
        .unwrap();
    revoke_all(&db, hidden_insert).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({"id": PAGED_OTHER_KID, "name": "Other kid renamed",
                "reason": "Visible write in an unrelated folder."}),
        )
        .await
        .unwrap();
    await_paged_published(&db, "hidden and unrelated").await;
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let sub_id = SubscriptionId::from_wire(&id);
    assert!(
        RealtimeHub::for_database(&db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed_dirty,
        "the burst must schedule keyed comparisons (vacuity guard)"
    );
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "hidden and unrelated",
    )
    .await;
    assert!(
        changed.is_empty(),
        "hidden or unrelated writes move no page"
    );

    // 3. A visible rename inside page 2 that keeps page 2's membership: only
    //    page 2 moves.
    let (renamed_name, renamed_id) = expected[250].clone();
    let page_two_before: BTreeSet<String> =
        expected[200..400].iter().map(|row| row.1.clone()).collect();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({"id": renamed_id, "name": format!("{renamed_name} renamed"),
                "reason": "Visible rename inside page 2."}),
        )
        .await
        .unwrap();
    let position = expected.iter().position(|row| row.1 == renamed_id).unwrap();
    expected[position].0 = format!("{renamed_name} renamed");
    expected.sort();
    assert_eq!(
        expected[200..400]
            .iter()
            .map(|row| row.1.clone())
            .collect::<BTreeSet<_>>(),
        page_two_before,
        "the rename stays inside page 2's boundaries"
    );
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "page 2 rename",
    )
    .await;
    assert_eq!(moved_in_chain(&chain, &changed), vec![1]);
    assert_eq!(changed.len(), 1, "only page 2's visible result moved");
    rechain_keyset_from(&registry, &db, &event, watch, &mut chain, 1, &mut tracked).await;
    assert_eq!(flatten_keyset(&chain), expected);

    // 4. A rename across the page 2 / page 3 boundary. The last row of
    //    page 2 shares its name with the first row of page 3; renaming it to
    //    sort after its partner moves both pages. Re-reading only those two
    //    repeats the partner and loses page 3's old last row.
    let (pair_name, crossing_id) = expected[399].clone();
    let partner = expected[400].clone();
    assert_eq!(partner.0, pair_name, "the boundary splits a name pair");
    assert!(crossing_id < partner.1);
    assert_eq!(chain[2].after, expected[399], "page 3's cursor is that row");
    let old_page_three_last = expected[599].clone();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            json!({"id": crossing_id, "name": format!("{pair_name} moved"),
                "reason": "Visible rename across the page 2 / page 3 boundary."}),
        )
        .await
        .unwrap();
    let position = expected
        .iter()
        .position(|row| row.1 == crossing_id)
        .unwrap();
    expected[position].0 = format!("{pair_name} moved");
    expected.sort();
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "boundary rename",
    )
    .await;
    let moved = moved_in_chain(&chain, &changed);
    assert_eq!(moved, vec![1, 2], "both pages at the boundary moved");
    let naive = naive_keyset_refresh(&registry, &db, &event, &chain, &moved).await;
    assert_eq!(
        naive.iter().filter(|row| **row == partner).count(),
        2,
        "re-reading only the moved pages repeats the partner"
    );
    assert!(
        !naive.contains(&old_page_three_last),
        "re-reading only the moved pages loses page 3's old last row"
    );
    rechain_keyset_from(&registry, &db, &event, watch, &mut chain, 1, &mut tracked).await;
    assert_eq!(
        flatten_keyset(&chain),
        expected,
        "re-chaining from the earliest moved page is exact-once again"
    );

    // 5. Deleting the row that is page 5's cursor, at a boundary that splits
    //    a name pair. Page 4 moves; page 5's keyset predicate is by value,
    //    so it keeps its result, and re-reading only page 4 repeats the row
    //    pulled forward.
    let deleted = expected[799].clone();
    let pulled = expected[800].clone();
    assert_eq!(deleted.0, pulled.0, "the boundary splits a name pair");
    assert!(deleted.1 < pulled.1);
    assert_eq!(
        chain[4].after, deleted,
        "the deleted row is page 5's cursor"
    );
    registry
        .call(
            db.clone(),
            Caller::local(),
            "delete_record",
            json!({"id": deleted.1, "reason": "Delete the page 5 cursor row."}),
        )
        .await
        .unwrap();
    expected.retain(|row| row.1 != deleted.1);
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "boundary deletion",
    )
    .await;
    let moved = moved_in_chain(&chain, &changed);
    assert_eq!(moved, vec![3], "only page 4 moved in the current chain");
    let naive = naive_keyset_refresh(&registry, &db, &event, &chain, &moved).await;
    assert_eq!(
        naive.iter().filter(|row| **row == pulled).count(),
        2,
        "re-reading only page 4 repeats the row pulled forward"
    );
    rechain_keyset_from(&registry, &db, &event, watch, &mut chain, 3, &mut tracked).await;
    assert!(!flatten_keyset(&chain).contains(&deleted));
    assert_eq!(
        flatten_keyset(&chain),
        expected,
        "re-chaining from the earliest moved page is exact-once again"
    );

    // 6. A visible insert sorting into page 1. Page 1 moves; later pages keep
    //    their cursors, so the row page 1 pushed out is in no held page until
    //    the chain is re-read from page 1.
    let displaced = expected[199].clone();
    let inserted = "c1d00000-0000-4000-8000-a00000000001";
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({"id": inserted, "type": "Document", "kind": "note",
                "name": "Child 0000 inserted", "body": "Inserted", "home_id": PAGED_FOLDER,
                "reason": "Visible insert sorting into page 1."}),
        )
        .await
        .unwrap();
    expected.push(("Child 0000 inserted".to_string(), inserted.to_string()));
    expected.sort();
    assert_eq!(expected.len(), 1_050);
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "page 1 insert",
    )
    .await;
    let moved = moved_in_chain(&chain, &changed);
    assert_eq!(moved, vec![0], "only page 1 moved in the current chain");
    let naive = naive_keyset_refresh(&registry, &db, &event, &chain, &moved).await;
    assert!(
        !naive.contains(&displaced),
        "re-reading only page 1 loses the displaced row"
    );
    rechain_keyset_from(&registry, &db, &event, watch, &mut chain, 0, &mut tracked).await;
    assert_eq!(chain.len(), 6);
    assert_eq!(
        flatten_keyset(&chain),
        expected,
        "re-chaining from the earliest moved page is exact-once again"
    );

    // 7. View loss on a visible child in page 3 of the current chain. Its
    //    page moves; later pages keep their cursors, so the row pulled
    //    forward is held twice until the chain is re-read from that page.
    let (_, lost_id) = expected[450].clone();
    let pulled_forward = expected[600].clone();
    revoke_all(&db, &lost_id).await;
    expected.retain(|row| row.1 != lost_id);
    let changed = drain_and_match_keyed_hints(
        &registry,
        &db,
        &event,
        &stream,
        &id,
        &mut sink,
        &mut tracked,
        "page 3 view loss",
    )
    .await;
    let moved = moved_in_chain(&chain, &changed);
    assert_eq!(moved, vec![2], "only page 3 moved in the current chain");
    let naive = naive_keyset_refresh(&registry, &db, &event, &chain, &moved).await;
    assert!(!naive.iter().any(|row| row.1 == lost_id));
    assert_eq!(
        naive.iter().filter(|row| **row == pulled_forward).count(),
        2,
        "re-reading only page 3 repeats the row pulled forward"
    );
    rechain_keyset_from(&registry, &db, &event, watch, &mut chain, 2, &mut tracked).await;
    let flat = flatten_keyset(&chain);
    assert!(!flat.iter().any(|row| row.1 == lost_id));
    assert_eq!(
        flat, expected,
        "re-chaining from the earliest moved page is exact-once again"
    );
    assert!(tracked.len() <= 32, "no eviction inside this proof");
    assert!(sink.try_recv().is_err(), "no stray frames");
}

/// Production Browse SQL, extracted from the second package's fixture
/// single-source so the keyed test binds the exact declared statements
/// (not a reduced copy). Same exact-marker boundary precedent as
/// `folders_fixture_sql` above: `export const {name} = \`` match, never a
/// broad substring.
const BROWSE_FIXTURE: &str =
    include_str!("../../experiments/demo-shell/fixtures/folders-browse-sql.mjs");

fn browse_fixture_sql(name: &str) -> String {
    let marker = format!("export const {name} = `");
    let body = BROWSE_FIXTURE
        .find(&marker)
        .unwrap_or_else(|| panic!("browse fixture lacks {name}"));
    let start = body + marker.len();
    let end = BROWSE_FIXTURE[start..]
        .find('`')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("browse fixture {name} is unterminated"));
    BROWSE_FIXTURE[start..end].to_string()
}

/// Browse `browse.children` keyed freshness (backend-only slice).
///
/// The independently authored second Folders package reads a distinct need
/// key (`browse.children`, parameter `folder`) with its own 32-variant LRU,
/// so its session load can never evict `folders.children` and vice versa.
/// Same shape as the first-package test: a post-subscription hidden-only
/// write burst (revoked child plus archiving it, across both declared
/// tables) leaves rows, revision, stored fingerprints, outbox and delivery
/// counter untouched, while a visible child write hints only the affected
/// folder with `at_revision` equal to the governed re-read digest. The 33rd
/// variant exercises the eviction/pull fallback and disable closes the pin.
/// Host routing (`pending.js` keyed allowlist) and package wiring stay
/// untouched in this slice.
#[tokio::test]
async fn browse_children_visible_result_only_hints_affected_folder() {
    const FOLDER_A: &str = "f7d00000-0000-4000-8000-0000000000a1";
    const FOLDER_B: &str = "f7d00000-0000-4000-8000-0000000000a2";
    const KID_A: &str = "f7d00000-0000-4000-8000-0000000000b1";
    const KID_B: &str = "f7d00000-0000-4000-8000-0000000000b2";
    const HIDDEN_KID: &str = "f7d00000-0000-4000-8000-0000000000c1";
    const VISIBLE_KID: &str = "f7d00000-0000-4000-8000-0000000000c2";
    let (db, registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&registry, &db).await;
    async fn folder(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"id": id, "type": "Collection", "kind": "folder",
                    "name": name, "body": name,
                    "reason": "Browse keyed freshness fixture."}),
            )
            .await
            .unwrap();
    }
    async fn kid(registry: &ToolRegistry, db: &Db, id: &str, name: &str, home: &str) {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"id": id, "type": "Document", "kind": "note",
                    "name": name, "body": name, "home_id": home,
                    "reason": "Browse keyed freshness fixture."}),
            )
            .await
            .unwrap();
    }
    folder(&registry, &db, FOLDER_A, "Folder A").await;
    folder(&registry, &db, FOLDER_B, "Folder B").await;
    kid(&registry, &db, KID_A, "Kid A", FOLDER_A).await;
    kid(&registry, &db, KID_B, "Kid B", FOLDER_B).await;
    for id in [FOLDER_A, FOLDER_B, KID_A, KID_B] {
        grant(&db, id, ALICE, Capability::View).await;
    }
    let roots_sql = browse_fixture_sql("BROWSE_ROOTS_SQL");
    let children_sql = browse_fixture_sql("BROWSE_CHILDREN_SQL");
    let event = adopted_with_package(
        &registry,
        &db,
        ALICE,
        "agent.folders-browse",
        json!({
            "needs": [sql_need("browse.roots", "Roots", &roots_sql),
                {"need":"sql.snapshot.v1", "key":"browse.children", "label":"Children",
                 "sql": children_sql, "params":[{"name":"folder","type":"text","max_len":128}]}],
            "effects": []
        }),
    )
    .await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action":"live_read", "package":"agent.folders-browse",
            "expected_install_event_id":event, "subscribe":{"stream":stream}
        }),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let token = ConnectionToken::from_hex(&stream).unwrap();
    let sub_id = SubscriptionId::from_wire(&id);
    let mut sink = test_sink(&db, &stream);
    let read = |folder: &str| {
        json!({"action":"live_read", "package":"agent.folders-browse",
        "expected_install_event_id":event, "need":"browse.children",
        "params":{"folder":folder}, "watch":{"stream":stream,"subscription":id}})
    };
    let kids_a = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    let kids_b = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_B),
    )
    .await
    .unwrap();
    assert!(kids_a["keyed_freshness"]["variant"].is_string());
    assert!(kids_b["keyed_freshness"]["variant"].is_string());
    assert_ne!(
        kids_a["keyed_freshness"]["variant"],
        kids_b["keyed_freshness"]["variant"]
    );
    let retained = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert_eq!(retained.keyed.variants_for("browse.children").count(), 2);
    for variant in retained.keyed.variants_for("browse.children") {
        assert_eq!(
            variant.relations,
            std::collections::BTreeSet::from(["facet_values".to_string(), "records".to_string()])
        );
    }
    let digest_of = |read: &Value| {
        read["keyed_freshness"]["variant"]
            .as_str()
            .unwrap()
            .strip_prefix("browse.children:")
            .unwrap()
            .to_string()
    };
    let row_ids = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let digest_a = digest_of(&kids_a);
    let digest_b = digest_of(&kids_b);
    let stored_revision = |digest: &str| {
        RealtimeHub::for_database(&db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed
            .revision("browse.children", digest)
            .unwrap()
            .to_string()
    };
    let initial_rows = kids_a["result"]["rows"].clone();
    let initial_revision = kids_a["revision"]["revision_digest"].clone();
    // Baselines must be nonempty with exact membership: every later
    // equality (hidden re-read, reopened pull read) would otherwise pass
    // vacuously on empty query results.
    assert_eq!(row_ids(&initial_rows), vec![KID_A.to_string()]);
    assert_eq!(row_ids(&kids_b["result"]["rows"]), vec![KID_B.to_string()]);
    let fp_a_before = stored_revision(&digest_a);
    let fp_b_before = stored_revision(&digest_b);
    let keyed_dirty = || {
        RealtimeHub::for_database(&db)
            .unwrap()
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &sub_id)
            .unwrap()
            .keyed_dirty
    };
    // Causal pump barrier (precedent: the folders keyed test's #1637 fix):
    // await tail-pump publication of everything committed so far (durable
    // `content_events.seq` high-water) before a forced drain reads scheduler
    // state. Bounded fail-closed wait on the existing hidden seam — never a
    // sleep, and delivery never depends on it.
    let await_published = |label: &'static str| {
        let db = &db;
        async move {
            let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                native_ce::realtime::wait_until_published_for_tests(db, seq),
            )
            .await
            .unwrap_or_else(|_| panic!("{label}: pump did not publish seq {seq}"));
        }
    };
    // Settle the admission catch-up: silent when nothing changed, and the
    // scheduler consumes the pass (clean baseline for the vacuity guard).
    // Publish first: a backlog publishing between this drain and the
    // !keyed_dirty baseline (or after it) would violate the clean-settle
    // premise the vacuity guard rests on.
    await_published("admission catch-up").await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(
        sink.try_recv().is_err(),
        "admission catch-up must be silent"
    );
    assert!(!keyed_dirty());
    // Post-subscription hidden burst across both tables the key declares: a
    // revoked child (records) plus archiving it (facet_values, via the
    // governed archive path since `archived` is engine-reserved). Both stay
    // invisible to Alice, so rows, revision, stored fingerprints, outbox and
    // the delivery counter must not move.
    kid(&registry, &db, HIDDEN_KID, "Hidden kid", FOLDER_A).await;
    revoke_all(&db, HIDDEN_KID).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "archive_record",
            json!({"id": HIDDEN_KID, "reason": "Hidden archive burst."}),
        )
        .await
        .unwrap();
    // Publication must precede the guard: the async tail pump (not the
    // writes) schedules the keyed comparison, so assert only after it has
    // observably published the burst.
    await_published("hidden burst").await;
    // Vacuity guard: the hidden burst must actually schedule keyed
    // comparisons (intersect the table prefilter) before the drain.
    assert!(
        keyed_dirty(),
        "hidden burst must schedule keyed comparisons"
    );
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let hidden_again = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    assert_eq!(hidden_again["result"]["rows"], initial_rows);
    assert_eq!(
        hidden_again["revision"]["revision_digest"],
        initial_revision
    );
    assert_eq!(stored_revision(&digest_a), fp_a_before);
    assert_eq!(stored_revision(&digest_b), fp_b_before);
    assert!(
        sink.try_recv().is_err(),
        "hidden write cannot produce a hint"
    );
    let state = RealtimeHub::for_database(&db)
        .unwrap()
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &sub_id)
        .unwrap();
    assert_eq!(state.delivery, 0);
    // Visible child lands in folder B only: exactly one hint names B's
    // opaque variant and its revision matches the governed re-read.
    kid(&registry, &db, VISIBLE_KID, "Visible kid", FOLDER_B).await;
    grant(&db, VISIBLE_KID, ALICE, Capability::View).await;
    // Same publication barrier as the hidden burst: without it the forced
    // drain can keep a Content trigger with keyed_dirty false, skip the
    // keyed comparison, and leave the sink empty on a loaded runner.
    await_published("visible kid").await;
    assert!(
        keyed_dirty(),
        "visible write must schedule keyed comparisons"
    );
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let NeedSinkFrame::Keyed(hint) = sink.try_recv().expect("visible keyed hint") else {
        panic!("keyed frame expected")
    };
    assert_eq!(hint.key, kids_b["keyed_freshness"]["variant"]);
    assert_eq!(hint.delivery, 1);
    let fresh = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_B),
    )
    .await
    .unwrap();
    assert_eq!(hint.at_revision, fresh["revision"]["revision_digest"]);
    assert_ne!(fresh["result"]["rows"], kids_b["result"]["rows"]);
    assert!(sink.try_recv().is_err(), "folder A must not hint");
    // Bounded session state per declared key: the 33rd distinct folder
    // evicts one variant, reports the degraded key, and the evicted folder
    // remains a correct pull read when opened again.
    let mut overflow = Value::Null;
    for index in 0..31 {
        overflow = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            read(&format!("unknown-folder-{index}")),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        overflow["keyed_freshness"]["evicted"],
        json!(["browse.children"])
    );
    let reopened = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        read(FOLDER_A),
    )
    .await
    .unwrap();
    assert_eq!(reopened["result"]["rows"], initial_rows);
    // Disable closes the pin: hints stop and the subscription is gone.
    call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.folders-browse",
            "expected_install_event_id": event,
            "reason": "Pause the tab for the closure test.",
        }),
    )
    .await
    .unwrap();
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

/// Adversarial ordering: the scheduler wakes before the SSE loop processes
/// the access loss, so the registry flag/footing are still stale-valid. The
/// fresh hook must still win: close with `access_lost`, never a `need`.
#[tokio::test]
async fn scheduler_closes_when_hook_reports_loss_despite_stale_flag() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    // Visible write, so a stale-authority scheduler would emit a need.
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000004",
        "Visible hook",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000004",
        ALICE,
        Capability::View,
    )
    .await;
    mark_forcing(&db, &stream, &id);
    // The stream installs its hook at connect; here the hook reports loss
    // while the registry flag/footing are still stale-valid — the exact
    // scheduler-ahead-of-SSE ordering.
    let hook: AccessHook = Arc::new(|| Box::pin(async { None::<bool> }));
    RealtimeHub::for_database(&db)
        .expect("hub installed")
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_access_hook(&ConnectionToken::from_hex(&stream).unwrap(), hook);
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Closed(closed) = frame else {
        panic!("revoked access must close even when the SSE flag is stale, never emit");
    };
    assert_eq!(
        closed.reason,
        native_ce::need_subscriptions::NeedClosedReason::AccessLost
    );
    assert_eq!(subscription_count(&db, &stream), 0);
    assert!(sink.try_recv().is_err());
}

#[tokio::test]
async fn scheduler_delivers_visible_change_with_delivery_and_baseline() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000002",
        "Visible sched",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000002",
        ALICE,
        Capability::View,
    )
    .await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Need(need) = frame else {
        panic!("visible change must deliver a need frame");
    };
    assert_eq!(need.delivery, 1);
    assert!(need.result.is_some());
    assert!(need.as_of_ms.is_none());
    // Baseline advanced: a second drain with no new writes stays quiet.
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(sink.try_recv().is_err());
}

#[tokio::test]
async fn scheduler_stays_quiet_on_invisible_only_write() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000003",
        "Hidden sched",
        "open",
    )
    .await;
    // Exclusive grant to Bea, mirroring the noninterference fixture: the
    // create_record default policy would otherwise leave the row visible
    // to Alice, and any frame would be correct delivery, not leakage.
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000003",
        BEA,
        Capability::View,
    )
    .await;
    let plain = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(
        !plain["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row.get("id").and_then(Value::as_str)
                    == Some("f3d00000-0000-4000-8000-000000000003")
            }),
        "hidden row must be viewer-invisible before the scheduler runs"
    );
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(sink.try_recv().is_err());
}

#[tokio::test]
async fn guest_subscription_stays_quiet_on_unreadable_only_write() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let hub = RealtimeHub::for_database(&db).expect("hub installed");
    let token = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_connection(ALICE, &database, false);
    let stream = token.to_hex();
    let guest = Caller::authenticated(ALICE).with_hosting_member(false);
    let first = call_as(
        &registry,
        &db,
        guest.clone(),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"]
        .as_str()
        .expect("guest subscription accepted")
        .to_string();
    let mut sink = test_sink(&db, &stream);
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000017",
        "Unreadable to guest",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000017",
        BEA,
        Capability::View,
    )
    .await;
    let plain = call_as(
        &registry,
        &db,
        guest,
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(!plain["input"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| {
            row.get("id").and_then(Value::as_str) == Some("f3d00000-0000-4000-8000-000000000017")
        }));
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(
        sink.try_recv().is_err(),
        "unreadable-only write emitted a need"
    );
    assert_eq!(subscription_count(&db, &stream), 1);
}

#[tokio::test]
async fn scheduler_closes_on_access_loss_without_the_value() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    revoke_all(&db, ARTIFACT_A).await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Closed(closed) = frame else {
        panic!("access loss must close, never emit the value");
    };
    assert_eq!(
        closed.reason,
        native_ce::need_subscriptions::NeedClosedReason::AccessLost
    );
    assert_eq!(subscription_count(&db, &stream), 0);
}

/// Pending write between evaluation and registration (registry seam).
///
/// The tool registers pending before evaluating; a content wake during the
/// read must set the dirty flag so `activate` reports it and the tool runs
/// one immediate re-run instead of missing the write.
#[tokio::test]
async fn pending_write_during_evaluation_is_not_missed() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let hub = RealtimeHub::for_database(&db).expect("hub installed");
    let token = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_connection(ALICE, &database, true);
    let digest = native_ce::need_subscriptions::params_digest(None);
    let id = hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .subscribe_pending(
            &token,
            ALICE,
            &database,
            SurfaceBinding::alpha_tab("agent.attention-cockpit", &verified),
            "attention.query.v1",
            &digest,
        )
        .unwrap();
    // The write lands "during evaluation": the production content wake marks
    // the pending entry dirty without queueing it for the scheduler.
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000010",
        "Visible pending",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000010",
        ALICE,
        Capability::View,
    )
    .await;
    // Drain the tail pump past the setup writes before modelling the
    // during-evaluation write. The pump marks every subscription per
    // content event, so a late pump wake under parallel load would
    // otherwise re-dirty the record after the first activation clears it.
    // Draining first keeps the manual mark below as the single modelled
    // mid-evaluation write — the coverage (flag, immediate re-run,
    // visibility, quiescence) is unchanged.
    let fence = hub.inbox_invalidation_vector().await.unwrap().content;
    native_ce::realtime::wait_until_published_for_tests(&db, fence).await;
    hub.need_registry()
        .lock()
        .expect("need registry poisoned")
        .mark_all_dirty();
    assert_eq!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .dirty_len(&token),
        0,
        "pending entries keep the flag without scheduler queueing"
    );
    // Activation reports the dirtied write, so the tool's immediate re-run
    // path triggers.
    assert_eq!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .activate(&token, &id, "stale-baseline"),
        Some(true)
    );
    // The immediate re-run (an ordinary live_read here) sees the write.
    let reread = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(
        reread["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row.get("id").and_then(Value::as_str)
                    == Some("f3d00000-0000-4000-8000-000000000010")
            }),
        "pending write must be visible to the immediate re-run: {reread:#}"
    );
    let fresh = reread["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .activate(&token, &id, &fresh),
        Some(false)
    );
}

/// Revoke between the scheduler's re-run and its emit gate.
///
/// The scheduler resolves authority twice per subscription (re-run, then
/// emit). A counting hook that is valid for the first resolve and revoked
/// for the second models access lost in that window: the subscription must
/// close with `access_lost` and never emit the value.
#[tokio::test]
async fn revoke_between_rerun_and_emit_gate_closes_without_value() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    // A visible write guarantees the re-run has a new digest to emit, so the
    // emit gate is actually reached before the revocation lands.
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000011",
        "Visible revoke window",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000011",
        ALICE,
        Capability::View,
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let hook_calls = calls.clone();
    let hook: AccessHook = Arc::new(move || {
        let prior = hook_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if prior == 0 {
                Some(true)
            } else {
                None
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<bool>> + Send>>
    });
    RealtimeHub::for_database(&db)
        .expect("hub installed")
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .register_access_hook(&ConnectionToken::from_hex(&stream).unwrap(), hook);
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Closed(closed) = frame else {
        panic!("revoke between rerun and emit must close, never emit");
    };
    assert_eq!(closed.reason, NeedClosedReason::AccessLost);
    assert_eq!(subscription_count(&db, &stream), 0);
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "both the rerun and emit resolves must run"
    );
    assert!(sink.try_recv().is_err());
}

async fn disable_install(registry: &ToolRegistry, db: &Db, event: &str) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "disable", "package": "agent.attention-cockpit",
            "expected_install_event_id": event,
            "reason": "Pause the tab for the closure test.",
        }),
    )
    .await
    .unwrap()
}

async fn remove_install(registry: &ToolRegistry, db: &Db, event: &str) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "remove", "package": "agent.attention-cockpit",
            "expected_install_event_id": event,
            "reason": "Retire the tab for the closure test.",
        }),
    )
    .await
    .unwrap()
}

async fn restore_install(registry: &ToolRegistry, db: &Db, event: &str) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "restore", "package": "agent.attention-cockpit",
            "expected_install_event_id": event,
            "reason": "Resume the tab for the reinstall test.",
        }),
    )
    .await
    .unwrap()
}

async fn expect_closed(
    db: &Db,
    stream: &str,
    sink: &mut tokio::sync::mpsc::Receiver<NeedSinkFrame>,
    reason: NeedClosedReason,
) {
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Closed(closed) = frame else {
        panic!("control transition must close, never emit the value");
    };
    assert_eq!(closed.reason, reason);
    assert_eq!(subscription_count(db, stream), 0);
    assert!(sink.try_recv().is_err());
}

/// Control transitions close through the stable CAS precedence.
///
/// Every install transition mints a new install event, so the scheduler's
/// re-run sees `cas_mismatch` before it ever reaches the status gate: a
/// disable, a remove, and a disable+restore (reinstall) all close with
/// `reinstalled`. The wire reason stays in the closed set and the value is
/// never emitted.
#[tokio::test]
async fn disable_closes_with_reinstalled() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    disable_install(&registry, &db, &verified).await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

#[tokio::test]
async fn update_carry_closes_old_subscription_with_reinstalled() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    let inspected = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "inspect", "package": "agent.attention-cockpit"}),
    )
    .await
    .unwrap();
    let pin = &inspected["install"];
    let updated = call_as(&registry, &db, Caller::authenticated(ALICE), "manage_alpha_tabs",
        json!({"action": "update", "package": pin["package"], "version": pin["version"],
            "digest": pin["digest"], "artifact_id": pin["artifact_id"],
            "source_revision": pin["consented_source_revision"], "declaration": pin["consented_declaration"],
            "expected_install_event_id": verified, "reason": "Update without inheriting the subscription."})).await.unwrap();
    assert_eq!(updated["adoption_carried"], true);
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

#[tokio::test]
async fn remove_closes_with_reinstalled() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    remove_install(&registry, &db, &verified).await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

#[tokio::test]
async fn restore_after_disable_closes_with_reinstalled() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    let disabled = disable_install(&registry, &db, &verified).await;
    let disabled_token = disabled["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    restore_install(&registry, &db, &disabled_token).await;
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    expect_closed(&db, &stream, &mut sink, NeedClosedReason::Reinstalled).await;
}

/// Demotion narrows to the viewer's own grants without closing.
///
/// The demoted connection forces a gate re-check; direct grants still
/// deliver, the other account's row stays hidden, and the subscription stays
/// active. Demotion never over-closes and never leaks.
#[tokio::test]
async fn demotion_narrows_to_own_grants_without_close() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let mut sink = test_sink(&db, &stream);
    let hub = RealtimeHub::for_database(&db).expect("hub installed");
    let token = ConnectionToken::from_hex(&stream).unwrap();
    assert!(hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .set_connection_member(&token, false));
    assert!(
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .mark_connection_forcing(&token)
            >= 1
    );
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000012",
        "Visible demoted",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000012",
        ALICE,
        Capability::View,
    )
    .await;
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000013",
        "Hidden demoted",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000013",
        BEA,
        Capability::View,
    )
    .await;
    // The forcing entry queued by the demotion is enough; the write itself
    // needs no production broadcast in this manual scheduler.
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Need(need) = frame else {
        panic!("demotion must still deliver the viewer's own grant");
    };
    let serialized = serde_json::to_string(&need.result).unwrap();
    assert!(serialized.contains("f3d00000-0000-4000-8000-000000000012"));
    assert!(!serialized.contains("f3d00000-0000-4000-8000-000000000013"));
    assert_eq!(subscription_count(&db, &stream), 1);
    // Baseline advanced: a second drain with no new writes stays quiet.
    mark_forcing(&db, &stream, &id);
    drain_once(&db).await;
    assert!(sink.try_recv().is_err());
}

/// Slow consumer: a dropped frame marks stale, and the host's `if_revision`
/// re-read misses nothing.
#[tokio::test]
async fn slow_consumer_stale_then_reread_misses_nothing() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    let first = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    let id = first["subscription"]["id"].as_str().unwrap().to_string();
    let digest = first["revision"]["revision_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let mut sink = test_sink(&db, &stream);
    live_task(
        &registry,
        &db,
        "f3d00000-0000-4000-8000-000000000014",
        "Visible slow",
        "open",
    )
    .await;
    grant(
        &db,
        "f3d00000-0000-4000-8000-000000000014",
        ALICE,
        Capability::View,
    )
    .await;
    // Simulate the emit path hitting a full sink: the frame is dropped, the
    // subscription is marked stale, and the flush flag is raised.
    let hub = RealtimeHub::for_database(&db).expect("hub installed");
    let token = ConnectionToken::from_hex(&stream).unwrap();
    assert!(hub
        .need_registry()
        .lock()
        .expect("need registry poisoned")
        .mark_stale(&token, &SubscriptionId::from_wire(&id)));
    drain_once(&db).await;
    let frame = tokio::time::timeout(Duration::from_secs(5), sink.recv())
        .await
        .unwrap()
        .unwrap();
    let NeedSinkFrame::Stale(stale) = frame else {
        panic!("slow consumer must flush need-stale, never the value");
    };
    assert!(stale.subscriptions.contains(&id));
    // The host re-reads the stale id with its held revision and misses
    // nothing: the digest moved and the new row is present.
    let reread = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": "agent.attention-cockpit",
            "expected_install_event_id": verified,
            "if_revision": digest,
        }),
    )
    .await
    .unwrap();
    assert!(reread.get("unchanged").is_none());
    assert_ne!(
        reread["revision"]["revision_digest"].as_str().unwrap(),
        digest
    );
    assert!(
        reread["input"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row.get("id").and_then(Value::as_str)
                    == Some("f3d00000-0000-4000-8000-000000000014")
            }),
        "stale re-read must carry the missed write: {reread:#}"
    );
}

/// Caps refuse the newest subscribe but the ordinary read still succeeds.
#[tokio::test]
async fn over_cap_subscribe_refuses_but_read_succeeds() {
    let (db, registry) = fixture().await;
    let (_, verified) = adopted_live_fixture(&registry, &db).await;
    let database = native_ce::identity::database_id(&db).await.unwrap();
    let stream = hub_token(&db, ALICE, &database);
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CONNECTION {
        let subscribed = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "manage_alpha_tabs",
            subscribe_args(&verified, &stream),
        )
        .await
        .unwrap();
        assert!(subscribed["subscription"]["id"].is_string());
    }
    assert_eq!(
        subscription_count(&db, &stream),
        MAX_SUBSCRIPTIONS_PER_CONNECTION
    );
    let refused = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        subscribe_args(&verified, &stream),
    )
    .await
    .unwrap();
    assert_eq!(refused["subscribe_refused"], "subscription_limit");
    assert!(refused.get("subscription").is_none());
    assert!(refused["revision"]["revision_digest"].is_string());
    assert_eq!(
        subscription_count(&db, &stream),
        MAX_SUBSCRIPTIONS_PER_CONNECTION
    );
    // The plain read is unaffected by the cap.
    let plain = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        live_read_args(&verified),
    )
    .await
    .unwrap();
    assert!(plain.get("subscribe_refused").is_none());
    assert!(plain["revision"]["revision_digest"].is_string());
}
