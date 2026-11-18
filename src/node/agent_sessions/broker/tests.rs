//! Fake-daemon tests for the broker worker: one test per brief row that can
//! be driven without the node socket. The background `run` loop owns every
//! connection; tests spawn it and wait for the host table, exactly like
//! `serve` does.

use super::super::protocol::check_broker_outbound_allowed;
use super::super::test_support::{
    broker_for, epoch_of, password_env, recv_timeout, run_until_reachable, snap, text_entry,
    FakeDaemon, FakeScript,
};
use super::*;
use std::sync::atomic::Ordering;

#[test]
fn push_queue_overflow_yields_single_resync() {
    let mut queue = PushQueue::new(2);
    queue.push_update(json!([1]));
    queue.push_update(json!([2]));
    // Bound reached: the next update drops the queue and arms one resync.
    queue.push_update(json!([3]));
    queue.push_update(json!([4]));
    let flushed = queue.take_flush();
    assert_eq!(flushed.len(), 1);
    assert!(matches!(flushed[0], PushEvent::Resync));
    // A quiet queue flushes nothing.
    assert!(queue.take_flush().is_empty());
}

#[tokio::test]
async fn slow_consumer_coalesces_to_single_resync() {
    let (tx, mut rx) = mpsc::channel::<PushEvent>(1);
    let mut sink = SubSink::new(tx);
    assert!(sink.push_update(json!([1])));
    // Channel full: these collapse into one pending resync.
    assert!(sink.push_update(json!([2])));
    assert!(sink.push_update(json!([3])));
    assert!(sink.resync_pending());
    // Drain the one queued update, then the single resync follows.
    let first = recv_timeout(&mut rx, "queued update").await;
    assert!(matches!(first, PushEvent::Snapshot(_)));
    assert!(sink.flush_resync());
    let second = recv_timeout(&mut rx, "coalesced resync").await;
    assert!(matches!(second, PushEvent::Resync));
    assert!(!sink.resync_pending());
}

#[tokio::test]
async fn daemon_absent_at_start_lists_unreachable_host() {
    // A closed loopback port fails fast: no hang, no sessions, host listed.
    // Fail-fast needs no connection attempt: even a hanging port answers at
    // once, so bind a listener and never accept instead.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = dead.local_addr().unwrap();
    let url = format!("ws://{addr}/ws");
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&url, "srv_test", &env);
    // No run loop: with nothing connecting, the table stays unreachable and
    // the list answers immediately without touching the daemon slot.
    let listed = broker.list(None).await.expect("list answers").clone();
    assert_eq!(listed["sessions"], json!([]));
    let hosts = listed["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0]["id"], "srv_test");
    assert_eq!(hosts[0]["status"], "unreachable");
    assert!(hosts[0]["epoch"].is_null());
    drop(dead);
}

#[tokio::test]
async fn server_id_mismatch_fails_closed() {
    let fake = FakeDaemon::new(FakeScript {
        server_id: "srv_other".into(),
        agents: vec![snap("a")],
        timelines: HashMap::new(),
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = tokio::spawn(broker.clone().run());
    // Let the loop attempt (and fail) at least one handshake.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let listed = broker.list(None).await.expect("list answers").clone();
    assert_eq!(listed["sessions"], json!([]));
    assert_eq!(listed["hosts"][0]["status"], "unreachable");
    // The hello went out but no read was ever attempted against the wrong host.
    assert_eq!(fake.hellos.lock().await.len(), 1);
    assert!(
        fake.received.lock().await.is_empty(),
        "no daemon read may follow a serverId mismatch"
    );
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn broker_run_stays_within_allowlist() {
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let listed = broker.list(None).await.expect("list answers").clone();
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 1);
    let host_epoch = epoch_of(&broker).await;
    let history = broker
        .history("srv_test", &host_epoch, "a", None, None)
        .await
        .expect("history");
    assert!(!history["items"].as_array().unwrap().is_empty());
    let (tx, _rx) = mpsc::channel::<PushEvent>(PUSH_CHANNEL_BOUND);
    let (sub, _snapshot) = broker
        .follow("srv_test", &host_epoch, "a", tx)
        .await
        .expect("follow");
    broker.unfollow(&sub).await;
    // Broker identity on the wire, and every post-hello frame allowlisted.
    let hellos = fake.hellos.lock().await;
    assert_eq!(hellos.len(), 1);
    assert_eq!(hellos[0]["clientId"], "native-session-broker");
    let received = fake.received.lock().await;
    assert!(!received.is_empty(), "list+history+follow must send reads");
    assert!(
        received.iter().all(|m| m.get("subscribe").is_none()),
        "the broker owns no daemon subscriptions"
    );
    for message in received.iter() {
        assert!(
            check_broker_outbound_allowed(message).is_ok(),
            "non-allowlisted frame on the wire: {message}"
        );
        let kind = message.get("type").and_then(Value::as_str).unwrap_or("");
        assert!(
            !matches!(
                kind,
                "send_agent_message_request"
                    | "create_agent_request"
                    | "create_agent_with_id_request"
                    | "update_agent_request"
                    | "set_agent_mode_request"
                    | "get_agent_permission_form_request"
                    | "respond_to_permission_request"
            ),
            "forbidden daemon call: {message}"
        );
    }
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn restart_mid_follow_ends_gone_and_rotates_epoch() {
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch_v1 = epoch_of(&broker).await;
    let (tx, mut rx) = mpsc::channel::<PushEvent>(PUSH_CHANNEL_BOUND);
    let (sub, _snapshot) = broker
        .follow("srv_test", &epoch_v1, "a", tx)
        .await
        .expect("follow");
    let _ = sub;
    // Restart the daemon mid-follow: the poll fails and the follow ends.
    fake.kill.store(true, Ordering::SeqCst);
    let ended = recv_timeout(&mut rx, "restart ended event").await;
    match ended {
        PushEvent::Ended { code } => assert_eq!(code, "gone"),
        other => panic!("expected ended{{gone}}, got {other:?}"),
    }
    // The run loop reconnects (same serverId) with a fresh epoch.
    let epoch_v2 = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let epoch = epoch_of(&broker).await;
            if !epoch.is_empty() && epoch != epoch_v1 {
                return epoch;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("reconnect with a new epoch");
    assert_ne!(epoch_v1, epoch_v2, "reconnect must mint a new epoch");
    let relisted = broker.list(None).await.expect("list answers").clone();
    assert_eq!(relisted["hosts"][0]["status"], "reachable");
    // The stale epoch is gone for both history and follow.
    match broker.history("srv_test", &epoch_v1, "a", None, None).await {
        Err(Refusal::Gone(_)) => {}
        other => panic!("stale-epoch history must be gone, got {other:?}"),
    }
    let (tx2, _rx2) = mpsc::channel::<PushEvent>(PUSH_CHANNEL_BOUND);
    match broker.follow("srv_test", &epoch_v1, "a", tx2).await {
        Err(Refusal::Gone(_)) => {}
        other => panic!("stale-epoch follow must be gone, got {other:?}"),
    }
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn session_removed_ends_follow_with_gone() {
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch = epoch_of(&broker).await;
    let (tx, mut rx) = mpsc::channel::<PushEvent>(PUSH_CHANNEL_BOUND);
    let (_sub, _snapshot) = broker
        .follow("srv_test", &epoch, "a", tx)
        .await
        .expect("follow");
    // Remove the session: the next tail poll observes agent:null.
    {
        let mut script = fake.script.lock().await;
        script.agents.clear();
        script.timelines.remove("a");
    }
    let ended = recv_timeout(&mut rx, "removal ended event").await;
    match ended {
        PushEvent::Ended { code } => assert_eq!(code, "gone"),
        other => panic!("expected ended{{gone}}, got {other:?}"),
    }
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn history_of_unknown_session_is_gone() {
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch = epoch_of(&broker).await;
    match broker
        .history("srv_test", &epoch, "missing", None, None)
        .await
    {
        Err(Refusal::Gone(_)) => {}
        other => panic!("unknown session history must be gone, got {other:?}"),
    }
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn unfollow_stops_the_poll() {
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch = epoch_of(&broker).await;
    let (tx, mut rx) = mpsc::channel::<PushEvent>(PUSH_CHANNEL_BOUND);
    let (sub, _snapshot) = broker
        .follow("srv_test", &epoch, "a", tx)
        .await
        .expect("follow");
    assert!(broker.unfollow(&sub).await);
    assert!(!broker.unfollow(&sub).await);
    // Mutate the timeline: no update may arrive after the unfollow.
    {
        let mut script = fake.script.lock().await;
        script.timelines.insert(
            "a".into(),
            vec![text_entry(1, "hi"), text_entry(2, "changed")],
        );
    }
    // After the unfollow the poll is gone: either the channel stays quiet or
    // it is already closed because the aborted poll dropped its sender. A
    // delivered event of any kind is a leak.
    match tokio::time::timeout(Duration::from_millis(2200), rx.recv()).await {
        Err(_) => {}
        Ok(None) => {}
        Ok(Some(event)) => panic!("push arrived after unfollow: {event:?}"),
    }
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn stale_clear_after_reconnect_keeps_new_epoch() {
    // A failure handler working on the old connection must not clear the
    // newer connection or mark the host unreachable after a reconnect.
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch_v1 = epoch_of(&broker).await;
    // Restart: the run loop's ping fails, it clears v1 and reconnects as v2.
    fake.kill.store(true, Ordering::SeqCst);
    let epoch_v2 = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let epoch = epoch_of(&broker).await;
            if !epoch.is_empty() && epoch != epoch_v1 {
                return epoch;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("reconnect with a new epoch");
    // A delayed v1 error must be a no-op now.
    broker.clear_conn_if_epoch(&epoch_v1).await;
    assert_eq!(broker.host_summary().await["status"], "reachable");
    assert_eq!(epoch_of(&broker).await, epoch_v2);
    // The matching generation still clears.
    broker.clear_conn_if_epoch(&epoch_v2).await;
    assert_eq!(broker.host_summary().await["status"], "unreachable");
    run.abort();
    fake.stop();
}

#[tokio::test]
async fn contended_slot_answers_busy() {
    // Holding the daemon slot elsewhere makes tool paths answer `busy`
    // instead of queueing behind a hung daemon.
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let _guard = broker.conn.lock().await;
    match broker.list(None).await {
        Err(Refusal::Busy(_)) => {}
        other => panic!("contended list must be busy, got {other:?}"),
    }
    run.abort();
    fake.stop();
}

#[test]
fn followed_changes_are_pushed_as_replacing_snapshots() {
    // The pushed tail is the whole projected page, so it must be a `snapshot`
    // (replaces the view), never an `update` (which the app contract reserves
    // for changed items only).
    let wire = PushEvent::Snapshot(json!([{"id": "a", "kind": "status", "status": "running"}]))
        .notification("sub", "srv_x", "epoch", "session");
    assert_eq!(wire["method"], protocol::EVENT_NOTIFICATION);
    assert_eq!(wire["params"]["kind"], "snapshot");
    assert_eq!(wire["params"]["items"][0]["id"], "a");
}

#[tokio::test]
async fn list_failure_uses_captured_epoch_not_current_state() {
    // A list failure after a mid-list reconnect must clear the run's own
    // epoch, never the newer one: the slot drops, the new state survives.
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch_v1 = epoch_of(&broker).await;
    assert!(!epoch_v1.is_empty());
    run.abort();
    fake.hang_fetch.store(true, Ordering::SeqCst);
    // Start the hung list, wait until its fetch reaches the daemon, then
    // rotate the state epoch the way a reconnect would — the slot still
    // names v1 while the state already names the next generation.
    let listing = tokio::spawn({
        let broker = broker.clone();
        async move { broker.list(None).await }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fake.received.lock().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("list must reach the daemon");
    broker.state.lock().await.epoch = Some("epoch-v2-simulated-reconnect".into());
    // The hung fetch fails at the RPC timeout; the clear must use the
    // captured v1, taking the dead slot while leaving v2's state alone.
    let listed = tokio::time::timeout(Duration::from_secs(20), listing)
        .await
        .expect("list must answer")
        .expect("join")
        .expect("list answers")
        .clone();
    assert_eq!(listed["sessions"], json!([]));
    let hosts = listed["hosts"].as_array().unwrap();
    assert_eq!(hosts[0]["status"], "reachable");
    assert_eq!(hosts[0]["epoch"], json!("epoch-v2-simulated-reconnect"));
    assert!(
        broker.conn.lock().await.is_none(),
        "the stale failure must drop its own slot"
    );
    assert_eq!(epoch_of(&broker).await, "epoch-v2-simulated-reconnect");
    fake.stop();
}

#[tokio::test]
async fn hung_daemon_lists_answer_within_deadline() {
    // Two concurrent lists against a wedged daemon: the first hangs on its
    // page up to the RPC timeout, the second refuses `busy` on the contended
    // slot instead of chaining another thirty-second hold behind the first.
    let fake = FakeDaemon::new(FakeScript::one()).await;
    fake.hang_fetch.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let start = tokio::time::Instant::now();
    let (first, second) = tokio::time::timeout(Duration::from_secs(25), async {
        tokio::join!(broker.list(None), broker.list(None))
    })
    .await
    .expect("both lists must answer within the deadline");
    assert!(
        start.elapsed() < Duration::from_secs(18),
        "answered in {:?}, expected about the deadline",
        start.elapsed()
    );
    match first {
        Ok(listed) => assert_eq!(listed["sessions"], json!([])),
        Err(other) => panic!("first list must degrade to empty, got {other:?}"),
    }
    match second {
        Err(Refusal::Busy(_)) => {}
        other => panic!("second list must be busy, got {other:?}"),
    }
    run.abort();
    fake.stop();
}
