use super::*;

async fn fixture() -> Fixture {
    fixture_with_legacy_option(None).await
}

async fn fixture_with_legacy_option(online: Option<OnlineLocalReads>) -> Fixture {
    fixture_with_age(online, 0).await
}
async fn fixture_with_age(online: Option<OnlineLocalReads>, age: i64) -> Fixture {
    let fixture = Box::pin(Fixture::build_with_engine_policy(
        Some(true),
        None,
        false,
        online,
        false,
        true,
        FixtureReadPolicy {
            local_reads_by_default: true,
            snapshot_age_seconds: age,
            account_binding: "acct:fixture",
        },
    ))
    .await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !fixture.node.dispatcher.serving_kernel_v2() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("verified kernel-v2 reader");
    fixture.node.refresh_discovery().await;
    fixture.node.probe().await;
    fixture.fake.requests.lock().await.clear();
    fixture
}

fn record() -> Value {
    let mut message = read(true);
    message["params"]["arguments"]["arguments"]["ids"] = json!([crate::events::KERNEL_ROOT_ID]);
    message
}

fn assert_local(reply: &Value) {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "local_copy",
        "{reply}"
    );
}

fn assert_unavailable(reply: &Value, reason: &str) {
    assert_eq!(
        reply["error"]["data"]["outcome"], "local_unavailable",
        "{reply}"
    );
    assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    assert!(
        reply.get("result").is_none(),
        "refusal cannot look like read data: {reply}"
    );
}

/// Never a refusal and never an error without data: the caller got a result.
fn assert_not_refused(reply: &Value) {
    assert_ne!(
        reply["error"]["data"]["outcome"], "local_unavailable",
        "{reply}"
    );
    assert!(reply.get("error").is_none(), "error without data: {reply}");
    assert!(reply.get("result").is_some(), "no data: {reply}");
    assert_ne!(reply["result"]["isError"], true, "{reply}");
}

/// Answered by hosted (the option-off forwarding path), with the reason
/// disclosed in the answer's own text.
fn assert_hosted(reply: &Value) {
    assert!(reply.get("error").is_none(), "{reply}");
    let line = text(reply);
    assert!(line.contains("reads from hosted"), "{reply}");
    assert!(line.contains("comes from hosted Native because"), "{reply}");
}

fn routing(reply: &Value) -> &Value {
    &reply["result"]["structuredContent"]["node_routing"]
}

fn session_caller(id: u64) -> Caller {
    let mut caller = anonymous_caller();
    caller.session = Some(id);
    caller
}

async fn send_as(fixture: &Fixture, message: Value, caller: &Caller) -> Value {
    let reply = fixture
        .node
        .route(
            &message.to_string(),
            message,
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            caller,
        )
        .await
        .unwrap();
    serde_json::from_str(&reply).unwrap()
}

async fn copy_head(fixture: &Fixture) -> i64 {
    fixture
        .node
        .dispatcher
        .serving_context()
        .unwrap()
        .serving_head_act
        .unwrap()
}

/// Served from the local copy, disclosed as below a known hosted act.
fn assert_behind(reply: &Value, serving: i64, known: i64) {
    assert_local(reply);
    let node = routing(reply);
    assert_eq!(node["serving_head_act"], serving, "{reply}");
    assert_eq!(node["known_hosted_head_act"], known, "{reply}");
    assert_eq!(node["behind_known_write"], true, "{reply}");
    assert_ne!(
        reply["result"]["structuredContent"]["standby_context"]["freshness"]["state"], "fresh",
        "never fresh below a known hosted act: {reply}"
    );
    if reply
        .pointer("/result/structuredContent/bootstrap_readiness")
        .is_some()
    {
        assert!(
            text(reply).contains("Hosted has newer changes; their time lag is unknown"),
            "{reply}"
        );
    } else {
        assert!(
            text(reply).contains(&format!("hosted is known to be at act {known}")),
            "{reply}"
        );
    }
}

#[tokio::test]
async fn healthy_outage_and_recovery_use_the_same_local_engine_without_forwarding() {
    let fixture = fixture().await;
    for health in [
        Health::Reachable,
        Health::Unreachable,
        Health::ProtocolFailed,
        Health::Reachable,
    ] {
        fixture.node.state.lock().await.health = health;
        assert_local(&fixture.send(record()).await);
        assert_local(&fixture.send(local_only(record())).await);
        let sql = fixture
            .send(sql_read(
                json!({"sql":"SELECT id FROM records ORDER BY id"}),
                true,
            ))
            .await;
        assert_local(&sql);
        assert!(
            fixture.fake.requests.lock().await.is_empty(),
            "data reads must not contact hosted"
        );
    }
    // The retained contracts and verified copy also work before a new head
    // probe has settled; optimistic Reachable is not a data-source selector.
    fixture.node.state.lock().await.checked = false;
    assert_local(&fixture.send(record()).await);
    fixture.finish().await;
}

#[tokio::test]
async fn foreign_hosted_advance_is_a_following_signal_not_an_own_write() {
    let fixture = fixture().await;
    let before = fixture
        .node
        .dispatcher
        .serving_context()
        .unwrap()
        .serving_head_act
        .unwrap();
    let owner = crate::kernel::resolve_principal_by_binding(&fixture.db, "acct:fixture")
        .await
        .unwrap()
        .unwrap()
        .0;
    crate::kernel::create_record_as(&fixture.db, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    fixture.node.probe().await;
    {
        let state = fixture.node.state.lock().await;
        assert!(state.persisted.observed_hosted_head.as_ref().unwrap().0 > before);
        assert!(state.persisted.floor.act.is_none());
    }
    fixture.fake.requests.lock().await.clear();
    assert_local(&fixture.send(record()).await);
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn copy_behind_the_node_floor_is_answered_by_hosted_or_disclosed_never_refused() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .raise(head + 1);
    fixture.node.probe().await;
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.act,
        Some(head + 1)
    );
    fixture.fake.requests.lock().await.clear();
    // Hosted reachable: it answers, so the reader sees its own writes.
    let reply = fixture.send(record()).await;
    assert_hosted(&reply);
    assert_eq!(forwarded_reads(&fixture).await, 1);
    // Hosted unreachable: the copy answers and says it is behind.
    fixture.node.state.lock().await.health = Health::Unreachable;
    fixture.fake.requests.lock().await.clear();
    let reply = fixture.send(record()).await;
    assert_behind(&reply, head, head + 1);
    assert_eq!(routing(&reply)["own_write_floor_act"], head + 1);
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Explicit local routing is never answered by hosted, even when reachable.
    fixture.node.state.lock().await.health = Health::Reachable;
    let reply = fixture.send(local_only(record())).await;
    assert_behind(&reply, head, head + 1);
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Caught up: clean local answer.
    set_copy_head(&fixture, head + 1);
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    assert_eq!(routing(&reply)["behind_known_write"], false, "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn acknowledgment_during_a_local_query_never_presents_the_pre_write_answer_as_current() {
    for hosted_up in [true, false] {
        let fixture = fixture().await;
        let head = copy_head(&fixture).await;
        if !hosted_up {
            fixture.node.state.lock().await.health = Health::Unreachable;
        }
        let pause = Arc::new(DefaultReadPause {
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        *fixture.node.read_pause.lock().unwrap() = Some(pause.clone());
        let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(fixture.send(record()), async {
                pause.entered.notified().await;
                fixture
                    .node
                    .state
                    .lock()
                    .await
                    .persisted
                    .floor
                    .begin_write();
                let receipt =
                    json!({"jsonrpc":"2.0","id":20,"result":{"structuredContent":{"act":head+1}}})
                        .to_string();
                fixture.node.settle_write(Some(&receipt), None).await;
                pause.resume.notify_one();
            })
        })
        .await
        .expect("read/receipt race completes");
        if hosted_up {
            assert_hosted(&reply);
            assert_eq!(forwarded_reads(&fixture).await, 1);
        } else {
            assert_behind(&reply, head, head + 1);
            assert!(fixture.fake.requests.lock().await.is_empty());
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn old_known_copy_serves_with_its_real_age_instead_of_forwarding() {
    let fixture = fixture_with_age(None, 900).await;
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    let freshness = &reply["result"]["structuredContent"]["standby_context"]["freshness"];
    assert_eq!(freshness["state"], "beyond_rpo", "{reply}");
    assert!(freshness["age_seconds"].as_u64().unwrap() >= 900);
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

/// Restart continuity: while the post-restart integrity re-check runs, the
/// default policy keeps answering reads from the local copy with the
/// disclosure, online or offline, instead of sending the person to hosted or
/// to a refusal. Any other unrecognised degradation still refuses.
#[tokio::test]
async fn a_copy_being_rechecked_after_restart_still_serves_online_and_offline() {
    let fixture = fixture().await;
    let context = fixture.node.dispatcher.serving_context().unwrap();
    let act = context.serving_head_act.unwrap();
    let mut pending = context.clone();
    pending.degraded_reasons = vec!["restart_recheck_pending"];
    pending.freshness_degraded = true;
    assert_eq!(default_read_act(&pending, act), Some(act));
    pending.degraded_reasons.push("reader_not_upgraded");
    assert_eq!(default_read_act(&pending, act), None);

    // The node's session has its own store instance: hold the recheck open on
    // that one. The session's own startup recheck may still be finishing in
    // the background: let it end so the disclosure below is solely this
    // test's.
    let store = fixture.node.dispatcher.session_store();
    tokio::time::timeout(Duration::from_secs(60), async {
        while store.startup_recheck_pending() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the fixture's startup recheck finishes");
    let recheck = store.begin_startup_recheck();
    // Online, hosted reachable: answered locally, no hosted traffic.
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    let disclosed = &reply["result"]["structuredContent"]["standby_context"];
    assert!(
        disclosed["degraded_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|r| r == "restart_recheck_pending")),
        "{reply}"
    );
    assert!(disclosed["freshness"]["age_seconds"].as_u64().is_some());
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Offline: still local.
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert_local(&fixture.send(record()).await);
    // Completion clears the disclosure and nothing else changes.
    drop(recheck);
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    assert!(
        !reply.to_string().contains("restart_recheck_pending"),
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_verified_copy_of_unknown_age_serves_data_and_bootstrap_online_and_offline() {
    // A future-dated snapshot has no computable age (`snapshot_age_unavailable`).
    // The live legacy outage path serves such a copy; local-by-default must not
    // turn that into a refusal (G-N2). Integrity checks still apply.
    let fixture = fixture_with_age(None, -3600).await;
    let context = fixture.node.dispatcher.serving_context().unwrap();
    assert!(
        context
            .degraded_reasons
            .contains(&"snapshot_age_unavailable"),
        "fixture must exercise unknown age: {:?}",
        context.degraded_reasons
    );
    for health in [Health::Reachable, Health::Unreachable] {
        fixture.node.state.lock().await.health = health;
        fixture.fake.requests.lock().await.clear();
        let reply = fixture.send(record()).await;
        assert_local(&reply);
        assert_eq!(
            reply["result"]["structuredContent"]["standby_context"]["freshness"]["state"],
            "unavailable",
            "{reply}"
        );
        let mut text_record = record();
        text_record["params"]["arguments"]["format"] = json!("text");
        assert_not_refused(&fixture.send(text_record).await);
        assert_not_refused(&fixture.send(local_only(record())).await);
        for (id, format) in [(601, "json"), (602, "text")] {
            assert_not_refused(&fixture.send(boot(id, json!({ "format": format }))).await);
        }
        assert_eq!(
            forwarded_reads(&fixture).await,
            0,
            "served locally, not forwarded"
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn persisted_legacy_discovery_works_offline_without_a_client_tools_list() {
    let fixture = fixture().await;
    let persisted: Persisted =
        serde_json::from_slice(&fs::read(&fixture.node.file.path).unwrap()).unwrap();
    let mut legacy = serde_json::to_value(&persisted).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("observed_hosted_head");
    legacy["floor"]["act"] = json!(40);
    let migrated: Persisted = serde_json::from_value(legacy).unwrap();
    assert_eq!(migrated.floor.act, Some(40));
    assert!(migrated.observed_hosted_head.is_none());
    fixture.node.state.lock().await.health = Health::Unreachable;
    for protocol in crate::mcp::LEGACY_SUPPORTED_PROTOCOL_VERSIONS {
        assert!(!persisted.discovery[protocol].operations.is_empty());
        assert!(persisted.discovery[protocol].tools.is_some());
        assert_local(&fixture.send_protocol(record(), protocol).await);
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn unknown_carried_bootstrap_is_honest_and_new_keys_need_no_hosted_call() {
    let fixture = fixture().await;
    fixture.node.state.lock().await.health = Health::Unreachable;
    let carried = fixture
        .send(boot(
            100,
            json!({"run_key":"scout-chair-j748b2","format":"json"}),
        ))
        .await;
    assert_local(&carried);
    let run = &carried["result"]["structuredContent"]["run"];
    assert_eq!(run["run_key"], "scout-chair-j748b2");
    assert_eq!(run["status"], "unknown");
    assert_eq!(run["durable"], false);
    assert!(run["closed"].is_null());
    let carried_text = fixture
        .send(boot(
            102,
            json!({"run_key":"scout-chair-j748b2","format":"text"}),
        ))
        .await;
    let rendered = text(&carried_text);
    assert!(rendered.contains("unknown to this copy"));
    assert!(rendered
        .contains("No durable run, ownership, or open/closed status is established locally."));
    assert!(
        !rendered.contains("Bootstrap opens a durable run owned by the authenticated principal.")
    );
    assert!(rendered.contains("Read source: local_copy"));
    assert!(carried_text["result"].get("structuredContent").is_none());
    let fresh = fixture.send(boot(101, json!({"format":"json"}))).await;
    assert_local(&fresh);
    assert_eq!(
        fresh["result"]["structuredContent"]["run"]["issued_by"],
        "node"
    );
    assert_eq!(
        fresh["result"]["structuredContent"]["run"]["status"],
        "pending_on_hosted"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn auth_revision_persistence_and_contract_failures_are_answered_not_refused() {
    let fixture = fixture().await;
    // Authentication trouble is doubt: serve local, disclose, name the step.
    fixture.node.state.lock().await.health = Health::AuthRefused;
    for request in [record(), local_only(record())] {
        let reply = fixture.send(request).await;
        assert_local(&reply);
        assert_eq!(routing(&reply)["reauthenticate"], true, "{reply}");
        assert!(
            routing(&reply)["next_step"]
                .as_str()
                .unwrap()
                .contains("native login"),
            "{reply}"
        );
        assert!(text(&reply).contains("re-authenticate"), "{reply}");
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Hosted cannot be asked in any case below it would help: with it
    // reachable it answers, with it down the copy answers.
    for hosted_up in [true, false] {
        fixture.node.state.lock().await.health = if hosted_up {
            Health::Reachable
        } else {
            Health::Unreachable
        };
        fixture.fake.requests.lock().await.clear();
        fixture.node.state.lock().await.revision_unsupported = true;
        let reply = fixture.send(record()).await;
        if hosted_up {
            assert_hosted(&reply);
        } else {
            assert_local(&reply);
            assert!(
                text(&reply).contains("newer interchange revision"),
                "{reply}"
            );
        }
        {
            let mut state = fixture.node.state.lock().await;
            state.revision_unsupported = false;
            state.persistence_failed = true;
        }
        let reply = fixture.send(record()).await;
        if hosted_up {
            assert_hosted(&reply);
        } else {
            assert_local(&reply);
            assert_eq!(routing(&reply)["own_write_unresolved"], true, "{reply}");
        }
        fixture.node.state.lock().await.persistence_failed = false;
        assert_eq!(
            forwarded_reads(&fixture).await,
            if hosted_up { 2 } else { 0 }
        );
    }
    // A contract the copy does not hold: hosted answers; with hosted down
    // there is no local answer to give, and the error names a next step.
    {
        let mut state = fixture.node.state.lock().await;
        for row in &mut state
            .persisted
            .discovery
            .get_mut(crate::mcp::PROTOCOL_VERSION)
            .unwrap()
            .operations
        {
            if row["executor"] == "records_read" && row["operation"] == "get_record" {
                row["contract_digest"] = json!("wrong");
            }
        }
        state.health = Health::Reachable;
    }
    fixture.fake.requests.lock().await.clear();
    assert_hosted(&fixture.send(record()).await);
    assert_eq!(forwarded_reads(&fixture).await, 1);
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(record()).await;
    assert_eq!(reply["error"]["data"]["outcome"], "unavailable_offline");
    assert!(reply["error"]["data"]["next_step"].is_string(), "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn canonical_metadata_comes_from_hosted_and_a_local_stand_in_says_so() {
    // A rollout can retain the old option. It must not provide a second,
    // opportunistic route around the canonical metadata boundary.
    let fixture = fixture_with_legacy_option(Some(OnlineLocalReads {
        max_age_seconds: BOUND,
    }))
    .await;
    let query = sql_read(
        json!({"sql":"SELECT relation_name FROM catalog_relations"}),
        true,
    );
    let reply = fixture.send(query.clone()).await;
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "hosted",
        "{reply}"
    );
    // Hosted down: never refused. The reduced local catalogue answers if it
    // can, labelled as the offline surface.
    fixture.fake.requests.lock().await.clear();
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(query.clone()).await;
    assert_not_refused(&reply);
    if reply.get("result").is_some() {
        assert!(
            text(&reply).contains("supported offline surface"),
            "{reply}"
        );
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    // A midflight outage does not refuse either.
    fixture.node.state.lock().await.health = Health::Reachable;
    fixture.fake.status.store(502, Ordering::Release);
    assert_not_refused(&fixture.send(query).await);
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.requests.lock().await.clear();
    let data = fixture
        .send(sql_read(
            json!({"sql":"SELECT 'catalog_relations' AS label"}),
            true,
        ))
        .await;
    assert_local(&data);
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn writes_still_go_to_hosted_and_v2_held_replay_stays_disabled() {
    let fixture = fixture().await;
    assert!(!gate::Outage::held_replay_allowed(&*fixture.node).await);
    let reply = fixture.send(write()).await;
    assert_eq!(text(&reply), "hosted answer");
    assert_eq!(forwarded(&fixture, "create_record").await, 1);
    // The node cannot yet tell who wrote what: hosted answers the read.
    assert_hosted(&fixture.send(record()).await);
    fixture.node.probe().await;
    assert_local(&fixture.send(record()).await);
    let reply = fixture.send(local_only(write())).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    fixture.finish().await;
}

#[tokio::test]
async fn audit_age_is_disclosed_but_failed_or_unknown_verification_is_not_data() {
    use crate::standby::{StandbyAudit, StandbyFreshnessState};
    let fixture = fixture().await;
    let mut context = fixture.node.dispatcher.serving_context().unwrap();
    let act = context.serving_head_act.unwrap();
    context.freshness.state = StandbyFreshnessState::BeyondRpo;
    context.freshness.age_seconds = Some(900);
    context.freshness_degraded = true;
    context.degraded_reasons = vec!["snapshot_beyond_rpo"];
    for state in ["overdue", "unaudited"] {
        context.serving_audit = Some(StandbyAudit {
            state,
            age_seconds: Some(2000),
            interval_seconds: 900,
        });
        assert_eq!(default_read_act(&context, act), Some(act));
    }
    context.serving_audit.as_mut().unwrap().state = "failed";
    assert_eq!(default_read_act(&context, act), None);
    context.serving_audit = None;
    context.degraded_reasons.push("reader_not_upgraded");
    assert_eq!(default_read_act(&context, act), None);
    // Unknown age is disclosure, not integrity (G-N2): a verified copy whose
    // age cannot be computed still answers.
    context.freshness.state = StandbyFreshnessState::Unavailable;
    context.freshness.age_seconds = None;
    context.degraded_reasons = vec!["snapshot_age_unavailable"];
    assert_eq!(default_read_act(&context, act), Some(act));
    // ...but it never excuses a failed audit or an unrecognised degradation.
    context.serving_audit = Some(StandbyAudit {
        state: "failed",
        age_seconds: Some(10),
        interval_seconds: 900,
    });
    assert_eq!(default_read_act(&context, act), None);
    context.serving_audit = None;
    context.degraded_reasons.push("reader_not_upgraded");
    assert_eq!(default_read_act(&context, act), None);
    fixture.finish().await;
}

#[test]
fn old_state_keeps_its_floor_and_uncertain_lineage_settlement_is_conservative() {
    let mut floor = Floor {
        act: Some(40),
        lineage: Some("v2:one".into()),
        ..Default::default()
    };
    floor.observe_head(0, 100, "v2:one".into(), false);
    assert_eq!(floor.act, Some(40));
    floor.begin_write();
    floor.finish_write(true);
    floor.observe_head(floor.pending, 101, "v2:one".into(), false);
    assert_eq!(floor.act, Some(101));
    assert!(!floor.unresolved);
    floor.observe_head(floor.pending, 2, "v2:two".into(), false);
    assert_eq!(floor.act, Some(2));
    assert_eq!(floor.lineage.as_deref(), Some("v2:two"));
    for head in [1, 1000] {
        let mut migrated = Floor {
            act: Some(40),
            lineage: None,
            ..Default::default()
        };
        migrated.observe_head(0, head, "v2:known-head".into(), false);
        assert_eq!(migrated.act, Some(40));
        assert!(migrated.lineage.is_none());
    }
}

#[tokio::test]
async fn a_foreign_act_lineage_cannot_look_covered_by_a_larger_old_copy_head() {
    let fixture = fixture().await;
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.act = Some(1);
        state.persisted.floor.lineage = Some("v2:another-genesis".into());
    }
    assert_hosted(&fixture.send(record()).await);
    assert_eq!(forwarded_reads(&fixture).await, 1);
    // Hosted down: the copy answers, and does not pretend to be comparable.
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    assert!(routing(&reply)["behind_known_write"].is_null(), "{reply}");
    assert!(text(&reply).contains("could not be checked"), "{reply}");
    fixture.finish().await;
}

#[test]
fn default_read_mode_requires_v2_admission_and_excludes_pending_forks() {
    let valid = || {
        serde_json::from_value::<NodeConfig>(json!({
            "hosted_base_url":"https://example.test", "home_id":"h", "db_id":"d",
            "credential_file":"/credential", "socket_directory":"/socket",
            "account_id":"a", "standby_config":"/standby.json",
            "hosted_kernel_v2":true, "local_reads_by_default":true,
        }))
        .unwrap()
    };
    assert!(valid().endpoint().is_ok());
    let mut missing = valid();
    missing.standby_config = None;
    assert!(missing.endpoint().is_err());
    let mut v1 = valid();
    v1.hosted_kernel_v2 = false;
    assert!(v1.endpoint().is_err());
    let mut pending = valid();
    pending.pending_fork_reads = true;
    assert!(pending.endpoint().is_err());
}

#[tokio::test]
async fn final_response_fence_catches_receipts_after_the_query_check_including_bootstrap() {
    for bootstrap in [false, true] {
        for hosted_up in [true, false] {
            let fixture = fixture().await;
            let act = copy_head(&fixture).await;
            if !hosted_up {
                fixture.node.state.lock().await.health = Health::Unreachable;
            }
            let pause = Arc::new(DefaultReadPause {
                entered: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            });
            *fixture.node.final_read_pause.lock().unwrap() = Some(pause.clone());
            let request = if bootstrap {
                boot(500, json!({"run_key":"new", "format":"json"}))
            } else {
                record()
            };
            let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(fixture.send(request), async {
                    pause.entered.notified().await;
                    fixture
                        .node
                        .state
                        .lock()
                        .await
                        .persisted
                        .floor
                        .begin_write();
                    let receipt = json!({"result":{"structuredContent":{"act":act+1}}}).to_string();
                    fixture.node.settle_write(Some(&receipt), None).await;
                    pause.resume.notify_one();
                })
            })
            .await
            .expect("final response receipt fence completes");
            if hosted_up {
                // The pre-write local answer is replaced by hosted's.
                assert_hosted(&reply);
                if bootstrap {
                    assert_eq!(routing(&reply)["read_source"], "hosted", "{reply}");
                    assert_eq!(routing(&reply)["read_fallback_reason"], "own_write");
                }
            } else {
                // Or disclosed as behind: never presented as current.
                assert_behind(&reply, act, act + 1);
                assert!(fixture.fake.requests.lock().await.is_empty());
            }
            fixture.finish().await;
        }
    }
}

#[tokio::test]
async fn unknown_migrated_floor_is_disclosed_as_uncomparable_and_still_in_status() {
    let fixture = fixture().await;
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.act = Some(1);
        state.persisted.floor.lineage = None;
        state.health = Health::Unreachable;
    }
    // With hosted down the verified copy answers; it cannot be compared with
    // a floor from unknown numbering, and says so rather than refusing.
    for request in [record(), boot(501, json!({"format":"json"}))] {
        let reply = fixture.send(request).await;
        assert_not_refused(&reply);
        assert_eq!(routing(&reply)["read_source"], "local_copy", "{reply}");
    }
    let reply = fixture.send(record()).await;
    assert!(routing(&reply)["behind_known_write"].is_null(), "{reply}");
    fixture.node.probe().await;
    {
        let state = fixture.node.state.lock().await;
        assert_eq!(state.persisted.floor.act, Some(1));
        assert!(state.persisted.floor.lineage.is_none());
        assert!(state.persisted.observed_hosted_head.is_some());
    }
    fixture.node.state.lock().await.health = Health::Unreachable;
    assert_not_refused(&fixture.send(record()).await);
    let status = fixture.send(json!({"jsonrpc":"2.0","id":502,"method":"tools/call","params":{"name":"standby_status","arguments":{"format":"json"}}})).await;
    assert_eq!(
        status["result"]["structuredContent"]["node_local_read_admission"]["state"],
        "migration_unsettled",
        "{status}"
    );
    assert_eq!(
        fixture.node.hosted_summary().await["local_read_migration_required"],
        true
    );
    let binding = fixture.node.app_proof_binding().await.unwrap();
    assert_eq!(
        fixture.node.capture_read_barrier(&binding).await,
        Err("migration_unsettled")
    );
    // A migrated floor above hosted remains byte-for-byte numeric, too.
    fixture.node.state.lock().await.persisted.floor.act = Some(i64::MAX);
    fixture.node.probe().await;
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.act,
        Some(i64::MAX)
    );
    assert!(fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .lineage
        .is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn local_answers_scope_copy_capabilities_and_disclose_actual_write_health() {
    let fixture = fixture().await;
    for (health, writes) in [
        (Health::Unreachable, "unavailable"),
        (Health::AuthRefused, "authentication_refused"),
    ] {
        {
            let mut state = fixture.node.state.lock().await;
            state.health = health;
            state.persisted.floor.unresolved = true;
        }
        let reply = fixture.send(record()).await;
        assert_local(&reply);
        let node = routing(&reply);
        assert_eq!(node["canonical_writes"], writes, "{reply}");
        assert_eq!(node["hosted_health"], health.as_str());
        assert_eq!(node["own_write_unresolved"], true, "{reply}");
        let context = &reply["result"]["structuredContent"]["standby_context"];
        assert_eq!(context["local_copy"]["read_only"], true);
        assert!(context.get("read_only").is_none());
        assert!(context.get("writes_supported").is_none());
    }
    fixture.finish().await;
}

#[tokio::test]
async fn an_unusable_copy_with_hosted_down_is_the_only_error_and_names_a_next_step() {
    let fixture = fixture().await;
    let id = fixture
        .node
        .dispatcher
        .serving_context()
        .unwrap()
        .serving_generation_id
        .unwrap();
    // The controller reports the serving reader incompatible.
    fs::write(
        fixture
            .runtime
            .replica_root
            .join("accepted/heads")
            .join(format!("{id}.deferrals")),
        serde_json::to_vec(&json!({"reader_not_upgraded":11,"database_busy":0})).unwrap(),
    )
    .unwrap();
    // Hosted reachable: it answers.
    assert_hosted(&fixture.send(record()).await);
    // Hosted down and nothing verified to show: an error, with a way forward.
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(record()).await;
    assert_unavailable(&reply, "generation_or_integrity");
    assert!(
        reply["error"]["data"]["next_step"]
            .as_str()
            .unwrap()
            .contains("Retry"),
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn metadata_is_never_refused_on_auth_or_revision_doubt_and_ping_never_raises_the_floor() {
    let fixture = fixture().await;
    let metadata = vec![
        sql_read(
            json!({"sql":"SELECT relation_name FROM catalog_relations"}),
            true,
        ),
        json!({"jsonrpc":"2.0","id":503,"method":"tools/call","params":{"name":"describe_operation","arguments":{"executor":"records_read","operation":"get_record"}}}),
    ];
    for request in metadata {
        fixture.node.state.lock().await.health = Health::AuthRefused;
        let reply = fixture.send(request.clone()).await;
        assert_not_refused(&reply);
        if reply.get("result").is_some() {
            assert!(text(&reply).contains("re-authenticate"), "{reply}");
        }
        {
            let mut state = fixture.node.state.lock().await;
            state.health = Health::Reachable;
            state.revision_unsupported = true;
        }
        // Hosted is reachable and can read its own revision: it answers.
        let reply = fixture.send(request.clone()).await;
        assert!(text(&reply).contains("reads from hosted"), "{reply}");
        fixture.node.state.lock().await.revision_unsupported = false;
        // A 401 on the way: the local catalogue answers, disclosed.
        fixture.fake.status.store(401, Ordering::Release);
        assert_not_refused(&fixture.send(request).await);
        fixture.fake.status.store(0, Ordering::Release);
    }
    fixture.node.state.lock().await.health = Health::Reachable;
    let ping = json!({"jsonrpc":"2.0","id":504,"method":"tools/call","params":{"name":"system_read","arguments":{"operation":"ping","arguments":{},"format":"json"}}});
    let reply = fixture.send(ping).await;
    assert!(text(&reply).contains("reads from hosted"), "{reply}");
    let state = fixture.node.state.lock().await;
    assert!(!state.persisted.floor.unresolved);
    assert_eq!(state.persisted.floor.pending, 0);
    drop(state);
    fixture.finish().await;
}

#[tokio::test]
async fn mismatched_contract_recovers_per_protocol_with_bounded_retry() {
    let fixture = fixture().await;
    let protocol = crate::mcp::PROTOCOL_VERSION;
    {
        let mut state = fixture.node.state.lock().await;
        let cache = state.persisted.discovery.get_mut(protocol).unwrap();
        let row = cache
            .operations
            .iter_mut()
            .find(|row| row["executor"] == "records_read" && row["operation"] == "get_record")
            .unwrap();
        row["contract_digest"] = json!("old-contract");
        state.discovery_retry.clear();
    }
    assert_hosted(&fixture.send(record()).await);
    fixture.node.refresh_needed_discovery().await;
    assert_local(&fixture.send(record()).await);
    let requests = fixture.fake.requests.lock().await;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "tools/list")
            .count(),
        1,
        "only the deficient protocol is refreshed"
    );
    drop(requests);
    fixture.fake.requests.lock().await.clear();
    {
        let mut state = fixture.node.state.lock().await;
        state
            .persisted
            .discovery
            .get_mut(protocol)
            .unwrap()
            .operations
            .retain(|row| !(row["executor"] == "records_read" && row["operation"] == "get_record"));
        state.discovery_retry.clear();
    }
    assert_hosted(&fixture.send(record()).await);
    fixture.node.refresh_needed_discovery().await;
    assert_local(&fixture.send(record()).await);
    fixture.fake.requests.lock().await.clear();

    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.discovery.get_mut(protocol).unwrap().tools = None;
        state.discovery_retry.clear();
    }
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.refresh_needed_discovery().await;
    let first = fixture.fake.requests.lock().await.len();
    assert!(first > 0);
    fixture.node.refresh_needed_discovery().await;
    assert_eq!(
        fixture.fake.requests.lock().await.len(),
        first,
        "failed protocol backs off"
    );
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.state.lock().await.health = Health::Unreachable;
    fixture.node.probe().await;
    fixture.node.refresh_needed_discovery().await;
    assert!(
        fixture.node.state.lock().await.persisted.discovery[protocol]
            .tools
            .is_some(),
        "reconnect retries immediately"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn app_attributed_default_reads_keep_engine_admission_during_outage() {
    let fixture = fixture().await;
    fixture.node.state.lock().await.health = Health::Unreachable;
    let mut request = record();
    request["params"]["_meta"]["native/app"] =
        json!("offline.test@1; install=00000000-0000-4000-8000-000000000001");
    let reply = fixture.send(request).await;
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    // The fixture has no frozen apps, so activation is not what refuses: the
    // engine still refuses an unverified app caller, before any local-copy read.
    assert!(
        text(&reply).contains("database membership not found"),
        "{reply}"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn final_disclosure_tracks_a_health_change_without_switching_read_engines() {
    let fixture = fixture().await;
    let pause = Arc::new(DefaultReadPause {
        entered: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    *fixture.node.final_read_pause.lock().unwrap() = Some(pause.clone());
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(fixture.send(record()), async {
            pause.entered.notified().await;
            let mut state = fixture.node.state.lock().await;
            state.health = Health::Unreachable;
            state.health_epoch += 1;
            drop(state);
            pause.resume.notify_one();
        })
    })
    .await
    .expect("final health disclosure completes");
    assert_local(&reply);
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["hosted_health"],
        "unreachable"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["canonical_writes"],
        "unavailable"
    );
    assert!(
        !text(&reply).contains("Writes are forwarded to hosted Native"),
        "{reply}"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn discovery_auth_refusal_is_immediate_but_never_blocks_reads_and_an_unsupported_protocol_is_not_global_health(
) {
    for catalogue in [false, true] {
        let fixture = fixture().await;
        fixture.fake.status.store(401, Ordering::Release);
        if catalogue {
            fixture
                .node
                .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
                .await;
        } else {
            fixture.node.refresh_discovery().await;
            assert_eq!(
                fixture
                    .fake
                    .requests
                    .lock()
                    .await
                    .iter()
                    .filter(|r| r["method"] == "tools/list")
                    .count(),
                1,
                "initial sweep stops before the next protocol after authentication refusal"
            );
        }
        assert_eq!(fixture.node.state.lock().await.health, Health::AuthRefused);
        // Authentication doubt serves the copy with a re-authenticate step.
        let reply = fixture.send(record()).await;
        assert_local(&reply);
        assert_eq!(routing(&reply)["reauthenticate"], true, "{reply}");
        assert_local(&fixture.send(boot(510, json!({"format":"json"}))).await);
        fixture.fake.requests.lock().await.clear();
        fixture.fake.status.store(406, Ordering::Release);
        fixture.node.state.lock().await.health = Health::Reachable;
        fixture
            .node
            .refresh_discovery_for(crate::mcp::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[0])
            .await;
        assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
        assert_local(&fixture.send(record()).await);
        assert_local(
            &fixture
                .send_protocol(record(), crate::mcp::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[0])
                .await,
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn finalization_failure_goes_to_hosted_or_is_an_explicit_error_with_a_next_step() {
    let fixture = fixture().await;
    let dispatcher = fixture.node.dispatcher.local_dispatcher().unwrap();
    let act = dispatcher.serving_context().serving_head_act.unwrap();
    let ctx = ReadCtx {
        session: None,
        local: false,
    };
    let result = fixture
        .node
        .finalize_default_read(&record(), "not-json".into(), act, &dispatcher, ctx)
        .await;
    assert!(matches!(result, DefaultRead::Forward("response_encoding")));
    fixture.node.state.lock().await.health = Health::Unreachable;
    let DefaultRead::Reply(raw) = fixture
        .node
        .finalize_default_read(&record(), "not-json".into(), act, &dispatcher, ctx)
        .await
    else {
        panic!("explicit failure frame");
    };
    let reply: Value = serde_json::from_str(&raw).unwrap();
    assert_unavailable(&reply, "response_encoding");
    assert!(reply["error"]["data"]["next_step"].is_string());
    assert!(fixture.fake.requests.lock().await.is_empty());
    drop(dispatcher); // Release the captured reader before supervisor retirement.
    fixture.finish().await;
}

#[tokio::test]
async fn final_integrity_observation_uses_the_pinned_reader_for_data_and_bootstrap() {
    for (bootstrap, hosted_up) in [(false, true), (false, false), (true, true), (true, false)] {
        let fixture = fixture().await;
        if !hosted_up {
            fixture.node.state.lock().await.health = Health::Unreachable;
        }
        let id = fixture
            .node
            .dispatcher
            .serving_context()
            .unwrap()
            .serving_generation_id
            .unwrap();
        let pause = Arc::new(DefaultReadPause {
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        *fixture.node.final_read_pause.lock().unwrap() = Some(pause.clone());
        let request = if bootstrap {
            boot(520, json!({"format":"json"}))
        } else {
            record()
        };
        let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(fixture.send(request), async {
                pause.entered.notified().await;
                // Fixture-only controller standing: a pinned reader that the
                // controller now reports incompatible must withhold its data.
                let path = fixture
                    .runtime
                    .replica_root
                    .join("accepted/heads")
                    .join(format!("{id}.deferrals"));
                fs::write(
                    path,
                    serde_json::to_vec(&json!({"reader_not_upgraded":11,"database_busy":0}))
                        .unwrap(),
                )
                .unwrap();
                pause.resume.notify_one();
            })
        })
        .await
        .expect("final integrity fence completes");
        if hosted_up {
            // Hosted answers instead of data the pinned reader can no longer vouch for.
            assert_hosted(&reply);
        } else {
            assert_unavailable(&reply, "generation_or_integrity");
            assert!(reply["error"]["data"]["next_step"].is_string(), "{reply}");
            assert!(fixture.fake.requests.lock().await.is_empty());
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn incompatible_hosted_engine_goes_to_hosted_or_is_disclosed_and_stays_in_status() {
    let fixture = fixture().await;
    fixture.node.state.lock().await.head_engine_mismatch = true;
    assert_hosted(&fixture.send(record()).await);
    let boot_reply = fixture.send(boot(521, json!({"format":"json"}))).await;
    assert_eq!(
        routing(&boot_reply)["read_source"],
        "hosted",
        "{boot_reply}"
    );
    let summary = fixture.node.hosted_summary().await;
    assert_eq!(summary["head_engine_mismatch"], true);
    assert_eq!(summary["revision_unsupported"], false);
    fixture.fake.requests.lock().await.clear();
    fixture.node.state.lock().await.health = Health::Unreachable;
    for request in [record(), boot(522, json!({"format":"json"}))] {
        assert_not_refused(&fixture.send(request).await);
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn only_the_session_that_wrote_is_held_to_its_own_write() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    let writer = session_caller(11);
    let bystander = session_caller(12);
    // Session 11 writes (receipted at head+1); the node floor rises too.
    let write = fixture.node.session_begin_write(writer.session);
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .raise(head + 1);
    fixture
        .node
        .session_settle_write(write, Some(head + 1), true);
    fixture.fake.requests.lock().await.clear();
    // The writer must see it: hosted answers.
    let reply = send_as(&fixture, record(), &writer).await;
    assert_hosted(&reply);
    assert_eq!(forwarded_reads(&fixture).await, 1);
    // Another agent's write is ordinary staleness: local, disclosed.
    fixture.fake.requests.lock().await.clear();
    let reply = send_as(&fixture, record(), &bystander).await;
    assert_behind(&reply, head, head + 1);
    assert!(fixture.fake.requests.lock().await.is_empty());
    // A caller with no session identity keeps the strict node-wide rule.
    assert_hosted(&fixture.send(record()).await);
    // Hosted down: the writer is served the copy, disclosed as behind.
    fixture.node.state.lock().await.health = Health::Unreachable;
    fixture.fake.requests.lock().await.clear();
    assert_behind(&send_as(&fixture, record(), &writer).await, head, head + 1);
    assert!(fixture.fake.requests.lock().await.is_empty());
    // The copy catches up: the writer is local again, cleanly.
    fixture.node.state.lock().await.health = Health::Reachable;
    set_copy_head(&fixture, head + 1);
    let reply = send_as(&fixture, record(), &writer).await;
    assert_local(&reply);
    assert_eq!(routing(&reply)["behind_known_write"], false, "{reply}");
    // A closed connection's record is dropped.
    set_copy_head(&fixture, head);
    fixture.node.forget_session(11);
    assert_behind(&send_as(&fixture, record(), &writer).await, head, head + 1);
    fixture.finish().await;
}

#[tokio::test]
async fn a_forwarded_write_makes_only_its_own_session_read_from_hosted() {
    let fixture = fixture().await;
    let writer = session_caller(21);
    let bystander = session_caller(22);
    let reply = send_as(&fixture, write(), &writer).await;
    assert_eq!(text(&reply), "hosted answer");
    // The fake's receipt carries no act, so the write may have committed at an
    // unknown act: the node-wide floor is unresolved, and only the writer is
    // held to it.
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    fixture.fake.requests.lock().await.clear();
    assert_hosted(&send_as(&fixture, record(), &writer).await);
    assert_eq!(forwarded_reads(&fixture).await, 1);
    fixture.fake.requests.lock().await.clear();
    let reply = send_as(&fixture, record(), &bystander).await;
    assert_local(&reply);
    assert_eq!(routing(&reply)["own_write_unresolved"], true, "{reply}");
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn text_and_json_default_reads_follow_the_same_rules() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    let as_text = || {
        let mut request = record();
        request["params"]["arguments"]["format"] = json!("text");
        request
    };
    // A clean text read is served locally. (A text rendering carries no
    // structuredContent; that absence once read as a generation mismatch and
    // refused every text read while JSON was served.)
    let reply = fixture.send(as_text()).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(text(&reply).contains("reads from local_copy"), "{reply}");
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Below a known act and hosted down: both formats serve the copy and say so.
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .raise(head + 1);
    fixture.node.state.lock().await.health = Health::Unreachable;
    let json_reply = fixture.send(record()).await;
    let text_reply = fixture.send(as_text()).await;
    assert_behind(&json_reply, head, head + 1);
    assert_eq!(text_reply["result"]["isError"], false, "{text_reply}");
    assert!(text(&text_reply).contains(&format!("hosted is known to be at act {}", head + 1)));
    // Hosted reachable: both formats get the same hosted answer.
    fixture.node.state.lock().await.health = Health::Reachable;
    assert_hosted(&fixture.send(record()).await);
    assert_hosted(&fixture.send(as_text()).await);
    // And bootstrap follows the same rule in both formats.
    for format in ["json", "text"] {
        let reply = fixture.send(boot(530, json!({"format":format}))).await;
        assert!(text(&reply).contains("reads from hosted"), "{reply}");
    }
    fixture.finish().await;
}

#[tokio::test]
async fn freshness_is_never_fresh_while_hosted_is_known_to_be_ahead() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    let reply = fixture.send(record()).await;
    assert_eq!(
        reply["result"]["structuredContent"]["standby_context"]["freshness"]["state"],
        "fresh"
    );
    // A foreign write moves hosted ahead; it is observed, not an own write.
    let owner = crate::kernel::resolve_principal_by_binding(&fixture.db, "acct:fixture")
        .await
        .unwrap()
        .unwrap()
        .0;
    crate::kernel::create_record_as(&fixture.db, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    fixture.node.probe().await;
    let observed = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .observed_hosted_head
        .clone()
        .unwrap()
        .0;
    assert!(observed > head);
    // (The probe above is the only hosted traffic; the read itself is local.)
    fixture.fake.requests.lock().await.clear();
    let reply = fixture.send(record()).await;
    assert_behind(&reply, head, observed);
    let mut text_request = record();
    text_request["params"]["arguments"]["format"] = json!("text");
    let text_reply = fixture.send(text_request).await;
    // Text must disclose that hosted is ahead, and must not call the copy
    // fresh anywhere: the boundary is honest staleness, in text as in JSON.
    assert!(
        text(&text_reply).contains(&format!("hosted is known to be at act {observed}")),
        "{text_reply}"
    );
    assert!(
        text(&text_reply).contains("Source: local copy"),
        "{text_reply}"
    );
    assert!(!text(&text_reply).contains("`fresh`"), "{text_reply}");
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn a_binding_to_another_account_still_refuses_to_open_the_node_state() {
    let fixture = fixture().await;
    let persisted: Persisted =
        serde_json::from_slice(&fs::read(&fixture.node.file.path).unwrap()).unwrap();
    let mut other = persisted.binding.clone();
    other.account = "acct:someone-else".into();
    let dir = fixture.node.file.path.parent().unwrap().parent().unwrap();
    // State written under one account is never inherited by another.
    let (file, fresh) = StateFile::open(dir, other.clone()).unwrap();
    assert_ne!(file.path, fixture.node.file.path);
    assert!(fresh.floor.act.is_none());
    let mut forged = serde_json::to_value(&persisted).unwrap();
    forged["binding"] = serde_json::to_value(&other).unwrap();
    fs::write(
        &fixture.node.file.path,
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert!(StateFile::open(dir, persisted.binding.clone()).is_err());
    fixture.finish().await;
}

fn unusable_copy(fixture: &Fixture, id: &str) {
    // The controller reports the serving reader incompatible: the default
    // integrity checks reject the copy (as a failed audit would).
    fs::write(
        fixture
            .runtime
            .replica_root
            .join("accepted/heads")
            .join(format!("{id}.deferrals")),
        serde_json::to_vec(&json!({"reader_not_upgraded":11,"database_busy":0})).unwrap(),
    )
    .unwrap();
}

async fn serving_id(fixture: &Fixture) -> String {
    fixture
        .node
        .dispatcher
        .serving_context()
        .unwrap()
        .serving_generation_id
        .unwrap()
}

#[test]
fn only_a_confirmed_different_canonical_account_is_a_boundary() {
    // Confirmed: both sides are canonical and differ.
    assert_eq!(account_verdict(Some("acct_a"), Some("acct_b")), Some(false));
    assert_eq!(account_verdict(Some("acct_a"), Some("acct_a")), Some(true));
    // Doubt, never a refusal: nothing to compare, or a shape we do not trust.
    assert_eq!(account_verdict(Some("acct_a"), None), None);
    assert_eq!(account_verdict(None, Some("acct_b")), None);
    assert_eq!(account_verdict(Some("acct:fixture"), Some("acct_b")), None);
    assert_eq!(account_verdict(Some("acct_a"), Some("someone")), None);
}

#[tokio::test]
async fn a_credential_for_a_confirmed_different_account_refuses_local_reads_and_unverifiable_serves(
) {
    let fixture = fixture().await;
    // Unverifiable: hosted refuses the new credential (403), so who it is
    // cannot be established. That is doubt: keep serving, with the re-auth step.
    fixture.fake.status.store(403, Ordering::Release);
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    fixture.fake.status.store(0, Ordering::Release);
    assert!(!fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.node.state.lock().await.health = Health::AuthRefused;
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    assert_eq!(routing(&reply)["reauthenticate"], true, "{reply}");
    // Confirmed different: hosted says this credential is acct_bbb.
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    {
        // A new credential (`native login` rewrites the file).
        let path = &fixture.node.upstream.config.credential_file;
        fs::write(path, "second-token\n").unwrap();
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.fake.requests.lock().await.clear();
    // Explicit local, default-routed with hosted unable to answer, and the
    // outage path are all refused; none serves account A's copy.
    for health in [Health::AuthRefused, Health::Unreachable] {
        fixture.node.state.lock().await.health = health;
        for request in [
            local_only(record()),
            record(),
            boot(540, json!({"format":"json"})),
        ] {
            let reply = fixture.send(request).await;
            assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
            assert_eq!(
                reply["error"]["data"]["reason"], "account_changed",
                "{reply}"
            );
            assert!(reply["error"]["data"]["next_step"].is_string(), "{reply}");
            assert!(reply.get("result").is_none(), "{reply}");
        }
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Hosted reachable: it answers as the new account.
    fixture.node.state.lock().await.health = Health::Reachable;
    assert_hosted(&fixture.send(record()).await);
    // Signed back in as the bound account: reads are local again.
    *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "third-token\n",
    )
    .unwrap();
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(!fixture.node.state.lock().await.persisted.account_mismatch);
    assert_local(&fixture.send(record()).await);
    fixture.finish().await;
}

#[tokio::test]
async fn replaced_or_unreadable_credentials_without_a_prior_mismatch_are_doubt() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(local_only(record())).await;
    assert_local(&reply);

    // Renewal or login replaces the credential; no verification is available.
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "account-a-token",
    )
    .unwrap();
    for request in [
        record(),
        local_only(record()),
        boot(550, json!({"format":"json"})),
    ] {
        let reply = fixture.send(request).await;
        assert_local(&reply);
        assert_eq!(routing(&reply)["account_verified"], false, "{reply}");
        assert!(routing(&reply).get("reauthenticate").is_none(), "{reply}");
    }
    fs::remove_file(&fixture.node.upstream.config.credential_file).unwrap();
    assert_local(&fixture.send(local_only(record())).await);
    fixture.finish().await;
}

#[tokio::test]
async fn a_confirmed_mismatch_survives_renewal_unreadability_and_inconclusive_checks() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    // B's renewer replaces the bytes; the principal is still B. No hosted
    // check is possible during the outage, and the boundary must persist.
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "renewed-b-token",
    )
    .unwrap();
    fixture.node.state.lock().await.health = Health::Unreachable;
    for request in [
        record(),
        local_only(record()),
        boot(554, json!({"format":"json"})),
    ] {
        let reply = fixture.send(request).await;
        assert_eq!(
            reply["error"]["data"]["reason"], "account_changed",
            "{reply}"
        );
        assert!(reply.get("result").is_none(), "{reply}");
    }
    fs::remove_file(&fixture.node.upstream.config.credential_file).unwrap();
    let reply = fixture.send(record()).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_changed",
        "{reply}"
    );
    // Recreated after removal: give it the owner-only mode the guarded read
    // requires (a runner's default umask would leave it group/world readable,
    // which the node rightly treats as unreadable).
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "fixed-sign-in-token",
    )
    .unwrap();
    fs::set_permissions(
        &fixture.node.upstream.config.credential_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    fixture.fake.status.store(403, Ordering::Release);
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    let reply = fixture.send(record()).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_changed",
        "{reply}"
    );
    // Only successful confirmation of A clears the boundary. A loaded CI
    // runner can make one confirmation attempt inconclusive, which correctly
    // leaves the boundary in place; retry the confirmation (bounded) rather
    // than the read, so local data still needs a conclusive match.
    fixture.fake.status.store(0, Ordering::Release);
    *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
    for _ in 0..50 {
        fixture.node.state.lock().await.account_check = None;
        fixture.node.verify_account_against(Some("acct_aaa")).await;
        if !fixture.node.state.lock().await.persisted.account_mismatch {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    {
        let state = fixture.node.state.lock().await;
        assert!(
            !state.persisted.account_mismatch,
            "bound account never confirmed: check={:?} started={} applied={}",
            state.account_check.map(|(_, _, conclusive)| conclusive),
            state.account_check_started,
            state.account_check_applied
        );
    }
    assert_local(&fixture.send(record()).await);
    fixture.finish().await;
}

#[tokio::test]
async fn a_confirmed_account_mismatch_survives_restart_until_the_bound_account_is_confirmed() {
    let mut fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    let binding = fixture.node.state.lock().await.persisted.binding.clone();
    fixture.node = Arc::new(
        Failover::new(
            fixture.node.upstream.clone(),
            fixture.supervisor.dispatcher(),
            fixture.node.local.clone(),
            binding.origin.clone(),
        )
        .unwrap(),
    );
    fixture.node.state.lock().await.health = Health::Unreachable;
    for request in [
        record(),
        local_only(record()),
        boot(555, json!({"format":"json"})),
    ] {
        let reply = fixture.send(request).await;
        assert_eq!(
            reply["error"]["data"]["reason"], "account_changed",
            "{reply}"
        );
    }
    // Renewal and an inconclusive check cannot erase the durable boundary.
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "renewed-b-token",
    )
    .unwrap();
    fixture.fake.status.store(503, Ordering::Release);
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    let reply = fixture.send(local_only(record())).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_changed",
        "{reply}"
    );
    // A conclusive match clears both the current verdict and its disk copy.
    fixture.fake.status.store(0, Ordering::Release);
    *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert_local(&fixture.send(local_only(record())).await);
    let (_, recovered) =
        StateFile::open(&fixture.node.upstream.config.socket_directory, binding).unwrap();
    assert!(!recovered.account_mismatch);
    // Existing state files predate this field and remain readable.
    let mut legacy = serde_json::to_value(recovered).unwrap();
    legacy.as_object_mut().unwrap().remove("account_mismatch");
    let legacy: Persisted = serde_json::from_value(legacy).unwrap();
    assert!(!legacy.account_mismatch);
    fixture.finish().await;
}

#[tokio::test]
async fn a_cached_account_verdict_retries_failed_persistence() {
    let fixture = fixture().await;
    fs::remove_file(&fixture.node.file.path).unwrap();
    fs::create_dir(&fixture.node.file.path).unwrap();
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    {
        let state = fixture.node.state.lock().await;
        assert!(state.persisted.account_mismatch);
        assert!(state.persistence_failed);
    }
    fs::remove_dir(&fixture.node.file.path).unwrap();
    fixture.fake.requests.lock().await.clear();
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    let state = fixture.node.state.lock().await;
    assert!(!state.persistence_failed);
    let (_, recovered) = StateFile::open(
        &fixture.node.upstream.config.socket_directory,
        state.persisted.binding.clone(),
    )
    .unwrap();
    assert!(recovered.account_mismatch);
    drop(state);
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn a_sticky_mismatch_uses_hosted_when_reachable_after_renewal() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "renewed-b-token",
    )
    .unwrap();
    fixture.node.state.lock().await.health = Health::Reachable;
    fixture.fake.requests.lock().await.clear();
    for request in [record(), boot(555, json!({"format":"json"}))] {
        assert_hosted(&fixture.send(request).await);
    }
    assert_eq!(forwarded_reads(&fixture).await, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn a_principal_response_for_a_replaced_credential_is_discarded() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    // Force a new check and pause after hosted has identified the old token.
    fixture.node.state.lock().await.account_check = None;
    fixture.fake.pause_principal.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            fixture.node.verify_account_against(Some("acct_aaa")),
            async {
                fixture.fake.entered.notified().await;
                fs::write(
                    &fixture.node.upstream.config.credential_file,
                    "account-a-token",
                )
                .unwrap();
                fixture.fake.resume.notify_one();
            }
        );
    })
    .await
    .expect("credential replacement during verification");
    assert!(fixture.node.state.lock().await.account_check.is_none());
    let reply = fixture.send(record()).await;
    assert_local(&reply);
    assert_eq!(routing(&reply)["account_verified"], false, "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn an_older_principal_check_finishing_last_cannot_overwrite_a_newer_one() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    // The first check is held after hosted answered "acct_bbb"...
    fixture.fake.pause_principal.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            fixture.node.verify_account_against(Some("acct_aaa")),
            async {
                fixture.fake.entered.notified().await;
                // ...while a later check of the same credential confirms the
                // bound account and applies first.
                *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
                fixture.node.verify_account_against(Some("acct_aaa")).await;
                fixture.fake.resume.notify_one();
            }
        );
    })
    .await
    .expect("out-of-order principal checks");
    // The stale "different account" observation must not win.
    assert!(!fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.node.state.lock().await.health = Health::Unreachable;
    assert_local(&fixture.send(record()).await);
    fixture.finish().await;
}

#[tokio::test]
async fn a_newer_inconclusive_check_cannot_discard_an_older_confirmed_mismatch() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    // The older check is held after hosted identified "acct_bbb"...
    fixture.fake.pause_principal.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            fixture.node.verify_account_against(Some("acct_aaa")),
            async {
                fixture.fake.entered.notified().await;
                // ...while a newer check of the same credential is refused
                // (inconclusive) and finishes first.
                fixture.fake.status.store(403, Ordering::Release);
                fixture.node.verify_account_against(Some("acct_aaa")).await;
                fixture.fake.status.store(0, Ordering::Release);
                fixture.fake.resume.notify_one();
            }
        );
    })
    .await
    .expect("older conclusive, newer inconclusive");
    // The conclusive mismatch must stand.
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(record()).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_changed",
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_newer_confirmed_mismatch_survives_an_older_match_finishing_last() {
    let fixture = fixture().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_aaa".into());
    fixture.node.state.lock().await.account_check = None;
    // The older check is held after hosted identified the bound account...
    fixture.fake.pause_principal.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            fixture.node.verify_account_against(Some("acct_aaa")),
            async {
                fixture.fake.entered.notified().await;
                // ...while a newer check of the same credential confirms a
                // different account and applies first.
                *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
                fixture.node.verify_account_against(Some("acct_aaa")).await;
                fixture.fake.resume.notify_one();
            }
        );
    })
    .await
    .expect("older match, newer mismatch");
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(record()).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_changed",
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn an_inconclusive_principal_check_is_disclosed_even_when_head_succeeds() {
    let fixture = fixture().await;
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
    for format in ["text", "json"] {
        let mut request = record();
        request["params"]["arguments"]["format"] = json!(format);
        let reply = fixture.send(request).await;
        assert_not_refused(&reply);
        assert!(text(&reply).contains("has not been verified"), "{reply}");
        assert!(!text(&reply).contains("native login"), "{reply}");
        if format == "json" {
            assert_eq!(routing(&reply)["account_verified"], false, "{reply}");
            assert!(routing(&reply).get("reauthenticate").is_none(), "{reply}");
            assert!(routing(&reply).get("next_step").is_none(), "{reply}");
        }
    }
    fixture.finish().await;
}

#[tokio::test]
async fn an_unconfigured_account_emits_no_account_or_login_fields() {
    let mut fixture = fixture().await;
    let node = Arc::get_mut(&mut fixture.node).unwrap();
    let mut config = node.upstream.config.clone();
    config.account_id = None;
    node.upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
    for health in [Health::Reachable, Health::Unreachable] {
        fixture.node.state.lock().await.health = health;
        for format in ["json", "text"] {
            let mut request = record();
            request["params"]["arguments"]["format"] = json!(format);
            let reply = fixture.send(request).await;
            assert_not_refused(&reply);
            assert!(routing(&reply).get("account_verified").is_none(), "{reply}");
            assert!(routing(&reply).get("reauthenticate").is_none(), "{reply}");
            assert!(routing(&reply).get("next_step").is_none(), "{reply}");
            assert!(!text(&reply).contains("has not been verified"), "{reply}");
            assert!(!text(&reply).contains("native login"), "{reply}");
        }
    }
    fixture.finish().await;
}

#[tokio::test]
async fn a_confirmed_account_change_at_the_final_fence_withholds_local_data() {
    for offline in [false, true] {
        for bootstrap in [false, true] {
            let fixture = fixture().await;
            if offline {
                fixture.node.state.lock().await.health = Health::Unreachable;
            }
            let pause = Arc::new(DefaultReadPause {
                entered: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            });
            *fixture.node.final_read_pause.lock().unwrap() = Some(pause.clone());
            let mut request = if bootstrap {
                boot(551, json!({"format":"json"}))
            } else {
                record()
            };
            // Exercise offline() as well as normal default-read finalization.
            if offline {
                request = local_only(request);
                fixture.node.state.lock().await.revision_unsupported = true;
            }
            let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(fixture.send(request), async {
                    pause.entered.notified().await;
                    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
                    fixture.node.state.lock().await.account_check = None;
                    fixture.node.verify_account_against(Some("acct_aaa")).await;
                    fixture.node.state.lock().await.health = Health::Unreachable;
                    pause.resume.notify_one();
                })
            })
            .await
            .expect("final account fence");
            assert_eq!(
                reply["error"]["data"]["reason"], "account_changed",
                "{reply}"
            );
            assert!(reply.get("result").is_none(), "{reply}");
            fixture.finish().await;
        }
    }
}

#[tokio::test]
async fn a_rejected_copy_never_answers_when_hosted_then_fails() {
    for bootstrap in [false, true] {
        let fixture = fixture().await;
        let id = serving_id(&fixture).await;
        unusable_copy(&fixture, &id);
        // Hosted looks reachable, is asked, and fails mid-flight.
        fixture.fake.status.store(502, Ordering::Release);
        let request = if bootstrap {
            boot(541, json!({"format":"json"}))
        } else {
            record()
        };
        let reply = fixture.send(request).await;
        assert_unavailable(&reply, "generation_or_integrity");
        assert!(reply["error"]["data"]["next_step"].is_string(), "{reply}");
        assert!(!reply.to_string().contains(crate::events::KERNEL_ROOT_ID));
        // And with hosted already known to be down.
        fixture.fake.status.store(0, Ordering::Release);
        fixture.node.state.lock().await.health = Health::Unreachable;
        let request = if bootstrap {
            boot(542, json!({"format":"json"}))
        } else {
            local_only(record())
        };
        assert_unavailable(&fixture.send(request).await, "generation_or_integrity");
        fixture.finish().await;
    }
}

#[tokio::test]
async fn a_delayed_response_to_an_earlier_write_does_not_clear_a_later_uncertain_write() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    let floor = |unresolved| Floor {
        act: Some(head),
        unresolved,
        lineage: Some("v2:x".into()),
        ..Default::default()
    };
    // W1 begins; W2 begins, commits without a receipt act; W1's reply (act
    // 100-ish) lands last.
    let w1 = fixture.node.session_begin_write(Some(31));
    let w2 = fixture.node.session_begin_write(Some(31));
    fixture.node.session_settle_write(w2, None, true);
    fixture.node.session_settle_write(w1, Some(head + 5), true);
    let own = fixture.node.own_writes(Some(31), &floor(true));
    assert!(own.unresolved, "W2 is still uncertain: {own:?}");
    assert!(own.act >= head + 5);
    // Unresolved, so the session is answered by hosted, not the copy at W1's act.
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.unresolved = true;
    }
    fixture.fake.requests.lock().await.clear();
    assert_hosted(&send_as(&fixture, record(), &session_caller(31)).await);
    // A later request can replay an OLD receipt. Neither that nor a newer
    // receipt proves coverage of the uncertain write.
    let w3 = fixture.node.session_begin_write(Some(31));
    fixture.node.session_settle_write(w3, Some(head), true);
    let own = fixture.node.own_writes(Some(31), &floor(true));
    assert!(own.unresolved, "old idempotent receipt: {own:?}");
    let w3 = fixture.node.session_begin_write(Some(31));
    fixture.node.session_settle_write(w3, Some(head + 9), true);
    assert!(fixture.node.own_writes(Some(31), &floor(true)).unresolved);
    // Only a resolved, known floor covering this session settles it.
    assert!(fixture.node.own_writes(Some(31), &floor(false)).unresolved);
    let settled = Floor {
        act: Some(head + 9),
        ..floor(false)
    };
    let own = fixture.node.own_writes(Some(31), &settled);
    assert!(!own.unresolved, "{own:?}");
    assert_eq!(own.act, head + 9);
    assert!(!fixture.node.own_writes(Some(31), &floor(true)).unresolved);
    let w4 = fixture.node.session_begin_write(Some(32));
    fixture.node.session_settle_write(w4, None, true);
    assert!(fixture.node.own_writes(Some(32), &floor(true)).unresolved);
    let unknown = Floor {
        act: None,
        ..floor(false)
    };
    assert!(fixture.node.own_writes(Some(32), &unknown).unresolved);
    let own = fixture.node.own_writes(Some(32), &floor(false));
    assert!(!own.unresolved);
    assert_eq!(own.act, head);
    fixture.finish().await;
}

#[tokio::test]
async fn bootstrap_and_unusable_credentials_fall_back_to_the_verified_copy() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    // Behind a known act, so the read is sent to hosted first.
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .raise(head + 1);
    // Bootstrap forwarded for that reason, then hosted fails: served, not errored.
    fixture.fake.status.store(502, Ordering::Release);
    let reply = fixture.send(boot(543, json!({"format":"json"}))).await;
    assert_not_refused(&reply);
    assert_eq!(routing(&reply)["read_source"], "local_copy", "{reply}");
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.state.lock().await.health = Health::Reachable;
    // The credential cannot be used at all (never sent): that is auth doubt.
    fs::remove_file(&fixture.node.upstream.config.credential_file).unwrap();
    let reply = fixture.send(record()).await;
    assert_behind(&reply, head, head + 1);
    assert_eq!(routing(&reply)["reauthenticate"], true, "{reply}");
    fixture.node.state.lock().await.health = Health::Reachable;
    let reply = fixture.send(boot(544, json!({"format":"json"}))).await;
    assert_not_refused(&reply);
    fixture.finish().await;
}

async fn writer_behind_copy(fixture: &Fixture) -> (Caller, i64) {
    let head = copy_head(fixture).await;
    let writer = session_caller(71);
    let write = fixture.node.session_begin_write(writer.session);
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .raise(head + 1);
    fixture
        .node
        .session_settle_write(write, Some(head + 1), true);
    (writer, head)
}

fn server_failure_read_requests(id: u64) -> [Value; 4] {
    let mut text_record = record();
    text_record["params"]["arguments"]["format"] = json!("text");
    [
        record(),
        text_record,
        boot(id, json!({"format":"json"})),
        boot(id + 1, json!({"format":"text"})),
    ]
}

#[tokio::test]
async fn forwarded_own_write_reads_fall_back_after_hosted_server_or_protocol_failure() {
    let fixture = fixture().await;
    let (writer, head) = writer_behind_copy(&fixture).await;
    let failures = [
        (500, "server unavailable"),
        (501, "not implemented"),
        (505, "HTTP version unsupported"),
        (500, r#"{"error":"internal server failure"}"#),
        (
            500,
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"error":{"code":-32603,"message":"internal error"}}"#,
        ),
        (503, r#"{"error":"server overloaded","retryable":true}"#),
        (
            500,
            r#"{"error_code":"INTERNAL_ERROR","outcome":"unknown","applied":false}"#,
        ),
        (200, "broken protocol"),
        (
            200,
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"error":{"code":-32603,"message":"internal error"}}"#,
        ),
    ];
    for (status, body) in failures {
        *fixture.fake.read_reply.lock().unwrap() = Some((status, body.into()));
        for request in server_failure_read_requests(571) {
            fixture.node.state.lock().await.health = Health::Reachable;
            fixture.fake.requests.lock().await.clear();
            let reply = send_as(&fixture, request, &writer).await;
            if reply.pointer("/result/structuredContent").is_some() {
                assert_behind(&reply, head, head + 1);
                assert_eq!(routing(&reply)["own_write_floor_act"], head + 1, "{reply}");
                assert_eq!(
                    routing(&reply)["hosted_health"],
                    "protocol_failed",
                    "{reply}"
                );
                assert_eq!(
                    routing(&reply)["hosted_read_failure"]["http_status"],
                    status,
                    "{reply}"
                );
                // JSON's embedded text remains the same payload as structuredContent.
                let structured = &reply["result"]["structuredContent"];
                assert!(
                    reply["result"]["content"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|item| {
                            item["text"]
                                .as_str()
                                .and_then(|text| serde_json::from_str::<Value>(text).ok())
                                .as_ref()
                                == Some(structured)
                        }),
                    "{reply}"
                );
            } else {
                assert_not_refused(&reply);
                let rendered = text(&reply);
                // A raw read-only fallback may lack structured copy facts
                // and retain the detailed routing annotation. Normal compact
                // entry puts its generated source disclosure on line two.
                if rendered
                    .lines()
                    .nth(1)
                    .is_some_and(|line| line.starts_with("Read source: "))
                {
                    assert!(rendered.contains("Read source: local_copy"), "{reply}");
                    assert!(
                        rendered.contains("Hosted has newer changes; their time lag is unknown"),
                        "{reply}"
                    );
                } else {
                    assert!(rendered.contains("reads from local_copy"), "{reply}");
                    assert!(
                        rendered.contains(&format!("hosted is known to be at act {}", head + 1)),
                        "{reply}"
                    );
                }
            }
            assert!(
                text(&reply).contains(&format!("\"http_status\":{status}")),
                "{reply}"
            );
            if body.contains("-32603") {
                assert!(
                    text(&reply).contains("\"rpc_error_code\":-32603"),
                    "{reply}"
                );
            }
            assert!(
                text(&reply).contains("Hosted could not answer this read"),
                "{reply}"
            );
            assert_eq!(
                fixture.fake.requests.lock().await.len(),
                1,
                "the writer first attempted hosted; status {status}, body {body}"
            );
        }
    }
    fixture.finish().await;
}

#[tokio::test]
async fn forwarded_own_write_reads_preserve_canonical_validation_and_denial_answers() {
    let fixture = fixture().await;
    let (writer, _) = writer_behind_copy(&fixture).await;
    for status in [200, 400, 500] {
        for body in [
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"error":{"code":-32602,"message":"invalid parameters"}}"#,
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"error":{"code":-32000,"message":"access denied","data":{"http_status":500}}}"#,
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"result":{"isError":true,"content":[{"type":"text","text":"access denied"}]}}"#,
            r#"{"jsonrpc":"2.0","id":$REQUEST_ID,"result":{"isError":false,"content":[{"type":"text","text":"canonical success"}]}}"#,
        ] {
            *fixture.fake.read_reply.lock().unwrap() = Some((status, body.into()));
            for request in server_failure_read_requests(572) {
                fixture.node.state.lock().await.health = Health::Reachable;
                let expected: Value =
                    serde_json::from_str(&body.replace("$REQUEST_ID", &request["id"].to_string()))
                        .unwrap();
                let reply = send_as(&fixture, request, &writer).await;
                // Routing disclosure may be appended; the canonical failure remains.
                if expected.get("error").is_some() {
                    assert_eq!(reply["error"], expected["error"], "{reply}");
                } else {
                    assert_eq!(
                        reply["result"]["isError"], expected["result"]["isError"],
                        "{reply}"
                    );
                    assert_eq!(
                        reply["result"]["content"][0], expected["result"]["content"][0],
                        "{reply}"
                    );
                }
                assert_ne!(routing(&reply)["read_source"], "local_copy", "{reply}");
            }
        }
    }
    fixture.finish().await;
}

#[tokio::test]
async fn forwarded_own_write_reads_preserve_explicit_unframed_refusal() {
    let fixture = fixture().await;
    let (writer, _) = writer_behind_copy(&fixture).await;
    for status in [200, 400, 500, 503] {
        *fixture.fake.read_reply.lock().unwrap() = Some((
            status,
            json!({"outcome":"refused","error_code":"ACCESS_DENIED","applied":false}).to_string(),
        ));
        for request in server_failure_read_requests(575) {
            fixture.node.state.lock().await.health = Health::Reachable;
            let reply = send_as(&fixture, request, &writer).await;
            assert_eq!(reply["error"]["data"]["outcome"], "refused", "{reply}");
            assert_eq!(
                reply["error"]["data"]["error_code"], "ACCESS_DENIED",
                "{reply}"
            );
            assert_eq!(reply["error"]["data"]["applied"], false, "{reply}");
            assert_eq!(reply["error"]["data"]["http_status"], status, "{reply}");
            assert!(reply.get("result").is_none(), "{reply}");
        }
    }
    fixture.finish().await;
}

#[tokio::test]
async fn hosted_server_failure_fallback_keeps_integrity_and_account_fences() {
    for mismatch in [false, true] {
        let fixture = fixture().await;
        let (writer, _) = writer_behind_copy(&fixture).await;
        if mismatch {
            *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
            fixture.node.state.lock().await.account_check = None;
            fixture.node.verify_account_against(Some("acct_aaa")).await;
            assert!(fixture.node.state.lock().await.persisted.account_mismatch);
        } else {
            unusable_copy(&fixture, &serving_id(&fixture).await);
        }
        *fixture.fake.read_reply.lock().unwrap() = Some((500, "server failed".into()));
        for request in [record(), boot(573, json!({"format":"json"}))] {
            fixture.node.state.lock().await.health = Health::Reachable;
            fixture.fake.requests.lock().await.clear();
            let reply = send_as(&fixture, request, &writer).await;
            if mismatch {
                assert_eq!(
                    reply["error"]["data"]["reason"], "account_changed",
                    "{reply}"
                );
            } else {
                assert_unavailable(&reply, "generation_or_integrity");
            }
            assert!(reply.get("result").is_none(), "{reply}");
            assert_eq!(fixture.fake.requests.lock().await.len(), 1);
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn offline_bootstrap_executes_on_the_copy_it_pinned_before_a_swap() {
    let fixture = fixture().await;
    let first = serving_id(&fixture).await;
    let head = copy_head(&fixture).await;
    {
        let mut state = fixture.node.state.lock().await;
        state.health = Health::Unreachable;
        state.revision_unsupported = true; // Exercise offline bootstrap.
    }
    let pause = Arc::new(DefaultReadPause {
        entered: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    *fixture.node.offline_pin_pause.lock().unwrap() = Some(pause.clone());
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(fixture.send(boot(552, json!({"format":"json"}))), async {
            pause.entered.notified().await;
            let owner = crate::kernel::resolve_principal_by_binding(&fixture.db, "acct:fixture")
                .await
                .unwrap()
                .unwrap()
                .0;
            crate::kernel::create_record_as(&fixture.db, &owner, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap();
            let (snapshot, manifest) = stage(&fixture.store, &fixture.db, "bootstrap-swap").await;
            let next = fixture
                .store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap();
            assert_ne!(next.id, first);
            while serving_id(&fixture).await != next.id {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The current reader is now unusable; the pinned old reader is
            // still verified. Neither dispatch nor validation may switch.
            unusable_copy(&fixture, &next.id);
            pause.resume.notify_one();
        })
    })
    .await
    .expect("bootstrap generation swap");
    assert_local(&reply);
    assert_eq!(
        reply["result"]["structuredContent"]["standby_context"]["serving_generation_id"], first,
        "{reply}"
    );
    assert_eq!(routing(&reply)["serving_head_act"], head, "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn offline_disclosure_uses_the_answering_lineage_instead_of_the_current_dispatcher() {
    let fixture = fixture().await;
    let copy = fixture.node.dispatcher.local_dispatcher().unwrap();
    let head = copy.serving_context().serving_head_act.unwrap();
    let current_lineage = copy.act_lineage().unwrap();
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.act = Some(head + 1);
        state.persisted.floor.lineage = Some(current_lineage);
    }
    // A response captured before a lineage-changing publication: its larger
    // old act must not satisfy a floor in the current dispatcher's numbering.
    let response = json!({"jsonrpc":"2.0","id":553,"result":{
        "isError":false,"structuredContent":{"answer":"old verified copy"},"content":[]
    }});
    let raw = fixture
        .node
        .offline_response_with(
            response,
            Health::Unreachable,
            "records_read",
            "get_record",
            true,
            Some((
                None,
                Some(ReadPosition {
                    act: head + 10,
                    lineage: Some("v2:old-history".into()),
                }),
            )),
        )
        .await
        .unwrap();
    let reply: Value = serde_json::from_str(&raw).unwrap();
    assert_local(&reply);
    assert_eq!(routing(&reply)["serving_head_act"], head + 10);
    assert!(routing(&reply)["behind_known_write"].is_null(), "{reply}");
    assert!(
        routing(&reply)["known_hosted_head_act"].is_null(),
        "{reply}"
    );
    assert!(text(&reply).contains("could not be checked"), "{reply}");
    drop(copy);
    fixture.finish().await;
}

#[tokio::test]
async fn disclosure_is_from_the_position_the_answer_was_read_at() {
    let fixture = fixture().await;
    let head = copy_head(&fixture).await;
    let lineage = fixture
        .node
        .dispatcher
        .local_dispatcher()
        .unwrap()
        .act_lineage()
        .unwrap();
    // Hosted is known to be at head+1; the read starts at head.
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .observed_hosted_head = Some((head + 1, lineage));
    let pause = Arc::new(DefaultReadPause {
        entered: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    *fixture.node.read_pause.lock().unwrap() = Some(pause.clone());
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(fixture.send(record()), async {
            pause.entered.notified().await;
            // An in-place delta advances the pinned copy while the query ran.
            set_copy_head(&fixture, head + 1);
            pause.resume.notify_one();
        })
    })
    .await
    .expect("read/advance race completes");
    // The answer was read at `head`: it must not be disclosed as head+1
    // (behind=false, fresh) just because the copy has moved since.
    assert_behind(&reply, head, head + 1);
    fixture.finish().await;
}

#[tokio::test]
async fn custody_verified_credential_witness_survives_restart_without_a_probe() {
    let fixture = fixture().await;
    // Read fixtures use an intentionally nonportable account. Custody needs
    // the real portable binding contract, established through the probe.
    let mut config = fixture.node.upstream.config.clone();
    config.account_id = Some("acct_fixture".into());
    *fixture.fake.principal.lock().unwrap() = config.account_id.clone();
    let upstream = Arc::new(Upstream::new(config, Duration::from_secs(30)).unwrap());
    let origin = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .origin
        .clone();
    let router = Failover::new(
        upstream.clone(),
        fixture.supervisor.dispatcher(),
        fixture.node.local.clone(),
        origin.clone(),
    )
    .unwrap();
    router.probe().await;
    assert_eq!(router.state.lock().await.health, Health::Reachable);
    let expected = gate::Outage::custody_binding(&router)
        .await
        .expect("healthy head and verified portable credential establish custody binding");
    let replacement = Failover::new(
        upstream,
        fixture.supervisor.dispatcher(),
        fixture.node.local.clone(),
        origin,
    )
    .unwrap();
    assert!(replacement.state.lock().await.account_check.is_none());
    assert_eq!(
        gate::Outage::custody_binding(&replacement).await,
        Some(expected)
    );
    let credential = &fixture.node.upstream.config.credential_file;
    let original = fs::read(credential).unwrap();
    fs::write(credential, "replacement-unknown-credential").unwrap();
    assert!(gate::Outage::custody_binding(&replacement).await.is_none());
    fs::write(credential, original).unwrap();
    replacement.state.lock().await.persisted.account_mismatch = true;
    assert!(gate::Outage::custody_binding(&replacement).await.is_none());
    drop(replacement);
    drop(router);
    fixture.finish().await;
}

#[tokio::test]
async fn receiver_working_ingress_pairs_only_the_actual_legacy_note_codec() {
    for (operation, note, hosted95) in [
        ("update_record", false, false),
        ("manage_links.add", false, false),
        ("update_record", false, true),
        ("manage_links.add", false, true),
        ("update_record", true, true),
    ] {
        let mut fixture = Box::pin(Fixture::build_with_engine_policy(
            Some(true),
            None,
            false,
            None,
            false,
            true,
            FixtureReadPolicy {
                local_reads_by_default: true,
                snapshot_age_seconds: 0,
                account_binding: "acct_receiver",
            },
        ))
        .await;
        let actor = crate::kernel::resolve_principal_by_binding(&fixture.db, "acct_receiver")
            .await
            .unwrap()
            .unwrap()
            .0;
        for package in [
            crate::v2_standard::v1_compat::package(),
            crate::v2_standard::relates_to::package(),
        ] {
            let identity = package.identity().unwrap();
            crate::kernel::install_package_as(&fixture.db, &actor, &package)
                .await
                .unwrap();
            crate::kernel::adopt_package_at(
                &fixture.db,
                &actor,
                crate::events::KERNEL_ROOT_ID,
                &package,
                Some(&identity),
                &package.declared_reads,
            )
            .await
            .unwrap();
        }
        let home =
            crate::kernel::create_home(&fixture.db, crate::events::KERNEL_ROOT_ID, None, &actor)
                .await
                .unwrap();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let fields = if note {
                json!({"v1_type":"Document","v1_kind":"note","title":"Receiver note"})
            } else {
                json!({"v1_type":"WorkItem","v1_kind":"task","title":"Receiver task"})
            };
            let id = crate::kernel::create_json_as(
                &fixture.db,
                &actor,
                crate::v2_standard::v1_compat::FAMILY,
                "record",
                &fields.to_string(),
                &home,
            )
            .await
            .unwrap();
            let revision = crate::kernel::read_record_as(&fixture.db, &actor, &id)
                .await
                .unwrap()
                .unwrap()
                .revision;
            crate::kernel::set_body_as(&fixture.db, &actor, &id, "base", revision)
                .await
                .unwrap();
            ids.push(id);
        }
        let (snapshot, manifest) =
            stage(&fixture.store, &fixture.db, "receiver-codec-ingress").await;
        let accepted = fixture
            .store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        wait_status(&fixture, |s| {
            s["serving_generation"]["generation_id"] == accepted.id
        })
        .await;
        let previous = &fixture.node.upstream;
        let mut config = previous.config.clone();
        config.working_note_appends = true;
        let upstream = Arc::new(Upstream {
            compatibility: Default::default(),
            config,
            endpoint: previous.endpoint.clone(),
            client: previous.client.clone(),
            oauth: previous.oauth.clone(),
            install_key: previous.install_key.clone(),
        });
        let old = &fixture.node;
        let origin = old.state.lock().await.persisted.binding.origin.clone();
        fixture.node = Arc::new(
            Failover::new(
                upstream,
                fixture.supervisor.dispatcher(),
                old.local.clone(),
                origin,
            )
            .unwrap()
            .with_gate(old.gate.clone()),
        );
        *fixture.fake.principal.lock().unwrap() = Some("acct_receiver".into());
        let local =
            crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap();
        let contracts: BTreeMap<String, crate::mcp::executor_prototype::NodeHoldingContract> =
            if hosted95 {
                serde_json::from_str(include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/receiver-shapes/contracts95.json"
                )))
                .unwrap()
            } else {
                ["update_record", "manage_links.add", "attach_text"]
                    .into_iter()
                    .map(|operation| {
                        (
                            operation.to_owned(),
                            local.holding_contract("records_write", operation).unwrap(),
                        )
                    })
                    .collect()
            };
        let mut rows = fixture.fake.operations.clone();
        for (operation, contract) in contracts {
            let row = rows
                .iter_mut()
                .find(|row| row["executor"] == "records_write" && row["operation"] == operation)
                .unwrap();
            let description = &contract.description;
            for field in [
                "contract_digest",
                "contract_version",
                "executor",
                "operation",
                "surface",
            ] {
                row[field] = description[field].clone();
            }
            row["source_tool"] = description["source"]["tool"].clone();
            row["selector_field"] = description["source"]["selector"]["field"].clone();
            row["selector_value"] = description["source"]["selector"]["value"].clone();
            for (field, value) in contract.catalog.as_object().unwrap() {
                row[field] = value.clone();
            }
            assert_eq!(
                crate::mcp::executor_prototype::NodeHoldingContract::from_hosted(
                    description.clone(),
                    row
                ),
                Some(contract.clone()),
                "incoherent fixture discovery: {operation}"
            );
            fixture
                .fake
                .holding_descriptions
                .lock()
                .unwrap()
                .insert(operation, contract.description);
        }
        *fixture.fake.catalog_override.lock().unwrap() = Some(rows);
        fixture.node.probe().await;
        let key = crate::mcp::PROTOCOL_VERSION;
        fixture.node.refresh_catalogue(key, None).await;
        {
            let state = fixture.node.state.lock().await;
            assert_eq!(state.health, Health::Reachable);
            assert_eq!(fixture.node.current_account_verdict(&state), Some(true));
        }
        fixture.node.refresh_holding_contracts(key).await;
        let scope = gate::Outage::custody_binding(fixture.node.as_ref())
            .await
            .unwrap();
        let scoped = fixture
            .node
            .gate
            .as_ref()
            .unwrap()
            .scoped_v2_gate(&scope)
            .unwrap();
        let discovered = gate::Outage::holding_contract(
            fixture.node.as_ref(),
            "records_write",
            operation,
            Some(key),
        )
        .await
        .unwrap();
        assert_eq!(
            discovered.description["contract_digest"]
                == local
                    .holding_contract("records_write", operation)
                    .unwrap()
                    .description["contract_digest"],
            !hosted95
        );
        let args = if operation == "update_record" {
            json!({"id":ids[0],"body_append":"!","reason":"Sealed codec boundary","idempotency_key":"receiver-codec"})
        } else {
            json!({"source_id":ids[0],"target_id":ids[1],"relationship":"relates_to","idempotency_key":"receiver-codec"})
        };
        let message = json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":operation,"arguments":args}}});
        let events_before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
        let raw = fixture
            .node
            .try_working_route(&message, Some(key), &anonymous_caller())
            .await
            .unwrap();
        let reply: Value = serde_json::from_str(&raw).unwrap();
        if hosted95 && !note {
            assert_eq!(
                reply["error"]["data"]["outcome"], "not_sent",
                "{operation}: {reply}"
            );
            assert!(raw.contains("exact compiled v2 contract"), "{reply}");
            assert!(!raw.contains("working_applied"), "{reply}");
            assert!(scoped.journal.pending_entries().is_empty());
            let read = json!({"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"get_record","arguments":{"ids":[ids[0]]}}}});
            assert!(
                fixture
                    .node
                    .try_working_route(&read, Some(key), &anonymous_caller())
                    .await
                    .is_none(),
                "refused fresh custody must not initialize W"
            );
        } else {
            assert_eq!(
                reply["result"]["structuredContent"]["local_visibility"], "working_applied",
                "{operation}: {reply}"
            );
            let entries = scoped.journal.pending_entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].version,
                if note {
                    crate::node::journal::INSTALLED_WORKING_VERSION
                } else {
                    crate::node::journal::INSTALLED_RECORD_VERSION
                }
            );
            assert_eq!(entries[0].arguments.as_ref(), Some(&args));
            assert!(entries[0]
                .kernel_v2_custody
                .as_ref()
                .unwrap()
                .original
                .is_none());
            assert_eq!(
                entries[0]
                    .kernel_v2_custody
                    .as_ref()
                    .unwrap()
                    .contract_digest,
                local.digest("records_write", operation).unwrap()
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(fixture.db.pool())
                .await
                .unwrap(),
            events_before
        );
        assert!(!fixture
            .fake
            .requests
            .lock()
            .await
            .iter()
            .any(|r| target(r).is_some_and(|(e, op, _)| e == "records_write" && op == operation)));
        eprintln!(
            "receiver_ingress_case operation={operation} note={note} hosted95={hosted95} passed"
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn saved_state_unconfirmed_working_account_recovers_without_pausing() {
    let mut fixture = Fixture::new().await;
    fixture.node.probe().await;
    let binding = fixture.node.state.lock().await.persisted.binding.clone();
    let path = fixture.node.file.path.clone();
    fs::write(&path, b"{\"version\":2}").unwrap();
    let previous = &fixture.node.upstream;
    let mut config = previous.config.clone();
    config.working_note_appends = true;
    let upstream = Arc::new(Upstream {
        compatibility: Default::default(),
        config,
        endpoint: previous.endpoint.clone(),
        client: previous.client.clone(),
        oauth: previous.oauth.clone(),
        install_key: previous.install_key.clone(),
    });
    fixture.node = Arc::new(
        Failover::new(
            upstream,
            fixture.supervisor.dispatcher(),
            fixture.node.local.clone(),
            binding.origin,
        )
        .unwrap(),
    );
    let request = read(true);
    let refused = fixture
        .node
        .try_working_route(
            &request,
            Some(crate::mcp::PROTOCOL_VERSION),
            &anonymous_caller(),
        )
        .await
        .unwrap();
    let refused: Value = serde_json::from_str(&refused).unwrap();
    assert_eq!(refused["error"]["data"]["reason"], "account_unconfirmed");
    assert!(!fixture.node.working.acknowledgements_paused());
    *fixture.fake.principal.lock().unwrap() = fixture.node.upstream.config.account_id.clone();
    fixture.node.probe().await;
    assert_eq!(
        fixture
            .node
            .current_account_verdict(&*fixture.node.state.lock().await),
        Some(true)
    );
    assert!(!fixture.node.state.lock().await.account_unconfirmed);
    assert!(
        !fixture.node.working.acknowledgements_paused(),
        "account confirmation must not leave working acknowledgements paused"
    );
    // A real mismatch still closes the working account binding permanently.
    *fixture.fake.principal.lock().unwrap() = Some("acct_other".into());
    fs::write(
        &fixture.node.upstream.config.credential_file,
        b"other-account-token",
    )
    .unwrap();
    fixture.node.probe().await;
    assert!(fixture.node.working.acknowledgements_paused());
    let refused = fixture
        .node
        .try_working_route(
            &request,
            Some(crate::mcp::PROTOCOL_VERSION),
            &anonymous_caller(),
        )
        .await
        .unwrap();
    assert!(refused.contains("confirmed account change"));
    assert_eq!(fs::read(&path).unwrap(), b"{\"version\":2}");
    fixture.finish().await;
}

#[tokio::test]
async fn update_required_preserves_eligible_retained_reads_and_actual_age() {
    let fixture = fixture_with_age(None, 900).await;
    let (writer, head) = writer_behind_copy(&fixture).await;
    *fixture.fake.read_reply.lock().unwrap() = Some((
        426,
        r#"{"error_code":"client_update_required","outcome":"refused","applied":false}"#.into(),
    ));
    for request in [record(), boot(582, json!({"format":"json"}))] {
        fixture.node.state.lock().await.health = Health::Reachable;
        let reply = send_as(&fixture, request, &writer).await;
        assert_behind(&reply, head, head + 1);
        assert!(
            reply["result"]["structuredContent"]["standby_context"]["freshness"]["age_seconds"]
                .as_u64()
                .unwrap()
                >= 900
        );
        assert_eq!(
            routing(&reply)["hosted_read_failure"]["error_code"],
            "client_update_required"
        );
        assert_eq!(
            fixture.node.upstream.compatibility.status()["status"],
            "demand_recorded"
        );
    }
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    let reply = send_as(&fixture, record(), &writer).await;
    assert_eq!(reply["error"]["data"]["reason"], "account_changed");
    fixture.finish().await;
}
