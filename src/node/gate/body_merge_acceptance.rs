//! Slice-3 custody proofs through the real node gate and a faulting HTTP home.
use super::*;

const R1: &str = "70110000-0000-4000-8000-0000000000e1";
const Q: &str = "70110000-0000-4000-8000-0000000000e2";

fn merge(record: &str, key: Option<&str>, mine: &str) -> Value {
    let mut arguments = json!({
        "record_id":record, "base_version":"rec:1", "base_text":"base text",
        "my_text":mine, "reason":"preserve a body edit"
    });
    if let Some(key) = key {
        arguments["idempotency_key"] = json!(key);
    }
    json!({"executor":"records_write","operation":"merge_body","run_key":"run-body-merge","arguments":arguments})
}

async fn submit(rig: &Rig, envelope: Value, wait: &str) -> Value {
    let mut message = tool_call(7, "call_executor", envelope);
    message["params"]["_meta"] = json!({"native/body_merge":{
        "wait":wait, "editor":"acceptance-editor", "made_at_ms":1234
    }});
    forward_message(rig, message).await
}

pub(super) async fn forward_message(rig: &Rig, message: Value) -> Value {
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    serde_json::from_str(&report.reply.expect("one reply")).unwrap()
}

fn tool_reply(body: Value, error: bool) -> Fault {
    Fault::ToolReply(json!({"content":[],"structuredContent":body,"isError":error}))
}

fn expire_backoff(rig: &Rig, id: &str) {
    rig.gate
        .journal
        .update(id, |entry| entry.not_before_ms = 0)
        .unwrap();
}

#[tokio::test]
async fn body_merge_unrelated_record_progresses_behind_hosted_creator_custody() {
    let mut rig = Rig::new(fast()).await;
    let id = hold_create(&rig, "hosted-creator", "body").await["record_id"].clone();
    let dependent = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz",
        "arguments":{"id":id,"body_append":"tail","reason":"test dependent append","idempotency_key":"hosted-dependent"}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(&rig, dependent, None).await);
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    submit(
        &rig,
        merge(Q, Some("unrelated-merge"), "independent edit"),
        "none",
    )
    .await;
    rig.restart(fast());
    let before = rig.state().writes().len();
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    assert_eq!(rig.state().writes().len(), before + 1);
    assert_eq!(by_key(&rig, "unrelated-merge")["state"], "confirmed");
    assert_eq!(by_key(&rig, "hosted-dependent")["state"], "pending");
    assert_eq!(by_key(&rig, "hosted-creator")["state"], "hosted_pending");
}

#[tokio::test]
async fn body_merge_wait_none_is_durable_before_any_home_contact_and_survives_restart() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    let reply = submit(&rig, merge(R1, None, "my durable draft"), "none").await;
    assert_eq!(receipt(&reply)["outcome"], "saved_on_device", "{reply}");
    assert!(rig.state().writes().is_empty());
    assert_eq!(rig.state().describes.load(Ordering::SeqCst), 0);
    assert_eq!(rig.state().access_lookups.load(Ordering::SeqCst), 0);
    let saved = entries(&rig);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["version"], 2);
    assert_eq!(saved[0]["state"], "pending");
    assert_eq!(saved[0]["attempts"], 0);
    assert!(saved[0]
        .get("prepared")
        .is_none_or(|value| value == &json!(false)));
    assert_eq!(saved[0]["lineage_required"], true);
    assert_eq!(saved[0]["arguments"]["my_text"], "my durable draft");
    let frozen = saved[0]["arguments"].clone();
    let key = saved[0]["idempotency_key"].as_str().unwrap().to_owned();
    rig.restart(fast());
    rig.gate.set_kernel_v2_upstream(true);
    assert_eq!(entries(&rig)[0]["arguments"], frozen);
    rig.gate.hosted_contracts.lock().unwrap().clear();
    let repeated = submit(&rig, merge(R1, Some(&key), "my durable draft"), "none").await;
    assert_eq!(
        receipt(&repeated)["journal_entry"],
        receipt(&reply)["journal_entry"]
    );
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Empty
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let writes = rig.state().writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0]["params"]["arguments"]["arguments"], frozen);
    assert!(writes[0]
        .pointer("/params/_meta/native~1body_merge")
        .is_none());
    assert_eq!(entries(&rig)[0]["state"], "confirmed");
}

#[tokio::test]
async fn body_merge_structured_credential_refusal_preserves_prior_uncertainty_and_draft() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop]);
    submit(
        &rig,
        merge(
            R1,
            Some("auth-merge"),
            "retain this edit after credential refusal",
        ),
        "short",
    )
    .await;
    let saved = entries(&rig);
    let id = saved[0]["id"].as_str().unwrap();
    assert_eq!(saved[0]["maybe_applied"], true);
    expire_backoff(&rig, id);
    rig.state().script([Fault::Http(401, r#"{"jsonrpc":"2.0","id":7,"result":{"isError":true,"structuredContent":{"outcome":"refused","applied":false,"reason":"not_permitted"}}}"#)]);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Credentials(Some(401))
    );
    let after = entries(&rig);
    assert_eq!(after[0]["state"], "pending");
    assert_eq!(after[0]["maybe_applied"], true);
    assert_eq!(
        after[0]["arguments"]["my_text"],
        "retain this edit after credential refusal"
    );
    assert!(after[0]["recovery_item"].is_null());
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(entries(&rig)[0]["state"], "confirmed");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn body_merge_hosted_custody_is_neither_replayed_nor_settled_from_an_outbox_summary() {
    let rig = Rig::new(fast()).await;
    rig.state().script([tool_reply(
        json!({
            "outcome":"accepted_pending", "canonical":false,
            "journal_entry":"hosted-merge-handle", "idempotency_key":"hosted-merge"
        }),
        false,
    )]);
    let reply = submit(
        &rig,
        merge(R1, Some("hosted-merge"), "held by the home"),
        "none",
    )
    .await;
    assert_eq!(receipt(&reply)["outcome"], "saved_on_device");
    assert!(rig.state().writes().is_empty());
    // Custody is the invariant here; a short wait may legitimately expire.
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(entries(&rig)[0]["state"], "hosted_pending");
    assert_eq!(
        entries(&rig)[0]["hosted_journal_entry"],
        "hosted-merge-handle"
    );
    assert_eq!(
        rig.gate.status(&Default::default())["merge_body_nonterminal_count"],
        1
    );
    rig.gate.drain(&rig.upstream, None, None, None).await;
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(rig.state().writes().len(), 1);
    assert!(rig.state().status_reads.lock().unwrap().is_empty());
    assert_eq!(entries(&rig)[0]["arguments"]["my_text"], "held by the home");
}

#[tokio::test]
async fn body_merge_saved_and_held_replies_match_the_callers_protocol_era() {
    for modern in [false, true] {
        let rig = Rig::new(fast()).await;
        let message = |record, key, wait| {
            let mut call = tool_call(
                7,
                "call_executor",
                merge(record, Some(key), "protocol draft"),
            );
            let mut meta = if modern {
                crate::node::failover::probe_meta()
            } else {
                json!({})
            };
            meta["native/body_merge"] = json!({"wait":wait,"editor":"protocol-writer"});
            call["params"]["_meta"] = meta;
            call
        };
        let assert_framing = |reply: &Value| {
            assert_eq!(reply["result"]["isError"], false, "{reply}");
            if modern {
                assert_eq!(reply["result"]["resultType"], "complete", "{reply}");
                assert!(reply["result"]["_meta"]["io.modelcontextprotocol/serverInfo"].is_object());
            } else {
                assert!(reply["result"].get("resultType").is_none());
            }
        };
        let saved = forward_message(&rig, message(R1, "protocol-save", "none")).await;
        assert_framing(&saved);
        let repeated = forward_message(&rig, message(R1, "protocol-save", "none")).await;
        assert_framing(&repeated);
        assert_eq!(
            receipt(&saved)["journal_entry"],
            receipt(&repeated)["journal_entry"]
        );
        let turn = rig.gate.drain_lock.write().await;
        let held = forward_message(&rig, message(Q, "protocol-held", "short")).await;
        assert_eq!(receipt(&held)["outcome"], "accepted_pending");
        assert_framing(&held);
        drop(turn);
    }
}

#[tokio::test]
async fn body_merge_invalid_or_uncached_saves_never_claim_custody_or_contact_home() {
    for case in 0..6 {
        let rig = Rig::new(fast()).await;
        let mut envelope = merge(R1, None, "not acknowledged");
        let wait = if case == 0 { "forever" } else { "none" };
        match case {
            1 => envelope["arguments"]["base_version"] = json!("not-a-version"),
            2 => envelope["arguments"]["my_text"] = json!(false),
            3 => envelope["arguments"]["reason"] = json!("   "),
            4 => envelope["arguments"]["unexpected"] = json!(true),
            5 => rig.gate.hosted_contracts.lock().unwrap().clear(),
            _ => {}
        }
        let reply = submit(&rig, envelope, wait).await;
        assert_ne!(
            receipt(&reply)["outcome"],
            "saved_on_device",
            "case {case}: {reply}"
        );
        assert!(entries(&rig).is_empty(), "case {case}: nothing was saved");
        assert!(rig.state().writes().is_empty());
        assert_eq!(rig.state().describes.load(Ordering::SeqCst), 0);
        assert_eq!(rig.state().access_lookups.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn body_merge_failed_fsync_does_not_acknowledge_or_send() {
    let rig = Rig::new(fast()).await;
    rig.gate.journal.fail_after.store(0, Ordering::SeqCst);
    let reply = submit(&rig, merge(R1, None, "not saved"), "none").await;
    assert_ne!(receipt(&reply)["outcome"], "saved_on_device", "{reply}");
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
}

#[tokio::test]
async fn body_merge_wait_none_does_not_wait_for_an_unrelated_network_drain() {
    let rig = Rig::new(fast()).await;
    let network_turn = rig.gate.drain_lock.write().await;
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        submit(
            &rig,
            merge(Q, None, "save while the network drain is occupied"),
            "none",
        ),
    )
    .await
    .expect("local custody must not wait for a network drain");
    assert_eq!(receipt(&reply)["outcome"], "saved_on_device");
    assert_eq!(entries(&rig).len(), 1);
    assert!(rig.state().writes().is_empty());
    drop(network_turn);
}

#[tokio::test]
async fn body_merge_parked_record_chain_does_not_block_an_unrelated_record_across_restart() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    let r1 = submit(&rig, merge(R1, Some("r1"), "first draft"), "none").await;
    rig.state().script([tool_reply(
        json!({
            "outcome":"refused", "applied":false, "retryable":true,
            "error_code":"BODY_MERGE_NOT_ENABLED", "reason":"feature_not_enabled"
        }),
        true,
    )]);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Empty
    );
    submit(&rig, merge(R1, Some("r2"), "later draft"), "none").await;
    submit(&rig, merge(Q, Some("q"), "unrelated draft"), "none").await;
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Empty
    );
    assert_eq!(
        rig.state().keys_sent(),
        vec![Some("r1".into()), Some("q".into())]
    );
    let id = receipt(&r1)["journal_entry"].as_str().unwrap();
    let parked = rig.gate.journal.get(id).unwrap();
    assert_eq!(parked.state, EntryState::Pending);
    assert!(parked.not_before_ms > 0);
    rig.restart(fast());
    rig.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Empty
    );
    assert_eq!(
        rig.state().writes().len(),
        2,
        "restart must preserve cadence and R2 blocking"
    );
    expire_backoff(&rig, id);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::Empty
    );
    assert_eq!(
        rig.state().keys_sent(),
        vec![
            Some("r1".into()),
            Some("q".into()),
            Some("r1".into()),
            Some("r2".into())
        ]
    );
}

#[tokio::test]
async fn body_merge_committed_incomplete_receipt_keeps_the_original_request_on_both_wait_paths() {
    for wait in ["none", "short"] {
        let rig = Rig::new(fast()).await;
        rig.state().script([tool_reply(
            json!({
                "error_code":"REPLAY_BOUND_EXCEEDED", "applied":true, "retryable":true
            }),
            true,
        )]);
        let reply = submit(
            &rig,
            merge(R1, Some("bounded-key"), "keep my full draft"),
            wait,
        )
        .await;
        if wait == "none" {
            rig.gate.drain(&rig.upstream, None, None, None).await;
        }
        let saved = entries(&rig);
        assert_eq!(saved.len(), 1, "{reply}");
        assert_eq!(saved[0]["state"], "committed_unrecovered");
        assert_eq!(saved[0]["arguments"]["my_text"], "keep my full draft");
        assert_eq!(saved[0]["idempotency_key"], "bounded-key");
        assert!(saved[0]["not_before_ms"].as_u64().unwrap() > 0);
        let id = saved[0]["id"].as_str().unwrap();
        expire_backoff(&rig, id);
        rig.gate.drain(&rig.upstream, None, None, None).await;
        assert_eq!(entries(&rig)[0]["state"], "confirmed");
        assert!(rig
            .state()
            .keys_sent()
            .iter()
            .all(|k| k.as_deref() == Some("bounded-key")));
    }
}

#[tokio::test]
async fn body_merge_different_intent_is_terminal_recovery_that_survives_pruning() {
    let mut rig = Rig::new(fast()).await;
    rig.state().script([tool_reply(
        json!({
            "error_code":"IDEMPOTENCY_DIFFERENT_INTENT", "applied":false,
            "outcome":"refused", "reason":"different intent"
        }),
        true,
    )]);
    submit(
        &rig,
        merge(R1, Some("conflicting-key"), "recover this private draft"),
        "short",
    )
    .await;
    let saved = entries(&rig);
    assert_eq!(saved.len(), 1);
    assert_ne!(saved[0]["answer"], "already_applied");
    assert_eq!(saved[0]["state"], "confirmed");
    let recovery = rig.config.socket_directory.join("unmerged").join(format!(
        "{}.json",
        saved[0]["recovery_item"].as_str().unwrap()
    ));
    let recovery_bytes = fs::read(&recovery).unwrap();
    let item: Value = serde_json::from_slice(&recovery_bytes).unwrap();
    assert_eq!(item["kind"], "key_conflict");
    assert!(item.to_string().contains("recover this private draft"));
    for item in fs::read_dir(rig.config.socket_directory.join("journal")).unwrap() {
        let path = item.unwrap().path();
        let mut entry: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        entry["updated_at"] = json!("1970-01-01T00:00:00Z");
        fs::write(path, serde_json::to_vec(&entry).unwrap()).unwrap();
    }
    rig.restart(fast());
    rig.gate.journal.prune();
    assert_eq!(
        fs::read(&recovery).unwrap(),
        recovery_bytes,
        "recovery must not expire with journal receipts"
    );
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(
        rig.state().writes().len(),
        1,
        "key conflict is never retried"
    );
    assert!(!rig
        .gate
        .status(&Default::default())
        .to_string()
        .contains("recover this private draft"));
}

#[tokio::test]
async fn body_merge_full_size_clash_receipt_survives_the_normal_reply_cap_and_restart() {
    let mut config = fast();
    // This fixture proves large-receipt custody, not the fast network cap.
    config.attempt_timeout = Duration::from_secs(5);
    let mut rig = Rig::new(config).await;
    let canonical = "canonical passage ".repeat(20_000);
    let mine = "my unmerged passage ".repeat(15_000);
    let outcome = json!({
        "outcome":"merged_with_clashes", "applied":true, "record_id":R1,
        "idempotency_key":"large-clash", "result":{"version":"rec:4","body":canonical},
        "unmerged":[{"id":"u1","base":"base text","mine":mine,"theirs":"canonical passage","base_start":0,"base_end":9,"at_start":0,"at_end":17}],
        "applied_hunks":0
    });
    assert!(outcome.to_string().len() > 256 * 1024);
    rig.state().script([tool_reply(outcome, false)]);
    let reply = submit(&rig, merge(R1, Some("large-clash"), &mine), "none").await;
    assert_eq!(receipt(&reply)["outcome"], "saved_on_device");
    assert!(rig.state().writes().is_empty());
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(rig.state().writes().len(), 1);
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "confirmed");
    let recovery = rig.config.socket_directory.join("unmerged").join(format!(
        "{}.json",
        saved[0]["recovery_item"].as_str().unwrap()
    ));
    let bytes = fs::read(&recovery).unwrap();
    let item: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(item["passage"]["mine"], mine);
    let lineage = rig
        .gate
        .lineages
        .load(R1, "acceptance-editor")
        .unwrap()
        .unwrap();
    assert_eq!(lineage.c_prev.text, canonical);
    assert_eq!(lineage.d_prev, mine);
    rig.restart(fast());
    rig.gate.journal.prune();
    assert_eq!(fs::read(recovery).unwrap(), bytes);
}

#[tokio::test]
async fn body_merge_lost_reply_returns_a_handle_then_replays_the_original_key_once() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop]);
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        submit(
            &rig,
            merge(R1, Some("lost-merge"), "durable through a lost reply"),
            "short",
        ),
    )
    .await
    .expect("short wait must stay bounded");
    assert_eq!(receipt(&reply)["outcome"], "accepted_pending");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "pending");
    assert_eq!(saved[0]["maybe_applied"], true);
    expire_backoff(&rig, saved[0]["id"].as_str().unwrap());
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(entries(&rig)[0]["state"], "confirmed");
    assert_eq!(
        rig.state().created.load(Ordering::SeqCst),
        1,
        "key replay must not merge twice"
    );
    assert_eq!(
        rig.state().keys_sent(),
        vec![Some("lost-merge".into()), Some("lost-merge".into())]
    );
}

#[tokio::test]
async fn body_merge_incomplete_result_blocks_its_record_but_not_an_unrelated_merge() {
    let rig = Rig::new(fast()).await;
    submit(&rig, merge(R1, Some("missing-result"), "first"), "none").await;
    rig.state().script([tool_reply(
        json!({
            "outcome":"merged", "applied":true, "idempotency_key":"missing-result",
            "record_id":R1, "result":{"body":"no version is not a usable committed base"}
        }),
        false,
    )]);
    rig.gate.drain(&rig.upstream, None, None, None).await;
    // A prepared, unrecovered predecessor must block a later save. Before
    // preparation these two same-base drafts would legitimately coalesce.
    submit(&rig, merge(R1, Some("blocked-result"), "second"), "none").await;
    submit(&rig, merge(Q, Some("other-result"), "other"), "none").await;
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(
        rig.state().keys_sent(),
        vec![Some("missing-result".into()), Some("other-result".into())]
    );
    let first = entries(&rig)
        .into_iter()
        .find(|e| e["idempotency_key"] == "missing-result")
        .unwrap();
    assert_eq!(first["state"], "result_unrecovered");
    assert!(first["arguments"].is_object());
    assert_eq!(
        rig.gate.status(&Default::default())["merge_body_nonterminal_count"],
        2
    );
}

#[tokio::test]
async fn body_merge_disk_floor_and_short_references_are_not_acknowledged() {
    let mut config = fast();
    config.disk_floor_bytes = 1024;
    let rig = Rig::new(config).await;
    *rig.gate.free_override.lock().unwrap() = Some(0);
    let reply = submit(&rig, merge(R1, None, "cannot be saved"), "none").await;
    assert_ne!(receipt(&reply)["outcome"], "saved_on_device");
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
    *rig.gate.free_override.lock().unwrap() = None;
    let reply = submit(
        &rig,
        merge("7011000", None, "alias must be resolved first"),
        "none",
    )
    .await;
    assert_ne!(receipt(&reply)["outcome"], "saved_on_device");
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
}
