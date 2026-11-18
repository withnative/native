//! Slice-4 gate crash boundaries, frozen custody and owner controls.
use super::*;
use crate::node::lineage::{Advance, CommittedBody, LineageState};
use crate::node::unmerged::{RecoveryItem, RecoveryState};
use std::collections::HashSet;

const RECORD: &str = "70110000-0000-4000-8000-0000000000f4";
const EDITOR: &str = "fault-editor";

fn edit(version: u64, base: &str, draft: &str, key: &str) -> Value {
    json!({"executor":"records_write","operation":"merge_body","run_key":"fault-proof",
        "arguments":{"record_id":RECORD,"base_version":format!("rec:{version}"),"base_text":base,
            "my_text":draft,"reason":"fault proof","idempotency_key":key}})
}
async fn save(rig: &Rig, version: u64, base: &str, draft: &str, key: &str) -> Value {
    let mut message = tool_call(7, "call_executor", edit(version, base, draft, key));
    message["params"]["_meta"] = json!({"native/body_merge":{"wait":"none","editor":EDITOR}});
    body_merge_acceptance::forward_message(rig, message).await
}
fn stop(rig: &Rig, phase: &'static str) {
    *rig.gate.merge_stop_after.lock().unwrap() = Some(phase);
}
fn restart(rig: &mut Rig) {
    rig.restart(fast());
    rig.gate.set_kernel_v2_upstream(true);
}
fn recovery(rig: &Rig) -> Vec<RecoveryItem> {
    rig.gate
        .unmerged
        .list(Some(RECORD), Some(RecoveryState::Open), true)
        .unwrap()
}
fn seed_local_clash_predecessor(rig: &Rig) {
    let p = rig
        .gate
        .lineages
        .prepare(
            RECORD,
            EDITOR,
            "predecessor",
            CommittedBody {
                version: 1,
                text: "abc".into(),
            },
            "abc",
            &HashSet::new(),
        )
        .unwrap();
    assert_eq!(
        rig.gate
            .lineages
            .complete(
                RECORD,
                EDITOR,
                "predecessor",
                &p,
                Some(CommittedBody {
                    version: 2,
                    text: "ayc".into()
                }),
                Vec::new()
            )
            .unwrap(),
        Advance::Applied
    );
}
fn clash_reply(key: &str, version: u64) -> Fault {
    Fault::ToolReply(json!({"content":[],"structuredContent":{
        "outcome":"merged_with_clashes","applied":true,"record_id":RECORD,"idempotency_key":key,
        "base":{"version":"rec:1","verified":true},
        "result":{"version":format!("rec:{version}"),"body":"ayc"},
        "unmerged":[{"id":"home-passage","base":"b","mine":"x","theirs":"y",
            "base_start":1,"base_end":2,"at_start":1,"at_end":2}]},"isError":false}))
}
async fn control(rig: &Rig, name: &str, arguments: Value) -> Value {
    let request = tool_call(7, name, arguments);
    serde_json::from_str(&rig.gate.body_merge_control(&request).await.unwrap()).unwrap()
}

#[tokio::test]
async fn body_merge_crash_every_clean_send_boundary_replays_frozen_intent_once() {
    for phase in [
        "lineage_ready",
        "prepared",
        "local_recovery",
        "attempt_recorded",
        "result_received",
        "result_recorded",
        "recovery",
        "lineage_completed",
        "settled",
    ] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        let accepted = save(&rig, 1, "abc", "Abc", "crash-key").await;
        assert_eq!(receipt(&accepted)["outcome"], "saved_on_device");
        assert!(rig.state().writes().is_empty());
        let entry_id = receipt(&accepted)["journal_entry"]
            .as_str()
            .unwrap()
            .to_owned();
        stop(&rig, phase);
        assert_eq!(drain(&rig).await, Halt::Local, "injection phase {phase}");
        let stopped = by_key(&rig, "crash-key");
        let frozen = stopped["merge_preparation"].clone();
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty, "recovery phase {phase}");
        assert_eq!(
            rig.state().created.load(Ordering::SeqCst),
            1,
            "one home effect at {phase}"
        );
        let done = by_key(&rig, "crash-key");
        assert_eq!(done["state"], "confirmed");
        if !frozen.is_null() {
            assert_eq!(
                done["merge_preparation"], frozen,
                "frozen evaluation {phase}"
            );
        }
        for request in rig.state().writes() {
            let args = &request["params"]["arguments"]["arguments"];
            assert_eq!(args["idempotency_key"], "crash-key");
            assert_eq!(args["base_text"], "abc");
            assert_eq!(args["my_text"], "Abc");
        }
        let lineage = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
        assert_eq!(lineage.d_prev, "Abc");
        assert_eq!(lineage.c_prev.text, "Abc");
        assert_eq!(lineage.generation, 1);
        assert_eq!(
            lineage.last_completed_entry.as_deref(),
            Some(entry_id.as_str())
        );
        let before = rig.state().writes().len();
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), before);
        assert!(recovery(&rig).is_empty());
    }
}

#[tokio::test]
async fn body_merge_crash_no_send_local_clash_never_loses_recovery_or_reopens_dismissal() {
    for phase in [
        "lineage_ready",
        "prepared",
        "local_recovery",
        "result_recorded",
        "recovery",
        "lineage_completed",
        "settled",
    ] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        seed_local_clash_predecessor(&rig);
        save(&rig, 1, "abc", "axc", "local-key").await;
        stop(&rig, phase);
        assert_eq!(drain(&rig).await, Halt::Local, "local injection {phase}");
        if matches!(
            phase,
            "local_recovery" | "recovery" | "lineage_completed" | "settled"
        ) {
            let items = recovery(&rig);
            assert_eq!(items.len(), 1, "recovery durable at {phase}");
            assert_eq!(
                items[0].passage.as_ref().unwrap().mine.as_deref(),
                Some("x")
            );
        }
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert!(rig.state().writes().is_empty());
        let items = recovery(&rig);
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.passage.as_ref().unwrap().base.as_deref(), Some("b"));
        assert_eq!(item.passage.as_ref().unwrap().mine.as_deref(), Some("x"));
        assert_eq!(item.passage.as_ref().unwrap().theirs.as_deref(), Some("y"));
        let l = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
        assert_eq!(l.d_prev, "axc");
        assert_eq!(l.c_prev.text, "ayc");
        assert_eq!(
            l.last_completed_entry.as_deref(),
            by_key(&rig, "local-key")["id"].as_str()
        );
        // Replay completion from the journal after explicit dismissal. Neither
        // retrying the recovery upsert nor completion may reopen the item.
        rig.gate.unmerged.dismiss(&item.id).unwrap();
        let saved = rig
            .gate
            .journal
            .get(by_key(&rig, "local-key")["id"].as_str().unwrap())
            .unwrap();
        rig.gate.finish_recorded_merge(&saved).unwrap();
        assert!(recovery(&rig).is_empty());
        assert_eq!(
            rig.gate
                .unmerged
                .get(&item.id, true)
                .unwrap()
                .unwrap()
                .state,
            RecoveryState::Dismissed
        );
    }
}

#[tokio::test]
async fn body_merge_coalesces_only_unprepared_same_base_and_old_key_cannot_restore_old_draft() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    let first = save(&rig, 1, "abc", "Abc", "old-key").await;
    let latest = save(&rig, 1, "abc", "ABc", "latest-key").await;
    assert_eq!(
        receipt(&first)["journal_entry"],
        receipt(&latest)["journal_entry"]
    );
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(entries(&rig)[0]["merge_intent"]["draft_text"], "ABc");
    let repeat = save(&rig, 1, "abc", "Abc", "old-key").await;
    assert_eq!(receipt(&repeat)["outcome"], "superseded_on_device");
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(entries(&rig)[0]["merge_intent"]["draft_text"], "ABc");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(
        rig.state().writes()[0]["params"]["arguments"]["arguments"]["my_text"],
        "ABc"
    );
    // Expire the settled payload on disk, then reopen through the actual
    // startup/prune path. The digest-only key history must still recognize it.
    let mut aged = entries(&rig).into_iter().next().unwrap();
    aged["updated_at"] = json!("2000-01-01T00:00:00Z");
    let path = rig
        .config
        .socket_directory
        .join("journal")
        .join(format!("{}.json", aged["id"].as_str().unwrap()));
    fs::write(path, serde_json::to_vec(&aged).unwrap()).unwrap();
    restart(&mut rig);
    rig.gate.journal.prune();
    save(&rig, 1, "abc", "ABC", "newer-key").await;
    let before = rig.state().writes().len();
    let ancient = save(&rig, 1, "abc", "Abc", "old-key").await;
    assert_eq!(receipt(&ancient)["outcome"], "superseded_on_device");
    let settled = save(&rig, 1, "abc", "ABc", "latest-key").await;
    assert_eq!(receipt(&settled)["outcome"], "settled_on_device");
    assert_eq!(rig.state().writes().len(), before);
    assert_eq!(
        by_key(&rig, "newer-key")["merge_intent"]["draft_text"],
        "ABC"
    );
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), before + 1);
}

#[tokio::test]
async fn body_merge_prepared_unattempted_and_changed_base_saves_queue_separately() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    save(&rig, 1, "abc", "Abc", "prepared-first").await;
    stop(&rig, "prepared");
    assert_eq!(drain(&rig).await, Halt::Local);
    let frozen = by_key(&rig, "prepared-first");
    assert_eq!(frozen["attempts"], 0);
    assert_eq!(frozen["prepared"], true);
    save(&rig, 1, "abc", "ABc", "prepared-second").await;
    save(&rig, 9, "xyz", "Xyz", "fresh-third").await;
    assert_eq!(entries(&rig).len(), 3);
    assert_eq!(
        by_key(&rig, "prepared-first")["merge_preparation"],
        frozen["merge_preparation"]
    );
    restart(&mut rig);
    assert_eq!(drain(&rig).await, Halt::Empty);
    let sent = rig.state().writes();
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[0]["params"]["arguments"]["arguments"]["my_text"],
        "Abc"
    );
    assert_eq!(
        sent[1]["params"]["arguments"]["arguments"]["my_text"],
        "ABc"
    );
    assert_eq!(
        sent[2]["params"]["arguments"]["arguments"]["base_version"],
        "rec:9"
    );
    let l = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
    assert_eq!(l.generation, 2);
    assert_eq!(l.d_prev, "Xyz");
}

#[tokio::test]
async fn body_merge_retire_drains_existing_custody_and_requires_new_declared_base() {
    let rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    save(&rig, 1, "abc", "Abc", "retire-first").await;
    assert_eq!(drain(&rig).await, Halt::Empty);
    save(&rig, 1, "abc", "ABc", "retire-queued").await;
    let retired = control(&rig, "node_lineage_retire", json!({"editor":EDITOR})).await;
    assert_eq!(receipt(&retired)["retired"], 1);
    assert_eq!(
        rig.gate
            .lineages
            .load(RECORD, EDITOR)
            .unwrap()
            .unwrap()
            .state,
        LineageState::Retiring
    );
    let late = save(&rig, 1, "abc", "ABC", "retire-late").await;
    assert_eq!(receipt(&late)["reason"], "needs_fresh_base");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.gate
            .lineages
            .load(RECORD, EDITOR)
            .unwrap()
            .unwrap()
            .state,
        LineageState::Retired
    );
    let before = rig.state().writes().len();
    save(&rig, 9, "ABC", "ABCD", "retire-fresh").await;
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), before + 1);
    assert_eq!(
        rig.gate
            .lineages
            .load(RECORD, EDITOR)
            .unwrap()
            .unwrap()
            .d_prev,
        "ABCD"
    );
}

#[tokio::test]
async fn body_merge_reset_clash_does_not_overwrite_owned_recovery_and_freezes_new_id() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    rig.state().script([clash_reply("original-clash", 2)]);
    save(&rig, 1, "abc", "axc", "original-clash").await;
    assert_eq!(drain(&rig).await, Halt::Empty);
    let original = recovery(&rig);
    assert_eq!(original.len(), 1);
    let original_id = original[0].id.clone();
    save(&rig, 1, "abc", "ax!c", "owned-extension").await;
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        recovery(&rig)[0].passage.as_ref().unwrap().mine.as_deref(),
        Some("x!")
    );
    rig.state().script([clash_reply("fresh-clash", 4)]);
    save(&rig, 3, "abc", "axc", "fresh-clash").await;
    stop(&rig, "result_recorded");
    assert_eq!(drain(&rig).await, Halt::Local);
    let recorded = by_key(&rig, "fresh-clash");
    let new_id = recorded["merge_result"]["recovery_ids"][0]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_id, original_id);
    restart(&mut rig);
    assert_eq!(drain(&rig).await, Halt::Empty);
    let all = recovery(&rig);
    assert_eq!(all.len(), 2);
    assert_eq!(
        all.iter()
            .find(|i| i.id == original_id)
            .unwrap()
            .passage
            .as_ref()
            .unwrap()
            .mine
            .as_deref(),
        Some("x!")
    );
    assert_eq!(
        all.iter()
            .find(|i| i.id == new_id)
            .unwrap()
            .passage
            .as_ref()
            .unwrap()
            .mine
            .as_deref(),
        Some("x")
    );
    assert_eq!(
        by_key(&rig, "fresh-clash")["merge_result"]["recovery_ids"][0],
        new_id
    );
}

#[tokio::test]
async fn body_merge_local_read_metadata_dismiss_and_confirmed_forget_never_contact_hosted() {
    let rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    seed_local_clash_predecessor(&rig);
    save(&rig, 1, "abc", "axc", "controls-local").await;
    assert_eq!(drain(&rig).await, Halt::Empty);
    let read = control(&rig, "node_unmerged", json!({})).await;
    let items = receipt(&read)["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].get("base_text").is_none());
    assert!(items[0].get("my_text").is_none());
    assert!(items[0]
        .get("passage")
        .is_none_or(|p| p.get("mine").is_none()));
    let id = items[0]["id"].as_str().unwrap();
    let text = control(&rig, "node_unmerged", json!({"id":id,"include_text":true})).await;
    assert_eq!(receipt(&text)["items"][0]["passage"]["mine"], "x");
    let dismissed = control(&rig, "node_unmerged_dismiss", json!({"id":id})).await;
    assert_eq!(receipt(&dismissed)["state"], "dismissed");
    let warning = control(&rig, "node_body_merge_forget", json!({"reason":"sign_out"})).await;
    assert_eq!(receipt(&warning)["requires_confirmation"], true);
    assert!(!rig.gate.lineages.list().unwrap().is_empty());
    let erased = control(
        &rig,
        "node_body_merge_forget",
        json!({"reason":"sign_out","confirm":true}),
    )
    .await;
    assert_eq!(receipt(&erased)["forgotten"], true);
    assert!(rig.gate.lineages.list().unwrap().is_empty());
    assert!(rig.gate.unmerged.list(None, None, true).unwrap().is_empty());
    assert!(rig.state().writes().is_empty());
    assert_eq!(rig.state().describes.load(Ordering::SeqCst), 0);
    assert_eq!(rig.state().access_lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_merge_owner_controls_support_both_protocol_eras_refuse_apps_and_batches_locally() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    client.send(tool_call(1, "node_unmerged", json!({}))).await;
    let legacy = client.recv().await.unwrap();
    assert_eq!(receipt(&legacy)["local"], true);
    let mut modern = tool_call(2, "node_unmerged", json!({}));
    modern["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"lineage-proof","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    client.send(modern).await;
    let reply = client.recv().await.unwrap();
    assert_eq!(receipt(&reply)["local"], true);
    assert_eq!(reply["id"], 2);
    let mut app = tool_call(3, "node_unmerged", json!({"include_text":true}));
    app["params"]["_meta"] = json!({"native/app":"docs@1; install=evt"});
    client.send(app).await;
    let refused = client.recv().await.unwrap();
    assert_eq!(refused["error"]["data"]["reason"], "owner_only");
    client
        .send(json!([
            tool_call(4, "node_unmerged", json!({})),
            tool_call(5, "bootstrap", json!({}))
        ]))
        .await;
    let refused = client.recv().await.unwrap();
    assert_eq!(refused["error"]["data"]["reason"], "batch_refused");
    assert!(rig.state().writes().is_empty());
    assert_eq!(rig.state().describes.load(Ordering::SeqCst), 0);
    assert_eq!(rig.state().access_lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_merge_account_switch_blocks_old_private_state_until_confirmed_forget() {
    let mut config = fast();
    config.account_binding = Some(json!({"account_id":"acct_original","db_id":"one"}));
    let mut rig = Rig::new(config).await;
    rig.gate.set_kernel_v2_upstream(true);
    save(&rig, 1, "abc", "Abc", "account-original").await;
    let mut switched = fast();
    switched.account_binding = Some(json!({"account_id":"acct_new","db_id":"two"}));
    rig.restart(switched);
    rig.gate.set_kernel_v2_upstream(true);
    let refused = control(&rig, "node_unmerged", json!({"include_text":true})).await;
    assert_eq!(refused["result"]["isError"], true);
    assert!(receipt(&refused)["error"]
        .as_str()
        .unwrap()
        .contains("another account"));
    assert_eq!(entries(&rig).len(), 1);
    let warning = control(
        &rig,
        "node_body_merge_forget",
        json!({"reason":"account_switch"}),
    )
    .await;
    assert_eq!(receipt(&warning)["requires_confirmation"], true);
    assert_eq!(entries(&rig).len(), 1);
    let forgotten = control(
        &rig,
        "node_body_merge_forget",
        json!({"reason":"account_switch","confirm":true}),
    )
    .await;
    assert_eq!(receipt(&forgotten)["forgotten"], true);
    assert!(entries(&rig).is_empty());
    let accepted = save(&rig, 7, "fresh", "fresh!", "account-new").await;
    assert_eq!(receipt(&accepted)["outcome"], "saved_on_device");
    assert!(rig.state().writes().is_empty());
}

#[tokio::test]
async fn body_merge_home_clash_restart_keeps_frozen_passage_without_another_home_request() {
    for phase in [
        "result_recorded",
        "recovery",
        "lineage_completed",
        "settled",
    ] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        rig.state().script([clash_reply("home-clash-crash", 2)]);
        let accepted = save(&rig, 1, "abc", "axc", "home-clash-crash").await;
        let entry_id = receipt(&accepted)["journal_entry"]
            .as_str()
            .unwrap()
            .to_owned();
        stop(&rig, phase);
        assert_eq!(drain(&rig).await, Halt::Local, "clash stop {phase}");
        let stopped = by_key(&rig, "home-clash-crash");
        let recorded = stopped["merge_result"].clone();
        assert_eq!(recorded["kind"], "merged_with_clashes");
        assert_eq!(recorded["body"]["applied"], true);
        let ids = recorded["recovery_ids"].as_array().unwrap();
        assert_eq!(ids.len(), 1);
        let passage_id = ids[0].as_str().unwrap().to_owned();
        assert_eq!(
            rig.state().writes().len(),
            1,
            "one applied home receipt {phase}"
        );
        if phase != "result_recorded" {
            assert_eq!(recovery(&rig).len(), 1);
            assert_eq!(recovery(&rig)[0].id, passage_id);
        }
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty, "clash resume {phase}");
        assert_eq!(
            rig.state().writes().len(),
            1,
            "recorded result prevents another home call {phase}"
        );
        let done = by_key(&rig, "home-clash-crash");
        assert_eq!(done["state"], "confirmed");
        assert_eq!(done["answer"], "merged_with_clashes");
        assert_eq!(done["merge_result"], recorded);
        let items = recovery(&rig);
        assert_eq!(items.len(), 1, "exactly one recovered passage {phase}");
        assert_eq!(items[0].id, passage_id);
        assert_eq!(items[0].journal_entry, entry_id);
        let passage = items[0].passage.as_ref().unwrap();
        assert_eq!(passage.base.as_deref(), Some("b"));
        assert_eq!(passage.mine.as_deref(), Some("x"));
        assert_eq!(passage.theirs.as_deref(), Some("y"));
        assert_eq!((passage.base_start, passage.base_end), (1, 2));
        let lineage = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
        assert_eq!(lineage.d_prev, "axc");
        assert_eq!(lineage.c_prev.text, "ayc");
        assert_eq!(
            lineage.last_completed_entry.as_deref(),
            Some(entry_id.as_str())
        );
        assert_eq!(lineage.quarantine.len(), 1);
        assert_eq!(lineage.quarantine[0].item, passage_id);
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), 1);
        assert_eq!(recovery(&rig).len(), 1);
        assert_eq!(recovery(&rig)[0].id, passage_id);
    }
}

#[tokio::test]
async fn body_merge_terminal_refusal_restart_preserves_full_draft_without_advancing_lineage() {
    for phase in [
        "result_recorded",
        "recovery",
        "lineage_completed",
        "settled",
    ] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        let base = if phase == "recovery" {
            "αbc\n".repeat(70_000)
        } else {
            "αbc".into()
        };
        let draft = format!("{base}!");
        rig.state()
            .script([Fault::ToolReply(json!({"content":[],"structuredContent":{
            "outcome":"refused","applied":false,"reason":"not_permitted","retryable":false,
            "record_id":RECORD,"idempotency_key":"refusal-crash"},"isError":false}))]);
        let accepted = save(&rig, 1, &base, &draft, "refusal-crash").await;
        let entry_id = receipt(&accepted)["journal_entry"]
            .as_str()
            .unwrap()
            .to_owned();
        stop(&rig, phase);
        assert_eq!(drain(&rig).await, Halt::Local, "refusal stop {phase}");
        let recorded = by_key(&rig, "refusal-crash")["merge_result"].clone();
        assert_eq!(recorded["kind"], "refused");
        assert_eq!(recorded["body"]["applied"], false);
        let recovery_id = crate::node::unmerged::refusal_id(
            RECORD,
            EDITOR,
            &entry_id,
            crate::node::unmerged::RecoveryKind::Refusal,
        );
        assert_eq!(rig.state().writes().len(), 1);
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
        if phase != "result_recorded" {
            let items = recovery(&rig);
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, recovery_id);
            assert_eq!(items[0].base_text.as_deref(), Some(base.as_str()));
            assert_eq!(items[0].my_text.as_deref(), Some(draft.as_str()));
        }
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty, "refusal resume {phase}");
        let done = by_key(&rig, "refusal-crash");
        assert_eq!(done["state"], "confirmed");
        assert_eq!(done["answer"], "refused");
        assert_eq!(done["merge_result"], recorded);
        assert_eq!(
            rig.state().writes().len(),
            1,
            "recorded refusal is settled locally {phase}"
        );
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
        let items = recovery(&rig);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, recovery_id);
        assert_eq!(items[0].journal_entry, entry_id);
        assert_eq!(items[0].reason.as_deref(), Some("not_permitted"));
        assert_eq!(items[0].base_text.as_deref(), Some(base.as_str()));
        assert_eq!(items[0].my_text.as_deref(), Some(draft.as_str()));
        let lineage = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
        assert_eq!(lineage.d_prev, base);
        assert_eq!(lineage.c_prev.text, base);
        assert_eq!(lineage.c_prev.version, 1);
        assert!(lineage.last_completed_entry.is_none());
        assert!(lineage.quarantine.is_empty());
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), 1);
        assert_eq!(recovery(&rig).len(), 1);
        assert_eq!(recovery(&rig)[0].id, recovery_id);
    }
}

#[tokio::test]
async fn body_merge_restart_finishes_retirement_after_settlement_crash() {
    let mut rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    // Retirement closes an established editor lineage while its newer save
    // is still queued, before that save has been prepared or sent.
    rig.gate
        .lineages
        .prepare(
            RECORD,
            EDITOR,
            "baseline",
            CommittedBody {
                version: 1,
                text: "abc".into(),
            },
            "abc",
            &HashSet::new(),
        )
        .unwrap();
    save(&rig, 1, "abc", "Abc", "retirement-crash").await;
    let retired = control(
        &rig,
        "node_lineage_retire",
        json!({"editor":EDITOR,"record_id":RECORD}),
    )
    .await;
    assert_ne!(retired["result"]["isError"], true);
    stop(&rig, "settled");
    assert_eq!(drain(&rig).await, Halt::Local);
    assert_eq!(by_key(&rig, "retirement-crash")["state"], "confirmed");
    let before = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
    assert_eq!(before.state, LineageState::Retiring);
    assert_eq!(before.d_prev, "Abc");
    assert_eq!(rig.state().writes().len(), 1);
    restart(&mut rig);
    let after = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
    assert_eq!(after.state, LineageState::Retired);
    assert!(after.d_prev.is_empty());
    assert!(after.c_prev.text.is_empty());
    assert!(after.reset_base_text.is_empty());
    assert!(after.quarantine.is_empty());
    assert!(after.last_completed_entry.is_none());
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn body_merge_retire_first_queued_save_prevents_same_base_coalescing() {
    let rig = Rig::new(fast()).await;
    rig.gate.set_kernel_v2_upstream(true);
    let first = save(&rig, 1, "abc", "Abc", "first-ever-before-retire").await;
    assert_eq!(receipt(&first)["outcome"], "saved_on_device");
    assert!(rig.gate.lineages.load(RECORD, EDITOR).unwrap().is_none());
    let retired = control(
        &rig,
        "node_lineage_retire",
        json!({"editor":EDITOR,"record_id":RECORD}),
    )
    .await;
    assert_eq!(receipt(&retired)["retired"], 1);
    let lineage = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
    assert_eq!(lineage.state, LineageState::Retiring);
    assert_eq!(lineage.reset_base_version, 1);
    let refused = save(&rig, 1, "abc", "ABc", "first-ever-after-retire").await;
    assert_eq!(receipt(&refused)["reason"], "needs_fresh_base");
    assert_eq!(
        by_key(&rig, "first-ever-before-retire")["merge_intent"]["draft_text"],
        "Abc"
    );
    let items = recovery(&rig);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].reason.as_deref(), Some("needs_fresh_base"));
    assert_eq!(items[0].base_text.as_deref(), Some("abc"));
    assert_eq!(items[0].my_text.as_deref(), Some("ABc"));
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(
        rig.state().writes()[0]["params"]["arguments"]["arguments"]["my_text"],
        "Abc"
    );
    assert_eq!(
        rig.gate
            .lineages
            .load(RECORD, EDITOR)
            .unwrap()
            .unwrap()
            .state,
        LineageState::Retired
    );
    let fresh = save(&rig, 9, "Abc", "ABc", "fresh-after-first-retire").await;
    assert_eq!(receipt(&fresh)["outcome"], "saved_on_device");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), 2);
    let lineage = rig.gate.lineages.load(RECORD, EDITOR).unwrap().unwrap();
    assert_eq!(lineage.state, LineageState::Active);
    assert_eq!(lineage.reset_base_version, 9);
    assert_eq!(lineage.d_prev, "ABc");
}

fn age_merge_on_disk(rig: &Rig, key: &str) -> PathBuf {
    let mut entry = by_key(rig, key);
    entry["updated_at"] = json!("2000-01-01T00:00:00Z");
    let path = rig
        .config
        .socket_directory
        .join("journal")
        .join(format!("{}.json", entry["id"].as_str().unwrap()));
    fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
    path
}

fn single_lineage_bytes(rig: &Rig) -> Vec<u8> {
    let mut paths = fs::read_dir(rig.config.socket_directory.join("lineage"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths.len(), 1);
    fs::read(&paths[0]).unwrap()
}

#[tokio::test]
async fn body_merge_primary_key_retention_never_reapplies_old_noop_refusal_or_success() {
    for scenario in ["no_send", "refused", "merged"] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        let original_draft = match scenario {
            "no_send" => "abc",
            "refused" => "axc",
            _ => "Abc",
        };
        if scenario == "refused" {
            rig.state()
                .script([Fault::ToolReply(json!({"content":[],"structuredContent":{
                "outcome":"refused","applied":false,"reason":"not_permitted","retryable":false,
                "record_id":RECORD,"idempotency_key":"primary-old"},"isError":false}))]);
        }
        save(&rig, 1, "abc", original_draft, "primary-old").await;
        assert_eq!(drain(&rig).await, Halt::Empty);
        let original = rig.gate.journal.merge_with_key("primary-old").unwrap();
        assert!(original.merge_aliases.is_empty());
        assert_eq!(original.merge_result.as_ref().unwrap().kind, scenario);
        assert_eq!(original.state, EntryState::Confirmed);
        // A later edit changes canonical text. Retrying the old no-send draft
        // as a new delta would undo that change rather than remain a no-op.
        let later_draft = if scenario == "merged" { "ABc" } else { "Abc" };
        save(&rig, 1, "abc", later_draft, "primary-later").await;
        assert_eq!(drain(&rig).await, Halt::Empty);
        if scenario != "no_send" {
            // Also cross a declared-base reset: replaying an earlier canonical
            // receipt must never move the current lineage backward.
            save(&rig, 9, "xyz", "Xyz", "primary-reset").await;
            assert_eq!(drain(&rig).await, Halt::Empty);
        }
        let path = age_merge_on_disk(&rig, "primary-old");
        restart(&mut rig);
        rig.gate.journal.prune();
        let tombstone = rig.gate.journal.merge_with_key("primary-old").unwrap();
        assert!(
            tombstone.merge_key_tombstone,
            "primary key retained for {scenario}"
        );
        assert!(tombstone.arguments.is_none() && tombstone.reply.is_none());
        assert!(tombstone.merge_preparation.is_none() && tombstone.merge_result.is_none());
        let intent = tombstone.merge_intent.as_ref().unwrap();
        assert!(intent.declared_base_text.is_empty() && intent.draft_text.is_empty());
        let marker_before = fs::read(&path).unwrap();
        let lineage_before = single_lineage_bytes(&rig);
        let home_before = rig.state().store.lock().unwrap().clone();
        let effects_before = rig.state().created.load(Ordering::SeqCst);
        let requests_before = rig.state().writes().len();
        let result = save(&rig, 1, "abc", original_draft, "primary-old").await;
        assert_eq!(
            receipt(&result)["outcome"],
            "settled_on_device",
            "same old key is not a key conflict for {scenario}"
        );
        assert_eq!(receipt(&result)["journal_entry"], original.id);
        assert_ne!(result["result"]["isError"], true);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), requests_before);
        assert_eq!(rig.state().created.load(Ordering::SeqCst), effects_before);
        assert_eq!(*rig.state().store.lock().unwrap(), home_before);
        assert_eq!(single_lineage_bytes(&rig), lineage_before);
        assert_eq!(fs::read(&path).unwrap(), marker_before);
        restart(&mut rig);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), requests_before);
        assert_eq!(single_lineage_bytes(&rig), lineage_before);
        assert_eq!(fs::read(path).unwrap(), marker_before);
    }
}

#[tokio::test]
async fn body_merge_primary_not_sent_and_acknowledged_keys_never_return_to_queue() {
    for state in [EntryState::NotSent, EntryState::Acknowledged] {
        let mut rig = Rig::new(fast()).await;
        rig.gate.set_kernel_v2_upstream(true);
        save(&rig, 1, "abc", "Abc", "terminal-primary").await;
        assert_eq!(drain(&rig).await, Halt::Empty);
        let original = rig.gate.journal.merge_with_key("terminal-primary").unwrap();
        rig.gate
            .journal
            .update(&original.id, |entry| {
                entry.state = state;
            })
            .unwrap();
        let requests = rig.state().writes().len();
        let lineage_before = single_lineage_bytes(&rig);
        let repeated = save(&rig, 1, "abc", "Abc", "terminal-primary").await;
        assert_eq!(receipt(&repeated)["outcome"], "settled_on_device");
        assert_eq!(receipt(&repeated)["journal_entry"], original.id);
        assert_eq!(
            rig.gate
                .journal
                .merge_with_key("terminal-primary")
                .unwrap()
                .state,
            state
        );
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), requests);
        assert_eq!(single_lineage_bytes(&rig), lineage_before);
        let path = age_merge_on_disk(&rig, "terminal-primary");
        restart(&mut rig);
        let compact = rig.gate.journal.merge_with_key("terminal-primary").unwrap();
        assert!(compact.merge_key_tombstone);
        assert_eq!(compact.state, state);
        assert!(compact.arguments.is_none());
        let marker_before = fs::read(&path).unwrap();
        let repeated = save(&rig, 1, "abc", "Abc", "terminal-primary").await;
        assert_eq!(receipt(&repeated)["outcome"], "settled_on_device");
        assert_eq!(receipt(&repeated)["journal_entry"], original.id);
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), requests);
        assert_eq!(single_lineage_bytes(&rig), lineage_before);
        assert_eq!(fs::read(path).unwrap(), marker_before);
        assert_eq!(
            rig.gate
                .journal
                .merge_with_key("terminal-primary")
                .unwrap()
                .state,
            state
        );
    }
}
