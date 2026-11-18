use super::*;

fn new_entry(key: Option<&str>, body: &str) -> NewEntry {
    NewEntry {
        executor: "records_write".into(),
        operation: "create_record".into(),
        tool: "call_executor".into(),
        run_key: Some("run-1".into()),
        client_info: Some(json!({"name":"test-client","version":"1"})),
        app_identity: None,
        idempotency_key: key.map(str::to_owned),
        key_origin: key.map(|_| KeyOrigin::Caller),
        arguments: json!({"type":"Document","body":body,"idempotency_key":key}),
        parent_key: Some("parent-run".into()),
        title: Some("A title".into()),
        record_id: Some("70110000-0000-4000-8000-0000000000aa".into()),
        record_ids: Vec::new(),
        envelope: Some(json!({"run_key":"run-1","parent_key":"parent-run"})),
        intent_digest: Some("intent".into()),
    }
}

fn socket_directory() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

#[test]
fn hosted_custody_is_not_pruned_and_keeps_its_request_on_restart() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(Some("hosted-key"), "private body"))
        .unwrap();
    journal
        .hosted_pending(&entry.id, Some("hosted-entry".into()))
        .unwrap();
    journal.prune();
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = recovered.get(&entry.id).unwrap();
    assert_eq!(entry.state, EntryState::HostedPending);
    assert_eq!(entry.hosted_journal_entry.as_deref(), Some("hosted-entry"));
    assert_eq!(entry.arguments.unwrap()["body"], "private body");
    assert!(!recovered
        .held_writes(&StatusFilter::default(), None)
        .to_string()
        .contains("private body"));
    assert!(
        recovered.oldest_pending().is_none(),
        "not the node's replay queue"
    );
}

#[test]
fn files_and_directory_are_owner_only() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let entry = journal.begin(new_entry(Some("k1"), "secret body")).unwrap();
    let directory = temp.path().join("journal");
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let file = directory.join(format!("{}.json", entry.id));
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved["state"], "sent");
    assert_eq!(saved["idempotency_key"], "k1");
    assert_eq!(saved["run_key"], "run-1");
    assert_eq!(saved["client_info"]["name"], "test-client");
    assert!(saved["arguments"]["body"].as_str() == Some("secret body"));
    assert!(saved["received_at"].is_string());
    // A directory with loose permissions is refused rather than adopted.
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Journal::open(temp.path(), CONFIRMED_RETENTION).is_err());
}

#[test]
fn restart_turns_in_flight_entries_uncertain_and_keeps_their_arguments() {
    let temp = socket_directory();
    let id = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let sent = journal.begin(new_entry(Some("k1"), "one")).unwrap();
        let done = journal.begin(new_entry(Some("k2"), "two")).unwrap();
        journal
            .settle(&done.id, EntryState::Confirmed, Some("receipt"), None)
            .unwrap();
        sent.id
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let recovered = journal.get(&id).unwrap();
    assert_eq!(recovered.state, EntryState::Uncertain);
    assert!(recovered.detail.unwrap().contains("in flight"));
    assert_eq!(recovered.arguments.unwrap()["body"], "one");
    let status = journal.status();
    assert_eq!(status["uncertain"].as_array().unwrap().len(), 1);
    assert_eq!(status["uncertain"][0]["idempotency_key"], "k1");
    assert_eq!(status["entry_counts"]["confirmed"], 1);
    // The status read never carries record bodies.
    assert!(!status.to_string().contains("\"one\""));
    // And the recovery is persistent, not just in memory.
    let again = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    assert_eq!(again.get(&id).unwrap().state, EntryState::Uncertain);
}

#[test]
fn settled_entries_drop_arguments_and_are_pruned_but_uncertain_are_not() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let confirmed = journal.begin(new_entry(Some("k1"), "body")).unwrap();
    let uncertain = journal.begin(new_entry(Some("k2"), "body")).unwrap();
    let confirmed = journal
        .settle(&confirmed.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    assert!(confirmed.arguments.is_none());
    let on_disk: Value = serde_json::from_slice(
        &fs::read(
            temp.path()
                .join("journal")
                .join(format!("{}.json", confirmed.id)),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(on_disk["arguments"].is_null());
    journal
        .settle(
            &uncertain.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    journal.prune();
    assert!(journal.get(&confirmed.id).is_none());
    assert!(!temp
        .path()
        .join("journal")
        .join(format!("{}.json", confirmed.id))
        .exists());
    assert_eq!(
        journal.get(&uncertain.id).unwrap().state,
        EntryState::Uncertain
    );
}

#[test]
fn retry_with_the_same_key_and_arguments_settles_the_earlier_entry() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let first = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    journal
        .settle(&first.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    let other = journal.begin(new_entry(Some("k1"), "different")).unwrap();
    journal
        .settle(&other.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&journal.get(&other.id).unwrap());
    // Same key, different content: a different question, left open.
    assert_eq!(journal.get(&first.id).unwrap().state, EntryState::Uncertain);
    let retry = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    let retry = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&retry);
    let settled = journal.get(&first.id).unwrap();
    assert_eq!(settled.state, EntryState::Confirmed);
    assert_eq!(settled.resolved_by.as_deref(), Some(retry.id.as_str()));
}

#[test]
fn entries_from_a_newer_build_are_left_alone() {
    let temp = socket_directory();
    let id = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        journal.begin(new_entry(Some("k1"), "x")).unwrap().id
    };
    // A state only a future build knows: this build neither settles nor
    // sends it, and does not overwrite it.
    let path = temp.path().join("journal").join(format!("{id}.json"));
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["state"] = json!("quarantined");
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(journal.get(&id).unwrap().state, EntryState::Unrecognised);
    journal.prune();
    assert!(journal.get(&id).is_some());
    let again: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(again["state"], "quarantined");
    assert_eq!(journal.status()["entry_counts"]["unrecognised"], 1);
}

#[test]
fn a_refusal_does_not_resolve_an_earlier_uncertain_entry() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let first = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    journal
        .settle(&first.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    let retry = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    let refused = journal
        .settle(&retry.id, EntryState::Confirmed, Some("refused"), None)
        .unwrap();
    journal.resolve_earlier(&refused);
    assert_eq!(journal.get(&first.id).unwrap().state, EntryState::Uncertain);
}

#[test]
fn creating_the_journal_directory_syncs_its_parent_and_a_missing_parent_fails_startup() {
    let temp = socket_directory();
    assert!(Journal::open(temp.path(), CONFIRMED_RETENTION).is_ok());
    // No parent to create the directory in, so there is nothing to sync and
    // opening fails rather than carrying on with an undurable journal.
    assert!(Journal::open(&temp.path().join("missing"), CONFIRMED_RETENTION).is_err());
}

/// What a slice 2A build knows of an entry: the 2A state names and fields,
/// with `pending` unknown to it. Used to prove a rolled-back build still
/// reads a held entry, files it as `Unrecognised` and does not drop it.
#[derive(Deserialize)]
#[allow(dead_code)]
struct SliceAEntry {
    version: u32,
    id: String,
    state: SliceAState,
    arguments: Option<Value>,
    idempotency_key: Option<String>,
}
#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum SliceAState {
    Sent,
    Confirmed,
    NotSent,
    Uncertain,
    #[serde(other)]
    Unrecognised,
}

#[test]
fn a_held_entry_keeps_its_arguments_order_and_extras_and_survives_restart() {
    let temp = socket_directory();
    let (first, second, other) = {
        let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
        let first = journal.begin(new_entry(Some("k1"), "one")).unwrap();
        let second = journal.begin(new_entry(Some("k2"), "two")).unwrap();
        let other = journal.begin(new_entry(Some("k3"), "three")).unwrap();
        assert!(first.seq > 0 && first.seq < second.seq && second.seq < other.seq);
        assert_eq!(first.parent_key.as_deref(), Some("parent-run"));
        // Hold from `sent` (a refused forward) and from `uncertain`.
        let held = journal
            .hold(
                &first.id,
                HoldReason::DeploymentReadOnly,
                "read-only".into(),
                false,
            )
            .unwrap();
        assert_eq!(held.state, EntryState::Pending);
        assert_eq!(held.hold_reason, Some(HoldReason::DeploymentReadOnly));
        assert_eq!(held.arguments.as_ref().unwrap()["body"], "one");
        journal
            .settle(&second.id, EntryState::Uncertain, None, Some("lost".into()))
            .unwrap();
        journal
            .hold(
                &second.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        // A settled entry is not pulled back into the queue.
        journal
            .settle(&other.id, EntryState::Confirmed, Some("receipt"), None)
            .unwrap();
        let again = journal
            .hold(
                &other.id,
                HoldReason::HostedUnreachable,
                "late".into(),
                false,
            )
            .unwrap();
        assert_eq!(again.state, EntryState::Confirmed);
        (first.id, second.id, other.id)
    };
    // Zero retention prunes every settled entry; pending ones stay, with
    // their arguments, across a restart, and new entries sort after them.
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    journal.prune();
    assert!(journal.get(&other).is_none());
    for (id, body, reason) in [
        (&first, "one", HoldReason::DeploymentReadOnly),
        (&second, "two", HoldReason::HostedUnreachable),
    ] {
        let entry = journal.get(id).unwrap();
        assert_eq!(entry.state, EntryState::Pending);
        assert_eq!(entry.hold_reason, Some(reason));
        assert_eq!(entry.arguments.unwrap()["body"], body);
        assert_eq!(entry.title.as_deref(), Some("A title"));
    }
    let next = journal.begin(new_entry(None, "next")).unwrap();
    assert!(next.seq > journal.get(&second).unwrap().seq);
    assert_eq!(journal.status()["entry_counts"]["pending"], 2);
}

#[test]
fn a_slice_a_build_files_a_held_entry_as_unrecognised_and_a_2b_build_reads_slice_a_files() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let entry = journal.begin(new_entry(Some("k1"), "one")).unwrap();
    journal
        .hold(
            &entry.id,
            HoldReason::HostedUnreachable,
            "down".into(),
            false,
        )
        .unwrap();
    let path = temp
        .path()
        .join("journal")
        .join(format!("{}.json", entry.id));
    let bytes = fs::read(&path).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    // Version stays 1: a slice A reader accepts the file rather than counting
    // it unreadable, then meets a state it does not know.
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["state"], "pending");
    let as_slice_a: SliceAEntry = serde_json::from_slice(&bytes).unwrap();
    assert!(as_slice_a.version <= 1);
    assert_eq!(as_slice_a.state, SliceAState::Unrecognised);
    assert!(
        as_slice_a.arguments.is_some(),
        "arguments are kept for the next 2B build"
    );
    // And the other direction: a file with none of the 2B fields loads.
    let mut old = saved.clone();
    for field in ["seq", "parent_key", "title", "record_id", "hold_reason"] {
        old.as_object_mut().unwrap().remove(field);
    }
    old["state"] = json!("uncertain");
    fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
    drop(journal);
    let reopened = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let loaded = reopened.get(&entry.id).unwrap();
    assert_eq!(loaded.state, EntryState::Uncertain);
    assert_eq!(
        (loaded.seq, loaded.parent_key, loaded.hold_reason),
        (0, None, None)
    );
    // An unheld entry looks on disk exactly as it did in slice A.
    let plain = reopened.begin(new_entry(None, "plain")).unwrap();
    let plain_saved: Value = serde_json::from_slice(
        &fs::read(
            temp.path()
                .join("journal")
                .join(format!("{}.json", plain.id)),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(plain_saved.get("hold_reason").is_none());
}

#[test]
fn startup_pruning_keeps_refused_held_writes_for_their_own_retention() {
    let temp = socket_directory();
    let (refused, received) = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let refused = journal.begin(new_entry(Some("k1"), "refused")).unwrap();
        let received = journal.begin(new_entry(Some("k2"), "received")).unwrap();
        for entry in [&refused, &received] {
            journal
                .hold(
                    &entry.id,
                    HoldReason::DeploymentReadOnly,
                    "held".into(),
                    false,
                )
                .unwrap();
        }
        journal
            .finish_held(
                &refused.id,
                EntryState::Confirmed,
                Some("refused"),
                "no".into(),
                None,
                true,
                None,
            )
            .unwrap();
        journal
            .finish_held(
                &received.id,
                EntryState::Confirmed,
                Some("receipt"),
                "ok".into(),
                None,
                false,
                None,
            )
            .unwrap();
        (refused.id, received.id)
    };
    std::thread::sleep(Duration::from_millis(5));
    // Ordinary retention is nil; the refusal's is an hour. A restart prunes
    // at open, and must already know the longer figure.
    let journal =
        Journal::open_with(temp.path(), Duration::ZERO, Duration::from_secs(3600)).unwrap();
    assert!(
        journal.get(&refused).is_some(),
        "refusal survives the restart"
    );
    assert!(journal.get(&received).is_none());
}

#[test]
fn a_keyed_uncertain_entry_marked_possibly_applied_still_settles_on_a_keyed_receipt() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let first = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    journal
        .hold(
            &first.id,
            HoldReason::HostedUnreachable,
            "down".into(),
            true,
        )
        .unwrap();
    journal
        .finish_held(
            &first.id,
            EntryState::Uncertain,
            None,
            "partial".into(),
            None,
            true,
            None,
        )
        .unwrap();
    journal
        .update(&first.id, |e| e.maybe_applied = true)
        .unwrap();
    let retry = journal.begin(new_entry(Some("k1"), "same")).unwrap();
    let retry = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&retry);
    let settled = journal.get(&first.id).unwrap();
    assert_eq!(settled.state, EntryState::Confirmed);
    assert_eq!(settled.resolved_by.as_deref(), Some(retry.id.as_str()));
}

fn keyed_call(key: Option<&str>, arguments: Value) -> NewEntry {
    NewEntry {
        executor: "records_write".into(),
        operation: "create_record".into(),
        tool: "call_executor".into(),
        run_key: Some("run-1".into()),
        client_info: None,
        app_identity: None,
        idempotency_key: key.map(str::to_owned),
        key_origin: key.map(|_| KeyOrigin::Caller),
        arguments,
        parent_key: None,
        title: None,
        record_id: None,
        record_ids: Vec::new(),
        envelope: None,
        intent_digest: None,
    }
}

#[test]
fn reordered_nested_object_fields_with_the_same_key_settle() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let first_args = json!({
        "type": "Document", "body": "x",
        "nested": {"a": 1, "b": [1, 2]},
        "idempotency_key": "k1",
    });
    let first = journal.begin(keyed_call(Some("k1"), first_args)).unwrap();
    journal
        .settle(&first.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    // Same logical call, object fields in a different order.
    let retry_args = json!({
        "idempotency_key": "k1",
        "nested": {"b": [1, 2], "a": 1},
        "body": "x", "type": "Document",
    });
    let retry = journal.begin(keyed_call(Some("k1"), retry_args)).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(journal.get(&first.id).unwrap().state, EntryState::Confirmed);
}

#[test]
fn persisted_legacy_entry_settles_on_canonical_retry_after_restart() {
    use sha2::{Digest, Sha256};
    let temp = socket_directory();
    let first_args = json!({
        "type": "Document", "body": "legacy",
        "nested": {"a": 1, "b": 2},
        "idempotency_key": "k9",
    });
    let id = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let first = journal
            .begin(keyed_call(Some("k9"), first_args.clone()))
            .unwrap();
        journal
            .settle(&first.id, EntryState::Uncertain, None, Some("lost".into()))
            .unwrap();
        // Rewrite the stored digest the pre-canonical way (order-sensitive).
        let path = temp
            .path()
            .join("journal")
            .join(format!("{}.json", first.id));
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let legacy = hex::encode(Sha256::digest(first_args.to_string().as_bytes()));
        saved["arguments_digest"] = json!(legacy);
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        first.id
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    assert_eq!(journal.get(&id).unwrap().state, EntryState::Uncertain);
    let retry_args = json!({
        "idempotency_key": "k9",
        "nested": {"b": 2, "a": 1},
        "body": "legacy", "type": "Document",
    });
    let retry = journal.begin(keyed_call(Some("k9"), retry_args)).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(journal.get(&id).unwrap().state, EntryState::Confirmed);
}

#[test]
fn mismatched_value_operation_executor_or_array_order_stay_open() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let base = json!({"type": "D", "items": [1, 2], "idempotency_key": "km"});
    let ids: Vec<String> = [&base; 4]
        .iter()
        .map(|args| {
            let e = journal
                .begin(keyed_call(Some("km"), (*args).clone()))
                .unwrap();
            journal
                .settle(&e.id, EntryState::Uncertain, None, Some("lost".into()))
                .unwrap();
            e.id
        })
        .collect();
    // Overwrite three of them so only ids[0] is canonically equivalent.
    let tweak = [
        json!({"type": "D", "items": [1, 2], "idempotency_key": "km", "extra": 1}),
        json!({"type": "D", "items": [2, 1], "idempotency_key": "km"}),
        json!({"type": "CHANGED", "items": [1, 2], "idempotency_key": "km"}),
    ];
    for (id, args) in ids.iter().skip(1).zip(tweak.iter()) {
        journal
            .update(id, |e| {
                e.arguments = Some(args.clone());
                e.arguments_digest = crate::canonical_json::digest_json(args);
            })
            .unwrap();
    }
    let mut other_op = keyed_call(Some("km"), base.clone());
    other_op.operation = "other_op".into();
    let op_entry = journal.begin(other_op).unwrap();
    journal
        .settle(
            &op_entry.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    let mut other_ex = keyed_call(Some("km"), base.clone());
    other_ex.executor = "other_executor".into();
    let ex_entry = journal.begin(other_ex).unwrap();
    journal
        .settle(
            &ex_entry.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    let retry = journal.begin(keyed_call(Some("km"), base.clone())).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(journal.get(&ids[0]).unwrap().state, EntryState::Confirmed);
    for id in ids.iter().skip(1) {
        assert_eq!(journal.get(id).unwrap().state, EntryState::Uncertain);
    }
    assert_eq!(
        journal.get(&op_entry.id).unwrap().state,
        EntryState::Uncertain
    );
    assert_eq!(
        journal.get(&ex_entry.id).unwrap().state,
        EntryState::Uncertain
    );
}

#[test]
fn keyed_receipt_settles_uncertain_but_not_sent_unkeyed_or_closed() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let args = json!({"type": "D", "idempotency_key": "ks"});
    let open = journal.begin(keyed_call(Some("ks"), args.clone())).unwrap();
    journal
        .settle(&open.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    // An active sent call keeps its own finish path and is left alone.
    let sent = journal.begin(keyed_call(Some("ks"), args.clone())).unwrap();
    let unkeyed_args = json!({"type": "D"});
    let unkeyed = journal.begin(keyed_call(None, unkeyed_args)).unwrap();
    journal
        .settle(
            &unkeyed.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    let closed = journal.begin(keyed_call(Some("ks"), args.clone())).unwrap();
    journal
        .settle(&closed.id, EntryState::NotSent, None, Some("never".into()))
        .unwrap();
    let retry = journal.begin(keyed_call(Some("ks"), args.clone())).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(journal.get(&open.id).unwrap().state, EntryState::Confirmed);
    assert_eq!(journal.get(&sent.id).unwrap().state, EntryState::Sent);
    assert_eq!(
        journal.get(&unkeyed.id).unwrap().state,
        EntryState::Uncertain
    );
    assert_eq!(journal.get(&closed.id).unwrap().state, EntryState::NotSent);
}

#[test]
fn status_advice_is_scoped_by_key_presence() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    assert!(journal.status()["how_to_settle"]
        .as_str()
        .unwrap()
        .contains("No uncertain"));
    let keyed = journal
        .begin(keyed_call(Some("ka"), json!({"a": 1})))
        .unwrap();
    journal
        .settle(&keyed.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    let advice = journal.status()["how_to_settle"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(advice.contains("idempotency_key"));
    let unkeyed = journal.begin(keyed_call(None, json!({"a": 1}))).unwrap();
    journal
        .settle(
            &unkeyed.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    let both = journal.status()["how_to_settle"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(both.contains("Keyless"));
    journal
        .settle(&keyed.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.prune();
    let keyless_only = journal.status()["how_to_settle"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(keyless_only.contains("inspect"));
    assert!(!keyless_only.contains("Retry the same call"));
}

#[test]
fn arg_less_earlier_settles_only_on_matching_stored_digest() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let args = json!({"type": "D", "idempotency_key": "kf"});
    let matching = journal.begin(keyed_call(Some("kf"), args.clone())).unwrap();
    journal
        .settle(
            &matching.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    journal
        .update(&matching.id, |e| e.arguments = None)
        .unwrap();
    let other = json!({"type": "OTHER", "idempotency_key": "kf"});
    let stale = journal.begin(keyed_call(Some("kf"), args.clone())).unwrap();
    journal
        .settle(&stale.id, EntryState::Uncertain, None, Some("lost".into()))
        .unwrap();
    journal
        .update(&stale.id, |e| {
            e.arguments = None;
            e.arguments_digest = crate::canonical_json::digest_json(&other);
        })
        .unwrap();
    let retry = journal.begin(keyed_call(Some("kf"), args.clone())).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(
        journal.get(&matching.id).unwrap().state,
        EntryState::Confirmed
    );
    assert_eq!(journal.get(&stale.id).unwrap().state, EntryState::Uncertain);
}

#[test]
fn keyless_receipt_never_settles_a_keyed_earlier_entry() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let args = json!({"type": "D", "idempotency_key": "kx"});
    let earlier = journal.begin(keyed_call(Some("kx"), args.clone())).unwrap();
    journal
        .settle(
            &earlier.id,
            EntryState::Uncertain,
            None,
            Some("lost".into()),
        )
        .unwrap();
    let retry = journal.begin(keyed_call(None, args.clone())).unwrap();
    let receipt = journal
        .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    journal.resolve_earlier(&receipt);
    assert_eq!(
        journal.get(&earlier.id).unwrap().state,
        EntryState::Uncertain
    );
}

#[test]
fn settlement_survives_reopen_with_receipt_link_and_no_arguments() {
    use sha2::{Digest, Sha256};
    let temp = socket_directory();
    let canon_args = json!({"type": "D", "nested": {"a": 1, "b": 2}, "idempotency_key": "kd"});
    let legacy_args = json!({"type": "D", "nested": {"a": 1, "b": 2}, "idempotency_key": "kd"});
    let (canon_id, legacy_id, receipt_id) = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let canon = journal
            .begin(keyed_call(Some("kd"), canon_args.clone()))
            .unwrap();
        journal
            .settle(&canon.id, EntryState::Uncertain, None, Some("lost".into()))
            .unwrap();
        let legacy = journal
            .begin(keyed_call(Some("kd"), legacy_args.clone()))
            .unwrap();
        journal
            .settle(&legacy.id, EntryState::Uncertain, None, Some("lost".into()))
            .unwrap();
        let path = temp
            .path()
            .join("journal")
            .join(format!("{}.json", legacy.id));
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved["arguments_digest"] = json!(hex::encode(Sha256::digest(
            legacy_args.to_string().as_bytes()
        )));
        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let retry_args = json!({"idempotency_key": "kd", "nested": {"b": 2, "a": 1}, "type": "D"});
        let retry = journal.begin(keyed_call(Some("kd"), retry_args)).unwrap();
        let receipt = journal
            .settle(&retry.id, EntryState::Confirmed, Some("receipt"), None)
            .unwrap();
        journal.resolve_earlier(&receipt);
        (canon.id, legacy.id, receipt.id)
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    for id in [&canon_id, &legacy_id] {
        let settled = journal.get(id).unwrap();
        assert_eq!(settled.state, EntryState::Confirmed);
        assert_eq!(settled.resolved_by.as_deref(), Some(receipt_id.as_str()));
        assert!(settled.arguments.is_none());
    }
}

#[test]
fn hosted_status_cannot_overwrite_a_newer_receipt_or_drop_refused_content() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let entry = journal.begin(new_entry(Some("k"), "saved work")).unwrap();
    let pending = journal
        .hosted_pending(&entry.id, Some("hosted".into()))
        .unwrap();
    let refused = journal
        .finish_hosted(
            &pending,
            true,
            "Needs you".into(),
            Some("refusal".into()),
            None,
        )
        .unwrap();
    assert_eq!(refused.arguments.unwrap()["body"], "saved work");
    let stale = journal
        .finish_hosted(&pending, false, "old status".into(), None, None)
        .unwrap();
    assert_eq!(stale.answer.as_deref(), Some("refused"));
    assert_eq!(stale.detail.as_deref(), Some("Needs you"));
    assert!(stale.arguments.is_some());
}

#[test]
fn operator_acknowledgement_retains_request_and_audit_across_restart_and_prune() {
    for state in [
        EntryState::Uncertain,
        EntryState::HostedPending,
        EntryState::NotSent,
    ] {
        for outcome in ["landed", "not_applied", "superseded"] {
            let temp = socket_directory();
            let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
            let entry = journal
                .begin(new_entry(None, "recoverable original"))
                .unwrap();
            journal
                .update(&entry.id, |e| {
                    e.state = state;
                    e.hosted_journal_entry = Some("hosted-evidence".into());
                })
                .unwrap();
            let done = journal
                .operator_decision(
                    &entry.id,
                    Some(outcome),
                    "  checked canonical history  ",
                    42,
                    Some(99),
                )
                .unwrap();
            assert_eq!(done.state, EntryState::Acknowledged);
            assert_eq!(done.arguments_digest, entry.arguments_digest);
            assert_eq!(done.arguments, entry.arguments);
            assert_eq!(done.envelope, entry.envelope);
            let audit = done.operator_audit.unwrap();
            assert_eq!(audit.uid, 42);
            assert_eq!(audit.pid, Some(99));
            assert_eq!(audit.reason, "checked canonical history");
            assert_eq!(audit.outcome.as_deref(), Some(outcome));
            assert_eq!(audit.previous_state, state);
            assert!(chrono::DateTime::parse_from_rfc3339(&audit.at).is_ok());
            journal
                .update(&entry.id, |e| e.updated_at = "2000-01-01T00:00:00Z".into())
                .unwrap();
            journal.prune();
            drop(journal);
            let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
            let done = recovered.get(&entry.id).unwrap();
            assert_eq!(done.state, EntryState::Acknowledged);
            assert_eq!(done.arguments, entry.arguments);
            assert!(recovered.status()["uncertain"]
                .as_array()
                .unwrap()
                .is_empty());
            assert_eq!(
                recovered.queue_summary()["oldest_waiting_accepted_at"],
                Value::Null
            );
            assert!(recovered.hosted_entries(0, 100).is_empty());
            assert_eq!(
                recovered.held_counts_for_run("run-1"),
                (json!({}), json!({}))
            );
            assert!(recovered.oldest_pending().is_none());
            assert!(!recovered
                .held_writes(&StatusFilter::default(), None)
                .to_string()
                .contains("recoverable original"));
            // A previously captured hosted status must not overwrite the decision.
            recovered
                .finish_hosted(&entry, false, "stale status".into(), None, None)
                .unwrap();
            assert_eq!(
                recovered.get(&entry.id).unwrap().state,
                EntryState::Acknowledged
            );
            assert!(recovered
                .operator_decision(&entry.id, Some(outcome), "overwrite", 42, None)
                .is_err());
        }
    }
}

#[test]
fn operator_decisions_refuse_wrong_state_invalid_reason_and_failed_persistence() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    for state in [
        EntryState::Sent,
        EntryState::Pending,
        EntryState::Unrecognised,
    ] {
        let entry = journal.begin(new_entry(Some("key"), "body")).unwrap();
        journal.update(&entry.id, |e| e.state = state).unwrap();
        assert!(journal
            .operator_decision(&entry.id, Some("landed"), "reconciled", 42, None)
            .is_err());
    }
    let entry = journal.begin(new_entry(None, "body")).unwrap();
    journal
        .update(&entry.id, |e| {
            e.state = EntryState::Uncertain;
            e.in_flight = true;
        })
        .unwrap();
    assert!(journal
        .operator_decision(&entry.id, Some("landed"), "reconciled", 42, None)
        .is_err());
    journal.update(&entry.id, |e| e.in_flight = false).unwrap();
    for (outcome, reason) in [("invalid", "reason"), ("landed", "  ")] {
        assert!(journal
            .operator_decision(&entry.id, Some(outcome), reason, 42, None)
            .is_err());
    }
    journal
        .fail_after
        .store(0, std::sync::atomic::Ordering::SeqCst);
    assert!(journal
        .operator_decision(&entry.id, Some("landed"), "reconciled", 42, None)
        .is_err());
    assert_eq!(journal.get(&entry.id).unwrap().state, EntryState::Uncertain);
    assert!(journal.get(&entry.id).unwrap().operator_audit.is_none());
}

#[test]
fn withdrawal_retains_refusal_and_rejects_possibly_applied_or_hosted_writes() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(Some("withdraw-key"), "preserved work"))
        .unwrap();
    journal
        .hold(
            &entry.id,
            HoldReason::DeploymentReadOnly,
            "queued".into(),
            false,
        )
        .unwrap();
    for (state, in_flight, maybe_applied) in [
        (EntryState::Pending, true, false),
        (EntryState::Pending, false, true),
        (EntryState::Sent, false, false),
        (EntryState::HostedPending, false, false),
    ] {
        journal
            .update(&entry.id, |e| {
                e.state = state;
                e.in_flight = in_flight;
                e.maybe_applied = maybe_applied;
            })
            .unwrap();
        assert!(journal
            .operator_decision(&entry.id, None, "withdraw", 42, None)
            .is_err());
    }
    journal
        .update(&entry.id, |e| {
            e.state = EntryState::Pending;
            e.in_flight = false;
            e.maybe_applied = false;
        })
        .unwrap();
    let withdrawn = journal
        .operator_decision(&entry.id, None, "no longer needed", 42, None)
        .unwrap();
    assert_eq!(withdrawn.answer.as_deref(), Some("refused"));
    assert_eq!(withdrawn.arguments, entry.arguments);
    assert!(withdrawn.reply.unwrap().contains("operator_withdrawn"));
    journal
        .update(&entry.id, |e| e.updated_at = "2000-01-01T00:00:00Z".into())
        .unwrap();
    journal.prune();
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert!(recovered.oldest_pending().is_none());
    assert!(recovered
        .settled_held_with_key("records_write", "create_record", "withdraw-key", None)
        .is_some());
    assert_eq!(recovered.get(&entry.id).unwrap().arguments, entry.arguments);
}

#[test]
fn app_scope_separates_keyed_lookups_digests_and_receipt_resolution() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let scopes = [
        None,
        Some("docs@1; install=e"),
        Some("tracker@1; install=e"),
    ];
    let mut earlier = Vec::new();
    for app in scopes {
        let mut new = new_entry(Some("shared-key"), "identical");
        new.app_identity = app.map(str::to_owned);
        let entry = journal.begin(new).unwrap();
        journal
            .settle(&entry.id, EntryState::Uncertain, None, None)
            .unwrap();
        // Even an accidental hold call cannot grant app queue custody.
        if app.is_some() {
            assert_eq!(
                journal
                    .hold(
                        &entry.id,
                        HoldReason::HostedUnreachable,
                        "down".into(),
                        true
                    )
                    .unwrap()
                    .state,
                EntryState::Uncertain
            );
        }
        earlier.push(entry);
    }
    assert_ne!(earlier[0].arguments_digest, earlier[1].arguments_digest);
    assert_ne!(earlier[1].arguments_digest, earlier[2].arguments_digest);
    for (i, app) in scopes.into_iter().enumerate() {
        let mut new = new_entry(Some("shared-key"), "identical");
        new.app_identity = app.map(str::to_owned);
        let entry = journal.begin(new).unwrap();
        journal
            .hosted_pending(&entry.id, Some(format!("handle-{i}")))
            .unwrap();
        assert_eq!(
            journal
                .hosted_pending_with_key("records_write", "create_record", "shared-key", app)
                .unwrap()
                .id,
            entry.id
        );
        assert!(journal
            .pending_with_key("records_write", "create_record", "shared-key", app)
            .is_none());
        let receipt = journal
            .settle(&entry.id, EntryState::Confirmed, Some("receipt"), None)
            .unwrap();
        journal
            .update(&entry.id, |e| e.reply = Some("canonical receipt".into()))
            .unwrap();
        assert_eq!(
            journal
                .settled_held_with_key("records_write", "create_record", "shared-key", app)
                .unwrap()
                .id,
            entry.id
        );
        assert_eq!(
            journal
                .node_id_for_hosted(&format!("handle-{i}"), app)
                .as_deref(),
            Some(entry.id.as_str())
        );
        for other in scopes.into_iter().filter(|s| *s != app) {
            assert!(journal
                .node_id_for_hosted(&format!("handle-{i}"), other)
                .is_none());
        }
        journal.resolve_earlier(&receipt);
        assert_eq!(
            journal.get(&earlier[i].id).unwrap().state,
            EntryState::Confirmed
        );
        for prior in earlier.iter().skip(i + 1) {
            assert_eq!(journal.get(&prior.id).unwrap().state, EntryState::Uncertain);
        }
    }
}

#[test]
fn app_uncertainty_is_explicit_repeat_only_and_old_reader_has_no_pending_work() {
    let temp = socket_directory();
    let id = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let mut new = new_entry(Some("app-key"), "body");
        new.app_identity = Some("docs@1; install=e".into());
        let entry = journal.begin(new).unwrap();
        entry.id
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let entry = journal.get(&id).unwrap();
    assert_eq!(entry.state, EntryState::Uncertain);
    assert_eq!(journal.pending_count(), 0);
    let old: SliceAEntry = serde_json::from_value(serde_json::to_value(&entry).unwrap()).unwrap();
    assert_eq!(old.state, SliceAState::Uncertain);
    assert!(old.arguments.is_some());
    // Older readers ignore app_identity. They never automatically replay
    // ordinary uncertainty, but an explicit same-key retry on rollback lacks
    // this release's app-aware matching: that manual rollback gap is real.
}

#[test]
fn previous_reader_never_schedules_app_states_but_manual_scope_matching_is_unsafe() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let mut old_entries = Vec::new();
    for app in ["docs@1; install=e", "tracker@1; install=e"] {
        let mut new = new_entry(Some("rollback-shared-key"), "same arguments");
        new.app_identity = Some(app.into());
        let entry = journal.begin(new).unwrap();
        for state in [
            EntryState::Sent,
            EntryState::Uncertain,
            EntryState::HostedPending,
            EntryState::Confirmed,
            EntryState::NotSent,
        ] {
            let mut wire = serde_json::to_value(&entry).unwrap();
            wire["state"] = serde_json::to_value(state).unwrap();
            // Exact format downgrade: the prior reader ignores this new field.
            wire.as_object_mut().unwrap().remove("app_identity");
            let old: Entry = serde_json::from_value(wire).unwrap();
            assert!(old.app_identity.is_none());
            // The prior queue selects only Pending; recovery converts Sent to
            // Uncertain. HostedPending may issue status reads, never mutations.
            assert_ne!(old.state, EntryState::Pending);
        }
        let mut wire = serde_json::to_value(&entry).unwrap();
        wire.as_object_mut().unwrap().remove("app_identity");
        old_entries.push(serde_json::from_value::<Entry>(wire).unwrap());
    }
    // With retained arguments the old argument-equivalence branch disregards
    // attribution, so manual retry/receipt resolution on downgrade is unsafe.
    assert_eq!(
        old_entries[0].idempotency_key,
        old_entries[1].idempotency_key
    );
    assert!(arguments_equivalent(&old_entries[0], &old_entries[1]));
    let status = journal.status_for(&StatusFilter {
        run: Some("different-run".into()),
        states: vec!["pending".into()],
        limit: 1,
        ..Default::default()
    });
    assert_eq!(
        status["app_outstanding_count"], 2,
        "count must ignore status filters and page limits"
    );
    assert_eq!(status["app_outstanding"].as_array().unwrap().len(), 1);
    assert_eq!(status["app_outstanding_truncated"], true);
}

fn merge_entry(journal: &Journal, record: &str, key: &str) -> Entry {
    let mut new = new_entry(Some(key), "draft secret");
    new.operation = "merge_body".into();
    new.record_id = Some(record.into());
    new.arguments = json!({"record_id":record,"base_version":"rec:1","base_text":"base secret","my_text":"draft secret","reason":"edit","idempotency_key":key});
    let entry = journal
        .begin_merge(
            new,
            MergeIntent {
                declared_base_version: "rec:1".into(),
                declared_base_text: "base secret".into(),
                draft_text: "draft secret".into(),
                editor: "editor-1".into(),
                made_at_ms: Some(7),
                wait: "none".into(),
            },
        )
        .unwrap();
    journal
        .update(&entry.id, |entry| entry.prepared = true)
        .unwrap()
}

#[test]
fn merge_custody_is_v2_pending_on_first_write_and_prepared_at_attempt_zero() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = merge_entry(&journal, "R", "k");
    assert_eq!(entry.version, 2);
    assert_eq!(entry.state, EntryState::Pending);
    assert_eq!(entry.attempts, 0);
    assert!(entry.prepared);
    assert!(journal
        .update(&entry.id, |e| e.arguments.as_mut().unwrap()["my_text"] =
            json!("changed"))
        .is_err());
    assert!(journal
        .update(&entry.id, |e| e.idempotency_key = Some("different".into()))
        .is_err());
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let same = recovered.get(&entry.id).unwrap();
    assert_eq!(same.state, EntryState::Pending);
    assert_eq!(same.arguments, entry.arguments);
    assert!(same.prepared);
    assert_eq!(recovered.status()["merge_body_nonterminal_count"], 1);
}

#[test]
fn parked_merge_blocks_its_record_and_transitive_creates_but_not_unrelated_work() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let r1 = merge_entry(&journal, "R", "r1");
    let r2 = merge_entry(&journal, "R", "r2");
    journal
        .update(&r1.id, |e| e.not_before_ms = u64::MAX)
        .unwrap();
    let mut create = new_entry(Some("create"), "private child");
    create.record_id = Some("child".into());
    create.arguments["home_id"] = json!("R");
    let child = journal.begin(create).unwrap();
    journal
        .hold(
            &child.id,
            HoldReason::HostedUnreachable,
            "held".into(),
            false,
        )
        .unwrap();
    let dependant = merge_entry(&journal, "child", "dependant");
    let q = merge_entry(&journal, "Q", "q");
    assert_eq!(journal.oldest_pending().unwrap().id, q.id);
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(recovered.oldest_pending().unwrap().id, q.id);
    recovered.update(&r1.id, |e| e.not_before_ms = 0).unwrap();
    assert_eq!(recovered.oldest_pending().unwrap().id, r1.id);
    recovered
        .finish_held(
            &r1.id,
            EntryState::Confirmed,
            Some("receipt"),
            "synced".into(),
            None,
            true,
            None,
        )
        .unwrap();
    assert_eq!(recovered.oldest_pending().unwrap().id, r2.id);
    assert_ne!(recovered.oldest_pending().unwrap().id, dependant.id);
}

#[test]
fn merge_recovery_keeps_large_clash_reply_texts_and_private_permissions_past_pruning() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = merge_entry(&journal, "R", "clash");
    // Slice 3 wrote frozen v2 entries before the lineage-required marker
    // existed. Reconstruct that on-disk format rather than mutating a frozen
    // request through the current write API. Its raw recovery pointer must
    // continue protecting legacy custody until slice-4 import can establish it.
    let path = journal.path(&entry.id);
    let mut legacy: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("lineage_required");
    fs::write(path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    drop(journal);
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal.get(&entry.id).unwrap();
    assert!(!entry.lineage_required);
    let reply = json!({"outcome":"merged_with_clashes","unmerged":[{"mine":"x".repeat(MAX_STORED_REPLY + 1)}]}).to_string();
    let handle = journal
        .save_merge_recovery(&entry, "merged_with_clashes", Some(&reply))
        .unwrap();
    journal
        .update(&entry.id, |e| e.recovery_item = Some(handle.clone()))
        .unwrap();
    journal
        .finish_held(
            &entry.id,
            EntryState::Confirmed,
            Some("merged_with_clashes"),
            "Needs you".into(),
            Some(reply.clone()),
            true,
            None,
        )
        .unwrap();
    journal.prune();
    assert_eq!(
        journal.get(&entry.id).unwrap().reply.as_deref(),
        Some(reply.as_str())
    );
    let path = temp
        .path()
        .join("body-merge-recovery")
        .join(format!("{handle}.json"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let recovery: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(recovery["reply"], reply);
    assert_eq!(recovery["intent"]["draft_text"], "draft secret");
    let status = journal.status().to_string();
    assert!(!status.contains("draft secret"));
    assert!(!journal
        .held_writes(&StatusFilter::default(), None)
        .to_string()
        .contains("draft secret"));
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(
        recovered.get(&entry.id).unwrap().reply.as_deref(),
        Some(reply.as_str())
    );
}

#[test]
fn committed_and_result_unrecovered_merge_states_survive_restart_and_count() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let r1 = merge_entry(&journal, "R", "r1");
    let _r2 = merge_entry(&journal, "R", "r2");
    journal
        .update(&r1.id, |e| {
            e.state = EntryState::ResultUnrecovered;
            e.not_before_ms = u64::MAX;
        })
        .unwrap();
    assert!(journal.oldest_pending().is_none());
    assert_eq!(journal.status()["merge_body_nonterminal_count"], 2);
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(
        recovered.get(&r1.id).unwrap().state,
        EntryState::ResultUnrecovered
    );
    assert!(recovered.oldest_pending().is_none());
    recovered
        .update(&r1.id, |e| {
            e.state = EntryState::CommittedUnrecovered;
            e.not_before_ms = 0;
        })
        .unwrap();
    assert_eq!(recovered.oldest_pending().unwrap().id, r1.id);
}

#[test]
fn v2_loader_does_not_admit_unrelated_or_unprepared_entries() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let legacy = journal.begin(new_entry(Some("legacy"), "body")).unwrap();
    let merging = merge_entry(&journal, "R", "unprepared");
    let legacy_path = journal.path(&legacy.id);
    let merge_path = journal.path(&merging.id);
    let mut bytes: Value = serde_json::from_slice(&fs::read(&legacy_path).unwrap()).unwrap();
    bytes["version"] = json!(2);
    fs::write(&legacy_path, bytes.to_string()).unwrap();
    let mut bytes: Value = serde_json::from_slice(&fs::read(&merge_path).unwrap()).unwrap();
    bytes["prepared"] = json!(false);
    bytes.as_object_mut().unwrap().remove("lineage_required");
    fs::write(&merge_path, bytes.to_string()).unwrap();
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    // Unprepared v2 files without the newer lineage-required marker still
    // cannot enter the queue. The marked format is exercised separately.
    assert!(recovered.oldest_pending().is_none());
    assert!(recovered.get(&legacy.id).is_none());
    assert!(recovered.get(&merging.id).is_none());
    assert_eq!(recovered.status()["unreadable_files"], 2);
    assert!(legacy_path.exists());
    assert!(merge_path.exists());
}

#[test]
fn v2_loader_admits_unprepared_lineage_marked_custody() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let lineage_marked = merge_entry(&journal, "Q", "lineage-unprepared");
    let path = journal.path(&lineage_marked.id);
    let mut bytes: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    bytes["prepared"] = json!(false);
    assert_eq!(bytes["lineage_required"], true);
    fs::write(path, bytes.to_string()).unwrap();
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    // Slice 4 accepts unprepared custody because lineage preparation waits
    // for this save's turn rather than happening during admission.
    let admitted = recovered.get(&lineage_marked.id).unwrap();
    assert!(admitted.lineage_required);
    assert!(!admitted.prepared);
    assert_eq!(admitted.arguments, lineage_marked.arguments);
    assert_eq!(recovered.oldest_pending().unwrap().id, lineage_marked.id);
    assert_eq!(recovered.status()["unreadable_files"], 0);
}

#[test]
fn legacy_sent_and_uncertain_writes_do_not_block_the_legacy_held_queue() {
    for state in [EntryState::Sent, EntryState::Uncertain] {
        let temp = socket_directory();
        let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
        let mut earlier = new_entry(Some("legacy-open"), "earlier");
        earlier.operation = "update_record".into();
        earlier.record_id = Some("R".into());
        earlier.arguments =
            json!({"record_id":"R","body":"earlier","idempotency_key":"legacy-open"});
        let earlier = journal.begin(earlier).unwrap();
        journal.update(&earlier.id, |e| e.state = state).unwrap();
        let mut append = new_entry(Some("legacy-append"), "append");
        append.operation = "update_record".into();
        append.record_id = Some("R".into());
        append.arguments =
            json!({"record_id":"R","body_append":"append","idempotency_key":"legacy-append"});
        let append = journal.begin(append).unwrap();
        journal
            .hold(
                &append.id,
                HoldReason::HostedUnreachable,
                "held".into(),
                false,
            )
            .unwrap();
        assert_eq!(
            journal.oldest_pending().unwrap().id,
            append.id,
            "pure legacy queue: {state:?}"
        );
        let _same_record_merge = merge_entry(&journal, "R", "same-record-merge");
        let q = merge_entry(&journal, "Q", "unrelated-merge");
        assert_eq!(
            journal.oldest_pending().unwrap().id,
            append.id,
            "legacy queue with typed saves: {state:?}"
        );
        assert_eq!(
            journal.next_pending(true).unwrap().id,
            q.id,
            "typed save waits on its record, not unrelated records"
        );
        drop(journal);
        let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
        assert_eq!(recovered.oldest_pending().unwrap().id, append.id);
        assert_eq!(recovered.next_pending(true).unwrap().id, q.id);
    }
}

#[test]
fn skipped_hosted_create_dependants_retain_the_custody_barrier_after_unrelated_work() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let mut create = new_entry(Some("parent"), "parent draft");
    create.record_id = Some("R".into());
    let parent = journal.begin(create).unwrap();
    journal
        .hosted_pending(&parent.id, Some("hosted-parent".into()))
        .unwrap();
    let mut child = new_entry(Some("child"), "child draft");
    child.operation = "update_record".into();
    child.record_id = Some("R".into());
    child.arguments = json!({"record_id":"R","body_append":"tail","idempotency_key":"child"});
    let child = journal.begin(child).unwrap();
    journal
        .hold(
            &child.id,
            HoldReason::HostedUnreachable,
            "held".into(),
            false,
        )
        .unwrap();
    assert!(journal.has_pending_hosted_creator_dependency(false));
    assert!(
        !journal.has_pending_hosted_creator_dependency(true),
        "legacy-only barrier remains an engine-v2 refusal"
    );
    let q = merge_entry(&journal, "Q", "unrelated");
    assert_eq!(journal.next_pending(true).unwrap().id, q.id);
    assert_eq!(journal.oldest_pending().unwrap().id, q.id);
    journal
        .finish_held(
            &q.id,
            EntryState::Confirmed,
            Some("receipt"),
            "synced".into(),
            None,
            true,
            None,
        )
        .unwrap();
    assert!(journal.oldest_pending().is_none());
    assert!(journal.has_pending_hosted_creator_dependency(false));
    let _typed_child = merge_entry(&journal, "R", "typed-child");
    assert!(journal.next_pending(true).is_none());
    assert!(journal.has_pending_hosted_creator_dependency(true));
    drop(journal);
    let recovered = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert!(recovered.oldest_pending().is_none());
    assert!(recovered.has_pending_hosted_creator_dependency(false));
    assert!(recovered.has_pending_hosted_creator_dependency(true));
    let parent = recovered.get(&parent.id).unwrap();
    recovered
        .finish_hosted(&parent, false, "applied".into(), None, None)
        .unwrap();
    assert!(!recovered.has_pending_hosted_creator_dependency(false));
    assert_eq!(recovered.oldest_pending().unwrap().id, child.id);
}

#[test]
fn typed_merge_custody_is_untouched_by_fork_maintenance_and_pruning() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = merge_entry(&journal, "R", "typed-preview-exclusion");
    assert!(!super::super::pending_fork::previewable(&entry));
    assert!(journal.fork_entries(0).unwrap().is_empty());
    for state in [
        EntryState::Pending,
        EntryState::Sent,
        EntryState::HostedPending,
        EntryState::Uncertain,
        EntryState::CommittedUnrecovered,
        EntryState::ResultUnrecovered,
    ] {
        journal.update(&entry.id, |e| e.state = state).unwrap();
        assert!(journal.fork_blocked_by_merge(&["R".into()]));
        assert!(!journal.fork_blocked_by_merge(&["Q".into()]));
        let before = fs::read(journal.path(&entry.id)).unwrap();
        journal.retire_fork_payloads(Some(i64::MAX)).unwrap();
        journal.retire_fork_payloads(None).unwrap();
        journal.prune();
        assert_eq!(fs::read(journal.path(&entry.id)).unwrap(), before);
        let value: Value = serde_json::from_slice(&before).unwrap();
        assert!(value
            .as_object()
            .unwrap()
            .keys()
            .all(|k| !k.starts_with("fork_")));
    }
    drop(journal);
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(
        journal.get(&entry.id).unwrap().state,
        EntryState::ResultUnrecovered
    );
    assert!(journal.fork_blocked_by_merge(&["R".into()]));
    journal
        .finish_held(
            &entry.id,
            EntryState::Confirmed,
            Some("receipt"),
            "settled".into(),
            Some("x".repeat(MAX_STORED_REPLY + 1)),
            true,
            None,
        )
        .unwrap();
    assert!(!journal.fork_blocked_by_merge(&["R".into()]));
    assert!(journal.get(&entry.id).unwrap().reply.unwrap().len() > MAX_STORED_REPLY);
    // Wait past ZERO retention before pruning.
    std::thread::sleep(Duration::from_millis(2));
    journal.prune();
    let compact = journal.get(&entry.id).unwrap();
    assert!(compact.merge_key_tombstone);
    assert!(compact.arguments.is_none() && compact.reply.is_none());
    assert!(compact.merge_preparation.is_none() && compact.merge_result.is_none());
    assert!(compact.fork_arguments.is_none() && compact.fork_run_key.is_none());
    assert!(!journal.fork_blocked_by_merge(&["R".into()]));
    drop(journal);
    let reopened = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert!(
        reopened
            .merge_with_key("typed-preview-exclusion")
            .unwrap()
            .merge_key_tombstone
    );
}

#[test]
fn v3_custody_reopens_only_in_its_bound_namespace_and_is_immutable() {
    let temp = tempfile::tempdir().unwrap();
    let binding = CustodyBinding {
        account_id: "account-a".into(),
        database_id: "route-a".into(),
        origin_database_id: "canonical-origin".into(),
        history_lineage: "v2:origin:genesis".into(),
        resource_origin: "https://native.example".into(),
        install_id: None,
    };
    let journal = Journal::open_bound(
        temp.path(),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        Some(binding.clone()),
    )
    .unwrap();
    let mut new = new_entry(Some("v3-key"), "private content");
    new.operation = "update_record".into();
    new.arguments = json!({"id":"70110000-0000-4000-8000-000000000001","body_append":"private content","idempotency_key":"v3-key","reason":"test"});
    let entry = journal.begin_legacy_kernel_v2(new, "a".repeat(64)).unwrap();
    journal
        .hold(
            &entry.id,
            HoldReason::HostedUnreachable,
            "held".into(),
            false,
        )
        .unwrap();
    assert!(journal
        .update(&entry.id, |entry| entry
            .kernel_v2_custody
            .as_mut()
            .unwrap()
            .binding
            .account_id = "account-b".into())
        .is_err());
    drop(journal);
    let legacy = Journal::open(temp.path(), Duration::from_secs(3600)).unwrap();
    assert!(legacy.get(&entry.id).is_none());
    assert_eq!(legacy.status()["unreadable_files"], 1);
    drop(legacy);
    let mut wrong = binding.clone();
    wrong.history_lineage = "v2:origin:restored-genesis".into();
    let other = Journal::open_bound(
        temp.path(),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        Some(wrong),
    )
    .unwrap();
    assert!(other.get(&entry.id).is_none());
    drop(other);
    let reopened = Journal::open_bound(
        temp.path(),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        Some(binding),
    )
    .unwrap();
    assert_eq!(reopened.get(&entry.id).unwrap().state, EntryState::Pending);
    assert_eq!(reopened.pending_count(), 1);
}

fn combined_custody_binding() -> CustodyBinding {
    CustodyBinding {
        account_id: "account-combined".into(),
        database_id: "route-combined".into(),
        origin_database_id: "canonical-origin".into(),
        history_lineage: "v2:origin:genesis".into(),
        resource_origin: "https://native.example".into(),
        install_id: None,
    }
}

fn combined_append(key: &str) -> NewEntry {
    let mut new = new_entry(Some(key), "combined draft");
    new.operation = "update_record".into();
    new.arguments = json!({"id":"70110000-0000-4000-8000-0000000000aa",
        "body_append":"combined draft","reason":"combined format proof","idempotency_key":key});
    new
}

#[test]
fn combined_custody_formats_reopen_pending_and_terminal_receipts_in_their_namespaces() {
    let root = socket_directory();
    let scope = socket_directory();
    let binding = combined_custody_binding();
    let retention = Duration::from_secs(3600);
    let legacy = Journal::open(root.path(), retention).unwrap();
    let scoped =
        Journal::open_bound(scope.path(), retention, retention, Some(binding.clone())).unwrap();
    let v4 = legacy.begin(combined_append("legacy-v4")).unwrap();
    legacy
        .hold_with_contract(
            &v4.id,
            HoldReason::DeploymentReadOnly,
            "legacy guidance drift".into(),
            false,
            Some(CustodyCompatibility::SourceDescriptionOnly),
        )
        .unwrap();
    let v3 = scoped
        .begin_legacy_kernel_v2(combined_append("scoped-v3"), "a".repeat(64))
        .unwrap();
    scoped
        .hold(
            &v3.id,
            HoldReason::DeploymentReadOnly,
            "exact v2 contract".into(),
            false,
        )
        .unwrap();
    drop(legacy);
    drop(scoped);
    let legacy = Journal::open(root.path(), retention).unwrap();
    let scoped =
        Journal::open_bound(scope.path(), retention, retention, Some(binding.clone())).unwrap();
    let legacy_entry = legacy.get(&v4.id).unwrap();
    let scoped_entry = scoped.get(&v3.id).unwrap();
    assert_eq!(legacy_entry.version, DESCRIPTION_CUSTODY_VERSION);
    assert_eq!(scoped_entry.version, 3);
    assert!(legacy_entry.kernel_v2_custody.is_none());
    assert!(scoped_entry.custody_compatibility.is_none());
    assert_eq!(legacy_entry.state, EntryState::Pending);
    assert_eq!(scoped_entry.state, EntryState::Pending);
    for entry in [&legacy_entry, &scoped_entry] {
        assert!(!super::super::pending_fork::previewable(entry));
    }
    for (journal, id) in [(&legacy, &v4.id), (&scoped, &v3.id)] {
        journal
            .finish_held(
                id,
                EntryState::Confirmed,
                Some("receipt"),
                "canonical receipt".into(),
                Some(
                    json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"applied":true}}})
                        .to_string(),
                ),
                false,
                None,
            )
            .unwrap();
    }
    drop(legacy);
    drop(scoped);
    let legacy = Journal::open(root.path(), retention).unwrap();
    let scoped = Journal::open_bound(scope.path(), retention, retention, Some(binding)).unwrap();
    assert_eq!(legacy.status()["unreadable_files"], 0);
    assert_eq!(scoped.status()["unreadable_files"], 0);
    for entry in [legacy.get(&v4.id).unwrap(), scoped.get(&v3.id).unwrap()] {
        assert_eq!(entry.state, EntryState::Confirmed);
        assert_eq!(entry.answer.as_deref(), Some("receipt"));
        assert!(entry.arguments.is_none() && entry.envelope.is_none());
        assert!(!super::super::pending_fork::previewable(&entry));
    }
    // The format's own reader still cannot adopt the other namespace.
    let wrong_legacy = Journal::open(scope.path(), retention).unwrap();
    assert!(wrong_legacy.get(&v3.id).is_none());
    assert_eq!(wrong_legacy.status()["unreadable_files"], 1);
    let wrong_scoped = Journal::open_bound(
        root.path(),
        retention,
        retention,
        Some(combined_custody_binding()),
    )
    .unwrap();
    assert!(wrong_scoped.get(&v4.id).is_none());
    assert_eq!(wrong_scoped.status()["unreadable_files"], 1);
}

#[test]
fn combined_custody_formats_reject_dual_markers_and_cross_promotion_atomically() {
    let root = socket_directory();
    let scope = socket_directory();
    let retention = Duration::from_secs(3600);
    let legacy = Journal::open(root.path(), retention).unwrap();
    let scoped = Journal::open_bound(
        scope.path(),
        retention,
        retention,
        Some(combined_custody_binding()),
    )
    .unwrap();
    let v4 = legacy
        .begin(combined_append("legacy-v4-immutable"))
        .unwrap();
    let v4 = legacy
        .hold_with_contract(
            &v4.id,
            HoldReason::DeploymentReadOnly,
            "held".into(),
            false,
            Some(CustodyCompatibility::SourceDescriptionOnly),
        )
        .unwrap();
    let v3 = scoped
        .begin_legacy_kernel_v2(combined_append("scoped-v3-immutable"), "a".repeat(64))
        .unwrap();
    let v3 = scoped
        .hold(&v3.id, HoldReason::DeploymentReadOnly, "held".into(), false)
        .unwrap();
    let v3_bytes = fs::read(scoped.path(&v3.id)).unwrap();
    let v4_bytes = fs::read(legacy.path(&v4.id)).unwrap();
    for version in [ENTRY_VERSION, DESCRIPTION_CUSTODY_VERSION] {
        assert!(scoped
            .update(&v3.id, |entry| {
                entry.version = version;
                entry.custody_compatibility = Some(CustodyCompatibility::SourceDescriptionOnly);
            })
            .is_err());
    }
    assert!(scoped
        .update(&v3.id, |entry| {
            entry.custody_compatibility = Some(CustodyCompatibility::SourceDescriptionOnly);
        })
        .is_err());
    assert!(scoped
        .hold_with_contract(
            &v3.id,
            HoldReason::DeploymentReadOnly,
            "must not promote".into(),
            true,
            Some(CustodyCompatibility::PriorAttemptUnverified)
        )
        .is_err());
    assert!(legacy
        .update(&v4.id, |entry| entry.kernel_v2_custody =
            v3.kernel_v2_custody.clone())
        .is_err());
    assert!(legacy
        .update(&v4.id, |entry| {
            entry.version = 3;
            entry.custody_compatibility = None;
            entry.kernel_v2_custody = v3.kernel_v2_custody.clone();
        })
        .is_err());
    assert_eq!(fs::read(scoped.path(&v3.id)).unwrap(), v3_bytes);
    assert_eq!(fs::read(legacy.path(&v4.id)).unwrap(), v4_bytes);
    assert_eq!(
        serde_json::to_value(scoped.get(&v3.id).unwrap()).unwrap(),
        serde_json::to_value(&v3).unwrap()
    );
    assert_eq!(
        serde_json::to_value(legacy.get(&v4.id).unwrap()).unwrap(),
        serde_json::to_value(&v4).unwrap()
    );
    // Both operation shapes are valid update_record calls. Only the mixed
    // format markers, not a forbidden v2 operation, make these files invalid.
    for version in [ENTRY_VERSION, 3, DESCRIPTION_CUSTODY_VERSION] {
        let mut mixed = v4.clone();
        mixed.version = version;
        mixed.kernel_v2_custody = v3.kernel_v2_custody.clone();
        let path = legacy.path(&v4.id);
        fs::write(&path, serde_json::to_vec(&mixed).unwrap()).unwrap();
        assert!(read_entry(&path).is_err(), "mixed format version {version}");
    }
    fs::write(legacy.path(&v4.id), &v4_bytes).unwrap();
    assert!(read_entry(&legacy.path(&v4.id))
        .unwrap()
        .valid_description_custody());
    assert_eq!(read_entry(&scoped.path(&v3.id)).unwrap().version, 3);
}

// This runs on the actual pre-manager/default reader surface. Its unknown
// field handling and newer-version guard must preserve v5 content on rollback.
#[cfg(not(feature = "v2-kernel-probe"))]
#[test]
fn unsupported_working_v5_is_preserved_without_replay_or_compaction() {
    assert_working_decoder_unavailable(5);
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(Some("working-original"), "retained original"))
        .unwrap();
    let path = journal.path(&entry.id);
    let mut value = serde_json::to_value(entry).unwrap();
    value["version"] = json!(5);
    value["working_original"] =
        json!({"actor":"original", "request_fingerprint":"a".repeat(64), "identity":"FirstParty"});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    drop(journal);
    let reader = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(reader.status()["unreadable_files"], 1);
    assert!(reader.get(value["id"].as_str().unwrap()).is_none());
    reader.prune();
    assert_eq!(fs::read(path).unwrap(), bytes);
}

// Actual default/older-format reader: unsupported installed custody is kept
// opaque, never replayed or pruned. This fixture supplies no ingress authority.
#[cfg(not(feature = "v2-kernel-probe"))]
#[test]
fn unsupported_installed_working_v7_is_preserved_without_replay_or_compaction() {
    assert_working_decoder_unavailable(7);
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(Some("working-original"), "retained original"))
        .unwrap();
    let path = journal.path(&entry.id);
    let mut value = serde_json::to_value(entry).unwrap();
    value["version"] = json!(INSTALLED_WORKING_VERSION);
    value["working_original"] =
        json!({"actor":"original", "request_fingerprint":"a".repeat(64), "identity":"FirstParty"});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    drop(journal);
    let reader = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(reader.status()["unreadable_files"], 1);
    assert!(reader.get(value["id"].as_str().unwrap()).is_none());
    reader.prune();
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[cfg(not(feature = "v2-kernel-probe"))]
#[test]
fn unsupported_installed_working_v8_create_is_preserved_without_replay_or_compaction() {
    assert_working_decoder_unavailable(8);
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(
            Some("unsupported-final-create"),
            "retained create content",
        ))
        .unwrap();
    let path = journal.path(&entry.id);
    let mut value = serde_json::to_value(entry).unwrap();
    value["version"] = json!(INSTALLED_CREATE_VERSION);
    value["operation"] = json!("create_record");
    value["working_original"] = json!({"actor":"original","request_fingerprint":"retained provider JSON","identity":{"FirstPartyCreate":{"context":"first-party"}}});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    drop(journal);
    let reader = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(reader.status()["unreadable_files"], 1);
    assert!(reader.get(value["id"].as_str().unwrap()).is_none());
    reader.prune();
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[cfg(not(feature = "v2-kernel-probe"))]
#[test]
fn unsupported_installed_working_v9_records_is_preserved_without_replay_or_compaction() {
    assert_working_decoder_unavailable(9);
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let entry = journal
        .begin(new_entry(
            Some("unsupported-family-original"),
            "retained create content",
        ))
        .unwrap();
    let path = journal.path(&entry.id);
    let mut value = serde_json::to_value(entry).unwrap();
    value["version"] = json!(INSTALLED_RECORD_VERSION);
    value["operation"] = json!("update_record");
    value["working_original"] = json!({"actor":"original","request_fingerprint":"retained provider JSON","identity":{"Record":{"operation":"update","mint_context":null}},"native_arguments":{"id":"11111111-1111-4111-8111-111111111111","name":"Retain this unsynced name","idempotency_key":"unsupported-family-original"}});
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    drop(journal);
    let reader = Journal::open(temp.path(), Duration::ZERO).unwrap();
    assert_eq!(reader.status()["unreadable_files"], 1);
    assert!(reader.get(value["id"].as_str().unwrap()).is_none());
    reader.prune();
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn installed_working_operator_refusal_is_format_based_even_for_invalid_codec_state() {
    let temp = tempfile::tempdir().unwrap();
    let journal = Journal::open(temp.path(), Duration::ZERO).unwrap();
    let mut entry = journal
        .begin(new_entry(Some("invalid-v7-format"), "retained"))
        .unwrap();
    entry.version = INSTALLED_WORKING_VERSION; // Deliberately lacks the installed codec's original/scope fields.
    let id = entry.id.clone();
    journal.write(&entry).unwrap();
    journal.entries.lock().unwrap().insert(id.clone(), entry);
    let bytes = fs::read(journal.path(&id)).unwrap();
    for outcome in [None, Some("not_applied")] {
        let error = journal
            .operator_decision(&id, outcome, "format boundary", 0, None)
            .unwrap_err();
        assert!(
            error.to_string().contains("qualified reconciliation"),
            "{error}"
        );
        assert_eq!(fs::read(journal.path(&id)).unwrap(), bytes);
        assert!(journal.get(&id).unwrap().operator_audit.is_none());
    }
}

#[test]
fn forwarded_uncertainty_is_visible_without_changing_custody() {
    let temp = socket_directory();
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let entry = journal
        .begin(new_entry(Some("legacy-key"), "private original"))
        .unwrap();
    journal
        .settle(
            &entry.id,
            EntryState::Uncertain,
            None,
            Some("reply lost".into()),
        )
        .unwrap();
    let before = fs::read(journal.directory().join(format!("{}.json", entry.id))).unwrap();
    let view = journal.held_writes(
        &StatusFilter {
            states: vec!["uncertain".into()],
            limit: 5,
            ..Default::default()
        },
        None,
    );
    assert_eq!(view["matched"], 1);
    assert_eq!(view["writes"][0]["id"], entry.id);
    assert_eq!(view["counts"]["uncertain"], 1);
    assert_eq!(journal.held_counts_for_run("run-1").0["uncertain"], 1);
    let summary = journal.waiting_summary();
    assert_eq!(summary["waiting"], 1);
    assert_eq!(summary["oldest_accepted_at"], entry.received_at);
    assert!(!view.to_string().contains("private original"));
    assert!(!summary.to_string().contains("A title"));
    assert!(
        journal.oldest_pending().is_none(),
        "forwards never become the replay queue"
    );
    assert_eq!(
        fs::read(journal.directory().join(format!("{}.json", entry.id))).unwrap(),
        before
    );
    journal
        .operator_decision(
            &entry.id,
            Some("landed"),
            "test canonical evidence",
            42,
            None,
        )
        .unwrap();
    assert_eq!(journal.waiting_summary()["waiting"], 0);
    assert_eq!(
        journal.held_writes(
            &StatusFilter {
                limit: 5,
                ..Default::default()
            },
            None
        )["counts"]["acknowledged"],
        1
    );
}

// The persistence format is engine-independent. Hosted-v2 descriptors and actual
// replay are exercised by gate/v2_holding_tests.rs in the existing v2 lane.
fn v6_original() -> (String, OriginalContract) {
    let contract = crate::mcp::executor_prototype::NodeOperationContracts::local()
        .unwrap()
        .holding_contract("records_write", "update_record")
        .unwrap()
        .for_custody()
        .unwrap();
    (
        contract.description["contract_digest"]
            .as_str()
            .unwrap()
            .into(),
        OriginalContract { rule: 1, contract },
    )
}

#[test]
fn v6_evidence_and_request_tampering_cannot_change_or_discard_held_content() {
    let temp = socket_directory();
    let journal = Journal::open_bound(
        temp.path(),
        Duration::ZERO,
        Duration::ZERO,
        Some(combined_custody_binding()),
    )
    .unwrap();
    let (digest, original) = v6_original();
    let entry = journal
        .begin_kernel_v2(combined_append("v6-immutable"), digest, original)
        .unwrap();
    journal
        .hold(
            &entry.id,
            HoldReason::HostedUnreachable,
            "held".into(),
            false,
        )
        .unwrap();
    for mutation in 0..11 {
        assert!(
            journal
                .update(&entry.id, |e| match mutation {
                    0 =>
                        e.kernel_v2_custody
                            .as_mut()
                            .unwrap()
                            .original
                            .as_mut()
                            .unwrap()
                            .rule = 99,
                    1 =>
                        e.kernel_v2_custody
                            .as_mut()
                            .unwrap()
                            .original
                            .as_mut()
                            .unwrap()
                            .contract
                            .description["contract_version"] = json!("other"),
                    2 => e.arguments.as_mut().unwrap()["body_append"] = json!("changed"),
                    3 => e.envelope = None,
                    4 => e.idempotency_key = Some("other-key".into()),
                    5 => e.arguments_digest = "other".into(),
                    6 => e.intent_digest = None,
                    7 => e.id = uuid::Uuid::new_v4().to_string(),
                    8 => e.received_at = "2000-01-01T00:00:00Z".into(),
                    9 => e.received_unix_ms = 0,
                    _ => e.version = 3,
                })
                .is_err(),
            "mutation {mutation}"
        );
    }
    let kept = journal.get(&entry.id).unwrap();
    assert_eq!(kept.arguments, entry.arguments);
    assert_eq!(kept.kernel_v2_custody, entry.kernel_v2_custody);
    journal.prune();
    drop(journal);
    let journal = Journal::open_bound(
        temp.path(),
        Duration::ZERO,
        Duration::ZERO,
        Some(combined_custody_binding()),
    )
    .unwrap();
    assert_eq!(journal.get(&entry.id).unwrap().arguments, entry.arguments);
}

#[test]
fn v6_load_refuses_malformed_evidence_without_pruning_or_rewriting_it() {
    let temp = socket_directory();
    let binding = combined_custody_binding();
    let journal = Journal::open_bound(
        temp.path(),
        Duration::ZERO,
        Duration::ZERO,
        Some(binding.clone()),
    )
    .unwrap();
    let (digest, original) = v6_original();
    let entry = journal
        .begin_kernel_v2(combined_append("v6-malformed"), digest, original)
        .unwrap();
    let path = journal.path(&entry.id);
    drop(journal);
    let valid = serde_json::to_value(&entry).unwrap();
    let mut unknown_container = valid["kernel_v2_custody"]["original"]["contract"].clone();
    unknown_container["future_authority"] = json!(true);
    for (pointer, value) in [
        ("/kernel_v2_custody/original/contract", unknown_container),
        ("/kernel_v2_custody/original/rule", json!(99)),
        ("/kernel_v2_custody/contract_digest", json!("not-a-digest")),
        (
            "/kernel_v2_custody/original/contract/description/contract_digest",
            json!("0".repeat(64)),
        ),
        (
            "/kernel_v2_custody/original/contract/description/executor",
            json!("other"),
        ),
        (
            "/kernel_v2_custody/original/contract/description/operation",
            json!("other"),
        ),
        (
            "/kernel_v2_custody/original/contract/catalog",
            json!({"access":"mutation","requires_acceptance":false,"plan_required":false}),
        ),
        (
            "/kernel_v2_custody/original/contract/catalog",
            json!({"access":"mutation","requires_acceptance":false,"plan_required":false,"direct_execution_enabled":true,"extra":false}),
        ),
        (
            "/kernel_v2_custody/original/contract/description/source",
            json!("malformed"),
        ),
    ] {
        let mut value_on_disk = valid.clone();
        *value_on_disk.pointer_mut(pointer).unwrap() = value;
        let bytes = serde_json::to_vec(&value_on_disk).unwrap();
        fs::write(&path, &bytes).unwrap();
        let opened = Journal::open_bound(
            temp.path(),
            Duration::ZERO,
            Duration::ZERO,
            Some(binding.clone()),
        )
        .unwrap();
        assert!(opened.get(&entry.id).is_none(), "{pointer}");
        assert!(opened.has_opaque_custody());
        assert_eq!(opened.status()["unreadable_custody"]["status"], "needs_you");
        opened.prune();
        assert_eq!(fs::read(&path).unwrap(), bytes, "{pointer}");
    }
}

#[test]
fn v6_maximum_legacy_request_and_bounded_evidence_fit_and_reopen() {
    let temp = socket_directory();
    let binding = combined_custody_binding();
    let journal = Journal::open_bound(
        temp.path(),
        Duration::from_secs(3600),
        Duration::from_secs(3600),
        Some(binding.clone()),
    )
    .unwrap();
    let (digest, mut original) = v6_original();
    for operation in ["update_record", "manage_links.add", "attach_text"] {
        let c = crate::mcp::executor_prototype::NodeOperationContracts::local()
            .unwrap()
            .holding_contract("records_write", operation)
            .unwrap()
            .for_custody()
            .unwrap();
        assert!(serde_json::to_vec(&c).unwrap().len() < MAX_CONTRACT_EVIDENCE_BYTES as usize);
    }
    let mut entry = journal
        .make_entry(combined_append("v6-largest"), None, None, Some(digest))
        .unwrap();
    let resize = |entry: &mut Entry, len: usize| {
        entry.arguments.as_mut().unwrap()["body_append"] = json!("x".repeat(len));
        entry.arguments_bytes = entry.arguments.as_ref().unwrap().to_string().len();
        entry.arguments_digest = scoped_arguments_digest(entry.arguments.as_ref().unwrap(), None);
    };
    let (mut lo, mut hi) = (0, MAX_ENTRY_BYTES as usize);
    while lo < hi {
        let n = (lo + hi).div_ceil(2);
        resize(&mut entry, n);
        if serde_json::to_vec(&entry).unwrap().len() <= MAX_ENTRY_BYTES as usize {
            lo = n
        } else {
            hi = n - 1
        }
    }
    resize(&mut entry, lo);
    journal.write(&entry).unwrap();
    resize(&mut entry, lo + 1);
    assert!(journal.write(&entry).is_err(), "old bound is exercised");
    resize(&mut entry, lo);
    original.contract.description["bounded_future_field"] = json!("");
    let remaining =
        MAX_CONTRACT_EVIDENCE_BYTES as usize - serde_json::to_vec(&original).unwrap().len();
    original.contract.description["bounded_future_field"] = json!("y".repeat(remaining));
    assert_eq!(
        serde_json::to_vec(&original).unwrap().len(),
        MAX_CONTRACT_EVIDENCE_BYTES as usize
    );
    entry.version = 6;
    entry.kernel_v2_custody.as_mut().unwrap().original = Some(original);
    assert!(entry.valid_v6());
    journal.write(&entry).unwrap();
    let read = read_entry(&journal.path(&entry.id)).unwrap();
    assert_eq!(read.arguments, entry.arguments);
    assert_eq!(read.kernel_v2_custody, entry.kernel_v2_custody);
}

// Step 4 cross-version upgrade fixtures (root journal only). Each test writes
// entries, drops the journal (shutdown), and reopens it from disk
// (upgrade/restart) instead of reusing in-memory state.

/// (a) A held `Pending` write keeps its identity and fingerprints across restart.
#[test]
fn upgrade_pending_keeps_identity_and_fingerprints_across_restart() {
    let temp = socket_directory();
    let (id, digest, intent) = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let entry = journal
            .begin(new_entry(Some("upgrade-a"), "pending body"))
            .unwrap();
        let held = journal
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        assert_eq!(held.state, EntryState::Pending);
        // Capture fingerprints before shutdown; the post-restart entry must
        // match these, not merely the file it was just loaded from.
        (
            entry.id,
            held.arguments_digest.clone(),
            held.intent_digest.clone(),
        )
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let recovered = journal.get(&id).unwrap();
    assert_eq!(recovered.state, EntryState::Pending);
    assert_eq!(recovered.idempotency_key.as_deref(), Some("upgrade-a"));
    assert_eq!(recovered.key_origin, Some(KeyOrigin::Caller));
    assert_eq!(recovered.run_key.as_deref(), Some("run-1"));
    assert_eq!(recovered.parent_key.as_deref(), Some("parent-run"));
    assert_eq!(recovered.hold_reason, Some(HoldReason::HostedUnreachable));
    assert_eq!(recovered.title.as_deref(), Some("A title"));
    assert_eq!(
        recovered.record_id.as_deref(),
        Some("70110000-0000-4000-8000-0000000000aa")
    );
    assert_eq!(
        recovered.arguments.as_ref().unwrap()["body"],
        "pending body"
    );
    assert_eq!(recovered.arguments_digest, digest);
    assert_eq!(recovered.intent_digest, intent);
    // Fingerprints survive byte-for-byte on disk.
    let on_disk: Value = serde_json::from_slice(
        &fs::read(temp.path().join("journal").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(on_disk["arguments_digest"], json!(digest));
    assert_eq!(on_disk["intent_digest"], json!(intent));
    // Still the queue's oldest waiting write: nothing was lost or resent.
    assert_eq!(journal.oldest_pending().map(|e| e.id), Some(id));
}

/// (b) A held `Pending` entry caught mid-send restarts `Pending` with
/// `maybe_applied`; only replay-safe entries are resent automatically.
#[test]
fn upgrade_pending_send_at_shutdown_restarts_pending_with_maybe_applied() {
    let temp = socket_directory();
    let id = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let entry = journal
            .begin(new_entry(Some("upgrade-b"), "held body"))
            .unwrap();
        // Production only sends `Pending` entries: the queue drains
        // `next_pending`, and `begin_queue_send` runs on that send path
        // (src/node/gate/queue.rs:322). One in-flight attempt, then shutdown.
        journal
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        let sending = journal.begin_queue_send(&entry.id).unwrap();
        assert!(sending.in_flight);
        assert!(!sending.maybe_applied, "no earlier attempt survived yet");
        entry.id
    };
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    let recovered = journal.get(&id).unwrap();
    assert_eq!(recovered.state, EntryState::Pending);
    assert!(
        recovered.maybe_applied,
        "the interrupted send may have applied"
    );
    assert!(!recovered.in_flight);
    assert_eq!(recovered.attempts, 1);
    assert_eq!(recovered.arguments.as_ref().unwrap()["body"], "held body");
    // Whether it is resent automatically depends on replay safety
    // (`automatic_replay_safe`, src/node/gate.rs:2755; unsafe entries become
    // `Uncertain` instead, src/node/gate/queue.rs:397-404). That gate-level
    // outcome is proved by the queue rig tests
    // (`restart_between_send_and_reply_leaves_an_honest_uncertain_entry_and_no_duplicate`
    // at src/node/gate/tests.rs:1081 and
    // `batch_queue_lost_reply_and_recovered_in_flight_marker_stop_replay` at
    // src/node/gate/tests.rs:5013), not by journal state alone.
    let on_disk: Value = serde_json::from_slice(
        &fs::read(temp.path().join("journal").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(on_disk["state"], "pending");
    assert_eq!(on_disk["maybe_applied"], json!(true));
}

/// (c) A newer-version entry file is unreadable, retained, and blocks custody.
#[test]
fn upgrade_newer_version_file_is_unreadable_retained_and_blocks_custody() {
    let temp = socket_directory();
    let (known, future) = {
        let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
        let known = journal
            .begin(new_entry(Some("upgrade-c"), "known"))
            .unwrap()
            .id;
        // A future build's file: same shape, a version this build does not know.
        let path = temp.path().join("journal").join(format!("{known}.json"));
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved["id"] = json!("future-entry");
        saved["version"] = json!(999);
        fs::write(
            temp.path().join("journal").join("future-entry.json"),
            serde_json::to_vec(&saved).unwrap(),
        )
        .unwrap();
        drop(journal);
        (known, "future-entry".to_string())
    };
    // Restart onto the "older" build: the future file is counted, not parsed.
    let journal = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    assert!(journal.get(&future).is_none());
    assert!(journal.get(&known).is_some(), "known entries still load");
    assert_eq!(journal.status()["unreadable_files"], json!(1));
    // The gate consults `has_opaque_custody` before admitting body writes
    // (src/node/gate.rs:1315-1327; src/node/gate/body_merge.rs:407,519):
    // unreadable custody blocks appends until roll-forward.
    assert!(journal.has_opaque_custody());
    // Outcome, not just the flag: an unreadable file may hold the predecessor
    // for any record, so the body barrier stays up for ordinary appends.
    assert!(journal.has_open_body_custody("70110000-0000-4000-8000-0000000000aa", false));
    // Body-merge erasure cannot be established while files are unreadable.
    assert!(journal.forget_merges().is_err());
    // Pruning and another restart never delete or downgrade the future file.
    journal.prune();
    let future_path = temp.path().join("journal").join("future-entry.json");
    assert!(future_path.exists());
    drop(journal);
    let again = Journal::open(temp.path(), CONFIRMED_RETENTION).unwrap();
    assert_eq!(again.status()["unreadable_files"], json!(1));
    assert!(again.get(&future).is_none());
    let saved: Value = serde_json::from_slice(&fs::read(&future_path).unwrap()).unwrap();
    assert_eq!(saved["version"], 999);
}

/// (d) Pruning follows the upgrade matrix, using seeded `updated_at` stamps.
///
/// Only `Confirmed` and `NotSent` prune at 1 h; held refusals get 7 d; every
/// other state is retained (src/node/journal.rs:2075-2150, matrix at
/// 2123-2143). `update` restamps `updated_at` (src/node/journal.rs:1212), so
/// fixtures seed it in the files, then restart: `open` prunes at startup with
/// the running node's retentions. (`Acknowledged` retention is covered by
/// `operator_acknowledgement_retains_request_and_audit_across_restart_and_prune`.)
#[test]
fn upgrade_pruning_follows_the_matrix_with_seeded_timestamps() {
    use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
    let hours_ago =
        |h: i64| (Utc::now() - ChronoDuration::hours(h)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let days_ago =
        |d: i64| (Utc::now() - ChronoDuration::days(d)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let temp = socket_directory();
    // (key, id, updated_at seed). `None` keeps the fresh stamp from this run.
    let seeds: Vec<(&str, String, Option<String>)> = {
        let journal = Journal::open_with(
            temp.path(),
            Duration::from_secs(3600),
            Duration::from_secs(7 * 24 * 3600),
        )
        .unwrap();
        let mut out = Vec::new();
        let settle_old = |key: &str, state: EntryState, answer: Option<&str>| {
            let entry = journal.begin(new_entry(Some(key), key)).unwrap();
            journal
                .settle(&entry.id, state, answer, Some("seeded".into()))
                .unwrap();
            entry.id
        };
        // Terminal, older than 1 h: pruned.
        out.push((
            "d-receipt-old",
            settle_old("d-receipt-old", EntryState::Confirmed, Some("receipt")),
            Some(hours_ago(2)),
        ));
        out.push((
            "d-notsent-old",
            settle_old("d-notsent-old", EntryState::NotSent, None),
            Some(hours_ago(2)),
        ));
        // Terminal receipt, fresh: retained (arguments already dropped by settle).
        out.push((
            "d-receipt-fresh",
            settle_old("d-receipt-fresh", EntryState::Confirmed, Some("receipt")),
            None,
        ));
        // Held refusals: 2 h is inside the 7 d refusal retention, 8 d is out.
        for (key, stamp) in [
            ("d-refused-kept", hours_ago(2)),
            ("d-refused-old", days_ago(8)),
        ] {
            let entry = journal.begin(new_entry(Some(key), key)).unwrap();
            journal
                .hold(
                    &entry.id,
                    HoldReason::DeploymentReadOnly,
                    "held".into(),
                    false,
                )
                .unwrap();
            journal
                .finish_held(
                    &entry.id,
                    EntryState::Confirmed,
                    Some("refused"),
                    "no".into(),
                    None,
                    true,
                    None,
                )
                .unwrap();
            out.push((key, entry.id, Some(stamp)));
        }
        // Open states, older than 8 d: never pruned.
        let pending = journal
            .begin(new_entry(Some("d-pending-old"), "d-pending-old"))
            .unwrap();
        journal
            .hold(
                &pending.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        out.push(("d-pending-old", pending.id, Some(days_ago(8))));
        out.push((
            "d-uncertain-old",
            settle_old("d-uncertain-old", EntryState::Uncertain, None),
            Some(days_ago(8)),
        ));
        let hosted = journal
            .begin(new_entry(Some("d-hosted-old"), "d-hosted-old"))
            .unwrap();
        journal
            .hosted_pending(&hosted.id, Some("handle-d".into()))
            .unwrap();
        out.push(("d-hosted-old", hosted.id, Some(days_ago(8))));
        // Unresolved outcomes, older than 8 d: never pruned.
        for (key, state) in [
            ("d-committed-old", EntryState::CommittedUnrecovered),
            ("d-result-old", EntryState::ResultUnrecovered),
        ] {
            let entry = journal.begin(new_entry(Some(key), key)).unwrap();
            journal.update(&entry.id, |e| e.state = state).unwrap();
            out.push((key, entry.id, Some(days_ago(8))));
        }
        drop(journal);
        out
    };
    for (_, id, stamp) in &seeds {
        if let Some(stamp) = stamp {
            let path = temp.path().join("journal").join(format!("{id}.json"));
            let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            saved["updated_at"] = json!(stamp);
            fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        }
    }
    let journal = Journal::open_with(
        temp.path(),
        Duration::from_secs(3600),
        Duration::from_secs(7 * 24 * 3600),
    )
    .unwrap();
    journal.prune();
    let id_of = |key: &str| {
        seeds
            .iter()
            .find(|(k, _, _)| *k == key)
            .map(|(_, id, _)| id.clone())
            .unwrap()
    };
    let live = |key: &str| journal.get(&id_of(key)).is_some();
    // Terminal entries older than 1 h prune; a fresh receipt is retained.
    assert!(!live("d-receipt-old"), "1 h Confirmed receipt prunes");
    assert!(!live("d-notsent-old"), "1 h NotSent prunes");
    assert!(live("d-receipt-fresh"), "fresh Confirmed receipt retained");
    // Held refusal at 2 h retained with its arguments; at 8 d pruned.
    assert!(live("d-refused-kept"), "2 h held refusal retained");
    assert_eq!(
        journal
            .get(&id_of("d-refused-kept"))
            .unwrap()
            .arguments
            .as_ref()
            .unwrap()["body"],
        "d-refused-kept"
    );
    assert!(!live("d-refused-old"), "8 d held refusal prunes");
    // Open and unresolved states survive far past every retention.
    for key in [
        "d-pending-old",
        "d-uncertain-old",
        "d-hosted-old",
        "d-committed-old",
        "d-result-old",
    ] {
        assert!(live(key), "{key} retained past every retention");
    }
    assert_eq!(
        journal
            .get(&id_of("d-pending-old"))
            .unwrap()
            .arguments
            .as_ref()
            .unwrap()["body"],
        "d-pending-old"
    );
    // Pruned files are gone from disk; retained ones are intact.
    assert!(!temp
        .path()
        .join("journal")
        .join(format!("{}.json", id_of("d-receipt-old")))
        .exists());
    assert!(temp
        .path()
        .join("journal")
        .join(format!("{}.json", id_of("d-refused-kept")))
        .exists());
}

/// Second upgrade PR (a): a v6 entry in `v2-held/<hash>/journal/` survives
/// restart with its original contract evidence, key and fingerprints intact.
/// The entry is reached after restart through the production
/// `scoped_v2_gate` derivation, so a change to the namespace derivation is
/// caught instead of silently opening an empty namespace.
#[cfg(feature = "v2-kernel-probe")]
#[test]
fn upgrade_v6_scoped_entry_survives_restart_with_evidence_key_and_fingerprints() {
    let temp = socket_directory();
    let binding = combined_custody_binding();
    let namespace_key =
        crate::canonical_json::digest_json(&serde_json::to_value(&binding).unwrap());
    let held_root = temp.path().join("v2-held");
    fs::create_dir(&held_root).unwrap();
    fs::set_permissions(&held_root, fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = held_root.join(&namespace_key);
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
    let retention = Duration::from_secs(3600);
    let (id, seq, args_digest, intent_digest, contract_digest, original_bytes) = {
        let journal =
            Journal::open_bound(&namespace, retention, retention, Some(binding.clone())).unwrap();
        assert_eq!(journal.directory(), namespace.join("journal"));
        let (digest, original) = v6_original();
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let entry = journal
            .begin_kernel_v2(
                combined_append("upgrade-v6-survive"),
                digest.clone(),
                original,
            )
            .unwrap();
        let held = journal
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        assert_eq!(held.version, V2_EVIDENCE_VERSION);
        (
            entry.id,
            held.seq,
            held.arguments_digest.clone(),
            held.intent_digest.clone(),
            digest,
            original_bytes,
        )
    };
    let journal =
        Journal::open_bound(&namespace, retention, retention, Some(binding.clone())).unwrap();
    let recovered = journal.get(&id).unwrap();
    assert_eq!(recovered.version, V2_EVIDENCE_VERSION);
    assert_eq!(recovered.state, EntryState::Pending);
    assert_eq!(recovered.seq, seq);
    assert_eq!(
        recovered.idempotency_key.as_deref(),
        Some("upgrade-v6-survive")
    );
    assert_eq!(recovered.key_origin, Some(KeyOrigin::Caller));
    assert_eq!(recovered.run_key.as_deref(), Some("run-1"));
    assert_eq!(recovered.parent_key.as_deref(), Some("parent-run"));
    assert_eq!(
        recovered.record_id.as_deref(),
        Some("70110000-0000-4000-8000-0000000000aa")
    );
    assert_eq!(recovered.arguments_digest, args_digest);
    assert_eq!(recovered.intent_digest, intent_digest);
    assert_eq!(
        recovered.arguments.as_ref().unwrap()["body_append"],
        "combined draft"
    );
    let custody = recovered.kernel_v2_custody.as_ref().unwrap();
    assert_eq!(custody.engine, "native-kernel-v2");
    assert_eq!(custody.binding, binding);
    assert_eq!(custody.contract_digest, contract_digest);
    let stored = custody.original.as_ref().unwrap();
    assert_eq!(stored.rule, SOURCE_DESCRIPTION_RULE);
    assert_eq!(serde_json::to_vec(stored).unwrap(), original_bytes);
    assert!(recovered.valid_v6());
    let on_disk: Value = serde_json::from_slice(
        &fs::read(namespace.join("journal").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(on_disk["version"], 6);
    // Recompute the digest from the stored arguments instead of echoing the
    // value the test just wrote.
    assert_eq!(
        on_disk["arguments_digest"],
        json!(scoped_arguments_digest(&on_disk["arguments"], None))
    );
    assert_eq!(journal.status()["unreadable_files"], 0);
    assert_eq!(journal.oldest_pending().map(|e| e.id), Some(id.clone()));
    // The production namespace derivation reaches the same entry: a changed
    // derivation would open an empty namespace and fail here.
    let gate =
        super::super::gate::WriteGate::open(temp.path(), super::super::gate::GateConfig::default())
            .unwrap();
    let scoped = gate.scoped_v2_gate(&binding).unwrap();
    assert_eq!(scoped.journal.directory(), namespace.join("journal"));
    assert_eq!(scoped.journal.get(&id).unwrap().version, 6);
}

/// Second upgrade PR (b): an older-node load of v6 files counts them
/// unreadable, deletes/rewrites nothing, and keeps the body-custody barrier
/// up in that namespace until roll-forward. The load uses an injected reader
/// that refuses version >= 6 (reproduces the version ceiling only). The
/// refused-write outcome itself is proved at gate level by
/// `v2_compat_rollback_retains_sent_and_pending_files_blocks_all_appends_until_roll_forward`,
/// where `forward_scoped` refuses the append; here the journal proves the
/// counting, retention, and barrier-flag side of the same rollback.
#[cfg(feature = "v2-kernel-probe")]
#[test]
fn upgrade_v6_older_node_load_counts_unreadable_and_blocks_body_appends() {
    let temp = socket_directory();
    let binding = combined_custody_binding();
    let namespace_key =
        crate::canonical_json::digest_json(&serde_json::to_value(&binding).unwrap());
    let held_root = temp.path().join("v2-held");
    fs::create_dir(&held_root).unwrap();
    fs::set_permissions(&held_root, fs::Permissions::from_mode(0o700)).unwrap();
    let namespace = held_root.join(&namespace_key);
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
    let retention = Duration::from_secs(3600);
    let (id, bytes) = {
        let journal =
            Journal::open_bound(&namespace, retention, retention, Some(binding.clone())).unwrap();
        let (digest, original) = v6_original();
        let entry = journal
            .begin_kernel_v2(combined_append("upgrade-v6-rollback"), digest, original)
            .unwrap();
        journal
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        let path = journal.path(&entry.id);
        (entry.id, fs::read(&path).unwrap())
    };
    let older = Journal::open_bound_with_reader(
        &namespace,
        retention,
        retention,
        Some(binding.clone()),
        read_before_v6,
    )
    .unwrap();
    assert!(older.get(&id).is_none(), "older node cannot parse v6");
    assert_eq!(older.status()["unreadable_files"], 1);
    assert!(older.has_opaque_custody());
    assert!(
        older.has_open_body_custody("70110000-0000-4000-8000-0000000000aa", false),
        "an unreadable file may hold any record's predecessor, so appends block"
    );
    assert!(older.forget_merges().is_err());
    older.prune();
    let path = namespace.join("journal").join(format!("{id}.json"));
    assert_eq!(fs::read(&path).unwrap(), bytes, "prune must not rewrite v6");
    drop(older);
    let rolled =
        Journal::open_bound(&namespace, retention, retention, Some(binding.clone())).unwrap();
    assert_eq!(rolled.status()["unreadable_files"], 0);
    let recovered = rolled.get(&id).unwrap();
    assert_eq!(recovered.state, EntryState::Pending);
    assert_eq!(recovered.version, V2_EVIDENCE_VERSION);
    assert!(recovered.valid_v6());
    assert_eq!(
        recovered.arguments.as_ref().unwrap()["body_append"],
        "combined draft"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

/// Second upgrade PR (c): a v3 entry opened under the wrong namespace counts
/// as unreadable and is kept byte-for-byte; the bound namespace still loads it.
/// Beyond `v3_custody_reopens_only_in_its_bound_namespace_and_is_immutable`,
/// this test pins the byte-for-byte file check after prune.
#[test]
fn upgrade_namespace_mismatched_v3_is_unreadable_and_kept() {
    let temp = socket_directory();
    let binding = combined_custody_binding();
    let retention = Duration::from_secs(3600);
    let (id, bytes) = {
        let journal =
            Journal::open_bound(temp.path(), retention, retention, Some(binding.clone())).unwrap();
        let mut new = combined_append("upgrade-v3-scope");
        new.operation = "update_record".into();
        let entry = journal.begin_legacy_kernel_v2(new, "a".repeat(64)).unwrap();
        journal
            .hold(
                &entry.id,
                HoldReason::HostedUnreachable,
                "down".into(),
                false,
            )
            .unwrap();
        let path = journal.path(&entry.id);
        (entry.id, fs::read(&path).unwrap())
    };
    let mut wrong = binding.clone();
    wrong.history_lineage = "v2:origin:restored-genesis".into();
    let mismatched = Journal::open_bound(temp.path(), retention, retention, Some(wrong)).unwrap();
    assert!(
        mismatched.get(&id).is_none(),
        "wrong namespace must not adopt the entry"
    );
    assert_eq!(mismatched.status()["unreadable_files"], 1);
    assert!(mismatched.has_opaque_custody());
    mismatched.prune();
    let path = temp.path().join("journal").join(format!("{id}.json"));
    assert!(path.exists(), "mismatched entry must be retained");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    drop(mismatched);
    let bound = Journal::open_bound(temp.path(), retention, retention, Some(binding)).unwrap();
    assert_eq!(bound.status()["unreadable_files"], 0);
    let recovered = bound.get(&id).unwrap();
    assert_eq!(recovered.version, 3);
    assert_eq!(recovered.state, EntryState::Pending);
}

pub(super) fn assert_declared_entry(entry: &Entry, fresh_writer: &str) {
    let report = runtime_declaration();
    let rows = report["formats"].as_array().unwrap();
    let row = rows
        .iter()
        .find(|row| row["version"] == entry.version)
        .unwrap();
    assert_eq!(row["decoder_compiled"], true);
    assert_eq!(row["fresh_writer"], fresh_writer);
    assert_eq!(row["retained_entry_rewrite"], true);
    assert!(!row["continuation_conditions"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn runtime_declaration_tracks_real_journal_writers_and_retained_codecs() {
    let root = socket_directory();
    let scope = socket_directory();
    let journal = Journal::open(root.path(), CONFIRMED_RETENTION).unwrap();
    let ordinary = journal
        .begin(new_entry(Some("decl-ordinary"), "ordinary"))
        .unwrap();
    let merge = merge_entry(&journal, "R", "decl-merge");
    let scoped = Journal::open_bound(
        scope.path(),
        CONFIRMED_RETENTION,
        CONFIRMED_RETENTION,
        Some(combined_custody_binding()),
    )
    .unwrap();
    let legacy = scoped
        .begin_legacy_kernel_v2(combined_append("decl-legacy"), "a".repeat(64))
        .unwrap();
    let (digest, original) = v6_original();
    let keyed = scoped
        .begin_kernel_v2(combined_append("decl-keyed"), digest, original)
        .unwrap();
    let description = journal.begin(combined_append("decl-description")).unwrap();
    journal
        .hold_with_contract(
            &description.id,
            HoldReason::DeploymentReadOnly,
            "contract drift".into(),
            false,
            Some(CustodyCompatibility::SourceDescriptionOnly),
        )
        .unwrap();
    let description = journal.get(&description.id).unwrap();
    for (owner, entry, writer) in [
        (&journal, &ordinary, "production"),
        (&journal, &merge, "production"),
        (&scoped, &legacy, "test_only"),
        (&scoped, &keyed, "production"),
        (&journal, &description, "promotion_from_retained_v1"),
    ] {
        let decoded = read_entry(&owner.path(&entry.id)).unwrap();
        assert_eq!(decoded.version, entry.version);
        assert_declared_entry(&decoded, writer);
    }
    let mut future_enums = serde_json::to_value(&ordinary).unwrap();
    future_enums["state"] = json!("future_state");
    future_enums["hold_reason"] = json!("future_reason");
    let decoded: Entry = serde_json::from_value(future_enums).unwrap();
    assert_eq!(decoded.state, EntryState::Unrecognised);
    assert_eq!(decoded.hold_reason, Some(HoldReason::Other));
    let rewritten = serde_json::to_value(&decoded).unwrap();
    assert_eq!(rewritten["state"], "unrecognised");
    assert_eq!(rewritten["hold_reason"], "other");
    assert_eq!(
        runtime_declaration()["unknown_hold_reason"],
        "decode_as_other_not_round_tripped_on_rewrite_not_semantic_rollback_qualification"
    );
    // v0 is a real decoder fallthrough, separately disclosed and never listed
    // as a supported format. This test deliberately does not tighten it.
    let path = journal.path(&ordinary.id);
    let mut value = serde_json::to_value(&ordinary).unwrap();
    value["version"] = json!(0);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(read_entry(&path).unwrap().version, 0);
    let declaration = runtime_declaration();
    assert!(!declaration["formats"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["version"] == 0));
    assert_eq!(
        declaration["decoder_exceptions"][0]["contract_status"],
        "not_supported_contract"
    );
    value["version"] = json!(999);
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(read_entry(&path).is_err());
    drop(journal);
    let reopened = Journal::open(root.path(), CONFIRMED_RETENTION).unwrap();
    reopened.prune();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        declaration["unknown_format"],
        "preserve_opaque_file_count_unreadable_do_not_continue"
    );
}

#[cfg(not(feature = "v2-kernel-probe"))]
fn assert_working_decoder_unavailable(version: u32) {
    let report = runtime_declaration();
    let row = report["formats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["version"] == version)
        .unwrap();
    assert_eq!(row["decoder_compiled"], false);
    assert_eq!(row["fresh_writer"], "unavailable");
    assert_eq!(row["retained_entry_rewrite"], false);
}
