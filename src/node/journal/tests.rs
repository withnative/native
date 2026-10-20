use super::*;

fn new_entry(key: Option<&str>, body: &str) -> NewEntry {
    NewEntry {
        executor: "records_write".into(),
        operation: "create_record".into(),
        tool: "call_executor".into(),
        run_key: Some("run-1".into()),
        client_info: Some(json!({"name":"test-client","version":"1"})),
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
