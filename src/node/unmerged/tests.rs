use super::*;

fn item() -> RecoveryItem {
    RecoveryItem {
        version: ITEM_VERSION,
        id: passage_id("record", "editor", "base", "mine", &text_digest("theirs")),
        kind: RecoveryKind::Clash,
        record_id: "record".into(),
        journal_entry: "entry".into(),
        editor: "editor".into(),
        made_at: Some(1),
        created_at: 2,
        last_seen_at: 2,
        state: RecoveryState::Open,
        dismissed_at: None,
        reason: None,
        base_text: None,
        my_text: None,
        passage: Some(Passage {
            base: Some("base".into()),
            mine: Some("mine".into()),
            theirs: Some("theirs".into()),
            base_start: 0,
            base_end: 4,
            at_start: Some(0),
            at_end: Some(6),
            theirs_truncated: false,
        }),
    }
}

#[test]
fn retry_restart_and_owned_edits_preserve_identity_and_dismissal() {
    let directory = tempfile::tempdir().unwrap();
    let retention = Duration::from_secs(7 * 24 * 3600);
    let store = RecoveryStore::open(directory.path(), retention).unwrap();
    let original = item();
    store.upsert(original.clone()).unwrap();
    let mut changed = original.clone();
    changed.created_at = 90;
    changed.last_seen_at = 100;
    changed.passage.as_mut().unwrap().mine = Some("mine!".into());
    let updated = store.upsert(changed).unwrap();
    assert_eq!(updated.created_at, 2);
    assert_eq!(updated.last_seen_at, 100);
    assert_eq!(store.counts().unwrap().open, 1);
    assert_eq!(updated.passage.unwrap().mine.as_deref(), Some("mine!"));
    let dismissed = store.dismiss(&original.id).unwrap();
    drop(store);
    let store = RecoveryStore::open(directory.path(), retention).unwrap();
    let retried = store.upsert(original.clone()).unwrap();
    assert_eq!(retried.state, RecoveryState::Dismissed);
    assert_eq!(retried.dismissed_at, dismissed.dismissed_at);
    assert_eq!(retried.passage.unwrap().mine.as_deref(), Some("mine!"));
    assert!(!store.is_open(&original.id).unwrap());
    assert!(store.open_ids().unwrap().is_empty());
}

#[test]
fn pruning_erases_dismissed_payload_but_never_reopens_it_or_expires_open_items() {
    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let original = item();
    store.upsert(original.clone()).unwrap();
    let mut still_open = original.clone();
    still_open.id = "another-passage".into();
    store.upsert(still_open.clone()).unwrap();
    let dismissed = store.dismiss(&original.id).unwrap();
    assert_eq!(
        store
            .prune_at(dismissed.dismissed_at.unwrap() + 60_000)
            .unwrap(),
        1
    );
    let bytes = fs::read_to_string(store.path(&original.id).unwrap()).unwrap();
    for private in ["base", "mine", "theirs", "record", "editor", "entry"] {
        assert!(!bytes.contains(private));
    }
    assert!(store.get(&original.id, true).unwrap().is_none());
    assert!(store.is_open(&still_open.id).unwrap());
    drop(store);
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    assert_eq!(
        store.upsert(original.clone()).unwrap().state,
        RecoveryState::Dismissed
    );
    assert!(!store.is_open(&original.id).unwrap());
    assert_eq!(store.counts().unwrap().tombstones, 1);
    store.wipe().unwrap();
    assert_eq!(store.upsert(original).unwrap().state, RecoveryState::Open);
}

#[test]
fn metadata_omits_all_texts_while_large_payload_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let mut original = item();
    let large = "\"\nsecret".repeat(70_000);
    original.passage.as_mut().unwrap().mine = Some(large.clone());
    store.upsert(original.clone()).unwrap();
    let metadata = serde_json::to_value(store.get(&original.id, false).unwrap().unwrap()).unwrap();
    assert!(metadata.get("base_text").is_none());
    assert!(metadata.get("my_text").is_none());
    let passage = &metadata["passage"];
    for field in ["base", "mine", "theirs"] {
        assert!(passage.get(field).is_none());
    }
    assert_eq!(passage["base_end"], 4);
    drop(store);
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    assert_eq!(
        store
            .get(&original.id, true)
            .unwrap()
            .unwrap()
            .passage
            .unwrap()
            .mine
            .unwrap(),
        large
    );
}

#[test]
fn unsafe_or_malformed_files_fail_closed_without_overwriting_known_data() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let original = item();
    store.upsert(original.clone()).unwrap();
    assert_eq!(
        fs::metadata(&store.directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let path = store.path(&original.id).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::write(&path, b"{broken").unwrap();
    assert!(store.upsert(original.clone()).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"{broken");
    assert!(RecoveryStore::open(directory.path(), Duration::ZERO).is_err());
    fs::remove_file(&path).unwrap();
    let outside = directory.path().join("outside");
    fs::write(&outside, "private").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.upsert(original).is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "private");
    store.wipe().unwrap();
    assert_eq!(fs::read_to_string(outside).unwrap(), "private");
    assert!(fs::read_dir(&store.directory).unwrap().next().is_none());
}

#[test]
fn refusal_keeps_complete_sent_text_and_path_ids_are_guarded() {
    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let mut refused = item();
    refused.kind = RecoveryKind::Refusal;
    refused.id = refusal_id("record", "editor", "entry", refused.kind);
    refused.base_text = Some("a".repeat(300_000));
    refused.my_text = Some("b".repeat(300_000));
    refused.passage = None;
    refused.reason = Some("not_permitted".into());
    store.upsert(refused.clone()).unwrap();
    assert_eq!(
        store
            .get(&refused.id, true)
            .unwrap()
            .unwrap()
            .my_text
            .unwrap()
            .len(),
        300_000
    );
    assert!(store.get("../escape", true).is_err());
    refused.id = "../escape".into();
    assert!(store.upsert(refused).is_err());
}

#[test]
fn owned_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let path = store.path("fifo").unwrap();
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(store.counts().is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    // Explicit boundary erasure can remove the owned special file safely.
    store.wipe().unwrap();
    assert!(!path.exists());
}

#[test]
fn identical_passage_occurrences_have_stable_independent_sticky_items() {
    let original = item();
    let allocate = || {
        let mut used = BTreeSet::new();
        (0..3)
            .map(|_| next_passage_id(original.id.clone(), &mut used))
            .collect::<Vec<_>>()
    };
    let ids = allocate();
    assert_eq!(ids, allocate());
    assert_eq!(ids[0], original.id);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), 3);
    let mut seeded = BTreeSet::from([ids[0].clone(), ids[1].clone()]);
    assert_eq!(next_passage_id(original.id.clone(), &mut seeded), ids[2]);

    let directory = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    for (index, id) in ids.iter().enumerate() {
        let mut occurrence = original.clone();
        occurrence.id = id.clone();
        let passage = occurrence.passage.as_mut().unwrap();
        passage.base_start += index * 10;
        passage.base_end += index * 10;
        store.upsert(occurrence).unwrap();
    }
    store.dismiss(&ids[1]).unwrap();
    drop(store);
    let store = RecoveryStore::open(directory.path(), Duration::from_secs(60)).unwrap();
    let mut retry = original.clone();
    retry.id = ids[1].clone();
    retry.passage.as_mut().unwrap().mine = Some("later owned edit".into());
    assert_eq!(store.upsert(retry).unwrap().state, RecoveryState::Dismissed);
    assert_eq!(store.counts().unwrap().open, 2);
    assert_eq!(store.counts().unwrap().dismissed, 1);
    assert!(store.is_open(&ids[0]).unwrap());
    assert!(store.is_open(&ids[2]).unwrap());
}

#[test]
fn confirmed_boundary_startup_can_open_and_erase_owned_malformed_payloads() {
    let root = tempfile::tempdir().unwrap();
    let store = RecoveryStore::open(root.path(), Duration::from_secs(60)).unwrap();
    let path = store.path("broken").unwrap();
    fs::write(&path, b"{private corrupt draft").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    assert!(RecoveryStore::open(root.path(), Duration::from_secs(60)).is_err());
    let store =
        RecoveryStore::open_for_pending_forget(root.path(), Duration::from_secs(60)).unwrap();
    assert!(store.counts().is_err());
    store.wipe().unwrap();
    assert!(!path.exists());
    assert_eq!(store.counts().unwrap().open, 0);
}
