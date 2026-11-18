use super::*;

fn body(version: u64, text: &str) -> CommittedBody {
    CommittedBody {
        version,
        text: text.into(),
    }
}
fn fixture(draft: &str, canonical: &str) -> Lineage {
    Lineage {
        version: 2,
        record_id: "r".into(),
        editor: "e".into(),
        generation: 1,
        reset_base_version: 1,
        reset_base_text: draft.into(),
        reset_base_digest: digest(draft),
        d_prev: draft.into(),
        c_prev: body(2, canonical),
        quarantine: Vec::new(),
        last_completed_entry: None,
        state: LineageState::Active,
        fresh_base_required: false,
    }
}
fn owned(draft: &str, canonical: &str, start: usize, end: usize) -> Lineage {
    let mut l = fixture(draft, canonical);
    l.quarantine.push(Quarantine {
        item: "passage".into(),
        start,
        end,
    });
    l
}
fn open() -> HashSet<String> {
    HashSet::from(["passage".into()])
}
fn store() -> (tempfile::TempDir, LineageStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = LineageStore::new(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn three_saves_keep_remote_character_and_exact_editor_draft() {
    let l = fixture("Abc", "AbC");
    let p = evaluate(&l, "ABc", &HashSet::new()).unwrap();
    assert_eq!(p.submission, "ABC");
    let mut next = l;
    next.d_prev = p.d_k;
    next.c_prev = body(3, "ABC");
    assert_eq!(
        evaluate(&next, "ABcd", &HashSet::new()).unwrap().submission,
        "ABCd"
    );
}
#[test]
fn stale_unchanged_draft_sends_nothing_and_new_edit_only_extends() {
    let l = fixture("axb", "axb");
    assert!(evaluate(&l, "axb", &HashSet::new()).unwrap().no_send);
    let p = evaluate(&l, "axb!", &HashSet::new()).unwrap();
    let merged = merge_hunks(
        &hunks_between(&p.c_prev.text, &p.submission),
        &p.c_prev.text,
        "ab",
    )
    .unwrap();
    assert_eq!(merged.merged, "ab!");
}
#[test]
fn undo_clear_and_continued_typing_are_new_deltas() {
    for (before, canonical, next, expected) in [
        ("Abc", "Abc", "abc", "abc"),
        ("Abc", "AbC", "abc", "abC"),
        ("x", "x", "", ""),
        ("Hello", "Hello", "Hello world", "Hello world"),
    ] {
        assert_eq!(
            evaluate(&fixture(before, canonical), next, &HashSet::new())
                .unwrap()
                .submission,
            expected
        );
    }
}
#[test]
fn quarantine_owns_both_edges_with_empty_and_nonempty_canonical_passage() {
    for canonical in ["", "theirs"] {
        for draft in ["mine!", "!mine"] {
            let p = evaluate(&owned("mine", canonical, 0, 4), draft, &open()).unwrap();
            assert!(p.no_send);
            assert_eq!(p.submission, canonical);
            assert_eq!(p.local_clashes[0].item.as_deref(), Some("passage"));
            assert_eq!(p.local_clashes[0].mine, draft);
            assert_eq!(
                (p.updated_quarantine[0].start, p.updated_quarantine[0].end),
                (0, 5)
            );
        }
    }
}
#[test]
fn empty_deleted_passage_owns_insert_at_point() {
    let p = evaluate(&owned("ab", "aXb", 1, 1), "a🙂b", &open()).unwrap();
    assert!(p.no_send);
    assert_eq!(p.local_clashes[0].mine, "🙂");
    assert_eq!(
        (p.updated_quarantine[0].start, p.updated_quarantine[0].end),
        (1, 2)
    );
}
#[test]
fn free_unicode_edit_shifts_range_and_only_submits_itself() {
    let p = evaluate(
        &owned("a🙂mineZ", "a🙂theirZ", 2, 6),
        "🦕a🙂mineZ!",
        &open(),
    )
    .unwrap();
    assert_eq!(p.submission, "🦕a🙂theirZ!");
    assert!(p.local_clashes.is_empty());
    assert_eq!(
        (p.updated_quarantine[0].start, p.updated_quarantine[0].end),
        (3, 7)
    );
}
#[test]
fn dismissed_quarantine_is_removed_before_ownership() {
    let p = evaluate(&owned("mine", "mine", 0, 4), "mine!", &HashSet::new()).unwrap();
    assert_eq!(p.submission, "mine!");
    assert!(p.updated_quarantine.is_empty());
}
#[test]
fn local_clash_freezes_full_fact_before_no_send_completion() {
    let (dir, store) = store();
    store.write(&fixture("abc", "ayc")).unwrap();
    let mut p = store
        .prepare("r", "e", "entry", body(1, "abc"), "axc", &HashSet::new())
        .unwrap();
    assert!(p.no_send);
    assert_eq!(p.local_clashes[0].mine, "x");
    p.assign_local_items(|_| "passage".into());
    let frozen = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        store
            .complete("r", "e", "entry", &p, None, Vec::new())
            .unwrap(),
        Advance::Applied
    );
    drop(store);
    let store = LineageStore::new(dir.path()).unwrap();
    let replay: PreparedMerge = serde_json::from_slice(&frozen).unwrap();
    assert_eq!(
        store
            .complete("r", "e", "entry", &replay, None, Vec::new())
            .unwrap(),
        Advance::AlreadyCompleted
    );
    let l = store.load("r", "e").unwrap().unwrap();
    assert_eq!(l.d_prev, "axc");
    assert_eq!(l.c_prev.text, "ayc");
    assert_eq!(l.quarantine[0].item, "passage");
    let next = evaluate(&l, "axc!", &open()).unwrap();
    assert_eq!(next.submission, "ayc!");
}
#[test]
fn reset_is_durable_before_freezing_and_old_generation_cannot_advance() {
    let (dir, store) = store();
    let old = store
        .prepare("r", "e", "one", body(1, "abc"), "Abc", &HashSet::new())
        .unwrap();
    drop(store);
    let store = LineageStore::new(dir.path()).unwrap();
    let repeated = store
        .prepare("r", "e", "one", body(1, "abc"), "Abc", &HashSet::new())
        .unwrap();
    assert_eq!(old, repeated);
    let reset = store
        .prepare("r", "e", "two", body(2, "abC"), "ABc", &HashSet::new())
        .unwrap();
    assert_eq!(reset.generation, old.generation + 1);
    assert_eq!(
        store
            .complete("r", "e", "one", &old, Some(body(3, "Abc")), Vec::new())
            .unwrap(),
        Advance::GenerationChanged
    );
    assert_eq!(store.load("r", "e").unwrap().unwrap().d_prev, "abC");
}
#[test]
fn same_version_different_declared_text_defensively_resets() {
    let (_dir, store) = store();
    let one = store
        .prepare("r", "e", "one", body(1, "a"), "A", &HashSet::new())
        .unwrap();
    let two = store
        .prepare("r", "e", "two", body(1, "b"), "B", &HashSet::new())
        .unwrap();
    assert_eq!(two.generation, one.generation + 1);
    assert_eq!(two.d_prev, "b");
}
#[test]
fn retirement_drains_queued_entries_and_keeps_same_version_tombstone() {
    let (dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "mine"), "mine", &HashSet::new())
        .unwrap();
    store.retire("r", "e").unwrap();
    let queued = store
        .prepare(
            "r",
            "e",
            "queued",
            body(1, "mine"),
            "mine!",
            &HashSet::new(),
        )
        .unwrap();
    store.drain_retired("r", "e", true).unwrap();
    assert_eq!(
        store.load("r", "e").unwrap().unwrap().state,
        LineageState::Retiring
    );
    store
        .complete(
            "r",
            "e",
            "queued",
            &queued,
            Some(body(2, "mine!")),
            Vec::new(),
        )
        .unwrap();
    store.drain_retired("r", "e", false).unwrap();
    drop(store);
    let store = LineageStore::new(dir.path()).unwrap();
    let tombstone = store.load("r", "e").unwrap().unwrap();
    assert_eq!(tombstone.state, LineageState::Retired);
    assert!(tombstone.d_prev.is_empty());
    assert!(tombstone.reset_base_text.is_empty());
    assert_eq!(
        store
            .prepare(
                "r",
                "e",
                "late",
                body(1, "changed too"),
                "mine?",
                &HashSet::new()
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let fresh = store
        .prepare("r", "e", "new", body(2, "mine!"), "mine!?", &HashSet::new())
        .unwrap();
    assert_eq!(fresh.generation, tombstone.generation + 1);
}
#[test]
fn base_unverified_requires_fresh_base_even_for_already_queued_save() {
    let (_dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    store.mark_needs_fresh_base("r", "e").unwrap();
    assert!(store
        .prepare("r", "e", "queued", body(1, "a"), "c", &HashSet::new())
        .is_err());
    assert_eq!(store.load("r", "e").unwrap().unwrap().d_prev, "a");
}
#[test]
fn editors_are_independent_and_signout_clears_tombstones() {
    let (_dir, store) = store();
    store
        .prepare("r", "vault", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    store
        .prepare("r", "agent", "two", body(2, "x"), "y", &HashSet::new())
        .unwrap();
    assert_eq!(store.load("r", "vault").unwrap().unwrap().d_prev, "a");
    assert_eq!(store.load("r", "agent").unwrap().unwrap().d_prev, "x");
    store.retire("r", "vault").unwrap();
    store.drain_retired("r", "vault", false).unwrap();
    store.clear().unwrap();
    assert!(store.load("r", "vault").unwrap().is_none());
    assert!(store.load("r", "agent").unwrap().is_none());
}
#[test]
fn corrupt_or_symlinked_file_fails_closed_and_modes_are_private() {
    let (dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    let path = store.path("r", "e");
    assert_eq!(
        fs::metadata(dir.path().join("lineage")).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    fs::write(&path, "broken").unwrap();
    assert!(store
        .prepare("r", "e", "two", body(2, "c"), "d", &HashSet::new())
        .is_err());
    fs::remove_file(&path).unwrap();
    let other = dir.path().join("other");
    fs::write(&other, "secret").unwrap();
    std::os::unix::fs::symlink(&other, &path).unwrap();
    assert!(store.load("r", "e").is_err());
    assert_eq!(fs::read_to_string(other).unwrap(), "secret");
}
#[test]
fn home_clash_maps_replacement_to_full_draft_in_scalar_coordinates() {
    let p = evaluate(&fixture("a🙂c", "a🙂c"), "a🦕XYZc", &HashSet::new()).unwrap();
    let q = p.home_quarantine("passage".into(), 1, 2);
    assert_eq!(scalar_slice(&p.d_k, q.start, q.end), "🦕XYZ");
}

#[test]
fn list_validates_every_lineage_and_includes_retirement_markers() {
    let (_dir, store) = store();
    store
        .prepare("r1", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    store
        .prepare("r2", "e", "two", body(2, "x"), "y", &HashSet::new())
        .unwrap();
    store.retire("r1", "e").unwrap();
    store.drain_retired("r1", "e", false).unwrap();
    let all = store.list().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].state, LineageState::Retired);
    fs::write(store.path("r2", "e"), "broken").unwrap();
    assert!(store.list().is_err());
    store.clear().unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn signout_unlinks_owned_symlink_without_touching_target_and_erases_bad_modes() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    let path = store.path("r", "e");
    fs::write(&path, "broken").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let target = dir.path().join("outside");
    fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, store.directory.join("link")).unwrap();
    assert!(store.list().is_err());
    store.clear().unwrap();
    assert!(store.list().unwrap().is_empty());
    assert_eq!(fs::read_to_string(target).unwrap(), "keep");
}

#[test]
fn restart_ignores_complete_and_partial_owned_atomic_temps() {
    let (dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "abc"), "Abc", &HashSet::new())
        .unwrap();
    let expected = store.load("r", "e").unwrap().unwrap();
    for payload in [
        serde_json::to_vec(&expected).unwrap(),
        b"{\"version\":2,".to_vec(),
    ] {
        let path = store
            .directory
            .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&payload).unwrap();
        file.sync_all().unwrap();
    }
    drop(store);
    let store = LineageStore::new(dir.path()).unwrap();
    assert_eq!(store.list().unwrap(), vec![expected.clone()]);
    assert_eq!(store.load("r", "e").unwrap(), Some(expected));
    // Leftover files do not prevent editor retirement/status scans.
    store.retire("r", "e").unwrap();
    store.drain_retired("r", "e", false).unwrap();
    assert_eq!(store.list().unwrap()[0].state, LineageState::Retired);
}

#[test]
fn temp_namespace_does_not_hide_symlinks_or_unknown_files() {
    let (dir, store) = store();
    let target = dir.path().join("outside");
    fs::write(&target, "keep").unwrap();
    let path = store
        .directory
        .join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(store.list().is_err());
    fs::remove_file(path).unwrap();
    let path = store.directory.join(".not-an-atomic-write.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(b"broken").unwrap();
    assert!(store.list().is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "keep");
}

#[test]
fn hardlinks_fail_closed_but_signout_only_unlinks_the_owned_name() {
    let (dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    let path = store.path("r", "e");
    let alias = dir.path().join("outside-alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(store.load("r", "e").is_err());
    assert!(store.list().is_err());
    assert!(store.retire("r", "e").is_err());
    store.clear().unwrap();
    assert!(!path.exists());
    assert!(alias.exists());
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn oversized_lineage_is_refused_before_reading_and_can_be_erased() {
    let (_dir, store) = store();
    store
        .prepare("r", "e", "one", body(1, "a"), "b", &HashSet::new())
        .unwrap();
    OpenOptions::new()
        .write(true)
        .open(store.path("r", "e"))
        .unwrap()
        .set_len(MAX_LINEAGE_BYTES + 1)
        .unwrap();
    assert!(store
        .load("r", "e")
        .unwrap_err()
        .to_string()
        .contains("oversized"));
    assert!(store.list().is_err());
    store.clear().unwrap();
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn repeated_identical_clashes_preserve_each_range_and_second_boundary_ownership() {
    let mut l = fixture("abc\nabc", "ayc\nayc");
    let mut prepared = evaluate(&l, "axc\naxc", &HashSet::new()).unwrap();
    assert_eq!(prepared.local_clashes.len(), 2);
    // Even a caller using identical content identities must not discard a
    // second range; occurrence IDs additionally keep subsequent updates apart.
    let mut same_content_ids = prepared.clone();
    same_content_ids.assign_local_items(|_| "same-content".into());
    assert_eq!(same_content_ids.updated_quarantine.len(), 2);
    let mut occurrence = 0;
    prepared.assign_local_items(|_| {
        occurrence += 1;
        format!("passage-{occurrence}")
    });
    assert_eq!(prepared.updated_quarantine.len(), 2);
    assert_ne!(
        prepared.updated_quarantine[0].item,
        prepared.updated_quarantine[1].item
    );
    l.d_prev = prepared.d_k;
    l.quarantine = prepared.updated_quarantine;
    let ids = HashSet::from(["passage-1".into(), "passage-2".into()]);
    let next = evaluate(&l, "axc\nax!c", &ids).unwrap();
    assert!(next.no_send);
    assert_eq!(next.submission, "ayc\nayc");
    assert_eq!(next.local_clashes.len(), 1);
    assert_eq!(next.local_clashes[0].item.as_deref(), Some("passage-2"));
    assert_eq!(next.local_clashes[0].mine, "x!");
    assert_eq!(next.updated_quarantine.len(), 2);
}

#[test]
fn replaced_lineage_directory_symlink_refuses_operations_without_touching_target() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, store) = store();
    let prepared = store
        .prepare("r", "e", "one", body(1, "abc"), "Abc", &HashSet::new())
        .unwrap();
    let original = store.path("r", "e");
    let filename = original.file_name().unwrap().to_owned();
    let payload = fs::read(&original).unwrap();
    let target = dir.path().join("other-private-directory");
    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
    let target_file = target.join(filename);
    fs::write(&target_file, &payload).unwrap();
    fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&store.directory, dir.path().join("original-lineage")).unwrap();
    std::os::unix::fs::symlink(&target, &store.directory).unwrap();
    assert!(store.load("r", "e").is_err());
    assert!(store
        .prepare("r", "e", "two", body(1, "abc"), "ABc", &HashSet::new())
        .is_err());
    assert!(store
        .complete("r", "e", "one", &prepared, Some(body(2, "Abc")), Vec::new())
        .is_err());
    assert!(store.list().is_err());
    assert!(store.clear().is_err());
    assert_eq!(fs::read(&target_file).unwrap(), payload);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
}
