//! Conservative slice-3 custody migration. No legacy request is re-prepared,
//! replayed, or treated as evidence of a completed editor lineage here.
use super::*;
use crate::node::journal::MergeIntent;
use crate::node::lineage::CommittedBody;
use crate::node::unmerged::{self, Passage, RecoveryItem, RecoveryKind, RecoveryState};
use std::io::{Read, Write};

const MAX_LEGACY_BYTES: u64 = 64 * 1024 * 1024;

fn invalid(message: &str) -> Error {
    Error::engine(message)
}

fn raw_path(directory: &Path, entry: &str) -> Result<PathBuf> {
    if entry.is_empty()
        || entry.len() > 128
        || !entry
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        return Err(invalid("invalid legacy body merge entry id"));
    }
    Ok(directory
        .join("body-merge-recovery")
        .join(format!("{entry}.json")))
}

fn read_raw(directory: &Path, entry: &str) -> Result<Option<Value>> {
    read_legacy_file(directory, entry, false)
}

fn read_legacy_file(directory: &Path, entry: &str, imported: bool) -> Result<Option<Value>> {
    let mut path = raw_path(directory, entry)?;
    if imported {
        path.set_file_name(format!("{entry}.imported.json"));
    }
    validate_credential_path(&path, "legacy body merge recovery")?;
    if let Some(parent) = path.parent() {
        match fs::symlink_metadata(parent) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(invalid("invalid legacy recovery directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = input.metadata()?;
    check_owned(&meta, 0o600)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_LEGACY_BYTES {
        return Err(invalid("invalid legacy body merge recovery file"));
    }
    let mut bytes = Vec::new();
    input.take(MAX_LEGACY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEGACY_BYTES {
        return Err(invalid("legacy body merge recovery exceeds bound"));
    }
    let raw: Value = serde_json::from_slice(&bytes)?;
    if raw["version"].as_u64() != Some(2)
        || raw["id"].as_str() != Some(entry)
        || raw["kind"].as_str().is_none()
    {
        return Err(invalid(
            "invalid legacy body merge recovery identity/version",
        ));
    }
    Ok(Some(raw))
}

fn write_import_marker(
    directory: &Path,
    entry: &str,
    raw_digest: &str,
    ids: &[String],
) -> Result<()> {
    let mut path = raw_path(directory, entry)?;
    path.set_file_name(format!("{entry}.imported.json"));
    validate_credential_path(&path, "legacy import marker")?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("legacy import marker parent missing"))?;
    let temporary = parent.join(format!("{entry}.{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec(
        &json!({"version":2,"id":entry,"kind":"imported","raw_digest":raw_digest,"recovery_ids":ids}),
    )?;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn body_of(reply: Option<&str>) -> Option<Value> {
    let value: Value = serde_json::from_str(reply?).ok()?;
    value
        .pointer("/result/structuredContent")
        .cloned()
        .or_else(|| {
            value.pointer("/error/data/upstream_body").map(|body| {
                body.get("error")
                    .filter(|error| error.is_object())
                    .unwrap_or(body)
                    .clone()
            })
        })
        .or_else(|| {
            value
                .pointer("/result/content")?
                .as_array()?
                .iter()
                .find_map(|block| serde_json::from_str(block.get("text")?.as_str()?).ok())
        })
}

fn intent_and_arguments(
    entry: &Entry,
    raw: Option<&Value>,
) -> Result<(MergeIntent, Option<Value>)> {
    let intent = match raw
        .and_then(|raw| raw.get("intent"))
        .filter(|value| !value.is_null())
    {
        Some(intent) => serde_json::from_value(intent.clone())?,
        None => entry
            .merge_intent
            .clone()
            .ok_or_else(|| invalid("legacy merge intent missing"))?,
    };
    if raw
        .and_then(|raw| raw.get("record_id"))
        .and_then(Value::as_str)
        .is_some_and(|record| Some(record) != entry.record_id.as_deref())
    {
        return Err(invalid("legacy recovery record identity mismatch"));
    }
    if entry
        .merge_intent
        .as_ref()
        .is_some_and(|original| original.editor != intent.editor)
    {
        return Err(invalid("legacy recovery editor identity mismatch"));
    }
    let args = raw
        .and_then(|raw| raw.get("arguments"))
        .filter(|args| !args.is_null())
        .cloned()
        .or_else(|| entry.arguments.clone());
    if args.as_ref().is_some_and(|args| !args.is_object()) {
        return Err(invalid("legacy recovery arguments must be an object"));
    }
    Ok((intent, args))
}

#[allow(clippy::too_many_arguments)]
fn recovery_item(
    entry: &Entry,
    intent: &MergeIntent,
    args: Option<&Value>,
    kind: RecoveryKind,
    id: String,
    passage: Option<Passage>,
    reason: Option<String>,
) -> Result<RecoveryItem> {
    let full = matches!(kind, RecoveryKind::Refusal | RecoveryKind::KeyConflict);
    let base = args
        .and_then(|args| args["base_text"].as_str())
        .unwrap_or(&intent.declared_base_text);
    let mine = args
        .and_then(|args| args["my_text"].as_str())
        .unwrap_or(&intent.draft_text);
    Ok(RecoveryItem {
        version: unmerged::ITEM_VERSION,
        id,
        kind,
        record_id: entry
            .record_id
            .clone()
            .ok_or_else(|| invalid("legacy merge record missing"))?,
        journal_entry: entry.id.clone(),
        editor: intent.editor.clone(),
        made_at: intent.made_at_ms,
        created_at: entry.received_unix_ms,
        last_seen_at: unmerged::now_ms(),
        state: RecoveryState::Open,
        dismissed_at: None,
        reason,
        base_text: full.then(|| base.to_owned()),
        my_text: full.then(|| mine.to_owned()),
        passage,
    })
}

fn coordinate(fact: &Value, name: &str) -> Result<usize> {
    fact[name]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid("invalid legacy clash coordinate"))
}

impl WriteGate {
    /// An old prepared request has no safe editor lineage. Retain its exact
    /// frozen request and key; never infer whether an attempted write applied.
    pub(in crate::node::gate) fn block_legacy_merge(&self, entry: &Entry) -> Result<Entry> {
        if !entry.is_merge() || entry.lineage_required || entry.merge_preparation.is_some() {
            return Err(invalid("entry is not a legacy body merge"));
        }
        self.ensure_account_binding()?;
        let unknown = entry.maybe_applied
            || entry.in_flight
            || entry.attempts > 0
            || matches!(
                entry.state,
                EntryState::CommittedUnrecovered
                    | EntryState::HostedPending
                    | EntryState::Uncertain
            );
        let reason = if unknown {
            "receipt_unrecovered"
        } else {
            "legacy_lineage_required"
        };
        let raw = match read_raw(&self.socket_directory, &entry.id)? {
            Some(raw) => raw,
            None => {
                self.journal
                    .save_merge_recovery(entry, reason, entry.reply.as_deref())?;
                read_raw(&self.socket_directory, &entry.id)?
                    .ok_or_else(|| invalid("legacy recovery custody missing after write"))?
            }
        };
        let (intent, args) = intent_and_arguments(entry, Some(&raw))?;
        let record = entry
            .record_id
            .as_deref()
            .ok_or_else(|| invalid("legacy merge record missing"))?;
        let id = unmerged::refusal_id(record, &intent.editor, &entry.id, RecoveryKind::Refusal);
        self.unmerged.upsert(recovery_item(
            entry,
            &intent,
            args.as_ref(),
            RecoveryKind::Refusal,
            id.clone(),
            None,
            Some(reason.into()),
        )?)?;
        self.require_fresh_legacy_base(entry, &intent)?;
        self.journal.update(&entry.id, |entry| {
            entry.state = EntryState::ResultUnrecovered;
            entry.not_before_ms = unmerged::now_ms().saturating_add(300_000);
            entry.recovery_item = Some(id);
            entry.in_flight = false;
            entry.detail = Some(if unknown {
                "legacy body merge lacks editor lineage; its outcome is unknown and it will not be resent automatically. Original request and draft remain in local recovery; inspect home history and use a fresh base before saving again."
            } else {
                "legacy body merge lacks editor lineage and was not sent by this migration. Original request and draft remain in local recovery; declare a fresh base before saving again."
            }.into());
        })
    }

    fn require_fresh_legacy_base(&self, entry: &Entry, intent: &MergeIntent) -> Result<()> {
        let record = entry
            .record_id
            .as_deref()
            .ok_or_else(|| invalid("legacy merge record missing"))?;
        // A newer active lineage is evidence of a later handoff. Never reset
        // it or put an earlier editor base back into use during migration.
        let version =
            crate::mcp::tools::merge_body::parse_base_version(&intent.declared_base_version)
                .ok_or_else(|| invalid("invalid legacy declared base version"))? as u64;
        if let Some(existing) = self.lineages.load(record, &intent.editor)? {
            // Repair a crash between baseline creation and the fresh-base
            // marker. A lineage with a completed save or another reset base
            // belongs to later work and must remain untouched.
            if existing.last_completed_entry.is_none()
                && existing.reset_base_version == version
                && existing.reset_base_text == intent.declared_base_text
                && existing.d_prev == intent.declared_base_text
            {
                self.lineages
                    .mark_needs_fresh_base(record, &intent.editor)?;
            }
            return Ok(());
        }
        self.lineages.prepare(
            record,
            &intent.editor,
            &entry.id,
            CommittedBody {
                version,
                text: intent.declared_base_text.clone(),
            },
            &intent.draft_text,
            &std::collections::HashSet::new(),
        )?;
        self.lineages
            .mark_needs_fresh_base(record, &intent.editor)?;
        Ok(())
    }

    /// Import complete legacy facts without removing raw custody or claiming
    /// the old receipt ever completed a slice-4 editor lineage.
    pub(in crate::node::gate) fn import_legacy_merge_recovery(&self) -> Result<()> {
        self.ensure_account_binding()?;
        for entry in self
            .journal
            .merge_entries()
            .into_iter()
            .filter(|entry| !entry.lineage_required && entry.recovery_item.is_some())
        {
            let raw = match read_raw(&self.socket_directory, &entry.id)? {
                Some(raw) => raw,
                None => {
                    if let Some(id) = &entry.recovery_item {
                        if self.unmerged.contains_id(id)? {
                            continue;
                        }
                    }
                    return Err(invalid(
                        "legacy recovery file missing; existing recovery cannot be established",
                    ));
                }
            };
            let raw_digest = unmerged::text_digest(&serde_json::to_string(&raw)?);
            if let Some(marker) = read_legacy_file(&self.socket_directory, &entry.id, true)? {
                if marker["kind"] != "imported"
                    || marker["raw_digest"].as_str() != Some(raw_digest.as_str())
                {
                    return Err(invalid(
                        "legacy import marker does not match retained custody",
                    ));
                }
                let ids = marker["recovery_ids"]
                    .as_array()
                    .filter(|ids| !ids.is_empty())
                    .ok_or_else(|| invalid("legacy import marker lacks recovery ids"))?;
                for id in ids {
                    let id = id
                        .as_str()
                        .ok_or_else(|| invalid("invalid legacy import recovery id"))?;
                    if !self.unmerged.contains_id(id)? {
                        return Err(invalid("completed legacy import recovery is missing"));
                    }
                }
                continue;
            }
            let mut imported_ids = Vec::new();
            let (intent, args) = intent_and_arguments(&entry, Some(&raw))?;
            let record = entry
                .record_id
                .as_deref()
                .ok_or_else(|| invalid("legacy merge record missing"))?;
            let reply = match raw.get("reply") {
                Some(Value::String(reply)) => Some(reply.as_str()),
                None | Some(Value::Null) => None,
                _ => return Err(invalid("invalid legacy reply")),
            };
            let body = body_of(reply);
            let kind = raw["kind"]
                .as_str()
                .ok_or_else(|| invalid("legacy recovery kind missing"))?;
            if kind == "merged_with_clashes"
                || body
                    .as_ref()
                    .is_some_and(|body| body["outcome"] == "merged_with_clashes")
            {
                let facts = body
                    .as_ref()
                    .and_then(|body| body["unmerged"].as_array())
                    .filter(|facts| !facts.is_empty())
                    .ok_or_else(|| invalid("legacy clash receipt missing or incomplete"))?;
                let mut used = std::collections::BTreeSet::new();
                for fact in facts {
                    let base = fact["base"]
                        .as_str()
                        .ok_or_else(|| invalid("legacy clash base missing"))?;
                    let mine = fact["mine"]
                        .as_str()
                        .ok_or_else(|| invalid("legacy clash draft missing"))?;
                    let theirs = fact["theirs"]
                        .as_str()
                        .ok_or_else(|| invalid("legacy clash current text missing"))?;
                    let start = coordinate(fact, "base_start")?;
                    let end = coordinate(fact, "base_end")?;
                    let at_start = coordinate(fact, "at_start")?;
                    let at_end = coordinate(fact, "at_end")?;
                    if start > end || at_start > at_end {
                        return Err(invalid("reversed legacy clash range"));
                    }
                    let truncated = match fact.get("theirs_truncated") {
                        None => false,
                        Some(Value::Bool(value)) => *value,
                        _ => return Err(invalid("invalid legacy clash truncation flag")),
                    };
                    let id = unmerged::passage_id(
                        record,
                        &intent.editor,
                        base,
                        mine,
                        &unmerged::text_digest(theirs),
                    );
                    let id = unmerged::next_passage_id(id, &mut used);
                    let passage = Passage {
                        base: Some(base.into()),
                        mine: Some(mine.into()),
                        theirs: Some(theirs.into()),
                        base_start: start,
                        base_end: end,
                        at_start: Some(at_start),
                        at_end: Some(at_end),
                        theirs_truncated: truncated,
                    };
                    imported_ids.push(id.clone());
                    self.import_legacy_item(recovery_item(
                        &entry,
                        &intent,
                        args.as_ref(),
                        RecoveryKind::Clash,
                        id,
                        Some(passage),
                        None,
                    )?)?;
                }
            } else {
                let key_conflict = kind == "key_conflict"
                    || body
                        .as_ref()
                        .is_some_and(|body| body["error_code"] == "IDEMPOTENCY_DIFFERENT_INTENT");
                let recovery_kind = if key_conflict {
                    RecoveryKind::KeyConflict
                } else {
                    RecoveryKind::Refusal
                };
                let id = unmerged::refusal_id(record, &intent.editor, &entry.id, recovery_kind);
                let reason = body
                    .as_ref()
                    .and_then(|body| body["reason"].as_str())
                    .unwrap_or(kind);
                imported_ids.push(id.clone());
                self.import_legacy_item(recovery_item(
                    &entry,
                    &intent,
                    args.as_ref(),
                    recovery_kind,
                    id,
                    None,
                    Some(reason.into()),
                )?)?;
            }
            self.require_fresh_legacy_base(&entry, &intent)?;
            write_import_marker(
                &self.socket_directory,
                &entry.id,
                &raw_digest,
                &imported_ids,
            )?;
        }
        Ok(())
    }

    fn import_legacy_item(&self, item: RecoveryItem) -> Result<()> {
        // Covers a crash after an individual durable item but before the
        // per-entry completion marker. Never overwrite later owned edits,
        // nor reconstruct a pruned dismissal's payload.
        if !self.unmerged.contains_id(&item.id)? {
            self.unmerged.upsert(item)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt};

    #[test]
    fn legacy_raw_read_preserves_large_receipts_and_rejects_unsafe_identity() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("body-merge-recovery");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = raw_path(root.path(), "entry").unwrap();
        let raw = json!({"version":2,"id":"entry","kind":"merged_with_clashes","reply":"x".repeat(300_000)});
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_raw(root.path(), "entry").unwrap().unwrap(), raw);
        assert!(raw_path(root.path(), "../escape").is_err());
        fs::write(&path, b"{broken").unwrap();
        assert!(read_raw(root.path(), "entry").is_err());
        fs::remove_file(&path).unwrap();
        let target = root.path().join("outside");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &path).unwrap();
        assert!(read_raw(root.path(), "entry").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn imports_both_mcp_receipt_eras_without_confusing_bad_json_with_receipts() {
        let receipt = json!({"outcome":"merged_with_clashes","unmerged":[{"mine":"kept"}]});
        let modern = json!({"result":{"structuredContent":receipt}}).to_string();
        let older =
            json!({"result":{"content":[{"type":"text","text":receipt.to_string()}]}}).to_string();
        assert_eq!(body_of(Some(&modern)), Some(receipt.clone()));
        assert_eq!(body_of(Some(&older)), Some(receipt));
        assert!(body_of(Some("not JSON")).is_none());
    }
    #[test]
    fn completed_legacy_import_never_overwrites_later_owned_edits_on_restart() {
        let root = tempfile::tempdir().unwrap();
        let gate = WriteGate::open(root.path(), GateConfig::default()).unwrap();
        let request = NewEntry {
            executor: "records_write".into(),
            operation: "merge_body".into(),
            tool: "records_write".into(),
            run_key: None,
            client_info: None,
            app_identity: None,
            idempotency_key: Some("key".into()),
            key_origin: Some(KeyOrigin::Caller),
            arguments: json!({"base_text":"abc","my_text":"axc","idempotency_key":"key"}),
            parent_key: None,
            title: None,
            record_id: Some("record".into()),
            record_ids: Vec::new(),
            envelope: None,
            intent_digest: Some("digest".into()),
        };
        let entry = gate
            .journal
            .begin_merge(
                request,
                MergeIntent {
                    declared_base_version: "rec:1".into(),
                    declared_base_text: "abc".into(),
                    draft_text: "axc".into(),
                    editor: "editor".into(),
                    made_at_ms: None,
                    wait: "none".into(),
                },
            )
            .unwrap();
        let receipt = json!({"result":{"structuredContent":{"outcome":"merged_with_clashes","unmerged":[
            {"base":"b","mine":"x","theirs":"y","base_start":1,"base_end":2,"at_start":1,"at_end":2}
        ]}}}).to_string();
        let legacy = gate
            .journal
            .update(&entry.id, |entry| {
                entry.lineage_required = false;
                entry.state = EntryState::Confirmed;
                entry.recovery_item = Some(entry.id.clone());
            })
            .unwrap();
        gate.journal
            .save_merge_recovery(&legacy, "merged_with_clashes", Some(&receipt))
            .unwrap();
        gate.import_legacy_merge_recovery().unwrap();
        let id = unmerged::passage_id("record", "editor", "b", "x", &unmerged::text_digest("y"));
        let mut changed = gate.unmerged.get(&id, true).unwrap().unwrap();
        changed.passage.as_mut().unwrap().mine = Some("x!".into());
        gate.unmerged.upsert(changed).unwrap();
        gate.import_legacy_merge_recovery().unwrap();
        assert_eq!(
            gate.unmerged
                .get(&id, true)
                .unwrap()
                .unwrap()
                .passage
                .unwrap()
                .mine
                .as_deref(),
            Some("x!")
        );
        drop(gate);
        let gate = WriteGate::open(root.path(), GateConfig::default()).unwrap();
        gate.import_legacy_merge_recovery().unwrap();
        assert_eq!(
            gate.unmerged
                .get(&id, true)
                .unwrap()
                .unwrap()
                .passage
                .unwrap()
                .mine
                .as_deref(),
            Some("x!")
        );
        assert!(read_raw(root.path(), &entry.id).unwrap().is_some());
        // Even if the final import marker was lost, existing item custody
        // prevents an interrupted importer from overwriting later edits.
        fs::remove_file(
            root.path()
                .join("body-merge-recovery")
                .join(format!("{}.imported.json", entry.id)),
        )
        .unwrap();
        gate.import_legacy_merge_recovery().unwrap();
        assert_eq!(
            gate.unmerged
                .get(&id, true)
                .unwrap()
                .unwrap()
                .passage
                .unwrap()
                .mine
                .as_deref(),
            Some("x!")
        );
    }

    /// Second upgrade PR (e): `body-merge-recovery/` files and
    /// `<id>.imported.json` markers survive restart and are not imported twice.
    #[test]
    fn upgrade_body_merge_recovery_and_import_markers_survive_restart_without_reimport() {
        let root = tempfile::tempdir().unwrap();
        let entry_id = {
            let gate = WriteGate::open(root.path(), GateConfig::default()).unwrap();
            let request = NewEntry {
                executor: "records_write".into(),
                operation: "merge_body".into(),
                tool: "records_write".into(),
                run_key: None,
                client_info: None,
                app_identity: None,
                idempotency_key: Some("upgrade-recovery".into()),
                key_origin: Some(KeyOrigin::Caller),
                arguments: json!({"base_text":"abc","my_text":"axc","idempotency_key":"upgrade-recovery"}),
                parent_key: None,
                title: None,
                record_id: Some("record".into()),
                record_ids: Vec::new(),
                envelope: None,
                intent_digest: Some("digest".into()),
            };
            let entry = gate
                .journal
                .begin_merge(
                    request,
                    MergeIntent {
                        declared_base_version: "rec:1".into(),
                        declared_base_text: "abc".into(),
                        draft_text: "axc".into(),
                        editor: "editor".into(),
                        made_at_ms: None,
                        wait: "none".into(),
                    },
                )
                .unwrap();
            let legacy = gate
                .journal
                .update(&entry.id, |entry| {
                    entry.lineage_required = false;
                    entry.state = EntryState::Confirmed;
                    entry.recovery_item = Some(entry.id.clone());
                })
                .unwrap();
            let receipt = json!({"result":{"structuredContent":{"outcome":"merged_with_clashes","unmerged":[
                {"base":"b","mine":"x","theirs":"y","base_start":1,"base_end":2,"at_start":1,"at_end":2}
            ]}}})
            .to_string();
            gate.journal
                .save_merge_recovery(&legacy, "merged_with_clashes", Some(&receipt))
                .unwrap();
            gate.import_legacy_merge_recovery().unwrap();
            // A later owned edit must win over a re-import, as in
            // `completed_legacy_import_never_overwrites_later_owned_edits_on_restart`.
            let passage =
                unmerged::passage_id("record", "editor", "b", "x", &unmerged::text_digest("y"));
            let mut edited = gate.unmerged.get(&passage, true).unwrap().unwrap();
            edited.passage.as_mut().unwrap().mine = Some("x!".into());
            gate.unmerged.upsert(edited).unwrap();
            entry.id
        };
        let raw_path = root
            .path()
            .join("body-merge-recovery")
            .join(format!("{entry_id}.json"));
        let marker_path = root
            .path()
            .join("body-merge-recovery")
            .join(format!("{entry_id}.imported.json"));
        assert!(raw_path.exists(), "raw recovery must exist before restart");
        assert!(
            marker_path.exists(),
            "import marker must exist before restart"
        );
        let raw_bytes = fs::read(&raw_path).unwrap();
        let marker_bytes = fs::read(&marker_path).unwrap();
        let gate = WriteGate::open(root.path(), GateConfig::default()).unwrap();
        assert_eq!(fs::read(&raw_path).unwrap(), raw_bytes);
        assert_eq!(fs::read(&marker_path).unwrap(), marker_bytes);
        gate.import_legacy_merge_recovery().unwrap();
        assert_eq!(fs::read(&raw_path).unwrap(), raw_bytes);
        assert_eq!(fs::read(&marker_path).unwrap(), marker_bytes);
        let passage =
            unmerged::passage_id("record", "editor", "b", "x", &unmerged::text_digest("y"));
        assert!(gate.unmerged.get(&passage, true).unwrap().is_some());
        let passage =
            unmerged::passage_id("record", "editor", "b", "x", &unmerged::text_digest("y"));
        let listed = gate.unmerged.list(None, None, true).unwrap();
        assert_eq!(listed.iter().filter(|item| item.id == passage).count(), 1);
        gate.import_legacy_merge_recovery().unwrap();
        assert_eq!(fs::read(&raw_path).unwrap(), raw_bytes);
        assert_eq!(fs::read(&marker_path).unwrap(), marker_bytes);
        // The owned edit survives the restart and the re-import.
        assert_eq!(
            gate.unmerged
                .get(&passage, true)
                .unwrap()
                .unwrap()
                .passage
                .unwrap()
                .mine
                .as_deref(),
            Some("x!")
        );
        assert_eq!(
            gate.unmerged.list(None, None, true).unwrap().len(),
            listed.len()
        );
    }
}
