//! Frozen preparation and recovery-before-lineage-before-settlement.
use super::*;
use crate::node::lineage::CommittedBody;
use crate::node::unmerged::{self, Passage, RecoveryItem, RecoveryKind, RecoveryState};

impl WriteGate {
    pub(super) fn prepare_merge_entry(&self, entry: &Entry) -> Result<Entry> {
        // Admission only waits for local work, never for the network. This
        // prevents a coalescing save racing a snapshot being prepared.
        let _admission = self.merge_admission.lock().expect("merge admission");
        self.ensure_account_binding()?;
        if self.body_merge_forget_pending() {
            return Err(Error::engine("body merge account erasure is incomplete"));
        }
        let current = self
            .journal
            .get(&entry.id)
            .ok_or_else(|| Error::engine("merge entry missing"))?;
        if current.prepared || current.merge_result.is_some() {
            return Ok(current);
        }
        let intent = current
            .merge_intent
            .as_ref()
            .ok_or_else(|| Error::engine("merge intent missing"))?;
        let record = current
            .record_id
            .as_deref()
            .ok_or_else(|| Error::engine("merge record missing"))?;
        let version =
            crate::mcp::tools::merge_body::parse_base_version(&intent.declared_base_version)
                .ok_or_else(|| Error::engine("invalid declared merge version"))? as u64;
        let open = self.unmerged.open_ids()?.into_iter().collect();
        let mut prepared = match self.lineages.prepare(
            record,
            &intent.editor,
            &current.id,
            CommittedBody {
                version,
                text: intent.declared_base_text.clone(),
            },
            &intent.draft_text,
            &open,
        ) {
            Ok(prepared) => prepared,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                let body = json!({"outcome":"refused","applied":false,"reason":"needs_fresh_base",
                    "record_id":record,"idempotency_key":current.idempotency_key});
                return self.record_merge_result(&current, "refused", body, None);
            }
            Err(error) => return Err(error.into()),
        };
        self.merge_checkpoint("lineage_ready")?;
        let mut used = prepared
            .updated_quarantine
            .iter()
            .map(|range| range.item.clone())
            .collect();
        for fact in &mut prepared.local_clashes {
            if fact.item.is_none() {
                fact.item = Some(self.allocate_passage_id(
                    record,
                    &intent.editor,
                    &fact.base,
                    &fact.mine,
                    &fact.theirs,
                    &mut used,
                )?);
            }
        }
        prepared.assign_local_items(|_| unreachable!("local recovery identities assigned"));
        let frozen = self.journal.update(&current.id, |entry| {
            let args = entry.arguments.as_mut().expect("merge arguments");
            args["base_version"] = json!(format!("rec:{}", prepared.c_prev.version));
            args["base_text"] = json!(prepared.c_prev.text);
            args["my_text"] = json!(prepared.submission);
            entry.arguments_bytes = args.to_string().len();
            entry.arguments_digest = crate::node::journal::scoped_arguments_digest(args, None);
            entry.merge_preparation = Some(prepared);
            entry.prepared = true;
        })?;
        self.merge_checkpoint("prepared")?;
        Ok(frozen)
    }

    pub(super) fn record_merge_result(
        &self,
        entry: &Entry,
        kind: &str,
        body: Value,
        reply: Option<String>,
    ) -> Result<Entry> {
        let mut recovery_ids = Vec::new();
        if kind == "merged_with_clashes" {
            let canonical = body["result"]["body"]
                .as_str()
                .ok_or_else(|| Error::engine("missing committed body"))?
                .chars()
                .collect::<Vec<_>>();
            let intent = entry
                .merge_intent
                .as_ref()
                .ok_or_else(|| Error::engine("merge intent missing"))?;
            let record = entry
                .record_id
                .as_deref()
                .ok_or_else(|| Error::engine("merge record missing"))?;
            let mut used = entry
                .merge_preparation
                .as_ref()
                .map(|prepared| {
                    prepared
                        .updated_quarantine
                        .iter()
                        .map(|range| range.item.clone())
                        .collect()
                })
                .unwrap_or_default();
            for fact in body["unmerged"]
                .as_array()
                .ok_or_else(|| Error::engine("missing home clashes"))?
            {
                let theirs = home_clash_text(&canonical, fact)?;
                recovery_ids.push(
                    self.allocate_passage_id(
                        record,
                        &intent.editor,
                        fact["base"]
                            .as_str()
                            .ok_or_else(|| Error::engine("missing clash base"))?,
                        fact["mine"]
                            .as_str()
                            .ok_or_else(|| Error::engine("missing clash draft"))?,
                        &theirs,
                        &mut used,
                    )?,
                );
            }
        }
        let recorded = self.journal.update(&entry.id, |entry| {
            entry.in_flight = false;
            if body["applied"] == true {
                entry.maybe_applied = true;
                entry.state = EntryState::ResultUnrecovered;
            }
            entry.not_before_ms = 0;
            entry.merge_result = Some(crate::node::journal::MergeResult {
                kind: kind.into(),
                body,
                reply,
                recovery_ids,
            });
        })?;
        self.merge_checkpoint("result_recorded")?;
        Ok(recorded)
    }

    fn allocate_passage_id(
        &self,
        record: &str,
        editor: &str,
        base: &str,
        mine: &str,
        theirs: &str,
        used: &mut std::collections::BTreeSet<String>,
    ) -> Result<String> {
        let base_id =
            unmerged::passage_id(record, editor, base, mine, &unmerged::text_digest(theirs));
        loop {
            let id = unmerged::next_passage_id(base_id.clone(), used);
            match self.unmerged.get(&id, true)? {
                None => return Ok(id), // Includes sticky, payload-pruned tombstones.
                Some(item)
                    if item.record_id == record
                        && item.editor == editor
                        && (item.state == RecoveryState::Dismissed
                            || item.passage.as_ref().is_some_and(|passage| {
                                passage.base.as_deref() == Some(base)
                                    && passage.mine.as_deref() == Some(mine)
                                    && passage.theirs.as_deref() == Some(theirs)
                                    && !passage.theirs_truncated
                            })) =>
                {
                    return Ok(id)
                }
                Some(_) => {} // A prior owned edit changed this item's text: preserve it.
            }
        }
    }

    fn recovery_item(
        &self,
        entry: &Entry,
        kind: RecoveryKind,
        id: String,
        passage: Option<Passage>,
        reason: Option<String>,
    ) -> RecoveryItem {
        let intent = entry.merge_intent.as_ref().expect("merge intent");
        let args = entry.arguments.as_ref();
        let local = kind == RecoveryKind::LocalClash;
        RecoveryItem {
            version: unmerged::ITEM_VERSION,
            id,
            kind,
            record_id: entry.record_id.clone().expect("merge record"),
            journal_entry: entry.id.clone(),
            editor: intent.editor.clone(),
            made_at: intent.made_at_ms,
            created_at: unmerged::now_ms(),
            last_seen_at: unmerged::now_ms(),
            state: RecoveryState::Open,
            dismissed_at: None,
            reason,
            base_text: Some(if local {
                entry
                    .merge_preparation
                    .as_ref()
                    .map(|p| p.d_prev.clone())
                    .unwrap_or_else(|| intent.declared_base_text.clone())
            } else {
                args.and_then(|a| a["base_text"].as_str())
                    .unwrap_or(&intent.declared_base_text)
                    .to_owned()
            }),
            my_text: Some(if local {
                intent.draft_text.clone()
            } else {
                args.and_then(|a| a["my_text"].as_str())
                    .unwrap_or(&intent.draft_text)
                    .to_owned()
            }),
            passage,
        }
    }

    pub(in crate::node::gate) fn write_prepared_local_recovery(
        &self,
        entry: &Entry,
    ) -> Result<Vec<String>> {
        let mut recovery = Vec::new();
        if let Some(prepared) = &entry.merge_preparation {
            for fact in &prepared.local_clashes {
                let id = fact
                    .item
                    .clone()
                    .ok_or_else(|| Error::engine("unidentified local clash"))?;
                let passage = Passage {
                    base: Some(fact.base.clone()),
                    mine: Some(fact.mine.clone()),
                    theirs: Some(fact.theirs.clone()),
                    base_start: fact.base_start,
                    base_end: fact.base_end,
                    at_start: Some(fact.theirs_start),
                    at_end: Some(fact.theirs_end),
                    theirs_truncated: false,
                };
                self.unmerged.upsert(self.recovery_item(
                    entry,
                    RecoveryKind::LocalClash,
                    id.clone(),
                    Some(passage),
                    None,
                ))?;
                recovery.push(id.clone());
            }
        }
        Ok(recovery)
    }

    /// Finishes only a recorded result. No network or re-evaluation is needed
    /// after a crash during any of these durable steps.
    pub(in crate::node::gate) fn finish_recorded_merge(&self, entry: &Entry) -> Result<Entry> {
        let result = entry
            .merge_result
            .as_ref()
            .ok_or_else(|| Error::engine("merge result missing"))?;
        let intent = entry
            .merge_intent
            .as_ref()
            .ok_or_else(|| Error::engine("merge intent missing"))?;
        let record = entry
            .record_id
            .as_deref()
            .ok_or_else(|| Error::engine("merge record missing"))?;
        let mut recovery = Vec::new();
        let mut home_quarantine = Vec::new();
        recovery.extend(self.write_prepared_local_recovery(entry)?);
        if result.kind == "merged_with_clashes" {
            let canonical = result.body["result"]["body"]
                .as_str()
                .ok_or_else(|| Error::engine("missing committed body"))?
                .chars()
                .collect::<Vec<_>>();
            let facts = result.body["unmerged"]
                .as_array()
                .ok_or_else(|| Error::engine("missing home clashes"))?;
            if result.recovery_ids.len() != facts.len() {
                return Err(Error::engine("home recovery identities are incomplete"));
            }
            for (fact, id) in facts.iter().zip(&result.recovery_ids) {
                let base = fact["base"]
                    .as_str()
                    .ok_or_else(|| Error::engine("missing clash base"))?;
                let mine = fact["mine"]
                    .as_str()
                    .ok_or_else(|| Error::engine("missing clash draft"))?;
                let theirs = home_clash_text(&canonical, fact)?;
                let start = fact["base_start"]
                    .as_u64()
                    .ok_or_else(|| Error::engine("missing clash range"))?
                    as usize;
                let end = fact["base_end"]
                    .as_u64()
                    .ok_or_else(|| Error::engine("missing clash range"))?
                    as usize;
                let passage = Passage {
                    base: Some(base.into()),
                    mine: Some(mine.into()),
                    theirs: Some(theirs),
                    base_start: start,
                    base_end: end,
                    at_start: fact["at_start"].as_u64().map(|n| n as usize),
                    at_end: fact["at_end"].as_u64().map(|n| n as usize),
                    theirs_truncated: false,
                };
                let saved = self.unmerged.upsert(self.recovery_item(
                    entry,
                    RecoveryKind::Clash,
                    id.clone(),
                    Some(passage),
                    None,
                ))?;
                if saved.state == RecoveryState::Open {
                    if let Some(prepared) = &entry.merge_preparation {
                        home_quarantine.push(prepared.home_quarantine(id.clone(), start, end));
                    }
                }
                recovery.push(id.clone());
            }
        }
        if matches!(result.kind.as_str(), "refused" | "key_conflict") {
            let kind = if result.kind == "key_conflict" {
                RecoveryKind::KeyConflict
            } else {
                RecoveryKind::Refusal
            };
            let id = unmerged::refusal_id(record, &intent.editor, &entry.id, kind);
            let reason = result.body["reason"]
                .as_str()
                .unwrap_or(&result.kind)
                .to_owned();
            self.unmerged.upsert(self.recovery_item(
                entry,
                kind,
                id.clone(),
                None,
                Some(reason),
            ))?;
            recovery.push(id);
            if result.body["reason"] == "base_unverified" {
                self.lineages
                    .mark_needs_fresh_base(record, &intent.editor)?;
            }
        }
        if let Some(id) = recovery.first() {
            self.journal
                .update(&entry.id, |entry| entry.recovery_item = Some(id.clone()))?;
        }
        self.merge_checkpoint("recovery")?;
        // All local and home recovery is durable before the lineage marker.
        if matches!(
            result.kind.as_str(),
            "merged" | "merged_with_clashes" | "no_send"
        ) {
            let mut prepared = entry
                .merge_preparation
                .clone()
                .ok_or_else(|| Error::engine("unprepared merge completion"))?;
            let open = self.unmerged.open_ids()?;
            prepared
                .updated_quarantine
                .retain(|range| open.contains(&range.item));
            let receipt = if result.kind == "no_send" {
                None
            } else {
                Some(CommittedBody {
                    version: crate::mcp::tools::merge_body::parse_base_version(
                        result.body["result"]["version"]
                            .as_str()
                            .ok_or_else(|| Error::engine("missing committed version"))?,
                    )
                    .ok_or_else(|| Error::engine("invalid committed version"))?
                        as u64,
                    text: result.body["result"]["body"]
                        .as_str()
                        .ok_or_else(|| Error::engine("missing committed body"))?
                        .into(),
                })
            };
            self.lineages.complete(
                record,
                &intent.editor,
                &entry.id,
                &prepared,
                receipt,
                home_quarantine,
            )?;
        }
        self.merge_checkpoint("lineage_completed")?;
        let reply = result
            .reply
            .clone()
            .or_else(|| local_merge_reply(entry, &result.body));
        let answer = if result.kind == "key_conflict" {
            "key_conflict"
        } else if result.kind == "refused" {
            "refused"
        } else if !recovery.is_empty() {
            "merged_with_clashes"
        } else {
            "receipt"
        };
        let done = self.journal.finish_held(
            &entry.id,
            EntryState::Confirmed,
            Some(answer),
            if recovery.is_empty() {
                "Synced."
            } else {
                "Needs you. Your unmerged changes are kept on this device."
            }
            .into(),
            reply,
            true,
            None,
        )?;
        self.merge_checkpoint("settled")?;
        self.lineages.drain_retired(
            record,
            &intent.editor,
            self.journal.has_open_merge(record, &intent.editor),
        )?;
        Ok(done)
    }
}

pub(super) fn home_clash_text(text: &[char], fact: &Value) -> Result<String> {
    let start = fact["at_start"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| Error::engine("invalid clash position"))?;
    let end = fact["at_end"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| Error::engine("invalid clash position"))?;
    if start > end || end > text.len() {
        return Err(Error::engine("clash position outside committed body"));
    }
    let exact = text[start..end].iter().collect::<String>();
    let quoted = fact["theirs"]
        .as_str()
        .ok_or_else(|| Error::engine("missing clash text"))?;
    let matches = if fact["theirs_truncated"].as_bool().unwrap_or(false) {
        exact.starts_with(quoted)
    } else {
        exact == quoted
    };
    if !matches {
        return Err(Error::engine("clash text does not match committed body"));
    }
    Ok(exact)
}

fn local_merge_reply(entry: &Entry, body: &Value) -> Option<String> {
    // Stored queue replies have no caller protocol. The forwarding path
    // reframes the result for each caller rather than freezing a wire era.
    crate::node::tool_reply(
        Some(&json!(format!("node-merge-{}", entry.id))),
        json!({
            "structuredContent":body,"content":[{"type":"text","text":body.to_string()}],
            "isError":body["outcome"] == "refused",
        }),
        false,
    )
}
