//! Journal-first body merge custody with frozen per-editor lineage.
use super::*;
use crate::node::journal::MergeIntent;
#[path = "body_merge_lineage.rs"]
mod lineage;

#[derive(Debug, PartialEq, Eq)]
enum MergeAnswer {
    Merged,
    HostedPending,
    Clashes,
    RetryLater(u64),
    CommittedUnrecovered,
    KeyConflict,
    Refused,
    Unknown,
}

pub(super) fn body_of(reply: Option<&str>) -> Option<Value> {
    let value: Value = serde_json::from_str(reply?).ok()?;
    value
        .pointer("/result/structuredContent")
        .cloned()
        .or_else(|| {
            value.pointer("/error/data/upstream_body").map(|b| {
                b.get("error")
                    .filter(|e| e.is_object())
                    .unwrap_or(b)
                    .clone()
            })
        })
        .or_else(|| {
            value
                .pointer("/result/content")?
                .as_array()?
                .iter()
                .find_map(|b| serde_json::from_str(b.get("text")?.as_str()?).ok())
        })
}

fn classify(body: Option<&Value>) -> MergeAnswer {
    let Some(body) = body else {
        return MergeAnswer::Unknown;
    };
    let code = body.get("error_code").and_then(Value::as_str).unwrap_or("");
    let reason = body.get("reason").and_then(Value::as_str).unwrap_or("");
    let outcome = body.get("outcome").and_then(Value::as_str).unwrap_or("");
    // These precede applied:true: a bounded replay is no receipt, and a clash
    // is a committed result whose unmerged passages still need custody.
    if code == "REPLAY_BOUND_EXCEEDED" {
        return MergeAnswer::CommittedUnrecovered;
    }
    if code == "IDEMPOTENCY_DIFFERENT_INTENT"
        || body.get("error").and_then(Value::as_str).is_some_and(|s| {
            s.contains("IDEMPOTENCY_DIFFERENT_INTENT")
                || s.contains(crate::provenance::IDEMPOTENCY_DIFFERENT_INTENT)
        })
    {
        return MergeAnswer::KeyConflict;
    }
    if body.get("applied") == Some(&json!(false)) {
        if reason == "home_busy" && body.get("retryable") == Some(&json!(true)) {
            return MergeAnswer::RetryLater(5_000);
        }
        if code == "BODY_MERGE_NOT_ENABLED"
            || reason == "feature_not_enabled"
            || reason == "merge_body_unsupported"
            || code == "merge_body_unsupported"
            || body
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("merge_body_unsupported"))
        {
            return MergeAnswer::RetryLater(300_000);
        }
    }
    match outcome {
        "accepted_pending" if body.get("canonical") == Some(&json!(false)) => {
            MergeAnswer::HostedPending
        }
        "merged_with_clashes" => MergeAnswer::Clashes,
        "merged" => MergeAnswer::Merged,
        "refused" | "not_sent" => MergeAnswer::Refused,
        _ if body.get("applied") == Some(&json!(false)) => MergeAnswer::Refused,
        _ => MergeAnswer::Unknown,
    }
}

fn complete_result(body: &Value, entry: &Entry, clashes: bool) -> bool {
    let matching = body.get("applied") == Some(&json!(true))
        && body.get("record_id").and_then(Value::as_str) == entry.record_id.as_deref()
        && body
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::trim)
            == entry.idempotency_key.as_deref().map(str::trim)
        && body
            .pointer("/result/body")
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() <= 1024 * 1024)
        && body
            .pointer("/result/version")
            .and_then(Value::as_str)
            .and_then(crate::mcp::tools::merge_body::parse_base_version)
            .is_some();
    if !matching {
        return false;
    }
    let result_body = body["result"]["body"].as_str().unwrap();
    if body.pointer("/result/body_digest").is_some_and(|digest| {
        digest.as_str() != Some(&crate::node::unmerged::text_digest(result_body))
    }) {
        return false;
    }
    if !clashes {
        return true;
    }
    let base = entry
        .arguments
        .as_ref()
        .and_then(|args| args["base_text"].as_str())
        .unwrap_or("")
        .chars()
        .collect::<Vec<_>>();
    let mine_bytes = entry
        .arguments
        .as_ref()
        .and_then(|args| args["my_text"].as_str())
        .map_or(0, str::len);
    let canonical = result_body.chars().collect::<Vec<_>>();
    body.get("unmerged")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            !items.is_empty()
                && items.windows(2).all(|pair| {
                    pair[0]["base_end"]
                        .as_u64()
                        .zip(pair[1]["base_start"].as_u64())
                        .is_some_and(|(end, start)| end <= start)
                        && pair[0]["at_end"]
                            .as_u64()
                            .zip(pair[1]["at_start"].as_u64())
                            .is_some_and(|(end, start)| end <= start)
                })
                && items.iter().all(|item| {
                    let Some(start) = item["base_start"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                    else {
                        return false;
                    };
                    let Some(end) = item["base_end"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                    else {
                        return false;
                    };
                    start <= end
                        && end <= base.len()
                        && item["id"].as_str().is_some_and(|id| !id.is_empty())
                        && item["base"].as_str()
                            == Some(&base[start..end].iter().collect::<String>())
                        && item["mine"]
                            .as_str()
                            .is_some_and(|mine| mine.len() <= mine_bytes)
                        && lineage::home_clash_text(&canonical, item).is_ok()
                })
        })
}

fn report(reply: Option<String>) -> SendReport {
    SendReport {
        reply,
        failure: None,
        attempt: Attempt::Answered,
        status: None,
        reply_kind: Default::default(),
    }
}

impl WriteGate {
    pub(super) async fn forward_merge(
        &self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
    ) -> SendReport {
        let id = request.message.get("id");
        let modern = crate::mcp::is_modern_request(request.message);
        let refuse = |text| not_sent_report(id, text);
        if self.ensure_account_binding().is_err() || self.body_merge_forget_pending() {
            return refuse("Body merge account state is unavailable; edit was not saved");
        }
        let mut message = request.message.clone();
        let options = message
            .pointer("/params/_meta/native~1body_merge")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Some(options) = options.as_object() else {
            return refuse("Body merge options must be an object; edit was not saved");
        };
        if options
            .keys()
            .any(|k| !matches!(k.as_str(), "wait" | "editor" | "made_at_ms"))
        {
            return refuse("Unknown body merge option; edit was not saved");
        }
        let wait = options
            .get("wait")
            .and_then(Value::as_str)
            .unwrap_or("short");
        if !matches!(wait, "none" | "short") || options.get("wait").is_some_and(|v| !v.is_string())
        {
            return refuse("Body merge wait must be none or short; edit was not saved");
        }
        let run = message
            .pointer("/params/arguments/run_key")
            .and_then(Value::as_str)
            .unwrap_or("node");
        let editor = options
            .get("editor")
            .and_then(Value::as_str)
            .unwrap_or(run)
            .to_owned();
        if editor.trim().is_empty()
            || editor.len() > 256
            || options.get("editor").is_some_and(|v| !v.is_string())
        {
            return refuse("Body merge editor must contain 1..256 bytes; edit was not saved");
        }
        let made_at_ms = options.get("made_at_ms").and_then(Value::as_u64);
        if options.get("made_at_ms").is_some() && made_at_ms.is_none() {
            return refuse(
                "Body merge made_at_ms must be a nonnegative integer; edit was not saved",
            );
        }
        if let Some(meta) = message
            .pointer_mut("/params/_meta")
            .and_then(Value::as_object_mut)
        {
            meta.remove("native/body_merge");
        }
        let Some((_, _, envelope)) = super::super::failover::target(&message) else {
            return refuse("Invalid body merge envelope; edit was not saved");
        };
        let Some((key, origin)) = prepare_key(&mut message, &envelope) else {
            return refuse("Invalid body merge key; edit was not saved");
        };
        let mut args = message
            .pointer("/params/arguments/arguments")
            .cloned()
            .unwrap_or(Value::Null);
        if !args.as_object().is_some_and(|a| {
            a.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "record_id"
                        | "base_version"
                        | "base_text"
                        | "my_text"
                        | "reason"
                        | "idempotency_key"
                )
            })
        }) || ["record_id", "reason", "idempotency_key"].iter().any(|k| {
            args.get(*k)
                .and_then(Value::as_str)
                .is_none_or(|s| s.trim().is_empty())
        }) || key.chars().count() > 200
            || args
                .get("base_version")
                .and_then(Value::as_str)
                .and_then(crate::mcp::tools::merge_body::parse_base_version)
                .is_none()
            || ["base_text", "my_text"].iter().any(|k| {
                args.get(*k)
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.len() > 1024 * 1024)
            })
        {
            return refuse("Invalid body merge arguments; edit was not saved");
        }
        // Offline custody cannot resolve short references. Require a full UUID
        // and normalize it locally so aliases cannot evade per-record ordering.
        let Some(record_id) = args["record_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        else {
            return refuse(
                "Body merge device custody requires a full record UUID; edit was not saved",
            );
        };
        if args["record_id"].as_str().unwrap().len() != 36 {
            return refuse(
                "Body merge device custody requires a full record UUID; edit was not saved",
            );
        }
        args["record_id"] = json!(record_id.to_string());
        message["params"]["arguments"]["arguments"] = args.clone();
        let digest = hold::intent_digest(&args);
        // Existing custody survives an expired contract cache or low disk.
        // Checking every state under one journal lock also permits repeats
        // while an unrelated queue send holds the network turn.
        if let Some(held) = self.journal.merge_with_key(&key) {
            if !held.merge_identity_matches(&key, &digest, &editor) {
                return report(hold::conflict_reply(id, &held));
            }
            if held.idempotency_key.as_deref() != Some(key.as_str()) {
                return report(superseded_merge_reply(&held, &key, id, modern));
            }
            if held.merge_key_tombstone
                || matches!(
                    held.state,
                    EntryState::Confirmed | EntryState::Acknowledged | EntryState::NotSent
                )
            {
                return report(stored_merge_reply(&held, id, modern));
            }
            self.wake_queue();
            return report(merge_pending_reply(
                id,
                &held,
                if wait == "none" {
                    "saved_on_device"
                } else {
                    "accepted_pending"
                },
                modern,
            ));
        }
        // Validate the caller's fields after key insertion: merge_body requires
        // a key at home, while the node is allowed to mint the missing key.
        // This path performs no network lookup before custody is durable.
        let validated = WriteRequest {
            body: request.body,
            message: &message,
            revision: request.revision,
            caller: request.caller,
            outage: request.outage,
            no_hold: request.no_hold,
        };
        if let Err(refusal) = self.validate_hold(&validated, &message, None).await {
            return refusal;
        }
        if self.below_floor().is_some() {
            return refuse("Edit was not saved: device disk space is below the custody floor");
        }
        let record_id = args["record_id"].as_str().unwrap().to_owned();
        let intent = MergeIntent {
            declared_base_version: args["base_version"].as_str().unwrap().into(),
            declared_base_text: args["base_text"].as_str().unwrap().into(),
            draft_text: args["my_text"].as_str().unwrap().into(),
            editor,
            made_at_ms,
            wait: wait.into(),
        };
        // Reopen the verified ordinary namespace before admission, including
        // after restart. Unknown credentials cannot inspect or adopt its order.
        let ordinary_scope = if self.kernel_v2_upstream() {
            let retained = match self.retained_v2_namespaces() {
                Ok(count) => count,
                Err(_) => return refuse("Local body custody namespace inventory is unreadable; edit was not sent or saved. Keep the draft until ordering can be established"),
            };
            match super::v2_holding::binding(request.outage).await {
                Some(binding) => match self.scoped_v2_gate(&binding) {
                    Ok(gate) => Some(gate),
                    Err(_) => return refuse("Body merge ordering is unavailable; edit was not sent or saved"),
                },
                None if retained > 0 => return refuse("Local body merge custody needs its verified account binding to establish prior append order; edit was not sent or saved. Keep the draft and retry after account verification"),
                None => None,
            }
        } else {
            None
        };
        // Local admission never waits behind a network send. One locked
        // all-state lookup avoids missing a key as the queue settles it.
        let entry = {
            let _admission = self.merge_admission.lock().expect("merge admission");
            if self.ensure_account_binding().is_err() || self.body_merge_forget_pending() {
                return refuse("Body merge account state is unavailable; edit was not saved");
            }
            if let Some(held) = self.journal.merge_with_key(&key) {
                if !held.merge_identity_matches(&key, &digest, &intent.editor) {
                    return report(hold::conflict_reply(id, &held));
                }
                if held.idempotency_key.as_deref() != Some(key.as_str()) {
                    return report(superseded_merge_reply(&held, &key, id, modern));
                }
                if held.merge_key_tombstone
                    || matches!(
                        held.state,
                        EntryState::Confirmed | EntryState::Acknowledged | EntryState::NotSent
                    )
                {
                    return report(stored_merge_reply(&held, id, modern));
                }
                held
            } else {
                // Namespace creation can race the earlier lookup. Admission
                // is shared with ordinary Sent insertion, so do not infer an
                // empty body scope from a pre-lock inventory under doubt.
                if self.kernel_v2_upstream()
                    && ordinary_scope.is_none()
                    && !matches!(self.retained_v2_namespaces(), Ok(0))
                {
                    return refuse("Local body custody ordering is unavailable without its verified scope; edit was not sent or saved");
                }
                if self.journal.has_opaque_custody() {
                    return refuse("Body custody ordering is unreadable; merge was not sent or saved. Keep the draft until the retained journal can be inspected");
                }
                if ordinary_scope
                    .as_ref()
                    .is_some_and(|gate| gate.journal.has_open_body_custody(&record_id, false))
                {
                    return refuse("Ordinary body append custody is open or unreadable in this ordering scope; merge was not sent or saved. Keep the draft and retry after its outcome or unreadable custody is resolved");
                }
                let needs_fresh = match self.lineages.load(&record_id, &intent.editor) {
                    Ok(lineage) => lineage.is_some_and(|lineage| {
                        (lineage.state != crate::node::lineage::LineageState::Active
                            || lineage.fresh_base_required)
                            && Some(lineage.reset_base_version as i64)
                                == crate::mcp::tools::merge_body::parse_base_version(
                                    &intent.declared_base_version,
                                )
                    }),
                    Err(_) => return refuse("Draft lineage is unreadable; edit was not saved"),
                };
                let local_refusal = json!({"outcome":"refused","applied":false,"reason":"needs_fresh_base",
                    "record_id":record_id,"idempotency_key":key,"canonical":false});
                let mut extra = message
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                for field in ["arguments", "executor", "operation"] {
                    extra.as_object_mut().unwrap().remove(field);
                }
                let new = NewEntry {
                    executor: "records_write".into(),
                    operation: "merge_body".into(),
                    tool: message
                        .pointer("/params/name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                    run_key: envelope
                        .get("run_key")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    parent_key: envelope
                        .get("parent_key")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    client_info: request.caller.client_info.clone(),
                    app_identity: None,
                    idempotency_key: Some(key),
                    key_origin: Some(origin),
                    arguments: args,
                    title: None,
                    record_id: Some(record_id),
                    record_ids: Vec::new(),
                    envelope: Some(extra),
                    intent_digest: Some(digest),
                };
                match if needs_fresh {
                    self.journal.begin_merge_refused(new, intent, local_refusal)
                } else {
                    self.journal.begin_merge(new, intent)
                } {
                    Ok(e) => e,
                    Err(_) => return refuse(
                        "Edit was not saved: device journal could not be written; nothing was sent",
                    ),
                }
            }
        };
        if entry.merge_result.is_some() {
            match self.finish_recorded_merge(&entry) {
                Ok(done) => return report(stored_merge_reply(&done, id, modern)),
                Err(_) => {
                    self.wake_queue();
                    return report(merge_pending_reply(id, &entry, "saved_on_device", modern));
                }
            }
        }
        if wait == "none" {
            // Save first, then notify. The queue cannot send this entry until
            // the fsync above completed, and this request never contacts home.
            let reply = merge_pending_reply(id, &entry, "saved_on_device", modern);
            self.wake_queue();
            return report(reply);
        }
        self.wake_queue();
        let deadline = Instant::now() + self.config.merge_short_budget;
        self.drain(
            upstream,
            request.outage,
            Some(deadline),
            Some(&request.caller.cancel),
        )
        .await;
        let current = self.journal.get(&entry.id).unwrap_or(entry);
        if current.state == EntryState::Confirmed {
            return report(stored_merge_reply(&current, id, modern));
        }
        report(merge_pending_reply(
            id,
            &current,
            "accepted_pending",
            modern,
        ))
    }

    pub(super) async fn send_merge(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        entry: Entry,
        deadline: Option<Instant>,
    ) -> queue::Step {
        if self.journal.has_opaque_custody() {
            return queue::Step::Halt(queue::Halt::Local);
        }
        if self.kernel_v2_upstream() {
            let retained = match self.retained_v2_namespaces() {
                Ok(count) => count,
                Err(_) => return queue::Step::Halt(queue::Halt::Local),
            };
            let ordinary = match super::v2_holding::binding(hooks).await {
                Some(binding) => match self.scoped_v2_gate(&binding) {
                    Ok(gate) => Some(gate),
                    Err(_) => return queue::Step::Halt(queue::Halt::Local),
                },
                None if retained > 0 => return queue::Step::Halt(queue::Halt::Local),
                None => None,
            };
            if entry.record_id.as_deref().is_some_and(|record| {
                ordinary
                    .as_ref()
                    .is_some_and(|gate| gate.journal.has_open_body_custody(record, false))
            }) {
                return queue::Step::Halt(queue::Halt::Local);
            }
        }
        let entry = match self.prepare_merge_entry(&entry) {
            Ok(entry) => entry,
            Err(_) => return queue::Step::Halt(queue::Halt::Local),
        };
        if entry.merge_result.is_some() {
            return match self.finish_recorded_merge(&entry) {
                Ok(_) => queue::Step::Next,
                Err(_) => queue::Step::Halt(queue::Halt::Local),
            };
        }
        if entry.merge_preparation.is_none() {
            return match self.block_legacy_merge(&entry) {
                Ok(_) => queue::Step::Next,
                Err(_) => queue::Step::Halt(queue::Halt::Local),
            };
        }
        if self
            .write_prepared_local_recovery(&entry)
            .and_then(|_| self.merge_checkpoint("local_recovery"))
            .is_err()
        {
            return queue::Step::Halt(queue::Halt::Local);
        }
        if entry
            .merge_preparation
            .as_ref()
            .is_some_and(|prepared| prepared.no_send)
        {
            let prepared = entry.merge_preparation.as_ref().unwrap();
            let body = json!({"outcome":"unchanged","applied":false,"sent":false,"canonical":false,
                "record_id":entry.record_id,"idempotency_key":entry.idempotency_key,
                "reason":"no_new_edit","result":{"version":format!("rec:{}",prepared.c_prev.version),
                "body":prepared.c_prev.text,"source":"previous_receipt"}});
            return match self
                .record_merge_result(&entry, "no_send", body, None)
                .and_then(|recorded| self.finish_recorded_merge(&recorded))
            {
                Ok(_) => queue::Step::Next,
                Err(_) => queue::Step::Halt(queue::Halt::Local),
            };
        }
        let (report, _) = match self.send_once(upstream, hooks, &entry, deadline).await {
            Ok(sent) => sent,
            Err(halt) => return queue::Step::Halt(halt),
        };
        if self.merge_checkpoint("result_received").is_err() {
            return queue::Step::Halt(queue::Halt::Local);
        }
        // An authentication refusal judges the transport credential, never
        // the saved edit. Do not interpret even a Native-shaped 401/403 body
        // as the proposal's refusal, or discard an earlier unknown outcome.
        if report.failure == Some(Health::AuthRefused) || report.attempt == Attempt::Stopped {
            if self
                .journal
                .update(&entry.id, |e| e.in_flight = false)
                .is_err()
            {
                return queue::Step::Halt(queue::Halt::Local);
            }
            return queue::Step::Halt(if report.failure == Some(Health::AuthRefused) {
                queue::Halt::Credentials(report.status)
            } else if deadline.is_some_and(|d| d <= Instant::now() + self.config.min_attempt) {
                queue::Halt::Time
            } else {
                queue::Halt::Credentials(None)
            });
        }
        let body = body_of(report.reply.as_deref());
        let answer = classify(body.as_ref());
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let park = |state, delay, maybe, detail: &str| {
            self.journal.update(&entry.id, |e| {
                e.state = state;
                e.in_flight = false;
                e.maybe_applied |= maybe;
                e.not_before_ms = now.saturating_add(delay);
                e.detail = Some(detail.into());
            })
        };
        let saved = match report.attempt {
            Attempt::Answered
                if report
                    .reply
                    .as_deref()
                    .is_some_and(hold::is_deployment_read_only) =>
            {
                park(
                    EntryState::Pending,
                    5_000,
                    false,
                    "Saved, waiting for Native. It will go in on its own.",
                )
            }
            Attempt::Answered => match answer {
                MergeAnswer::HostedPending => self
                    .journal
                    .hosted_pending(&entry.id, hosted_pending_journal(report.reply.as_deref())),
                MergeAnswer::RetryLater(delay) => park(
                    EntryState::Pending,
                    delay,
                    false,
                    "Saved, waiting for Native. It will go in on its own.",
                ),
                MergeAnswer::CommittedUnrecovered => park(
                    EntryState::CommittedUnrecovered,
                    1_000,
                    true,
                    "Saved, waiting for Native to recover the committed result.",
                ),
                MergeAnswer::Merged | MergeAnswer::Clashes => {
                    // A full exact body is mandatory on the KernelV2 home.
                    // Never settle an omitted result as a successful receipt.
                    if !body.as_ref().is_some_and(|body| {
                        complete_result(body, &entry, answer == MergeAnswer::Clashes)
                    }) {
                        park(
                            EntryState::ResultUnrecovered,
                            1_000,
                            true,
                            "Saved, waiting for Native to recover the full result.",
                        )
                    } else {
                        self.settle_merge(
                            &entry,
                            answer == MergeAnswer::Clashes,
                            "merged_with_clashes",
                            report.reply.clone(),
                        )
                    }
                }
                MergeAnswer::KeyConflict => {
                    self.settle_merge(&entry, true, "key_conflict", report.reply.clone())
                }
                MergeAnswer::Refused => {
                    self.settle_merge(&entry, true, "refused", report.reply.clone())
                }
                MergeAnswer::Unknown => park(
                    EntryState::Pending,
                    1_000,
                    true,
                    "Saved, waiting for Native to confirm the outcome.",
                ),
            },
            _ => park(
                EntryState::Pending,
                1_000,
                matches!(report.attempt, Attempt::Lost | Attempt::Unclear),
                "Saved, waiting for Native. It will go in on its own.",
            ),
        };
        if saved.is_err() {
            return queue::Step::Halt(queue::Halt::Local);
        }
        if let Some(hooks) = hooks {
            hooks.note_receipt(report.reply.as_deref()).await;
        }
        queue::Step::Next
    }

    pub(super) fn settle_merge(
        &self,
        entry: &Entry,
        recovery: bool,
        kind: &str,
        reply: Option<String>,
    ) -> Result<Entry> {
        let kind = if recovery { kind } else { "merged" };
        let body = body_of(reply.as_deref()).unwrap_or_else(|| {
            json!({
                "outcome":"refused","applied":false,"reason":kind,
                "record_id":entry.record_id,"idempotency_key":entry.idempotency_key,
            })
        });
        let recorded = self.record_merge_result(entry, kind, body, reply)?;
        self.finish_recorded_merge(&recorded)
    }
}

fn superseded_merge_reply(
    entry: &Entry,
    key: &str,
    id: Option<&Value>,
    modern: bool,
) -> Option<String> {
    let body = json!({"outcome":"superseded_on_device","applied":false,"canonical":false,
        "journal_entry":entry.id,"idempotency_key":key,"superseded_by":entry.idempotency_key});
    crate::node::tool_reply(
        id,
        json!({"structuredContent":body,"content":[{"type":"text","text":body.to_string()}],"isError":false}),
        modern,
    )
}

fn stored_merge_reply(entry: &Entry, id: Option<&Value>, modern: bool) -> Option<String> {
    if entry.merge_key_tombstone
        || matches!(entry.state, EntryState::Acknowledged | EntryState::NotSent)
    {
        let body = json!({"outcome":"settled_on_device","canonical":false,
            "reason":if entry.merge_key_tombstone { "receipt_pruned" } else { "settled_locally" },
            "state":entry.state,"journal_entry":entry.id,"idempotency_key":entry.idempotency_key,
            "answer":entry.answer,"recovery_item":entry.recovery_item});
        return crate::node::tool_reply(
            id,
            json!({"structuredContent":body,"content":[{"type":"text","text":body.to_string()}],"isError":false}),
            modern,
        );
    }
    let raw = entry.reply.as_deref()?;
    let reply: Value = serde_json::from_str(raw).ok()?;
    let Some(mut result) = reply.get("result").cloned() else {
        return Some(with_request_id(raw, id));
    };
    if let Some(object) = result.as_object_mut() {
        object.remove("resultType");
        object.remove("serverInfo");
    }
    crate::node::tool_reply(id, result, modern)
}

fn merge_pending_reply(
    id: Option<&Value>,
    entry: &Entry,
    outcome: &str,
    modern: bool,
) -> Option<String> {
    let body = json!({"outcome":outcome,"canonical":false,"journal_entry":entry.id,
        "idempotency_key":entry.idempotency_key,"maybe_applied":entry.maybe_applied,"hosted_journal_entry":entry.hosted_journal_entry,
        "message":"Saved on this device. It will go in on its own.","how_to_check":{"tool":"node_status"}});
    crate::node::tool_reply(
        id,
        json!({
            "structuredContent":body,
            "content":[{"type":"text","text":body.to_string()}],
            "isError":false,
        }),
        modern,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_classification_preserves_committed_recovery_before_applied_true() {
        assert_eq!(
            classify(Some(
                &json!({"applied":true,"error_code":"REPLAY_BOUND_EXCEEDED"})
            )),
            MergeAnswer::CommittedUnrecovered
        );
        assert_eq!(
            classify(Some(
                &json!({"applied":true,"outcome":"merged_with_clashes"})
            )),
            MergeAnswer::Clashes
        );
        assert_eq!(
            classify(Some(
                &json!({"applied":false,"error_code":"idempotency_conflict","error":crate::provenance::IDEMPOTENCY_DIFFERENT_INTENT})
            )),
            MergeAnswer::KeyConflict
        );
    }

    #[test]
    fn merge_classification_parks_disabled_busy_and_v1_home() {
        for body in [
            json!({"applied":false,"error_code":"BODY_MERGE_NOT_ENABLED"}),
            json!({"applied":false,"reason":"feature_not_enabled"}),
            json!({"applied":false,"error":"merge_body_unsupported: requires KernelV2"}),
        ] {
            assert_eq!(classify(Some(&body)), MergeAnswer::RetryLater(300_000));
        }
        assert_eq!(
            classify(Some(
                &json!({"applied":false,"reason":"home_busy","retryable":true})
            )),
            MergeAnswer::RetryLater(5_000)
        );
        assert_eq!(
            classify(Some(
                &json!({"applied":false,"reason":"not_permitted","retryable":false})
            )),
            MergeAnswer::Refused
        );
        assert_eq!(classify(None), MergeAnswer::Unknown);
    }
}
