//! Follow hosted custody using authenticated, read-only status calls. A failed
//! lookup is never a refusal, and background checks never replay a mutation.
use super::*;

const BATCH: usize = 32;
const SWEEP_BUDGET: Duration = Duration::from_secs(5);

impl WriteGate {
    /// Runs on the existing queue/recovery cadence, even with no node-held
    /// writes. Rotate so an old inaccessible entry cannot starve later ones.
    pub(super) async fn settle_hosted_batch(&self, upstream: &Upstream) {
        if self.kernel_v2_upstream() {
            return;
        }
        let deadline = Instant::now() + SWEEP_BUDGET.min(self.config.budget);
        let cursor = *self.hosted_cursor.lock().expect("hosted cursor");
        for entry in self.journal.hosted_entries(cursor, BATCH) {
            // App receipts require the live, matching socket context. Never
            // query as an unattributed user or reconstruct an app mutation.
            if entry.app_identity.is_some() || entry.is_merge() {
                *self.hosted_cursor.lock().expect("hosted cursor") = entry.seq;
                continue;
            }
            if deadline < Instant::now() + self.config.min_attempt {
                break;
            }
            let Ok(_turn) =
                tokio::time::timeout_at(deadline.into(), self.hosted_check.lock()).await
            else {
                break;
            };
            *self.hosted_cursor.lock().expect("hosted cursor") = entry.seq;
            let Some(current) = self
                .journal
                .get(&entry.id)
                .filter(|e| e.state == EntryState::HostedPending)
            else {
                continue;
            };
            if self
                .poll_hosted(upstream, &current, deadline, None)
                .await
                .is_err()
            {
                tracing::warn!(target: "native_ce::node::journal", "hosted outcome could not be saved; custody retained");
                break;
            }
        }
    }

    /// Same-key callers retrieve the full hosted receipt with the saved
    /// arguments (including node-chosen IDs), without creating a journal slot.
    /// The turn excludes status settlement while this explicit retry is open.
    pub(super) async fn repeat_hosted(
        &self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
        entry: Entry,
    ) -> SendReport {
        let id = request.message.get("id");
        let deadline = request.caller.received + self.config.budget;
        let cancel = &request.caller.cancel;
        let turn = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            turn = tokio::time::timeout_at(deadline.into(), self.hosted_check.lock()) => turn.ok(),
        };
        if !self.scope_matches(request.outage).await {
            return not_sent_report(
                id,
                "Pending credential binding changed; saved outcome was not read or sent",
            );
        }
        let Some(_turn) = turn else {
            return self.hosted_waiting(&entry, request);
        };
        let entry = self.journal.get(&entry.id).unwrap_or(entry);
        // The operator can reconcile custody after this caller captured its
        // entry but before it acquires hosted_check. That is a local assertion,
        // not a hosted receipt, and must never fall through to canonical success.
        if entry.state == EntryState::Acknowledged {
            return SendReport {
                reply: tool_reply(
                    id,
                    json!({
                        "isError":false,
                        "content":[{"type":"text","text":"This write was acknowledged by the local operator. The retained audit is an operator assertion, not a canonical hosted receipt. This call did not resend the write."}],
                        "structuredContent":{
                            "outcome":"acknowledged", "canonical":false,
                            "receipt_available":false, "operator_audit":entry.operator_audit,
                            "idempotency_key":entry.idempotency_key,
                            "journal_entry":entry.hosted_journal_entry, "node_journal_entry":entry.id,
                        }
                    }),
                    crate::mcp::is_modern_request(request.message),
                ),
                failure: None,
                attempt: Attempt::Answered,
                status: None,
                reply_kind: Default::default(),
            };
        }
        if let Some(reply) = entry
            .reply
            .as_deref()
            .filter(|_| entry.state == EntryState::Confirmed)
        {
            return SendReport {
                reply: id.map(|_| with_request_id(reply, id)),
                failure: None,
                attempt: Attempt::Answered,
                status: None,
                reply_kind: Default::default(),
            };
        }
        // Background status can have settled this while the caller waited.
        // Its original request was then dropped; ask hosted using caller bytes
        // for the full receipt through the ordinary gate on the next call.
        if entry.state != EntryState::HostedPending {
            return SendReport {
                reply: tool_reply(
                    id,
                    json!({
                        "isError":false,"content":[{"type":"text","text":"Synced: hosted reports this write applied. This is a status summary; repeat the keyed call for the original receipt."}],
                        "structuredContent":{"outcome":"applied","applied":true,"canonical":true,
                            "receipt_available":false,"idempotency_key":entry.idempotency_key,
                            "journal_entry":entry.hosted_journal_entry,"node_journal_entry":entry.id,
                            "record_id":entry.record_id,"record_ids":entry.record_ids}
                    }),
                    crate::mcp::is_modern_request(request.message),
                ),
                failure: None,
                attempt: Attempt::Answered,
                status: None,
                reply_kind: Default::default(),
            };
        }
        if (self.kernel_v2_upstream() && self.custody_scope.is_none())
            || entry.app_identity.is_some()
        {
            return self.hosted_waiting(&entry, request);
        }
        let Some(arguments) = entry.arguments.clone() else {
            return self.hosted_waiting(&entry, request);
        };
        // Keep this explicit caller's envelope and metadata, as on an ordinary
        // keyed retry; reuse the prepared arguments, including generated IDs.
        let mut message = request.message.clone();
        message["params"]["arguments"]["arguments"] = arguments;
        let body = message.to_string();
        let (mut report, _, _) = self
            .send_with_retry(upstream, request, &message, &body, &entry, false)
            .await;
        if report.attempt == Attempt::Answered
            && answer_of(report.reply.as_deref()) == Answer::Receipt
        {
            match self.journal.finish_hosted(
                &entry,
                false,
                "hosted returned the canonical receipt on a same-key check".into(),
                report.reply.clone(),
                None,
            ) {
                Ok(done) => {
                    self.journal.resolve_earlier(&done);
                    self.wake_queue();
                }
                Err(_) => {
                    tracing::warn!(target: "native_ce::node::journal", "hosted receipt could not be saved; custody retained")
                }
            }
        } else {
            // Only authenticated status can distinguish a durable refusal from
            // a refusal of this check (expired credentials, changed intent).
            let mut entry = entry;
            if report.attempt == Attempt::Answered
                && answer_of(report.reply.as_deref()) == Answer::HostedPending
            {
                if let Some(handle) = hosted_pending_journal(report.reply.as_deref()) {
                    if entry.hosted_journal_entry.as_deref() != Some(&handle) {
                        match self.journal.hosted_pending(&entry.id, Some(handle)) {
                            Ok(updated) => entry = updated,
                            Err(_) => {
                                tracing::warn!(target: "native_ce::node::journal", "hosted custody handle could not be saved")
                            }
                        }
                    }
                }
            }
            if self
                .poll_hosted(upstream, &entry, deadline, Some(cancel.clone()))
                .await
                .is_err()
            {
                tracing::warn!(target: "native_ce::node::journal", "hosted outcome could not be saved; custody retained");
            }
            if let Some(done) = self
                .journal
                .get(&entry.id)
                .filter(|e| e.state == EntryState::Confirmed)
            {
                if let Some(reply) = done.reply {
                    report.reply = id.map(|_| with_request_id(&reply, id));
                }
            }
            if self
                .journal
                .get(&entry.id)
                .is_some_and(|e| e.state == EntryState::HostedPending)
            {
                // Do not imply that an unsuccessful check lost hosted custody.
                let waiting = self.hosted_waiting(&entry, request);
                report.reply = waiting.reply;
            }
        }
        report
    }

    fn hosted_waiting(&self, entry: &Entry, request: &WriteRequest<'_>) -> SendReport {
        SendReport {
            reply: tool_reply(
                request.message.get("id"),
                json!({
                    "isError":false,
                    "structuredContent": {"outcome":"accepted_pending", "canonical":false,
                        "journal_entry":entry.hosted_journal_entry, "node_journal_entry":entry.id,
                        "idempotency_key":entry.idempotency_key,"key_origin":entry.key_origin,
                        "record_id":entry.record_id,"record_ids":entry.record_ids,
                        "how_to_check": if entry.app_identity.is_some() {
                            "Hosted app custody remains unconfirmed. The node will not poll or replay it; reconcile the canonical outcome before retry or rollback."
                        } else {
                            "Hosted has custody; its current outcome is not yet known. The node will check again, or repeat this same keyed call."
                        }},
                    "content":[{"type":"text","text":"Held by hosted; the latest check has not established a canonical outcome."}]
                }),
                crate::mcp::is_modern_request(request.message),
            ),
            failure: None,
            attempt: Attempt::Answered,
            status: None,
            reply_kind: Default::default(),
        }
    }

    async fn poll_hosted(
        &self,
        upstream: &Upstream,
        entry: &Entry,
        deadline: Instant,
        cancel: Option<Cancel>,
    ) -> Result<()> {
        if entry.app_identity.is_some() {
            return Ok(());
        }
        let Some(handle) = entry.hosted_journal_entry.as_deref() else {
            return Ok(());
        };
        if self.kernel_v2_upstream() || deadline < Instant::now() + self.config.min_attempt {
            return Ok(());
        }
        let mut envelope = json!({"operation":"outbox_status","arguments":{"journal_entry":handle},"format":"json"});
        if let Some(run) = &entry.run_key {
            envelope["run_key"] = json!(run);
        }
        let message = json!({"jsonrpc":"2.0","id":format!("node-outcome-{}",entry.id),"method":"tools/call",
            "params":{"name":"system_read","arguments":envelope,"_meta":super::super::failover::probe_meta()}});
        let limits = Limits {
            deadline,
            custody_credential_sha256: None,
            attempt_timeout: self.config.attempt_timeout.min(SWEEP_BUDGET),
            min_attempt: self.config.min_attempt,
            cancel,
        };
        let report = upstream
            .send_attempt(
                &message.to_string(),
                &message,
                None,
                message.get("id"),
                Some(&limits),
            )
            .await;
        if report.attempt != Attempt::Answered || report.failure.is_some() {
            return Ok(());
        }
        let Some(status) = report
            .reply
            .as_deref()
            .and_then(|reply| status_entry(reply, entry))
        else {
            return Ok(());
        };
        let phase = status["status"].as_str().unwrap_or("");
        let refused = match phase {
            "applied" => false,
            "refused" | "dependency_failed" => true,
            _ => return Ok(()),
        };
        if !status["terminal_at"]
            .as_i64()
            .is_some_and(|stamp| stamp >= 0)
            || status["refusal"].as_bool() != Some(refused)
        {
            return Ok(());
        }
        let ancestor = status["dependency_failed_because"].as_str();
        let node_ancestor = ancestor.and_then(|handle| {
            self.journal
                .node_id_for_hosted(handle, entry.app_identity.as_deref())
        });
        let detail = if refused {
            "Needs you: hosted refused this held write; the saved request is retained"
        } else {
            "Synced: hosted reports this held write applied; repeat the keyed call for the full receipt"
        };
        let reply = refused.then(|| tool_reply(Some(&Value::Null), json!({
            "isError":true,"content":[{"type":"text","text":detail}],
            "structuredContent":{"outcome":"refused","applied":false,"needs_you":true,
                "reason":phase,"journal_entry":handle,"node_journal_entry":entry.id,
                "idempotency_key":entry.idempotency_key,"dependency_failed_because":ancestor,
                "depends_on":node_ancestor}
        }), true)).flatten();
        let done =
            self.journal
                .finish_hosted(entry, refused, detail.into(), reply, node_ancestor)?;
        if done.state == EntryState::Confirmed {
            if done.answer.as_deref() == Some("refused") {
                self.refuse_dependants(&done);
            } else {
                self.journal.resolve_earlier(&done);
            }
            self.wake_queue();
        }
        Ok(())
    }
}

/// Accept exactly one authenticated status row for this handle, key and run.
/// Errors, missing entries and unfamiliar envelopes leave custody untouched.
fn status_entry(reply: &str, entry: &Entry) -> Option<Value> {
    let reply: Value = serde_json::from_str(reply).ok()?;
    if reply.get("error").is_some() || reply.pointer("/result/isError") != Some(&Value::Bool(false))
    {
        return None;
    }
    let body = reply
        .pointer("/result/structuredContent")
        .cloned()
        .or_else(|| {
            reply
                .pointer("/result/content")?
                .as_array()?
                .iter()
                .find_map(|block| {
                    serde_json::from_str::<Value>(block.get("text")?.as_str()?)
                        .ok()
                        .filter(|v| v.get("entries").is_some())
                })
        })?;
    let rows = body["entries"].as_array()?;
    if rows.len() != 1 {
        return None;
    }
    let row = &rows[0];
    if row["journal_entry"].as_str() != entry.hosted_journal_entry.as_deref()
        || row["idempotency_key"].as_str() != entry.idempotency_key.as_deref()
        || row["run_key"].as_str() != entry.run_key.as_deref()
    {
        return None;
    }
    Some(row.clone())
}
