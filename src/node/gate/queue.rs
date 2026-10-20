//! The send queue: held writes go to hosted in the order they were accepted,
//! once hosted can take them (slice 2B).
//!
//! One drain runs at a time. It sends the oldest pending entry with the
//! arguments and key that were saved, so the engine sees the same call it
//! would have seen the first time, and a key it already used answers with the
//! original receipt. What each answer means:
//!
//! * a receipt, or an engine refusal: the entry is settled and the queue goes
//!   on. A refusal keeps the write's arguments and, for a create, refuses the
//!   later held writes that name its record IDs;
//! * `IDEMPOTENCY_DIFFERENT_INTENT`: the write had already committed, under an
//!   earlier intent. Reported as already applied, not as a refusal;
//! * read-only, unreachable, credentials refused, out of time: the drain stops
//!   and every entry stays pending. A refused credential says nothing about the
//!   write, so it never refuses one;
//! * an unreadable or partial answer: the entry becomes `uncertain`, which is
//!   how slice 2A treats the same answers.
//!
//! Sends are spaced by `queue_gap`. The queue is woken when the router sees
//! hosted reachable and otherwise tries again every `queue_retry`.
use super::*;
use crate::node::hold;

/// Why a drain stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum Halt {
    Empty,
    Unreachable,
    ReadOnly,
    /// Hosted refused the node's credential (with this status, if it gave
    /// one), or none were usable.
    Credentials(Option<u16>),
    /// The router could not record the send in its floor.
    Local,
    /// Out of the time it was given, or cancelled.
    Time,
    /// Another drain holds the queue.
    Busy,
}

enum Step {
    Next,
    Halt(Halt),
}

impl WriteGate {
    pub(in crate::node) fn wake_queue(&self) {
        self.queue_wake.notify_one();
    }

    /// Keep the queue moving in the background. `hooks` is the router, when
    /// there is one, so queue sends count in the own-write floor.
    pub(in crate::node) fn spawn_queue(
        self: &Arc<Self>,
        upstream: Arc<Upstream>,
        hooks: Option<Arc<dyn Outage>>,
    ) -> tokio::task::JoinHandle<()> {
        let gate = self.clone();
        tokio::spawn(async move {
            loop {
                gate.drain(&upstream, hooks.as_deref(), None, None).await;
                tokio::select! {
                    _ = gate.queue_wake.notified() => {}
                    _ = tokio::time::sleep(gate.config.queue_retry) => {}
                }
            }
        })
    }

    /// Send pending writes oldest first until none are left, one cannot be
    /// sent, or `deadline` passes.
    pub(in crate::node) async fn drain(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        deadline: Option<Instant>,
        cancel: Option<&Cancel>,
    ) -> Halt {
        let _turn = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(left, self.drain_lock.write()).await {
                    Ok(turn) => turn,
                    Err(_) => return Halt::Busy,
                }
            }
            None => self.drain_lock.write().await,
        };
        self.drain_locked(upstream, hooks, deadline, cancel).await
    }

    /// `drain`, by a caller that already holds the queue's turn.
    pub(in crate::node) async fn drain_locked(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        deadline: Option<Instant>,
        cancel: Option<&Cancel>,
    ) -> Halt {
        let mut sent = false;
        loop {
            if cancel.is_some_and(Cancel::is_cancelled) {
                return Halt::Time;
            }
            let Some(entry) = self.journal.oldest_pending() else {
                return Halt::Empty;
            };
            if self.journal.hosted_pending_creator_of(&entry) {
                return Halt::ReadOnly;
            }
            // Checked from the journal itself before every send, not only when
            // a refusal happens: a crash between a refusal and the refusals
            // that follow from it, and writes held after the refusal, are
            // both caught here. Entries go in `seq` order, so a dependant's own
            // dependants are found in turn.
            if deadline.is_some_and(|d| d < Instant::now() + self.config.min_attempt) {
                return Halt::Time;
            }
            if let Some((root, ids)) = self.journal.refused_creator_of(&entry) {
                // If this cannot be saved the same entry would be picked again
                // at once, forever: stop instead.
                if self.refuse_as_dependant(&entry, &root, &ids).is_none() {
                    return Halt::Local;
                }
                continue;
            }
            if sent {
                let gap = match deadline {
                    Some(deadline) => self
                        .config
                        .queue_gap
                        .min(deadline.saturating_duration_since(Instant::now())),
                    None => self.config.queue_gap,
                };
                tokio::time::sleep(gap).await;
            }
            if deadline.is_some_and(|d| d < Instant::now() + self.config.min_attempt) {
                return Halt::Time;
            }
            match self.send_held(upstream, hooks, entry, deadline).await {
                Step::Next => sent = true,
                Step::Halt(halt) => return halt,
            }
        }
    }

    /// The request exactly as the first attempt sent it, rebuilt from what
    /// the entry saved. Sent under the node's own credential, so the same
    /// account, with the original run key in the envelope.
    fn request_for(entry: &Entry) -> Option<(Value, String)> {
        let arguments = entry.arguments.clone()?;
        let mut envelope = entry.envelope.clone()?.as_object()?.clone();
        if entry.tool == "call_executor" {
            envelope.insert("executor".into(), json!(entry.executor));
        }
        envelope.insert("operation".into(), json!(entry.operation));
        envelope.insert("arguments".into(), arguments);
        let mut meta = super::super::failover::probe_meta();
        if let Some(info) = &entry.client_info {
            meta["io.modelcontextprotocol/clientInfo"] = info.clone();
        }
        let message = json!({
            "jsonrpc": "2.0",
            "id": format!("node-queue-{}", entry.id),
            "method": "tools/call",
            "params": {"name": entry.tool, "arguments": envelope, "_meta": meta},
        });
        let body = message.to_string();
        Some((message, body))
    }

    /// Leave a note on a pending entry saying why it is still waiting, and
    /// record that the send that was in flight has ended, in one write.
    /// `maybe_applied` can only be set here, never cleared.
    fn note_waiting(
        &self,
        entry: &Entry,
        detail: &str,
        reason: Option<HoldReason>,
        maybe_applied: bool,
    ) -> Result<Entry> {
        let detail = format!("waiting: {detail}");
        self.journal.update(&entry.id, |e| {
            e.detail = Some(detail.clone());
            e.in_flight = false;
            e.maybe_applied |= maybe_applied;
            if let Some(reason) = reason {
                e.hold_reason = Some(reason);
            }
        })
    }

    /// One send of a held write, with the floor bookkeeping around it.
    /// `Err` is a local failure: nothing was sent.
    async fn send_once(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        entry: &Entry,
        deadline: Option<Instant>,
    ) -> std::result::Result<(SendReport, Option<Answer>), Halt> {
        let Some((message, body)) = Self::request_for(entry) else {
            return Err(Halt::Local);
        };
        if let Some(hooks) = hooks {
            if !hooks.before_send().await {
                return Err(Halt::Local);
            }
        }
        // Saved before the send, in one write: the attempt, and that it is in
        // flight. If this cannot be saved, nothing is sent.
        if self.journal.begin_queue_send(&entry.id).is_err() {
            if let Some(hooks) = hooks {
                hooks.after_send(false).await;
            }
            return Err(Halt::Local);
        }
        let mut limit = Instant::now() + self.config.attempt_timeout;
        if let Some(deadline) = deadline {
            limit = limit.min(deadline);
        }
        let limits = Limits {
            deadline: limit,
            attempt_timeout: self.config.attempt_timeout,
            min_attempt: self.config.min_attempt,
            cancel: None,
        };
        let report = upstream
            .send_attempt(&body, &message, None, message.get("id"), Some(&limits))
            .await;
        let answer =
            (report.attempt == Attempt::Answered).then(|| answer_of(report.reply.as_deref()));
        if let Some(hooks) = hooks {
            let may_commit = match report.attempt {
                Attempt::Answered => {
                    !matches!(answer, Some(Answer::Refused | Answer::RetryableNotReady))
                }
                Attempt::Lost | Attempt::Unclear => true,
                Attempt::NotSent | Attempt::Stopped => false,
            };
            hooks.after_send(may_commit).await;
        }
        Ok((report, answer))
    }

    async fn send_held(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        entry: Entry,
        deadline: Option<Instant>,
    ) -> Step {
        // What came of an attempt is saved in one write. If it cannot be
        // saved the drain stops, never moves on: the entry stays as it is on
        // disk (with its in-flight marker, which the next attempt reads as
        // possibly applied), and picking it up again at once would only fail
        // again.
        macro_rules! saved {
            ($result:expr) => {
                match $result {
                    Ok(done) => done,
                    Err(_) => return Step::Halt(Halt::Local),
                }
            };
        }
        if Self::request_for(&entry).is_none() {
            saved!(self.journal.finish_held(
                &entry.id,
                EntryState::Uncertain,
                None,
                "the held write lost its saved request; it was not sent".into(),
                None,
                true,
                None,
            ));
            return Step::Next;
        }
        // An attempt whose outcome could not be saved left its marker behind:
        // it may have been applied.
        let possibly_applied = entry.maybe_applied || entry.in_flight;
        let (report, answer) = match self.send_once(upstream, hooks, &entry, deadline).await {
            Ok(sent) => sent,
            Err(halt) => return Step::Halt(halt),
        };
        let reply = report.reply.clone();

        if report.failure == Some(Health::AuthRefused) || report.attempt == Attempt::Stopped {
            // The write itself was not judged, and nothing was applied.
            let status = report
                .status
                .filter(|_| report.failure == Some(Health::AuthRefused));
            let timed_out = deadline.is_some_and(|d| d < Instant::now() + self.config.min_attempt);
            saved!(self.journal.update(&entry.id, |e| {
                e.attempts = e.attempts.saturating_sub(1);
                e.in_flight = false;
                if !timed_out {
                    e.detail = Some("waiting: hosted refused the node's credentials, or none were usable; the write itself was not judged".into());
                }
            }));
            if timed_out {
                return Step::Halt(Halt::Time);
            }
            return Step::Halt(Halt::Credentials(status));
        }
        match (report.attempt, answer) {
            (Attempt::Answered, Some(answer)) => {
                if reply.as_deref().is_some_and(hold::is_deployment_read_only) {
                    saved!(self.note_waiting(
                        &entry,
                        "hosted is read-only for a deployment",
                        Some(HoldReason::DeploymentReadOnly),
                        false,
                    ));
                    return Step::Halt(Halt::ReadOnly);
                }
                match answer {
                    Answer::RetryableNotReady => {
                        saved!(self.note_waiting(
                            &entry,
                            "hosted outbox is preparing; this attempt was not accepted",
                            Some(HoldReason::DeploymentReadOnly),
                            false,
                        ));
                        return Step::Halt(Halt::ReadOnly);
                    }
                    Answer::HostedPending => {
                        saved!(self
                            .journal
                            .hosted_pending(&entry.id, hosted_pending_journal(reply.as_deref())));
                    }
                    Answer::Receipt => {
                        let done = saved!(self.journal.finish_held(
                            &entry.id,
                            EntryState::Confirmed,
                            Some("receipt"),
                            "sent by the node after hosted recovered".into(),
                            reply,
                            false,
                            None,
                        ));
                        self.journal.resolve_earlier(&done);
                    }
                    Answer::Refused if is_different_intent(reply.as_deref()) => {
                        // Hosted already holds this write, committed under an
                        // earlier intent than the run has now.
                        saved!(self.journal.finish_held(
                            &entry.id,
                            EntryState::Confirmed,
                            Some("already_applied"),
                            "already applied: hosted had committed this write under an earlier intent; check the record".into(),
                            Some(already_applied_reply(&entry, true)),
                            false,
                            None,
                        ));
                    }
                    Answer::Refused => {
                        // Hosted may refuse the key the node minted (a document
                        // open in the live editor, for one). The node does not
                        // send the write without it: refused, and the person
                        // decides.
                        let mut detail = if refuses_key(reply.as_deref())
                            && entry.key_origin == Some(KeyOrigin::Node)
                        {
                            "Hosted would not accept this write with an idempotency key (e.g. a document open in the live editor). The node did not send it without one. Check the record, then send it again without a key if it is still wanted.".to_owned()
                        } else {
                            "hosted refused this write when the node sent it".to_owned()
                        };
                        let mut reply = reply;
                        if possibly_applied {
                            detail.push_str(" An earlier attempt of this write may already have been applied: check the record first.");
                            // A later refusal says nothing about an earlier
                            // attempt that may have landed.
                            reply = reply.map(|r| {
                                annotate_hosted_reply(
                                    &r,
                                    json!({
                                        "outcome": "refused",
                                        "may_already_be_applied": true,
                                        "idempotency_key": entry.idempotency_key,
                                        "journal_entry": entry.id,
                                    }),
                                    entry.idempotency_key.as_deref().unwrap_or_default(),
                                )
                            });
                        }
                        let done = saved!(self.journal.finish_held(
                            &entry.id,
                            EntryState::Confirmed,
                            Some("refused"),
                            detail,
                            reply,
                            true,
                            None,
                        ));
                        self.refuse_dependants(&done);
                    }
                    Answer::Partial => {
                        saved!(self.journal.finish_held(
                            &entry.id,
                            EntryState::Uncertain,
                            None,
                            "hosted reported a partial or unknown outcome for the held write; inspect before retrying".into(),
                            None,
                            true,
                            None,
                        ));
                    }
                }
                Step::Next
            }
            (Attempt::NotSent, _) => {
                saved!(self.note_waiting(&entry, "hosted is unreachable", None, false));
                Step::Halt(Halt::Unreachable)
            }
            (Attempt::Lost, _) => {
                // One write: possibly applied, and the send has ended.
                saved!(self.note_waiting(
                    &entry,
                    "hosted is unreachable; the last attempt may have been applied",
                    None,
                    true,
                ));
                Step::Halt(Halt::Unreachable)
            }
            _ => {
                saved!(self.journal.finish_held(
                    &entry.id,
                    EntryState::Uncertain,
                    None,
                    "hosted's answer to the held write could not be read; inspect before retrying"
                        .into(),
                    None,
                    true,
                    None,
                ));
                Step::Next
            }
        }
    }

    /// A refused create takes its dependants with it: held writes after it
    /// that name a record it would have made (an append to it, a link to it,
    /// an attachment on it, a create inside it), and in turn theirs.
    fn refuse_dependants(&self, refused: &Entry) {
        let mut work = vec![refused.clone()];
        while let Some(root) = work.pop() {
            if !hold::creates(&root.operation) {
                continue;
            }
            let mut ids = root.record_ids.clone();
            ids.extend(root.record_id.clone());
            if ids.is_empty() {
                continue;
            }
            for dependant in self.journal.pending_referring_to(&ids, root.seq) {
                if let Some(done) = self.refuse_as_dependant(&dependant, &root, &ids) {
                    work.push(done);
                }
            }
        }
    }

    /// Settle `dependant` as refused because it refers to a record `root`
    /// would have created. It keeps its arguments, like any refused write.
    fn refuse_as_dependant(
        &self,
        dependant: &Entry,
        root: &Entry,
        ids: &[String],
    ) -> Option<Entry> {
        let detail = format!(
            "depends on a refused write: it names a record that write would have created ({}), so it was not sent",
            ids.join(", ")
        );
        let reply = frame_error(
            Some(&Value::Null),
            "Held write refused: it depends on a write hosted refused; it was not sent",
            json!({
                "outcome": "refused",
                "reason": "depends_on_refused_write",
                "depends_on": root.id,
                "refused_record_ids": ids,
                "idempotency_key": dependant.idempotency_key,
            }),
        );
        self.journal
            .finish_held(
                &dependant.id,
                EntryState::Confirmed,
                Some("refused"),
                detail,
                reply,
                true,
                Some(root.id.clone()),
            )
            .ok()
    }
}

/// Hosted's refusal for a key reused under a different resolved intent (the
/// run's intent changed after a write had already committed). Distinguished
/// from the other `idempotency_conflict`, which is a genuine content conflict.
fn is_different_intent(reply: Option<&str>) -> bool {
    reply.is_some_and(|reply| {
        reply.contains("idempotency_conflict")
            && reply.contains(crate::provenance::IDEMPOTENCY_DIFFERENT_INTENT)
    })
}

pub(super) fn already_applied_reply(entry: &Entry, modern: bool) -> String {
    let info = json!({
        "outcome": "already_applied",
        "idempotency_key": entry.idempotency_key,
        "record_id": entry.record_id,
        "record_ids": entry.record_ids,
        "journal_entry": entry.id,
        "detail": "Hosted had already committed this write, under the run's earlier intent. It was not applied twice. Check the record.",
    });
    super::super::tool_reply(Some(&Value::Null), json!({
        "content":[{"type":"text","text":"Already applied: hosted had committed this write under the run's earlier intent, so it was not applied again. Check the record."}],
        "structuredContent": info,
        "isError": false,
    }), modern).expect("stored reply has an id")
}
