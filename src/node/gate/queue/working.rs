//! The only runtime producer of installed working canonical verdicts. A
//! capability is created here solely after the real scoped send_once response;
//! W, ingress arguments and manager constructors cannot manufacture one.
use super::*;
use crate::node::journal::working_v2::OriginalAppend;
use crate::node::journal::MAX_STORED_REPLY;

mod custody;

async fn enrolled_request(
    upstream: &Upstream,
    token: &str,
    endpoint: &str,
    request: &impl serde::Serialize,
    timeout: Duration,
) -> Result<reqwest::Response> {
    let key = upstream
        .install_key
        .as_ref()
        .ok_or_else(|| Error::engine("node install key unavailable"))?;
    let mut url = upstream.endpoint.clone();
    url.path_segments_mut()
        .map_err(|_| Error::engine("node settlement endpoint unavailable"))?
        .clear()
        .extend([
            "internal",
            "node",
            "databases",
            &upstream.config.db_id,
            endpoint,
        ]);
    let builder = upstream
        .client
        .post(url)
        .header(
            crate::client_compatibility::HEADER,
            crate::client_compatibility::advertisement(),
        )
        .bearer_auth(token)
        .json(request)
        .timeout(timeout);
    crate::node_credential::send_request(&upstream.client, builder, Some(key))
        .await
        .map_err(|_| Error::engine("enrolled original transport unavailable"))
}

impl WriteGate {
    pub(super) async fn send_enrolled_once(
        &self,
        upstream: &Upstream,
        entry: &Entry,
        id: Option<&Value>,
        limits: &Limits,
    ) -> SendReport {
        use crate::kernel::original_settlement::installed::{Request, RequestAction};
        let not_sent = || not_sent_report(id, "No verified enrolled original was sent");
        if self
            .journal
            .enrolled_qualification()
            .and_then(tokio::sync::OnceCell::get)
            .is_none()
            || entry.seq == 0
        {
            return not_sent();
        }
        let Ok(original) = crate::node::journal::working_v2::settlement_original(entry) else {
            return not_sent();
        };
        let Some(install_id) = entry
            .kernel_v2_custody
            .as_ref()
            .and_then(|custody| custody.binding.install_id.as_deref())
        else {
            return not_sent();
        };
        if upstream.install_key.as_ref().map(|key| key.id()).as_deref() != Some(install_id) {
            return not_sent();
        }
        if let Some(oauth) = &upstream.oauth {
            if !matches!(
                super::super::super::bounded(oauth.ensure_fresh_before_send(), limits).await,
                Ok(Ok(()))
            ) {
                return not_sent();
            }
        }
        let Ok(token) = read_guarded_credential(&upstream.config.credential_file, "node") else {
            return not_sent();
        };
        use sha2::Digest;
        let token_sha256: [u8; 32] = sha2::Sha256::digest(&*token).into();
        if limits.custody_credential_sha256 != Some(token_sha256) {
            return not_sent();
        }
        let timeout = limits
            .attempt_timeout
            .min(limits.deadline.saturating_duration_since(Instant::now()));
        if timeout < limits.min_attempt {
            return not_sent();
        }
        let binding = original.expected_binding_sha256.clone();
        let request = Request {
            action: RequestAction::Write,
            original,
            custody_sequence: Some(entry.seq),
        };
        let unknown = |status| SendReport {
            reply: None,
            failure: None,
            attempt: Attempt::Unclear,
            status,
            reply_kind: ReplyKind::Node,
        };
        let Ok(response) = enrolled_request(
            upstream,
            std::str::from_utf8(&token).expect("guarded UTF-8"),
            "originals",
            &request,
            timeout,
        )
        .await
        else {
            return unknown(None);
        };
        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            return SendReport {
                failure: Some(Health::AuthRefused),
                attempt: Attempt::Answered,
                ..unknown(Some(status))
            };
        }
        let Ok(response) = crate::client_compatibility::inspect(
            response,
            &upstream.compatibility,
            "installed-original",
            "write",
        )
        .await
        else {
            return unknown(Some(status));
        };
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > MAX_STORED_REPLY as u64)
        {
            return unknown(Some(status));
        }
        let Ok(answer) = read_enrolled_answer(response).await else {
            return unknown(Some(status));
        };
        if answer["schema"] != "native.installed-original-write.answer.v1"
            || answer["verdict"] != "accepted"
            || answer["install_id"] != install_id
            || answer["original_binding_sha256"] != binding
            || !answer["receipt"].is_object()
        {
            return unknown(Some(status));
        }
        SendReport {
            attempt: Attempt::Answered,
            reply_kind: ReplyKind::CanonicalRpc,
            reply: Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content":[],"structuredContent": answer["receipt"],"isError": false},
            }).to_string()),
            ..unknown(Some(status))
        }
    }
}

async fn read_enrolled_answer(mut response: reqwest::Response) -> Result<Value> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::engine("enrolled original response unavailable"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_STORED_REPLY {
            return Err(Error::engine("enrolled original response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
pub(in crate::node) struct WorkingVerdict {
    id: String,
    original: OriginalAppend,
    answer: &'static str,
    reply: String,
    prior_uncertain: bool,
}
impl WorkingVerdict {
    pub(in crate::node) fn id(&self) -> &str {
        &self.id
    }
    pub(in crate::node) fn matches(&self, current: &Entry) -> Result<()> {
        if !installed_working_version(current.version)
            || current.id != self.id
            || current.working_original_ref() != Some(&self.original)
        {
            return Err(Error::engine("canonical working response original changed"));
        }
        Ok(())
    }
    pub(in crate::node) fn apply(&self, entry: &mut Entry) {
        entry.state = EntryState::Confirmed;
        entry.answer = Some(self.answer.into());
        entry.reply = Some(self.reply.clone());
        entry.in_flight = false;
        entry.maybe_applied |= self.prior_uncertain;
        entry.detail = Some(if self.prior_uncertain && self.answer == "refused" {
            "hosted refused this attempt; an earlier attempt may already have applied; original retained"
        } else { "canonical response retained; accepted materialization is not yet verified" }.into());
    }
}
impl WriteGate {
    pub(super) async fn send_working(
        &self,
        upstream: &Upstream,
        hooks: Option<&dyn Outage>,
        entry: &Entry,
        deadline: Option<Instant>,
    ) -> Step {
        let ordinal = self.journal.working_ordinal(&entry.id);
        let Some(scope) = self.custody_scope.as_ref() else {
            return Step::Halt(Halt::Local);
        };
        let Some(hooks) = hooks else {
            return Step::Halt(Halt::Local);
        };
        let Some(ordinal) = ordinal else {
            return Step::Halt(Halt::Local);
        };
        if !hooks.working_published(scope, ordinal).await {
            return Step::Halt(Halt::Local);
        }
        let (report, answer) = match self.send_once(upstream, Some(hooks), entry, deadline).await {
            Ok(result) => result,
            Err(halt) => return Step::Halt(halt),
        };
        // Never hold the proposal/publication fence across hosted I/O: local
        // typing/ACK and native reads must continue during a stalled request.
        // Only durability of the real response waits for an in-flight W commit.
        let _authority = self.journal.working_serial.lock().await;
        let update = report.update_required();
        let maintenance = report
            .reply
            .as_deref()
            .is_some_and(hold::is_deployment_read_only);
        let not_before = if maintenance
            && report.attempt == Attempt::Answered
            && report.failure != Some(Health::AuthRefused)
        {
            report.reply.as_deref().and_then(|reply| {
                hold::deployment_read_only_retry_not_before(reply, crate::node::unmerged::now_ms())
            })
        } else {
            None
        };
        let decision = if report.failure != Some(Health::AuthRefused)
            && report.attempt == Attempt::Answered
            && !maintenance
            && update.is_none()
        {
            match answer {
                Some(Answer::Receipt) => Some("receipt"),
                Some(Answer::Refused) => Some("refused"),
                _ => None,
            }
        } else {
            None
        };
        if let Some(answer) = decision {
            let Some(original) = entry.working_original_ref().cloned() else {
                return Step::Halt(Halt::Local);
            };
            let Some(mut reply) = report.reply else {
                return Step::Halt(Halt::Local);
            };
            if answer == "refused" && (entry.maybe_applied || entry.in_flight) {
                reply = annotate_hosted_reply(
                    &reply,
                    json!({"outcome":"unknown", "may_already_be_applied":true,"hosted_refusal_this_attempt":true}),
                    entry.idempotency_key.as_deref().unwrap_or_default(),
                );
            }
            if reply.len() > MAX_STORED_REPLY {
                return Step::Halt(Halt::Local);
            }
            let verdict = WorkingVerdict {
                id: entry.id.clone(),
                original,
                answer,
                reply,
                prior_uncertain: entry.maybe_applied || entry.in_flight,
            };
            if self.journal.canonical_working_verdict(&verdict).is_err() {
                return Step::Halt(Halt::Local);
            }
            drop(_authority); // Notification must never wait on the durability fence.
            hooks.working_canonical_changed(scope).await;
            return Step::Next;
        }
        let credentials = report.failure == Some(Health::AuthRefused);
        let uncertain = update.is_some_and(|u| !u.definitely_unapplied)
            || matches!(report.attempt, Attempt::Lost | Attempt::Unclear)
            || (report.attempt == Attempt::Answered
                && !maintenance
                && update.is_none()
                && matches!(answer, Some(Answer::Partial | Answer::HostedPending) | None));
        if self
            .journal
            .update(&entry.id, |saved| {
                saved.in_flight = false;
                saved.maybe_applied |= uncertain;
                if let Some(not_before) = not_before {
                    saved.not_before_ms = saved.not_before_ms.max(not_before);
                }
                saved.state = if saved.maybe_applied {
                    EntryState::Uncertain
                } else {
                    EntryState::Pending
                };
                if update.is_some() {
                    saved.hold_reason = Some(HoldReason::ClientUpdateRequired);
                }
                saved.detail = Some(
                    if update.is_some() {
                        "client update demand recorded; updater unavailable; original retained"
                    } else if credentials {
                        "hosted credentials refused; write not judged"
                    } else if uncertain {
                        "canonical outcome uncertain; same original/key retained"
                    } else {
                        "hosted not ready; original remains pending"
                    }
                    .into(),
                );
            })
            .is_err()
        {
            return Step::Halt(Halt::Local);
        }
        // Attempt uncertainty is a wake-up, not a canonical verdict. It must
        // pause new ACKs without erasing the original or possibly-applied past.
        drop(_authority);
        if uncertain || entry.maybe_applied {
            hooks.working_canonical_changed(scope).await;
        }
        Step::Halt(if credentials {
            Halt::Credentials(report.status)
        } else if update.is_some() {
            Halt::ClientUpdateRequired
        } else if report.failure.is_some() {
            Halt::Unreachable
        } else {
            Halt::ReadOnly
        })
    }
}

/// Minted only here from an actual scoped, authenticated settlement response.
/// A replay error, owner command body, or W cannot construct this verdict.
pub(in crate::node) struct WorkingSettlementVerdict {
    before: Entry,
    answer: Value,
}
impl WorkingSettlementVerdict {
    pub(in crate::node) fn id(&self) -> &str {
        &self.before.id
    }
    pub(in crate::node) fn matches(&self, current: &Entry) -> Result<()> {
        if current.working_original_ref() != self.before.working_original_ref()
            || current.kernel_v2_custody != self.before.kernel_v2_custody
            || current.arguments != self.before.arguments
            || current.idempotency_key != self.before.idempotency_key
            || current.working_resolution_ref().map(|r| r.binding())
                != self.before.working_resolution_ref().map(|r| r.binding())
        {
            return Err(Error::engine("settlement original changed"));
        }
        if let Some(old) = current.working_resolution_ref().and_then(|r| r.answer()) {
            if old != &self.answer {
                return Err(Error::engine("conflicting retained settlement"));
            }
        }
        Ok(())
    }
    pub(in crate::node) fn resolution(
        &self,
    ) -> crate::node::journal::working_v2::WorkingResolution {
        crate::node::journal::working_v2::WorkingResolution::Verified {
            schema: "native.node-original-resolution.v1".into(),
            expected_binding_sha256: self
                .before
                .working_resolution_ref()
                .expect("requested before HTTP")
                .binding()
                .into(),
            answer: self.answer.clone(),
        }
    }
}
impl WriteGate {
    pub(in crate::node) async fn settle_working_original(
        &self,
        upstream: &Upstream,
        hooks: &dyn Outage,
        id: &str,
        principal: &str,
        deadline: Instant,
    ) -> Result<Entry> {
        let before = {
            let _turn = self.journal.working_serial.lock().await;
            if !self.scope_matches(Some(hooks)).await || !self.scope_targets(upstream) {
                return Err(Error::engine("resolution account binding unavailable"));
            }
            let before = self
                .journal
                .get(id)
                .ok_or_else(|| Error::engine("working original missing"))?;
            if before
                .working_original_ref()
                .is_none_or(|o| o.actor() != principal)
            {
                return Err(Error::engine("resolution principal differs"));
            }
            self.journal.request_working_resolution(id)?
        };
        let original = crate::node::journal::working_v2::settlement_original(&before)?;
        if before
            .working_resolution_ref()
            .and_then(|r| r.answer())
            .is_some()
        {
            return Ok(before);
        }
        let request = crate::kernel::original_settlement::Request {
            schema: "native.original-settlement.request.v1".into(),
            action: "settle_original".into(),
            purpose: "held_refusal_resolution".into(),
            abandon_if_unapplied: true,
            original: original.clone(),
        };
        let result: Result<Value> = async {
            if let Some(oauth) = &upstream.oauth {
                oauth
                    .ensure_fresh_before_send()
                    .await
                    .map_err(|_| Error::engine("resolution credentials unavailable"))?;
            }
            let expected = self
                .credential_for_scope(Some(hooks))
                .await
                .flatten()
                .ok_or_else(|| Error::engine("resolution credentials unverified"))?;
            let token = read_guarded_credential(&upstream.config.credential_file, "node")?;
            use sha2::Digest;
            let actual: [u8; 32] = sha2::Sha256::digest(&*token).into();
            if actual != expected || !self.scope_matches(Some(hooks)).await {
                return Err(Error::engine("resolution credential binding changed"));
            }
            if upstream.install_key.is_some() {
                use crate::kernel::original_settlement::installed::{Request, RequestAction};
                let request = Request {
                    action: RequestAction::Abandon,
                    original: original.clone(),
                    custody_sequence: None,
                };
                let response = enrolled_request(
                    upstream,
                    std::str::from_utf8(&token).expect("guarded UTF-8"),
                    "originals",
                    &request,
                    self.config
                        .attempt_timeout
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .await?;
                let response = crate::client_compatibility::inspect(
                    response,
                    &upstream.compatibility,
                    "installed-original",
                    "abandon",
                )
                .await?;
                return read_enrolled_answer(response).await;
            }
            let mut url = upstream.endpoint.clone();
            url.set_query(None);
            url.set_fragment(None);
            url.path_segments_mut()
                .map_err(|_| Error::engine("resolution endpoint unavailable"))?
                .clear()
                .extend([
                    "internal",
                    "databases",
                    &original.database_id,
                    "original-settlements",
                ]);
            let mut response = upstream
                .client
                .post(url)
                .header(
                    crate::client_compatibility::HEADER,
                    crate::client_compatibility::advertisement(),
                )
                .bearer_auth(
                    std::str::from_utf8(&token)
                        .map_err(|_| Error::engine("resolution credential encoding unavailable"))?,
                )
                .json(&request)
                .timeout(
                    self.config
                        .attempt_timeout
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .send()
                .await
                .map_err(|_| Error::engine("resolution transport unavailable"))?;
            response = crate::client_compatibility::inspect(
                response,
                &upstream.compatibility,
                "original-settlement",
                "settle",
            )
            .await?;
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| Error::engine("resolution response unavailable"))?
            {
                if body
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|size| size > MAX_STORED_REPLY)
                {
                    return Err(Error::engine("resolution response too large"));
                }
                body.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&body).map_err(Into::into)
        }
        .await;
        let _turn = self.journal.working_serial.lock().await;
        if !self.scope_matches(Some(hooks)).await || !self.scope_targets(upstream) {
            self.journal
                .working_resolution_diagnostic(id, "binding_changed")?;
            return Err(Error::engine(
                "resolution account changed; original retained",
            ));
        }
        let answer = match result {
            Ok(answer) => answer,
            Err(Error::Engine(detail))
                if detail == crate::client_compatibility::UPDATE_REQUIRED =>
            {
                self.journal
                    .working_resolution_diagnostic(id, "transport_unavailable")?;
                return Err(Error::engine("Client update demand recorded; updater unavailable; original retained and queue paused"));
            }
            Err(_) => {
                self.journal
                    .working_resolution_diagnostic(id, "transport_unavailable")?;
                return Err(Error::engine(
                    "Original status unavailable; payload retained and queue paused",
                ));
            }
        };
        if crate::node::journal::working_v2::validate_settlement_for_entry(
            &before, &original, &answer,
        )
        .is_err()
        {
            let diagnostic =
                if answer["verdict"] == "status_required" || answer["verdict"] == "mismatch" {
                    "status_required"
                } else {
                    "response_unverified"
                };
            self.journal.working_resolution_diagnostic(id, diagnostic)?;
            return Err(Error::engine(
                "Original remains unresolved; payload retained and queue paused",
            ));
        }
        self.journal
            .verified_working_settlement(&WorkingSettlementVerdict { before, answer })
    }
}
