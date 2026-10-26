//! Version-bound management confirmations (§3.8, §4.7.3). Ordinary suggestions
//! are a best-effort UI; only sealed mappings and verified local resolution
//! outputs establish authority. Content sequence numbers are compared only
//! with other content sequence numbers, never with control sequence numbers.
use super::{
    client::ClientIdentity,
    conflicts,
    model::Entry,
    store::{payload_of, record_id_of, sha256_hex, Store, Stored, WriteTx},
};
use crate::{
    control::{ControlEventPayload, HcpEntryConfirmedPayload, HcpEntrySuggestionPayload},
    error::Result,
};
use serde_json::{json, Value};
use sqlx::Row;

impl Store<'_> {
    pub(super) async fn consume_all_resolutions(&self) -> Result<()> {
        for urn in self.fold_all().await?.entries.keys() {
            self.consume_resolutions(urn).await?;
        }
        Ok(())
    }

    /// A failed control append rolls back the confirmation and every status
    /// consequence together. Projection is deliberately outside this boundary.
    pub(super) async fn consume_resolutions(&self, urn: &str) -> Result<()> {
        let mut tx = self.begin().await?;
        let mut act = crate::act::ActAllocation::new();
        if self.consume_resolutions_in(&mut tx, &mut act, urn).await? {
            self.commit(tx).await?;
            self.sync_version_views(urn).await;
        } else {
            tx.rollback().await?;
        }
        Ok(())
    }

    /// Recheck under the revision writer's own lock too: a UI resolution can
    /// commit after its preliminary reconciliation but before the version's
    /// transaction starts. No revision may race past that pending rejection.
    pub(super) async fn consume_resolutions_in(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        urn: &str,
    ) -> Result<bool> {
        let fold = self.fold_all_in(tx).await?;
        let Some(folded) = fold.entries.get(urn) else {
            return Ok(false);
        };
        let version = folded.current().version();
        let mut pending = Vec::new();
        for mapping in fold.suggestions.values().filter(|p| {
            p.entry_id == urn
                && p.version == version
                && !fold.resolutions.contains_key(&p.suggestion_id)
        }) {
            if let Some((seq, payload)) = self.verified_resolution(tx, mapping).await? {
                pending.push((seq, payload));
            }
        }
        pending.sort_by_key(|(seq, _)| *seq);
        let changed = !pending.is_empty();
        for (_, payload) in pending {
            let fold = self.fold_all_in(tx).await?;
            let current = Stored::from(&fold.entries[urn]);
            self.append(
                tx,
                act,
                format!("hcp-confirm:{}:{}", self.account(), payload.suggestion_id),
                "Record the person's Native suggestion resolution".into(),
                ControlEventPayload::HcpEntryConfirmed(payload.clone()),
            )
            .await?;
            let accepted = payload.disposition == "confirmed";
            let client = || payload_of(&ClientIdentity::native());
            if accepted && current.entry.status() == "conflicted" {
                for other in fold.entries.values().map(Stored::from).filter(|o| {
                    o.entry.id() != urn
                        && conflicts::in_conflict(&current.entry, &o.entry, chrono::Utc::now())
                        && conflicts::authoritative(&o.entry)
                }) {
                    self.append_transition(
                        tx,
                        act,
                        &other,
                        "deprecated",
                        "deprecated",
                        "the person's confirmation supersedes the authoritative counterpart",
                        Some(urn),
                        client(),
                    )
                    .await?;
                }
            }
            let to = if accepted && current.entry.status() == "conflicted" {
                "active"
            } else if !accepted && current.entry.status() != "deprecated" {
                "deleted"
            } else {
                current.entry.status()
            };
            if to != current.entry.status() {
                // Re-fold after confirmation so the status event's view digest
                // contains the confirmation too.
                let current = self.entry_in(tx, urn).await?.unwrap();
                self.append_transition(
                    tx,
                    act,
                    &current,
                    to,
                    if accepted { "confirmed" } else { "rejected" },
                    "the person resolved the inference in Native",
                    None,
                    client(),
                )
                .await?;
            }
            // No conflict reevaluation on rejection: the counterpart stays pinned.
        }
        Ok(changed)
    }

    async fn verified_resolution(
        &self,
        tx: &mut WriteTx,
        mapping: &HcpEntrySuggestionPayload,
    ) -> Result<Option<(i64, HcpEntryConfirmedPayload)>> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            return super::kernel_human::verified_resolution(tx, self.account(), mapping).await;
        }
        let target = record_id_of(&mapping.entry_id).unwrap();
        if super::view::private_revision(self, tx, &target)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let row = sqlx::query("SELECT s.body,s.lifecycle,s.archived,s.deleted_at,
            (SELECT count(*) FROM links WHERE source_id=s.id AND relationship='part_of') AS targets,
            (SELECT target_id FROM links WHERE source_id=s.id AND relationship='part_of' LIMIT 1) AS target
            FROM records s WHERE s.id=? AND s.type='Annotation' AND s.kind='suggestion'")
            .bind(&mapping.suggestion_id).fetch_optional(&mut **tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let life: Option<String> = row.try_get("lifecycle")?;
        if !matches!(life.as_deref(), Some("accepted" | "rejected"))
            || row.try_get::<bool, _>("archived")?
            || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
            || row.try_get::<i64, _>("targets")? != 1
            || row.try_get::<Option<String>, _>("target")?.as_deref() != Some(&target)
            || row
                .try_get::<Option<String>, _>("body")?
                .is_none_or(|b| sha256_hex(&b) != mapping.body_digest)
        {
            return Ok(None);
        }
        // Suggestion privacy is independently checked; entry kind checking in
        // private_revision is intentionally not reused for Annotation records.
        let policy_target =
            crate::authorization::authorization_target_on(tx, &mapping.suggestion_id).await?;
        let policy = crate::mcp::tools::policy::policy_snapshot(tx, &policy_target).await?;
        if policy.mode != native_policy_kernel::PolicyMode::Explicit
            || policy.entries
                != [native_policy_kernel::AllowEntry::account(
                    self.account(),
                    native_policy_kernel::Capability::Manage,
                )]
        {
            return Ok(None);
        }
        let created = sqlx::query("SELECT seq,act,payload FROM content_events WHERE id=? AND record_id=? AND type='record.created'")
            .bind(&mapping.created_event_id).bind(&mapping.suggestion_id).fetch_optional(&mut **tx).await?;
        let Some(created) = created else {
            return Ok(None);
        };
        let authored: Value = serde_json::from_str(&created.try_get::<String, _>("payload")?)?;
        if authored["body"]
            .as_str()
            .is_none_or(|b| sha256_hex(b) != mapping.body_digest)
        {
            return Ok(None);
        }
        let resolved = sqlx::query("SELECT id,seq,created_at FROM content_events WHERE record_id=? AND type='record.updated' AND json_extract(payload,'$.lifecycle')=? ORDER BY seq LIMIT 1")
            .bind(&mapping.suggestion_id).bind(&life).fetch_optional(&mut **tx).await?;
        let Some(resolved) = resolved else {
            return Ok(None);
        };
        let seq: i64 = resolved.try_get("seq")?;
        let created_seq: i64 = created.try_get("seq")?;
        if seq <= created_seq {
            return Ok(None);
        }
        // Reject edited/restored text, precondition changes, transplants and
        // relinks. Creation's own link/facet events may share its act.
        let changed: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND seq>? AND seq<? AND act IS NOT ?")
            .bind(&mapping.suggestion_id).bind(created_seq).bind(seq).bind(created.try_get::<Option<i64>,_>("act")?).fetch_one(&mut **tx).await?;
        if changed != 0 {
            return Ok(None);
        }
        // Open-additive link mutations can live in the relationship log. Check
        // its immutable history too; a remove/re-add must not launder a relink.
        // Act equality identifies creation's own events, without ordering two
        // independent sequence domains.
        let relinked: i64 = sqlx::query_scalar("SELECT count(*) FROM relationship_events e JOIN relationship_endpoints p ON p.relationship_origin_db_id=e.relationship_origin_db_id AND p.relationship_id=e.relationship_id WHERE p.record_id=? AND e.act IS NOT ?")
            .bind(&mapping.suggestion_id).bind(created.try_get::<Option<i64>,_>("act")?).fetch_one(&mut **tx).await?;
        if relinked != 0 {
            return Ok(None);
        }

        let body: Option<String> = sqlx::query_scalar(&format!("SELECT json_extract(payload,'$.body') FROM content_events WHERE record_id=? AND seq<=? AND ({}) ORDER BY seq DESC LIMIT 1",crate::record_body::BODY_CARRYING_EVENT_SQL))
            .bind(&target).bind(seq).fetch_optional(&mut **tx).await?.flatten();
        if body.is_none_or(|b| sha256_hex(&b) != mapping.body_digest) {
            return Ok(None);
        }
        let event: String = resolved.try_get("id")?;
        let evidence = sqlx::query("SELECT a.id,r.id AS receipt FROM provenance_action_outputs o
            JOIN provenance_action_attestations a ON a.id=o.action_attestation_id
            JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
            JOIN provenance_interaction_receipts r ON r.id=a.interaction_receipt_id AND r.principal=a.principal
            WHERE o.output_domain='content' AND o.output_event_id=? AND a.operation='resolve_suggestions'
              AND a.executor_kind='human' AND a.principal=?")
            .bind(&event).bind(self.account()).fetch_all(&mut **tx).await?;
        for row in evidence {
            let id: String = row.try_get("id")?;
            // Local issuance admitted the receipt's exact accepted-action
            // digest before writing any output. The validation rechecks local
            // authority, commitment, validity and exact output set. Web alone
            // and imported attestations are never evidence of a human action.
            let Ok(valid) = crate::provenance::validate_action_attestation_evidence_in(
                tx,
                self.caller,
                &id,
                Some("human"),
            )
            .await
            else {
                continue;
            };
            if valid.principal != self.account()
                || !valid.outputs.iter().any(|o| {
                    o.domain == crate::provenance::OutputDomain::Content && o.event_id == event
                })
            {
                continue;
            }
            return Ok(Some((
                seq,
                HcpEntryConfirmedPayload {
                    account_id: self.account().into(),
                    entry_id: mapping.entry_id.clone(),
                    version: mapping.version,
                    client: payload_of(&ClientIdentity::native()),
                    disposition: if life.as_deref() == Some("accepted") {
                        "confirmed"
                    } else {
                        "rejected"
                    }
                    .into(),
                    suggestion_id: mapping.suggestion_id.clone(),
                    resolution_event_id: event,
                    attestation_id: id,
                    interaction_receipt_id: row.try_get("receipt")?,
                    confirmed_at: resolved.try_get("created_at")?,
                },
            )));
        }
        Ok(None)
    }

    pub(super) async fn sync_suggestions(&self) {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            if let Err(error) = super::kernel_view::sync_suggestions(self).await {
                eprintln!("[native-ce] kernel HCP suggestions: {error}");
            }
            return;
        }

        // Hosted SQLite has one serving process. Serialize this best-effort
        // read/create/map projection across concurrent touches; durable HCP
        // state itself remains serialized by its write transaction.
        let _projection = super::super::hcp::locks::acquire(&format!(
            "hcp-v2-suggestions:{}:{}",
            self.db.path().display(),
            self.account()
        ))
        .await;
        if let Err(error) = Box::pin(self.try_sync_suggestions()).await {
            eprintln!("[native-ce] hcp_v2: suggestion projection not written: {error}");
        }
    }

    async fn try_sync_suggestions(&self) -> Result<()> {
        let fold = self.fold_all().await?;
        let mut open_versions = std::collections::BTreeSet::new();
        for mapping in fold.suggestions.values() {
            let live = fold.entries.get(&mapping.entry_id).is_some_and(|f| {
                f.current().version() == mapping.version
                    && f.current().status() == "conflicted"
                    && sha256_hex(&f.current().view_body()) == mapping.body_digest
            });
            let open: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND lifecycle='open' AND archived=0 AND deleted_at IS NULL)")
                .bind(&mapping.suggestion_id).fetch_one(self.db.write_pool()).await?;
            let target = record_id_of(&mapping.entry_id).unwrap();
            let expected = fold
                .entries
                .get(&mapping.entry_id)
                .map(|f| f.current().view_body());
            let usable: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records r WHERE r.id=? AND r.body=? AND (SELECT count(*) FROM links WHERE source_id=r.id AND relationship='part_of')=1 AND EXISTS(SELECT 1 FROM links WHERE source_id=r.id AND target_id=? AND relationship='part_of'))")
                .bind(&mapping.suggestion_id).bind(expected).bind(target).fetch_one(self.db.write_pool()).await?;
            if live && open && usable && !fold.resolutions.contains_key(&mapping.suggestion_id) {
                open_versions.insert((mapping.entry_id.clone(), mapping.version));
            }
            if !live || fold.resolutions.contains_key(&mapping.suggestion_id) {
                // Withdraw only still-open projections; keep resolved history.
                if open {
                    Box::pin(crate::mcp::tools::lifecycle::archive_record(self.db.clone(),self.caller.clone(),json!({"id":mapping.suggestion_id,"archived":true,"reason":"HCP inference suggestion is obsolete"}))).await?;
                }
            }
        }
        for folded in fold.entries.values() {
            let entry = folded.current();
            if entry.status() != "conflicted"
                || entry.declaration_type() != "model-inferred"
                || open_versions.contains(&(entry.id().to_string(), entry.version()))
            {
                continue;
            }
            self.create_suggestion(entry).await?;
        }
        Ok(())
    }

    async fn create_suggestion(&self, entry: &Entry) -> Result<()> {
        let target = record_id_of(entry.id()).unwrap();
        let body = entry.view_body();
        let digest = sha256_hex(&body);
        let mut tx = self.begin().await?;
        let private = super::view::private_revision(self, &mut tx, &target)
            .await?
            .is_some();
        let held: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&target)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
        tx.rollback().await?;
        if !private || held.as_deref() != Some(body.as_str()) {
            return Ok(());
        }
        let id = uuid::Uuid::new_v4().to_string();
        Box::pin(crate::mcp::tools::lifecycle::create_record(self.db.clone(),self.caller.clone(),json!({
            "id":id,"type":"Annotation","kind":"suggestion","name":"Confirm or reject this inferred preference",
            "lifecycle":"open","body":body,
            "links":[{"target_id":target,"relationship":"part_of"}],
            "facets":{"proposal.precondition":"digest","anchor.base_digest":digest},
            "reason":"HCP asks you to resolve this conflicted inference","sources":[],"confirm":true
        }))).await?;
        let mut tx = self.begin().await?;
        let current = self.fold_all_in(&mut tx).await?;
        if !current.entries.get(entry.id()).is_some_and(|f| {
            f.current().version() == entry.version() && f.current().status() == "conflicted"
        }) {
            tx.rollback().await?;
            self.withdraw_suggestion(&id).await?;
            return Ok(());
        }
        let created: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='record.created' ORDER BY seq LIMIT 1").bind(&id).fetch_one(&mut *tx).await?;
        let appended = self
            .append(
                &mut tx,
                &mut crate::act::ActAllocation::new(),
                format!("hcp-suggestion:{}:{}", self.account(), id),
                "Bind an ordinary Native suggestion to this inference version".into(),
                ControlEventPayload::HcpEntrySuggestion(HcpEntrySuggestionPayload {
                    account_id: self.account().into(),
                    entry_id: entry.id().into(),
                    version: entry.version(),
                    client: payload_of(&ClientIdentity::native()),
                    suggestion_id: id.clone(),
                    created_event_id: created,
                    body_digest: digest,
                }),
            )
            .await;
        let result = match appended {
            Ok(()) => self.commit(tx).await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        };
        if result.is_err() {
            self.withdraw_suggestion(&id).await?;
        }
        result
    }

    async fn withdraw_suggestion(&self, id: &str) -> Result<()> {
        Box::pin(crate::mcp::tools::lifecycle::archive_record(
            self.db.clone(),
            self.caller.clone(),
            json!({"id":id,"reason":"Withdraw an obsolete or unbound HCP suggestion"}),
        ))
        .await?;
        Ok(())
    }
}
