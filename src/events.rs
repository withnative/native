//! Event types — the rows of the authoritative `events` log and the payload
//! shapes the projector folds.
//!
//! The projector distinguishes an *absent* payload key from an explicit `null`
//! (e.g. `persistence` defaults only when absent), so record create/update
//! payloads are handled as raw JSON objects rather than lossy structs.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The canonical event types the projector folds into projections.
pub const EVENT_TYPES: [&str; 46] = [
    "record.created",
    "record.updated",
    "record.type_corrected.v1",
    "record.deleted",
    "facet.set",
    "facet.unset",
    "link.added",
    "link.removed",
    "annotation.target.set",
    "annotation.target.removed",
    "attribution.target.bound.v1",
    "attribution.asserted.v1",
    "attribution.evidence.added.v1",
    "attribution.retracted.v1",
    "message.audience.declared",
    "message.audience.legacy_unknown",
    "message.origin.declared.v1",
    "message.shared",
    "message.send_evaluated.v1",
    "message.delivery.authorized.v1",
    "message.reaction.added.v1",
    "message.reaction.removed.v1",
    "intervention.raised.v1",
    "intervention.cancelled.v1",
    "intervention.execution_resumed.v1",
    "module.release_published",
    "module.release_deprecated",
    "module.release_withdrawn",
    "recipe.release_published",
    "recipe.release_deprecated",
    "recipe.release_withdrawn",
    "artifact.source_attested",
    "artifact.input_bound",
    "artifact.input_carried",
    "artifact.input_unbound",
    "artifact.module_grant_set",
    "artifact.module_grant_carried",
    "artifact.module_grant_unset",
    "unit.created.v1",
    "unit.revision.recorded.v1",
    "occurrence.bound.v1",
    "receipt.committed.v1",
    "reconciliation.recorded.v1",
    "unit.superseded.v1",
    "receipt.dependency_audited.v1",
    "canvas.batch.committed.v1",
];

pub const MESSAGE_REACTION_FORMAT: &str = "native.message-reaction.v1";
pub const MESSAGE_REACTION_EMOJIS: [&str; 5] = ["👍", "❤️", "😂", "🎉", "👀"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReactionPayload {
    pub format: String,
    pub emoji: String,
    pub idempotency_key: String,
    pub command: String,
    pub changed: bool,
    pub actor_account_id: String,
    pub executor_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_ref: Option<String>,
    pub reason: String,
}

impl MessageReactionPayload {
    pub fn validate(&self, event_actor: Option<&str>) -> crate::Result<()> {
        if self.format != MESSAGE_REACTION_FORMAT {
            return Err(crate::Error::engine("invalid Message reaction format"));
        }
        validate_message_reaction_emoji(&self.emoji)?;
        if self.idempotency_key.trim().is_empty() || self.reason.trim().is_empty() {
            return Err(crate::Error::engine(
                "Message reaction idempotency_key and reason must not be blank",
            ));
        }
        if !matches!(
            self.command.as_str(),
            "add_reaction"
                | "remove_reaction"
                | "satisfy_acknowledgement_expectation_with_reaction"
        ) {
            return Err(crate::Error::engine("invalid Message reaction command"));
        }
        if !matches!(
            self.executor_kind.as_str(),
            "human_attested" | "agent" | "delegated_service" | "authenticated_principal" | "local"
        ) {
            return Err(crate::Error::engine(
                "invalid Message reaction executor kind",
            ));
        }
        if self.actor_account_id.trim().is_empty()
            || event_actor != Some(self.actor_account_id.as_str())
        {
            return Err(crate::Error::engine(
                "Message reaction actor does not match event attribution",
            ));
        }
        match (self.executor_kind.as_str(), self.executor_ref.as_deref()) {
            ("human_attested" | "agent" | "delegated_service", Some(value))
                if !value.trim().is_empty() => {}
            ("human_attested" | "agent" | "delegated_service", _) => {
                return Err(crate::Error::engine(
                    "attested Message reaction executors require a nonblank executor_ref",
                ));
            }
            ("local" | "authenticated_principal", None) => {}
            ("local" | "authenticated_principal", Some(_)) => {
                return Err(crate::Error::engine(
                    "unattested Message reaction executors cannot carry executor_ref",
                ));
            }
            _ => {}
        }
        if self.command == "satisfy_acknowledgement_expectation_with_reaction" && self.emoji != "👍"
        {
            return Err(crate::Error::engine(
                "acknowledgement reactions must use 👍",
            ));
        }
        Ok(())
    }
}

pub fn validate_message_reaction_emoji(emoji: &str) -> crate::Result<()> {
    if !MESSAGE_REACTION_EMOJIS.contains(&emoji) {
        return Err(crate::Error::engine(
            "reaction emoji must be one of the canonical v1 picker values: 👍 ❤️ 😂 🎉 👀",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordTypeIdentity {
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordTypeCorrectionMode {
    Autonomous,
    Confirmed,
}

/// The only content event allowed to change a record's closed-spine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordTypeCorrectedPayload {
    pub from: RecordTypeIdentity,
    pub to: RecordTypeIdentity,
    pub mode: RecordTypeCorrectionMode,
    pub reason: String,
    pub plan_id: String,
    pub effect_digest: String,
    pub schema_state_revision: String,
    pub confirmation_required: bool,
}

use crate::freshness::{
    AffectedConclusion, AssessmentInput, ContextRequest, DependencyId, DependencyInput,
    DisclosureDecision, ExecutionDisposition, HistoryHighWater, MaterialityOutcome, OccurrenceId,
    OccurrenceSelector, ProvenanceUse, ReceiptId, ReconciliationEvidence, ReconciliationId,
    ResolutionPolicy, RevisionRef, UncertaintyLineage, UnitContent,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticCommandFinalization {
    pub operation: String,
    /// Authorization subject that owns this command's idempotency namespace.
    pub scope_record_id: String,
    pub idempotency_key: String,
    pub intent_sha256: String,
    pub authorization_revision_observed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCreatedPayload {
    pub semantic_contract_version: String,
    pub authority_bearer_record_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRevisionRecordedPayload {
    pub format: String,
    pub semantic_contract_version: String,
    pub content: UnitContent,
    pub content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub based_on_revision_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<SemanticCommandFinalization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceBoundPayload {
    pub semantic_contract_version: String,
    pub occurrence_id: OccurrenceId,
    pub unit_revision: RevisionRef,
    pub artefact_revision: RevisionRef,
    pub selectors: Vec<OccurrenceSelector>,
    pub expression_role: String,
    pub command: SemanticCommandFinalization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCommittedPayload {
    pub format: String,
    pub semantic_contract_version: String,
    pub runtime_contract_version: String,
    pub receipt_id: ReceiptId,
    pub expected_consumer_revision: RevisionRef,
    pub body: String,
    pub context_request: ContextRequest,
    pub resolution_policy: ResolutionPolicy,
    pub requested_source_record_ids: Vec<String>,
    pub selected_sources: Vec<RevisionRef>,
    pub history_high_water: HistoryHighWater,
    pub assembly_sha256: String,
    pub provenance: Vec<ProvenanceUse>,
    pub comparisons: Vec<crate::freshness::ImpactCandidate>,
    pub dependencies: Vec<DependencyInput>,
    pub assessments: Vec<AssessmentInput>,
    pub reconciliations: Vec<ReconciliationEvidence>,
    pub unresolved_uncertainty: Vec<UncertaintyLineage>,
    pub withheld_context: bool,
    pub dependency_declaration_outcome: String,
    pub dependency_budget_used: u32,
    pub execution: ExecutionDisposition,
    pub disclosure: DisclosureDecision,
    pub command: SemanticCommandFinalization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRecordedPayload {
    pub semantic_contract_version: String,
    pub runtime_contract_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalizing_receipt_id: Option<ReceiptId>,
    pub reconciliation_id: ReconciliationId,
    pub dependency_id: DependencyId,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub assessed_source_revision: RevisionRef,
    pub task_scope: String,
    pub affected_conclusion: AffectedConclusion,
    pub outcome: MaterialityOutcome,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<SemanticCommandFinalization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSupersededPayload {
    pub semantic_contract_version: String,
    pub runtime_contract_version: String,
    pub successors: Vec<RevisionRef>,
    pub rationale: String,
    pub command: SemanticCommandFinalization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDependencyAuditedPayload {
    pub semantic_contract_version: String,
    pub runtime_contract_version: String,
    pub receipt_id: ReceiptId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_dependency_id: Option<DependencyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_dependency: Option<crate::freshness::DependencyInput>,
    pub outcome: String,
    pub rationale: String,
    pub command: SemanticCommandFinalization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleReleasePublishedPayload {
    pub release_core: serde_json::Value,
    pub release_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleReleaseStatusPayload {
    pub publication_event_id: String,
    pub expected_status_event_seq: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSourceAttestedPayload {
    pub artifact_source: serde_json::Value,
    pub attestation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInputBoundPayload {
    pub artifact_id: String,
    pub port_name: String,
    pub collection_id: String,
    pub artifact_source_event_id: String,
    pub artifact_source_sha256: String,
    pub artifact_source_attestation_event_id: String,
    pub port_declaration: serde_json::Value,
    pub attestation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInputUnboundPayload {
    pub artifact_id: String,
    pub port_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInputCarriedPayload {
    pub binding: ArtifactInputBoundPayload,
    pub predecessor_binding_event_seq: i64,
    pub predecessor_source_attestation_event_id: String,
    pub predecessor_source_event_id: String,
    pub predecessor_source_sha256: String,
    pub old_declaration_surface_sha256: String,
    pub new_declaration_surface_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactModuleGrantPayload {
    pub artifact_id: String,
    pub subject_kind: String,
    pub subject_record_id: String,
    pub subject_event_id: String,
    pub source_sha256: String,
    pub capability: String,
    pub scope: serde_json::Value,
    pub scope_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactModuleGrantCarriedPayload {
    pub grant: ArtifactModuleGrantPayload,
    pub predecessor: ArtifactModuleGrantPayload,
    pub predecessor_grant_event_seq: i64,
    pub predecessor_source_attestation_event_id: String,
    pub predecessor_source_event_id: String,
    pub predecessor_source_sha256: String,
    pub old_declaration_surface_sha256: String,
    pub new_declaration_surface_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationTargetSetPayload {
    pub target_record_id: String,
    pub source_slot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    pub source_sha256: String,
    pub selectors: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionTargetBoundPayload {
    pub target_record_id: String,
    pub target_scope: String,
    pub source_event_id: String,
    pub source_body_sha256: String,
    pub selectors: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionAssertedPayload {
    pub contract_version: String,
    /// Native derives this from the accepted action's trusted executor facts.
    /// It is never accepted as an MCP argument.
    pub claimant_principal: String,
    pub claim_mode: String,
    pub relation: String,
    pub polarity: String,
    pub attributed_subject_kind: String,
    pub attributed_subject_ref: String,
    pub stance_as_of: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    pub transformation: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionEvidenceAddedPayload {
    pub evidence_id: String,
    pub role: String,
    pub action_attestation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionRetractedPayload {
    pub retraction_id: String,
    pub reason: String,
}

/// The closed causal-envelope version stored with every content event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalEnvelopeVersion {
    V1,
}

impl CausalEnvelopeVersion {
    pub(crate) const fn as_i64(self) -> i64 {
        match self {
            Self::V1 => 1,
        }
    }
}

/// How much of an event's source causal frontier is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalStatus {
    Complete,
    ImportIncomplete,
    LegacyUnknown,
}

impl CausalStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ImportIncomplete => "import_incomplete",
            Self::LegacyUnknown => "legacy_unknown",
        }
    }
}

/// A canonical v1 causal frontier. Event ids are opaque, sorted and unique.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CausalFrontierV1(Vec<String>);

impl CausalFrontierV1 {
    pub fn new(ids: impl IntoIterator<Item = String>) -> crate::Result<Self> {
        let mut canonical = BTreeSet::new();
        for id in ids {
            if id.trim().is_empty() {
                return Err(crate::Error::engine(
                    "causal frontier event ids must not be blank",
                ));
            }
            canonical.insert(id);
        }
        Ok(Self(canonical.into_iter().collect()))
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn validate_for_event(&self, event_id: &str) -> crate::Result<()> {
        if self.0.iter().any(|parent| parent == event_id) {
            return Err(crate::Error::engine(
                "causal frontier cannot contain the event itself",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CausalFrontierV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ids = Vec::<String>::deserialize(deserializer)?;
        Self::new(ids).map_err(serde::de::Error::custom)
    }
}

/// The versioned causal facts stored beside one content event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEnvelopeV1 {
    version: CausalEnvelopeVersion,
    status: CausalStatus,
    frontier: CausalFrontierV1,
}

impl<'de> Deserialize<'de> for CausalEnvelopeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredEnvelope {
            version: CausalEnvelopeVersion,
            status: CausalStatus,
            frontier: CausalFrontierV1,
        }

        let stored = StoredEnvelope::deserialize(deserializer)?;
        if stored.version != CausalEnvelopeVersion::V1 {
            return Err(serde::de::Error::custom(
                "unsupported causal envelope version",
            ));
        }
        Self::new(stored.status, stored.frontier).map_err(serde::de::Error::custom)
    }
}

impl CausalEnvelopeV1 {
    pub fn new(status: CausalStatus, frontier: CausalFrontierV1) -> crate::Result<Self> {
        if status == CausalStatus::LegacyUnknown && !frontier.is_empty() {
            return Err(crate::Error::engine(
                "legacy_unknown causal envelopes cannot carry frontier edges",
            ));
        }
        Ok(Self {
            version: CausalEnvelopeVersion::V1,
            status,
            frontier,
        })
    }

    pub fn complete(frontier: CausalFrontierV1) -> Self {
        Self {
            version: CausalEnvelopeVersion::V1,
            status: CausalStatus::Complete,
            frontier,
        }
    }

    pub fn import_incomplete(frontier: CausalFrontierV1) -> Self {
        Self {
            version: CausalEnvelopeVersion::V1,
            status: CausalStatus::ImportIncomplete,
            frontier,
        }
    }

    pub fn legacy_unknown() -> Self {
        Self {
            version: CausalEnvelopeVersion::V1,
            status: CausalStatus::LegacyUnknown,
            frontier: CausalFrontierV1::empty(),
        }
    }

    pub const fn version(&self) -> CausalEnvelopeVersion {
        self.version
    }

    pub const fn status(&self) -> CausalStatus {
        self.status
    }

    pub fn frontier(&self) -> &CausalFrontierV1 {
        &self.frontier
    }

    pub(crate) fn validate_for_event(&self, event_id: &str) -> crate::Result<()> {
        if self.version != CausalEnvelopeVersion::V1 {
            return Err(crate::Error::engine("unsupported causal envelope version"));
        }
        if self.status == CausalStatus::LegacyUnknown && !self.frontier.is_empty() {
            return Err(crate::Error::engine(
                "legacy_unknown causal envelopes cannot carry frontier edges",
            ));
        }
        self.frontier.validate_for_event(event_id)
    }
}

impl Default for CausalEnvelopeV1 {
    fn default() -> Self {
        Self::complete(CausalFrontierV1::empty())
    }
}

/// A source database's replay coordinate. It is meaningful only as this pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginReplayPosition {
    origin_database_id: String,
    local_seq: i64,
}

impl OriginReplayPosition {
    pub fn new(origin_database_id: String, local_seq: i64) -> crate::Result<Self> {
        if origin_database_id.trim().is_empty() || local_seq <= 0 {
            return Err(crate::Error::engine(
                "origin replay position requires a nonblank database id and positive local_seq",
            ));
        }
        Ok(Self {
            origin_database_id,
            local_seq,
        })
    }

    pub fn origin_database_id(&self) -> &str {
        &self.origin_database_id
    }

    pub const fn local_seq(&self) -> i64 {
        self.local_seq
    }
}

/// Private authority threaded through the physical append cursor. Ordinary
/// callers cannot choose a causal status because `AppendSpec` never contains
/// this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CausalAdmission {
    LocalComputed,
    GovernedImport(CausalEnvelopeV1),
}

/// A row as stored in / read from the `events` log. `payload` is JSON text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    pub local_seq: i64,
    pub id: String,
    pub record_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Option<String>,
    pub actor: Option<String>,
    /// Caller-stamped correlation annotations. They are part of the durable
    /// event envelope and history surface, but the projector deliberately
    /// ignores all three.
    pub run_key: Option<String>,
    pub parent_key: Option<String>,
    pub intent: Option<String>,
    pub created_at: String,
    pub causal_envelope: CausalEnvelopeV1,
}

#[cfg(test)]
mod causal_envelope_tests {
    use super::*;

    #[test]
    fn frontier_is_a_sorted_deduplicated_set() {
        let frontier = CausalFrontierV1::new([
            "event-b".to_string(),
            "event-a".to_string(),
            "event-b".to_string(),
        ])
        .unwrap();
        assert_eq!(frontier.as_slice(), ["event-a", "event-b"]);
    }

    #[test]
    fn malformed_frontiers_and_legacy_edges_fail_closed() {
        assert!(CausalFrontierV1::new(["  ".to_string()]).is_err());
        let self_parent =
            CausalEnvelopeV1::complete(CausalFrontierV1::new(["event-self".to_string()]).unwrap());
        assert!(self_parent.validate_for_event("event-self").is_err());
        assert!(CausalEnvelopeV1::new(
            CausalStatus::LegacyUnknown,
            CausalFrontierV1::new(["event-parent".to_string()]).unwrap(),
        )
        .is_err());
    }
}

// ---- Payload shapes (the JSON in events.payload), one per event type ----
//
// Record create/update payloads (`RecordFields` in TS) key straight onto
// `records` column names and need absent-vs-null fidelity, so they stay
// `serde_json::Value` objects end to end. The facet/link payloads below are
// closed shapes and get typed structs.

/// Payload of `facet.set`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacetSetPayload {
    pub key: String,
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vocab_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    /// When true, fold this event into valid-time history without changing the
    /// current facet assertion. Older events omit the field and retain their
    /// original current-plus-observation semantics during replay.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observation_only: bool,
}

/// Payload of `facet.unset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacetUnsetPayload {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observation_only: bool,
}

/// Payload of `link.added`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAddedPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Payload of `link.removed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRemovedPayload {
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
}

/// The complete immutable initial audience of one locally authored Message.
/// Values are local portable-person record ids; the projector resolves and
/// freezes each canonical `native-principal` address in `message_audiences`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAudienceDeclaredPayload {
    pub sender_id: String,
    pub sender_principal: String,
    pub addressed_to: Vec<MessageAudienceRecipient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageAudienceRecipient {
    pub recipient_id: String,
    pub principal: String,
}

/// The immutable communication context in which a Message was authored.
///
/// Placement, visibility and addressing are deliberately absent: those are
/// independent Message axes. The tagged wire shape leaves room for later
/// origin kinds without weakening the two variants admitted by this engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageOriginDeclaredPayload {
    Collection { collection_id: String },
    Direct { principals: Vec<String> },
}

/// Canonicalize an exact direct-context principal set before authoring its
/// immutable event. Callers must resolve portable people to canonical
/// `native-principal` identifiers first; this helper supplies stable ordering
/// and set normalization, not identity resolution.
pub fn normalize_direct_origin_principals<I, S>(principals: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut principals = principals.into_iter().map(Into::into).collect::<Vec<_>>();
    principals.sort();
    principals.dedup();
    principals
}

/// Stable identity for one already-normalized exact direct principal set.
/// Length-delimited components make the encoding unambiguous without making
/// a JSON serializer part of the durable digest contract.
pub fn direct_origin_set_digest(principals: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"native.message-direct-origin.v1\0");
    for principal in principals {
        digest.update((principal.len() as u64).to_be_bytes());
        digest.update(principal.as_bytes());
    }
    hex::encode(digest.finalize())
}

/// Stable stream key shared by send, reply-validation, projection and reads.
pub fn direct_origin_context_key(principals: &[String]) -> String {
    format!("direct:{}", direct_origin_set_digest(principals))
}

impl MessageOriginDeclaredPayload {
    /// Stable key for routing one authored communication context. Collection
    /// ids are already canonical record identities; direct contexts use their
    /// exact-set digest.
    pub fn context_key(&self) -> String {
        match self {
            Self::Collection { collection_id } => format!("collection:{collection_id}"),
            Self::Direct { principals } => direct_origin_context_key(principals),
        }
    }
}

/// One append-only visibility expansion for an existing Message. The original
/// audience remains unchanged; `selection_id` ties every per-Message event in
/// one exact/snapshot share operation back to its resolved selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageSharedPayload {
    pub grant_id: String,
    pub selection_id: String,
    pub recipient_id: String,
    pub recipient_principal: String,
    pub snapshot_seq: i64,
    pub reason: String,
}

/// One recipient resolved by the registry for an atomic Message send.  The
/// record id is portable inside the database; the principal is frozen so a
/// later binding change cannot rewrite the historical destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedMessageRecipient {
    pub recipient_id: String,
    pub principal: String,
}

/// Durable result of the policy gate for one attempted Message send.  This is
/// appended to the Message in the same transaction as its content and audience
/// declaration. `delivered=false` means the Message is a sender-only draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageSendEvaluatedPayload {
    pub format: String,
    pub idempotency_key: String,
    pub sender_principal_id: String,
    pub intent_digest: String,
    pub action: serde_json::Value,
    pub action_digest: String,
    pub disposition: String,
    pub delivered: bool,
    pub intended_recipients: Vec<ResolvedMessageRecipient>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure_preview: Option<String>,
    pub policy_trace: serde_json::Value,
    pub evaluation_digest: String,
}

/// The exact audience expansion that turns a blocked sender-only draft into a
/// delivered Message.  The corresponding policy replacement is committed in
/// the same transaction by the command handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDeliveryAuthorizedPayload {
    pub format: String,
    pub intervention_id: String,
    pub idempotency_key: String,
    pub action_digest: String,
    pub authority_evidence_record_id: String,
    pub recipients: Vec<ResolvedMessageRecipient>,
    pub fresh_policy_trace: serde_json::Value,
    pub fresh_evaluation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionRaisedPayload {
    pub format: String,
    pub intervention_id: String,
    pub idempotency_key: String,
    pub target_person_record_id: String,
    pub target_principal_id: String,
    pub sender_principal_id: String,
    pub disposition: String,
    pub requested_outcome: String,
    pub request: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure_preview: Option<String>,
    pub reason: String,
    pub context_refs: Vec<String>,
    pub action: serde_json::Value,
    pub action_digest: String,
    pub policy_trace: serde_json::Value,
    pub evaluation_digest: String,
    pub intended_recipients: Vec<ResolvedMessageRecipient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionCancelledPayload {
    pub format: String,
    pub intervention_id: String,
    pub target_principal_id: String,
    pub action_digest: String,
    pub idempotency_key: String,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionExecutionResumedPayload {
    pub format: String,
    pub intervention_id: String,
    pub target_principal_id: String,
    pub idempotency_key: String,
    pub basis_kind: String,
    pub basis_record_id: String,
    pub action_digest: String,
    pub delivery_event_id: String,
    pub fresh_evaluation_digest: String,
    pub summary: String,
}

#[cfg(test)]
mod message_origin_tests {
    use super::*;

    #[test]
    fn tagged_origin_shape_and_exact_set_key_are_stable() {
        let principals = normalize_direct_origin_principals([
            "native/zeta".to_string(),
            "native/alpha".to_string(),
            "native/zeta".to_string(),
        ]);
        assert_eq!(principals, ["native/alpha", "native/zeta"]);
        let origin = MessageOriginDeclaredPayload::Direct {
            principals: principals.clone(),
        };
        assert_eq!(
            serde_json::to_value(&origin).unwrap(),
            serde_json::json!({"type":"direct","principals":["native/alpha","native/zeta"]})
        );
        assert_eq!(origin.context_key(), direct_origin_context_key(&principals));
        assert_ne!(
            direct_origin_set_digest(&principals),
            direct_origin_set_digest(&["native/alpha".into()])
        );

        let collection = MessageOriginDeclaredPayload::Collection {
            collection_id: "collection-id".into(),
        };
        assert_eq!(
            serde_json::to_value(&collection).unwrap(),
            serde_json::json!({"type":"collection","collection_id":"collection-id"})
        );
        assert_eq!(collection.context_key(), "collection:collection-id");
    }
}
