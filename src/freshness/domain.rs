//! Backend-neutral values for the freshness kernel.
//!
//! Keep this file free of storage types and query vocabulary.  The SQLite
//! adapter in `kernel` is one implementation of these contracts, not their
//! definition.

use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::citations::SelectorInput;
use crate::error::{Error, Result};

pub const SEMANTIC_CONTRACT_VERSION: &str = "native.freshness-kernel.v1";
pub const RUNTIME_CONTRACT_VERSION: &str = "native.receipt-runtime.v1";
pub const RECEIPT_FORMAT: &str = "native.context-receipt.v1";
pub const UNIT_REVISION_FORMAT: &str = "native.unit-revision.v1";
pub const SEMANTIC_UNIT_RECORD_KIND: &str = "semantic-unit";

/// The semantic Unit envelope is created only by the promotion kernel, which
/// appends the envelope and its semantic identity atomically. Generic record
/// writers must not mint lookalikes that generic discovery would subordinate
/// without an authoritative `semantic_units` row.
pub(crate) fn reject_reserved_semantic_unit_kind(kind: &str, surface: &str) -> Result<()> {
    if kind == SEMANTIC_UNIT_RECORD_KIND {
        return Err(Error::engine(format!(
            "{surface}: kind '{SEMANTIC_UNIT_RECORD_KIND}' is reserved for freshness-kernel promotion"
        )));
    }
    Ok(())
}

fn opaque_id(value: impl Into<String>, label: &str) -> Result<String> {
    let value = value.into();
    if value.trim().is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(Error::engine(format!(
            "{label} must be a non-blank opaque id of at most 200 characters"
        )));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UnitId(String);

impl UnitId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(opaque_id(value, "unit id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OccurrenceId(String);

impl OccurrenceId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(opaque_id(value, "occurrence id")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        Ok(Self(opaque_id(value, "idempotency key")?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

macro_rules! deserialize_constrained_string {
    ($type:ty) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

deserialize_constrained_string!(UnitId);
deserialize_constrained_string!(OccurrenceId);
deserialize_constrained_string!(IdempotencyKey);

macro_rules! freshness_id {
    ($name:ident, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                Ok(Self(opaque_id(value, $label)?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        deserialize_constrained_string!($name);
    };
}

freshness_id!(ReceiptId, "receipt id");
freshness_id!(DependencyId, "dependency id");
freshness_id!(AssessmentId, "assessment id");
freshness_id!(ReconciliationId, "reconciliation id");
freshness_id!(UncertaintyId, "uncertainty id");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSubjectKind {
    Unit,
    Artefact,
}

impl RevisionSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Artefact => "artefact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionSourceSlot {
    UnitContent,
    RecordBody,
    Blob,
}

impl RevisionSourceSlot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnitContent => "unit_content",
            Self::RecordBody => "record_body",
            Self::Blob => "blob",
        }
    }
}

/// An exact durable address.  `current` is intentionally unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionRef {
    pub subject_kind: RevisionSubjectKind,
    pub subject_id: String,
    pub revision_event_id: String,
    pub revision_seq: i64,
    pub source_slot: RevisionSourceSlot,
    pub sha256: String,
}

impl RevisionRef {
    pub fn validate(&self) -> Result<()> {
        opaque_id(self.subject_id.clone(), "revision subject id")?;
        opaque_id(self.revision_event_id.clone(), "revision event id")?;
        if self.revision_seq <= 0 {
            return Err(Error::engine("revision sequence must be positive"));
        }
        validate_sha256(&self.sha256, "revision sha256")?;
        match (self.subject_kind, self.source_slot) {
            (RevisionSubjectKind::Unit, RevisionSourceSlot::UnitContent)
            | (RevisionSubjectKind::Artefact, RevisionSourceSlot::RecordBody)
            | (RevisionSubjectKind::Artefact, RevisionSourceSlot::Blob) => Ok(()),
            _ => Err(Error::engine(
                "revision subject kind and source slot are incompatible",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryHighWater {
    pub content_seq: i64,
    pub authorization_revision_observed: i64,
    pub semantic_contract_version: String,
}

impl HistoryHighWater {
    pub fn validate(&self) -> Result<()> {
        if self.content_seq < 0 || self.authorization_revision_observed < 0 {
            return Err(Error::engine(
                "history high-water values cannot be negative",
            ));
        }
        if self.semantic_contract_version != SEMANTIC_CONTRACT_VERSION {
            return Err(Error::engine(
                "unsupported freshness semantic contract version",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UnitContentMediaType(String);

impl UnitContentMediaType {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > 255
            || value.chars().any(char::is_control)
            || !value.contains('/')
        {
            return Err(Error::engine("unit content media type is invalid"));
        }
        Ok(Self(value))
    }

    pub fn plain_text() -> Self {
        Self("text/plain".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

deserialize_constrained_string!(UnitContentMediaType);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct UnitEncodingVersion(u32);

impl UnitEncodingVersion {
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            return Err(Error::engine("unit encoding version must be positive"));
        }
        Ok(Self(value))
    }

    pub const fn v1() -> Self {
        Self(1)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for UnitEncodingVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnitContent {
    pub content: String,
    pub content_media_type: UnitContentMediaType,
    pub encoding_version: UnitEncodingVersion,
}

impl UnitContent {
    pub fn text(content: impl Into<String>) -> Result<Self> {
        Self::new(
            content,
            UnitContentMediaType::plain_text(),
            UnitEncodingVersion::v1(),
        )
    }

    pub fn new(
        content: impl Into<String>,
        content_media_type: UnitContentMediaType,
        encoding_version: UnitEncodingVersion,
    ) -> Result<Self> {
        let content = content.into();
        if content.trim().is_empty() {
            return Err(Error::engine("unit content must not be blank"));
        }
        Ok(Self {
            content,
            content_media_type,
            encoding_version,
        })
    }

    /// Versioned, length-delimited bytes whose digest identifies the exact
    /// semantic representation, not an untyped string with ambient metadata.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let media = self.content_media_type.as_str().as_bytes();
        let content = self.content.as_bytes();
        let mut bytes = b"native.unit-content\0".to_vec();
        bytes.extend_from_slice(&self.encoding_version.get().to_be_bytes());
        bytes.extend_from_slice(&(media.len() as u64).to_be_bytes());
        bytes.extend_from_slice(media);
        bytes.extend_from_slice(&(content.len() as u64).to_be_bytes());
        bytes.extend_from_slice(content);
        bytes
    }

    pub fn sha256(&self) -> String {
        sha256(&self.canonical_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(
            self.content.clone(),
            UnitContentMediaType::new(self.content_media_type.as_str())?,
            UnitEncodingVersion::new(self.encoding_version.get())?,
        )
        .map(|_| ())
    }
}

impl<'de> Deserialize<'de> for UnitContent {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            content: String,
            content_media_type: UnitContentMediaType,
            encoding_version: UnitEncodingVersion,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.content, wire.content_media_type, wire.encoding_version)
            .map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpressionRole {
    Canonical,
    Paraphrase,
    Summary,
    Quotation,
}

impl ExpressionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Paraphrase => "paraphrase",
            Self::Summary => "summary",
            Self::Quotation => "quotation",
        }
    }
}

pub type OccurrenceSelector = SelectorInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceResolutionState {
    Current,
    Relocated,
    Stale,
    Conflict,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceResolution {
    pub occurrence_id: OccurrenceId,
    pub state: OccurrenceResolutionState,
    pub original_artefact_revision: RevisionRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_artefact_revision: Option<RevisionRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_range: Option<ResolvedRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitView {
    pub unit_id: UnitId,
    pub authority_bearer_record_id: String,
    pub label: Option<String>,
    pub creation_event_id: String,
    pub creation_event_seq: i64,
    pub current_heads: Vec<RevisionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitRevisionView {
    pub revision: RevisionRef,
    pub content: UnitContent,
    pub based_on_revision_event_id: Option<String>,
    pub rationale: Option<String>,
    pub actor: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceView {
    pub occurrence_id: OccurrenceId,
    pub unit_revision: RevisionRef,
    pub artefact_revision: RevisionRef,
    pub selectors: Vec<OccurrenceSelector>,
    pub expression_role: ExpressionRole,
    pub actor: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteIdeaInput {
    pub source_revision: RevisionRef,
    pub selectors: Vec<OccurrenceSelector>,
    pub first_content: UnitContent,
    pub expression_role: ExpressionRole,
    pub label: Option<String>,
    pub requested_unit_id: Option<UnitId>,
    pub requested_occurrence_id: Option<OccurrenceId>,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteIdeaResult {
    pub unit_id: UnitId,
    pub first_revision: RevisionRef,
    pub occurrence_id: OccurrenceId,
    pub high_water: HistoryHighWater,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindOccurrenceInput {
    pub unit_revision: RevisionRef,
    pub artefact_revision: RevisionRef,
    pub selectors: Vec<OccurrenceSelector>,
    pub expression_role: ExpressionRole,
    pub requested_occurrence_id: Option<OccurrenceId>,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindOccurrenceResult {
    pub occurrence: OccurrenceView,
    pub high_water: HistoryHighWater,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviseUnitInput {
    pub unit_id: UnitId,
    pub expected_current: RevisionRef,
    pub content: UnitContent,
    pub rationale: String,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviseUnitResult {
    pub previous_revision: RevisionRef,
    pub new_revision: RevisionRef,
    pub high_water: HistoryHighWater,
}

/// Why context was assembled.  This is retained in the Receipt so later
/// materiality assessments are relative to the task that produced the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRequest {
    pub intent: String,
    pub task_scope: String,
    #[serde(default)]
    pub risk_inputs: Vec<String>,
}

impl ContextRequest {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.intent, "context intent"),
            (&self.task_scope, "task scope"),
        ] {
            if value.trim().is_empty() {
                return Err(Error::engine(format!("{label} must not be blank")));
            }
        }
        if self.risk_inputs.iter().any(|value| value.trim().is_empty()) {
            return Err(Error::engine("risk inputs must not contain blank values"));
        }
        if self.risk_inputs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::engine(
                "risk inputs must be distinct and canonically ordered",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureRule {
    MaterialOnly,
    ExplainOnInspection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionPolicy {
    pub continue_by_default: bool,
    pub disclosure_rule: DisclosureRule,
    #[serde(default)]
    pub hard_stop_categories: Vec<String>,
    pub dependency_budget: u32,
    pub version: String,
}

impl ResolutionPolicy {
    pub fn agent_speed_default() -> Self {
        Self {
            continue_by_default: true,
            disclosure_rule: DisclosureRule::MaterialOnly,
            hard_stop_categories: Vec::new(),
            dependency_budget: 64,
            version: "native.resolution-policy.v1".into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version.trim().is_empty() || self.dependency_budget == 0 {
            return Err(Error::engine("resolution policy is invalid"));
        }
        if self
            .hard_stop_categories
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(Error::engine("hard-stop categories must not be blank"));
        }
        if self
            .hard_stop_categories
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::engine(
                "hard-stop categories must be distinct and canonically ordered",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceUse {
    pub source_revision: RevisionRef,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedConclusion {
    pub key: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyInput {
    pub dependency_id: DependencyId,
    pub source_revision: RevisionRef,
    pub semantic_role: String,
    pub affected_conclusion: AffectedConclusion,
    pub rationale: String,
    pub reconsideration_trigger: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl DependencyInput {
    pub fn validate(&self) -> Result<()> {
        self.dependency_id.validate()?;
        self.source_revision.validate()?;
        for (value, label) in [
            (&self.semantic_role, "semantic role"),
            (&self.affected_conclusion.key, "affected conclusion key"),
            (
                &self.affected_conclusion.description,
                "affected conclusion description",
            ),
            (&self.rationale, "dependency rationale"),
            (&self.reconsideration_trigger, "reconsideration trigger"),
        ] {
            if value.trim().is_empty() {
                return Err(Error::engine(format!("{label} must not be blank")));
            }
        }
        if self
            .confidence
            .is_some_and(|value| !(0.0..=1.0).contains(&value) || !value.is_finite())
        {
            return Err(Error::engine(
                "dependency confidence must be between zero and one",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialityOutcome {
    Immaterial,
    RemainsValid,
    Material,
    MateriallyUncertain,
    Contradicted,
    UnableToAssess,
}

impl MaterialityOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immaterial => "immaterial",
            Self::RemainsValid => "remains_valid",
            Self::Material => "material",
            Self::MateriallyUncertain => "materially_uncertain",
            Self::Contradicted => "contradicted",
            Self::UnableToAssess => "unable_to_assess",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentInput {
    pub assessment_id: AssessmentId,
    pub dependency_id: DependencyId,
    pub compared_source_revision: RevisionRef,
    /// Policy-facing risk category. This is deliberately separate from the
    /// task-relative materiality verdict so a policy can force a stop without
    /// pretending the underlying change is more material than assessed.
    pub category: String,
    pub outcome: MaterialityOutcome,
    pub could_materially_change: bool,
    pub rationale: String,
}

pub(crate) fn validate_assessment_materiality(assessment: &AssessmentInput) -> Result<()> {
    let required = match assessment.outcome {
        MaterialityOutcome::Immaterial | MaterialityOutcome::RemainsValid => Some(false),
        MaterialityOutcome::Material
        | MaterialityOutcome::MateriallyUncertain
        | MaterialityOutcome::Contradicted => Some(true),
        MaterialityOutcome::UnableToAssess => None,
    };
    if required.is_some_and(|required| assessment.could_materially_change != required) {
        return Err(Error::engine(
            "assessment materiality flag contradicts its outcome",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UncertaintyLineage {
    pub uncertainty_id: UncertaintyId,
    pub dependency_id: DependencyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inherited_from_receipt_id: Option<ReceiptId>,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub selected_source_revision: RevisionRef,
    pub affected_conclusion: AffectedConclusion,
    /// The scope of the assessment that introduced this uncertainty. This is
    /// intentionally distinct from the originating dependency Receipt's task
    /// scope: a dependency can be reconsidered under a later, different task.
    pub assessment_task_scope: String,
    pub verdict: MaterialityOutcome,
    pub evidence: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDisposition {
    Continued,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDecision {
    Silent,
    ExplainOnInspection,
    SurfaceNow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextAssembly {
    pub request: ContextRequest,
    pub high_water: HistoryHighWater,
    pub requested_source_record_ids: Vec<String>,
    pub sources: Vec<RevisionRef>,
    pub comparisons: Vec<ImpactCandidate>,
    pub inherited_uncertainty: Vec<UncertaintyLineage>,
    /// Authorization-redacted debt exists, but its count and identities must
    /// not be exposed. Redaction is never interpreted as freshness.
    pub withheld_context: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitDurableOutputInput {
    pub consumer_record_id: String,
    pub expected_consumer_revision: RevisionRef,
    pub output_body: String,
    pub assembly: ContextAssembly,
    pub policy: ResolutionPolicy,
    pub provenance: Vec<ProvenanceUse>,
    pub dependencies: Vec<DependencyInput>,
    #[serde(default)]
    pub assessments: Vec<AssessmentInput>,
    #[serde(default)]
    pub reconciliations: Vec<ReconciliationEvidence>,
    #[serde(default)]
    pub unresolved_uncertainty: Vec<UncertaintyLineage>,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitDurableOutputResult {
    pub receipt_id: ReceiptId,
    pub output_revision: RevisionRef,
    pub dependency_ids: Vec<DependencyId>,
    pub execution: ExecutionDisposition,
    pub disclosure: DisclosureDecision,
    pub high_water: HistoryHighWater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFailurePoint {
    AfterOutput,
    AfterDependency(usize),
    AfterAssessment(usize),
    AfterReconciliation(usize),
    AfterDependencies,
    BeforeReceipt,
    BeforeCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationEvidence {
    pub reconciliation_id: ReconciliationId,
    pub dependency_id: DependencyId,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub assessed_source_revision: RevisionRef,
    pub task_scope: String,
    pub affected_conclusion: AffectedConclusion,
    pub outcome: MaterialityOutcome,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileDependencyInput {
    pub reconciliation_id: ReconciliationId,
    pub dependency_id: DependencyId,
    pub assessed_source_revision: RevisionRef,
    /// The task-relative assessment scope this reconciliation resolves.
    pub task_scope: String,
    pub outcome: MaterialityOutcome,
    pub rationale: String,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersedeUnitInput {
    pub predecessor_unit_id: UnitId,
    pub successors: Vec<RevisionRef>,
    pub rationale: String,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyAuditOutcome {
    Confirmed,
    Missing,
    Overdeclared,
    Underdeclared,
}

impl DependencyAuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Missing => "missing",
            Self::Overdeclared => "overdeclared",
            Self::Underdeclared => "underdeclared",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDependencyInput {
    pub receipt_id: ReceiptId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_dependency_id: Option<DependencyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_dependency: Option<DependencyInput>,
    pub outcome: DependencyAuditOutcome,
    pub rationale: String,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUnitResolution {
    pub requested_unit_id: UnitId,
    pub terminal_successors: Vec<RevisionRef>,
    pub ambiguous: bool,
    pub withheld_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactCandidate {
    pub dependency_id: DependencyId,
    pub receipt_id: ReceiptId,
    pub pinned_source_revision: RevisionRef,
    pub candidate_source_revision: RevisionRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactCandidateSet {
    pub candidates: Vec<ImpactCandidate>,
    pub withheld_context: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessExplanation {
    pub receipt_id: ReceiptId,
    pub output_revision: RevisionRef,
    pub history_high_water: HistoryHighWater,
    pub context_request: ContextRequest,
    pub resolution_policy: ResolutionPolicy,
    pub execution: ExecutionDisposition,
    pub disclosure: DisclosureDecision,
    pub visible_provenance: Vec<ProvenanceUse>,
    pub visible_dependencies: Vec<DependencyInput>,
    pub visible_comparisons: Vec<ComparisonEvidence>,
    pub visible_assessments: Vec<AssessmentEvidence>,
    pub visible_reconciliations: Vec<ReconciliationEvidenceView>,
    pub visible_dependency_audits: Vec<DependencyAuditEvidence>,
    pub visible_occurrence_evidence: Vec<OccurrenceEvidence>,
    pub visible_impacts: Vec<ImpactCandidate>,
    pub unresolved_uncertainty: Vec<UncertaintyLineage>,
    pub provenance_completeness: ProvenanceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonEvidence {
    pub observed_in_receipt_id: ReceiptId,
    pub dependency_receipt_id: ReceiptId,
    pub dependency_id: DependencyId,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub selected_source_revision: RevisionRef,
    pub task_scope: String,
    pub affected_conclusion: AffectedConclusion,
    pub history_high_water: HistoryHighWater,
    pub mismatch: bool,
    pub evidence_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentEvidence {
    pub observed_in_receipt_id: ReceiptId,
    pub dependency_receipt_id: ReceiptId,
    pub assessment_id: AssessmentId,
    pub dependency_id: DependencyId,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub compared_source_revision: RevisionRef,
    pub task_scope: String,
    pub affected_conclusion: AffectedConclusion,
    pub history_high_water: HistoryHighWater,
    pub category: String,
    pub outcome: MaterialityOutcome,
    pub could_materially_change: bool,
    pub rationale: String,
    pub evaluator: String,
    pub evidence_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationEvidenceView {
    pub reconciliation_id: ReconciliationId,
    pub dependency_id: DependencyId,
    pub consumer_revision: RevisionRef,
    pub pinned_source_revision: RevisionRef,
    pub assessed_source_revision: RevisionRef,
    pub task_scope: String,
    pub affected_conclusion: AffectedConclusion,
    pub outcome: MaterialityOutcome,
    pub rationale: String,
    pub actor: String,
    pub evidence_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolving_receipt_id: Option<ReceiptId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolving_output_revision: Option<RevisionRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyAuditEvidence {
    pub audit_event_id: String,
    pub audit_event_seq: i64,
    pub receipt_id: ReceiptId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_dependency_id: Option<DependencyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_dependency: Option<DependencyInput>,
    pub outcome: DependencyAuditOutcome,
    pub rationale: String,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceEvidence {
    pub occurrence: OccurrenceView,
    pub resolution: OccurrenceResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceCompleteness {
    Complete,
    Withheld,
}

/// Derive the stored execution and disclosure projections from the sealed
/// request, policy, and assessments. These values are never accepted as an
/// independent assertion by a backend projector.
pub(crate) fn receipt_decisions(
    policy: &ResolutionPolicy,
    assessments: &[AssessmentInput],
    withheld_context: bool,
) -> (ExecutionDisposition, DisclosureDecision) {
    let material = assessments
        .iter()
        .any(|assessment| assessment.could_materially_change);
    let hard_stop = assessments.iter().any(|assessment| {
        policy
            .hard_stop_categories
            .iter()
            .any(|category| category == &assessment.category)
    });
    let execution = if hard_stop || ((material || withheld_context) && !policy.continue_by_default)
    {
        ExecutionDisposition::Stopped
    } else {
        ExecutionDisposition::Continued
    };
    let disclosure = if material || hard_stop || withheld_context {
        DisclosureDecision::SurfaceNow
    } else if matches!(policy.disclosure_rule, DisclosureRule::ExplainOnInspection)
        && assessments
            .iter()
            .any(|assessment| assessment.outcome == MaterialityOutcome::RemainsValid)
    {
        DisclosureDecision::ExplainOnInspection
    } else {
        DisclosureDecision::Silent
    };
    (execution, disclosure)
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(Error::engine(format!(
            "{label} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

pub(crate) fn intent_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256(&serde_jcs::to_vec(value)?))
}

#[derive(Serialize)]
pub(crate) struct ReceiptAssemblySeal<'a> {
    pub(crate) request: &'a ContextRequest,
    pub(crate) policy: &'a ResolutionPolicy,
    pub(crate) requested_source_record_ids: &'a [String],
    pub(crate) selected_sources: &'a [RevisionRef],
    pub(crate) provenance: &'a [ProvenanceUse],
    pub(crate) comparisons: &'a [ImpactCandidate],
    pub(crate) dependencies: &'a [DependencyInput],
    pub(crate) assessments: &'a [AssessmentInput],
    pub(crate) reconciliations: &'a [ReconciliationEvidence],
    pub(crate) lineage: &'a [UncertaintyLineage],
    pub(crate) withheld_context: bool,
    pub(crate) high_water: &'a HistoryHighWater,
}

pub(crate) fn receipt_assembly_sha256(seal: &ReceiptAssemblySeal<'_>) -> Result<String> {
    intent_sha256(seal)
}
