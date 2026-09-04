use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::canonical_json::{canonical_json, digest_json};

use crate::error::{Error, Result};

fn empty_object() -> Value {
    Value::Object(Default::default())
}

pub const DERIVATION_EVENT_SCHEMA_VERSION: i64 = 1;
pub const DERIVATION_EVENT_TYPES: [&str; 10] = [
    "derivation.series.created",
    "derivation.revision.completed",
    "derivation.attempt.failed",
    "derivation.target.bound",
    "derivation.target.detached",
    "derivation.target.published",
    "derivation.artifact_role.assigned",
    "derivation.artifact_role.retired",
    "derivation.revision.confirmed",
    "derivation.confirmation.retracted",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationEventRow {
    pub seq: i64,
    pub id: String,
    pub idempotency_key: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub schema_version: i64,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
    pub payload: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationSeriesCreated {
    pub id: String,
    pub series_key: String,
    pub definition: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationInput {
    pub input_role: String,
    pub input_kind: String,
    pub portable_id: String,
    pub sha256: String,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDerivationRequest {
    pub query_contract: String,
    pub query_contract_version: i64,
    pub selection: Value,
    pub scope: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveSourceBoundary {
    pub after_seq: Option<i64>,
    pub through_seq: i64,
    pub resolved_scope_membership_sha256: String,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeRevisionRef {
    pub definition_id: String,
    pub publication_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationOutputRef {
    pub output_kind: String,
    pub event_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationRevisionCompleted {
    pub id: String,
    pub series_id: String,
    pub predecessor_revision_id: Option<String>,
    pub canonical_request: CanonicalDerivationRequest,
    pub recipe_revision: RecipeRevisionRef,
    pub effective_source_boundary: EffectiveSourceBoundary,
    pub inputs: Vec<DerivationInput>,
    pub output_ref: DerivationOutputRef,
    #[serde(default = "empty_object")]
    pub completion_metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationAttemptFailed {
    pub id: String,
    pub series_id: String,
    /// The durable coordination identity whose fenced attempt produced this
    /// evidence. Legacy v1 events predate durable requests and omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_request_key_sha256: Option<String>,
    pub canonical_request: CanonicalDerivationRequest,
    pub recipe_revision: RecipeRevisionRef,
    pub effective_source_boundary: EffectiveSourceBoundary,
    pub attempt_ordinal: i64,
    pub retryable: bool,
    pub executor_descriptor: Value,
    pub failure_code: String,
    #[serde(default = "empty_object")]
    pub failure_metadata: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DerivationEventPayload {
    SeriesCreated(DerivationSeriesCreated),
    RevisionCompleted(DerivationRevisionCompleted),
    AttemptFailed(DerivationAttemptFailed),
    TargetBound(super::bindings::DerivationTargetBound),
    TargetDetached(super::bindings::DerivationTargetDetached),
    TargetPublished(super::bindings::DerivationTargetPublished),
    ArtifactRoleAssigned(super::confirmation::ArtifactRoleAssigned),
    ArtifactRoleRetired(super::confirmation::ArtifactRoleRetired),
    RevisionConfirmed(super::confirmation::RevisionConfirmed),
    ConfirmationRetracted(super::confirmation::ConfirmationRetracted),
}

impl DerivationEventPayload {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::SeriesCreated(_) => DERIVATION_EVENT_TYPES[0],
            Self::RevisionCompleted(_) => DERIVATION_EVENT_TYPES[1],
            Self::AttemptFailed(_) => DERIVATION_EVENT_TYPES[2],
            Self::TargetBound(_) => DERIVATION_EVENT_TYPES[3],
            Self::TargetDetached(_) => DERIVATION_EVENT_TYPES[4],
            Self::TargetPublished(_) => DERIVATION_EVENT_TYPES[5],
            Self::ArtifactRoleAssigned(_) => DERIVATION_EVENT_TYPES[6],
            Self::ArtifactRoleRetired(_) => DERIVATION_EVENT_TYPES[7],
            Self::RevisionConfirmed(_) => DERIVATION_EVENT_TYPES[8],
            Self::ConfirmationRetracted(_) => DERIVATION_EVENT_TYPES[9],
        }
    }

    pub fn aggregate_kind(&self) -> &'static str {
        match self {
            Self::SeriesCreated(_) => "derivation_series",
            Self::RevisionCompleted(_) => "derivation_revision",
            Self::AttemptFailed(_) => "derivation_attempt",
            Self::TargetBound(_) | Self::TargetDetached(_) => "derivation_binding",
            Self::TargetPublished(_) => "derivation_publication",
            Self::ArtifactRoleAssigned(_) | Self::ArtifactRoleRetired(_) => {
                "derivation_artifact_role"
            }
            Self::RevisionConfirmed(_) | Self::ConfirmationRetracted(_) => {
                "derivation_confirmation"
            }
        }
    }

    pub fn aggregate_id(&self) -> &str {
        match self {
            Self::SeriesCreated(value) => &value.id,
            Self::RevisionCompleted(value) => &value.id,
            Self::AttemptFailed(value) => &value.id,
            Self::TargetBound(value) => &value.binding_id,
            Self::TargetDetached(value) => &value.binding_id,
            Self::TargetPublished(value) => &value.publication_id,
            Self::ArtifactRoleAssigned(value) => &value.assignment_id,
            Self::ArtifactRoleRetired(value) => &value.assignment_id,
            Self::RevisionConfirmed(value) => &value.confirmation_id,
            Self::ConfirmationRetracted(value) => &value.confirmation_id,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        let value = match self {
            Self::SeriesCreated(value) => serde_json::to_value(value)?,
            Self::RevisionCompleted(value) => serde_json::to_value(value)?,
            Self::AttemptFailed(value) => serde_json::to_value(value)?,
            Self::TargetBound(value) => serde_json::to_value(value)?,
            Self::TargetDetached(value) => serde_json::to_value(value)?,
            Self::TargetPublished(value) => serde_json::to_value(value)?,
            Self::ArtifactRoleAssigned(value) => serde_json::to_value(value)?,
            Self::ArtifactRoleRetired(value) => serde_json::to_value(value)?,
            Self::RevisionConfirmed(value) => serde_json::to_value(value)?,
            Self::ConfirmationRetracted(value) => serde_json::to_value(value)?,
        };
        Ok(String::from_utf8(canonical_json(&value))
            .expect("canonical JSON serialization is UTF-8"))
    }
}

#[derive(Debug, Clone)]
pub struct NewDerivationEvent {
    pub idempotency_key: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
    pub payload: DerivationEventPayload,
}

impl NewDerivationEvent {
    pub fn authored(
        idempotency_key: impl Into<String>,
        actor: impl Into<String>,
        run_key: Option<String>,
        reason: impl Into<String>,
        payload: DerivationEventPayload,
    ) -> Result<Self> {
        let actor = actor.into();
        if actor.starts_with("engine:") {
            return Err(Error::engine(
                "authored derivation events cannot claim an engine actor",
            ));
        }
        Ok(Self {
            idempotency_key: idempotency_key.into(),
            actor,
            run_key,
            reason: reason.into(),
            payload,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn engine(
        idempotency_key: impl Into<String>,
        actor: impl Into<String>,
        run_key: Option<String>,
        reason: impl Into<String>,
        payload: DerivationEventPayload,
    ) -> Result<Self> {
        let actor = actor.into();
        if !actor.starts_with("engine:") {
            return Err(Error::engine(
                "engine derivation events require a reserved engine actor",
            ));
        }
        Ok(Self {
            idempotency_key: idempotency_key.into(),
            actor,
            run_key,
            reason: reason.into(),
            payload,
        })
    }
}
