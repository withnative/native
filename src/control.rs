//! Authoritative portable instruction-control events and synchronous projector.
//!
//! This is the fourth independent event-sourced tier. `control_events` is the
//! source of truth; the six product tables are projections. Appending and
//! projecting happen in one SQLite write transaction, and the deterministic
//! applications marker makes retries and full replay idempotent.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
// Used only by the postgres-gated canonical_projection_snapshot below.
#[cfg(feature = "postgres")]
use serde_json::json;
use sqlx::{Connection, Row, Sqlite, SqliteConnection, Transaction};
// Used only by the postgres-gated canonical_projection_snapshot below.
#[cfg(feature = "postgres")]
use sqlx::Executor;

#[cfg(test)]
use crate::db::begin_write;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::schema::DDL_STATEMENTS;
use crate::store::now_iso;

pub const CONTROL_EVENT_SCHEMA_VERSION: i64 = 1;

pub const CONTROL_EVENT_TYPES: [&str; 23] = [
    "agent_run.started.v1",
    "agent_run.closed.v1",
    "member_context.provisioned",
    "instruction_binding.created",
    "instruction_binding.changed",
    "instruction_binding.enabled",
    "instruction_binding.disabled",
    "instruction_binding.removed",
    "onboarding_programme.created",
    "onboarding_programme.changed",
    "onboarding_programme_source.added",
    "onboarding_programme_source.changed",
    "onboarding_programme_source.reordered",
    "onboarding_programme_source.removed",
    "onboarding_programme.generation_published",
    "member_obligation.activated",
    "member_obligation.progressed",
    "member_obligation.resolved",
    "member_obligation.reopened",
    "member_obligation.rebased",
    "member_obligation.rollout_baselined",
    "seeded_instruction_source.applied",
    "instruction_binding.reordered",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunStartedPayload {
    pub activity_id: String,
    pub account_id: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunClosedPayload {
    pub activity_id: String,
    pub ended_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEventRow {
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
pub struct MemberContextProvisionedPayload {
    pub account_id: String,
    pub person_record_id: String,
    pub root_record_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionBindingStatePayload {
    pub id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub source_record_id: String,
    pub position: i64,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionBindingTogglePayload {
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionBindingReorderedPayload {
    pub position: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyPayload {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingProgrammeStatePayload {
    pub id: String,
    pub trigger_key: String,
    pub generation: i64,
    pub position: i64,
    pub enabled: bool,
    pub created_by: String,
    /// Engine-owned rollout cutoff. Fresh-v16 programmes use `None`; workspace
    /// configuration events must preserve any migration-provisioned value.
    pub legacy_baseline_before: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingProgrammeSourcePayload {
    pub programme_id: String,
    pub source_record_id: String,
    pub source_role: String,
    pub position: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingProgrammeSourceRemovedPayload {
    pub programme_id: String,
    pub source_record_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgrammeGenerationPublishedPayload {
    pub previous_generation: i64,
    pub generation: i64,
    pub updated_at: String,
    #[serde(default)]
    pub audience_account_ids: Vec<String>,
    #[serde(default)]
    pub audience_digest: Option<String>,
    #[serde(default)]
    pub audience_kind: Option<String>,
    #[serde(default)]
    pub requested_account_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObligationStatePayload {
    pub account_id: String,
    pub programme_id: String,
    pub generation: i64,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObligationResolvedPayload {
    pub account_id: String,
    pub programme_id: String,
    pub generation: i64,
    pub state: String,
    pub updated_at: String,
    pub evidence: Value,
}

pub const MAX_OBLIGATION_PROGRESS_EVIDENCE_BYTES: usize = 4096;

pub const QUICKSTART_ROUTE_IDS: [&str; 3] = [
    "practical_workflow",
    "comparative_evaluation",
    "conceptual_explanation",
];

pub fn valid_quickstart_route_id(value: &str) -> bool {
    QUICKSTART_ROUTE_IDS.contains(&value)
}

pub(crate) fn valid_obligation_progress_transition(previous: Option<&str>, next: &str) -> bool {
    matches!(
        (previous, next),
        (None, "anchor_established" | "route_selected" | "deferred")
            | (
                Some("anchor_established"),
                "anchor_established" | "route_selected" | "artifact_previewed" | "deferred"
            )
            | (
                Some("route_selected"),
                "route_selected" | "artifact_previewed" | "value_delivered" | "deferred"
            )
            | (
                Some("artifact_previewed"),
                "artifact_previewed" | "artifact_written" | "deferred"
            )
            | (
                Some("artifact_written"),
                "route_selected" | "value_delivered" | "deferred"
            )
            | (Some("value_delivered"), "value_delivered" | "deferred")
            | (
                Some("deferred"),
                "anchor_established" | "route_selected" | "deferred"
            )
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObligationProgressedPayload {
    pub account_id: String,
    pub programme_id: String,
    pub generation: i64,
    pub phase: String,
    pub updated_at: String,
    pub evidence: Value,
    #[serde(default)]
    pub resume_after: Option<String>,
    #[serde(default)]
    pub artifact_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObligationReopenedPayload {
    pub account_id: String,
    pub programme_id: String,
    pub generation: i64,
    pub previous_state: String,
    pub updated_at: String,
    pub evidence: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberObligationRebasedPayload {
    pub account_id: String,
    pub programme_id: String,
    pub previous_generation: i64,
    pub generation: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeededInstructionSourceAppliedPayload {
    pub source_record_id: String,
    pub template_key: String,
    pub template_version: i64,
    pub last_applied_digest: String,
    pub last_applied_at: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub expected_body_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlEventPayload {
    AgentRunStarted(AgentRunStartedPayload),
    AgentRunClosed(AgentRunClosedPayload),
    MemberContextProvisioned(MemberContextProvisionedPayload),
    InstructionBindingCreated(InstructionBindingStatePayload),
    InstructionBindingChanged(InstructionBindingStatePayload),
    InstructionBindingEnabled(InstructionBindingTogglePayload),
    InstructionBindingDisabled(InstructionBindingTogglePayload),
    InstructionBindingReordered(InstructionBindingReorderedPayload),
    InstructionBindingRemoved(EmptyPayload),
    OnboardingProgrammeCreated(OnboardingProgrammeStatePayload),
    OnboardingProgrammeChanged(OnboardingProgrammeStatePayload),
    OnboardingProgrammeSourceAdded(OnboardingProgrammeSourcePayload),
    OnboardingProgrammeSourceChanged(OnboardingProgrammeSourcePayload),
    OnboardingProgrammeSourceReordered(OnboardingProgrammeSourcePayload),
    OnboardingProgrammeSourceRemoved(OnboardingProgrammeSourceRemovedPayload),
    ProgrammeGenerationPublished(ProgrammeGenerationPublishedPayload),
    MemberObligationActivated(MemberObligationStatePayload),
    MemberObligationProgressed(MemberObligationProgressedPayload),
    MemberObligationResolved(MemberObligationResolvedPayload),
    MemberObligationReopened(MemberObligationReopenedPayload),
    MemberObligationRebased(MemberObligationRebasedPayload),
    MemberObligationRolloutBaselined(MemberObligationStatePayload),
    SeededInstructionSourceApplied(SeededInstructionSourceAppliedPayload),
}

impl ControlEventPayload {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::AgentRunStarted(_) => "agent_run.started.v1",
            Self::AgentRunClosed(_) => "agent_run.closed.v1",
            Self::MemberContextProvisioned(_) => "member_context.provisioned",
            Self::InstructionBindingCreated(_) => "instruction_binding.created",
            Self::InstructionBindingChanged(_) => "instruction_binding.changed",
            Self::InstructionBindingEnabled(_) => "instruction_binding.enabled",
            Self::InstructionBindingDisabled(_) => "instruction_binding.disabled",
            Self::InstructionBindingReordered(_) => "instruction_binding.reordered",
            Self::InstructionBindingRemoved(_) => "instruction_binding.removed",
            Self::OnboardingProgrammeCreated(_) => "onboarding_programme.created",
            Self::OnboardingProgrammeChanged(_) => "onboarding_programme.changed",
            Self::OnboardingProgrammeSourceAdded(_) => "onboarding_programme_source.added",
            Self::OnboardingProgrammeSourceChanged(_) => "onboarding_programme_source.changed",
            Self::OnboardingProgrammeSourceReordered(_) => "onboarding_programme_source.reordered",
            Self::OnboardingProgrammeSourceRemoved(_) => "onboarding_programme_source.removed",
            Self::ProgrammeGenerationPublished(_) => "onboarding_programme.generation_published",
            Self::MemberObligationActivated(_) => "member_obligation.activated",
            Self::MemberObligationProgressed(_) => "member_obligation.progressed",
            Self::MemberObligationResolved(_) => "member_obligation.resolved",
            Self::MemberObligationReopened(_) => "member_obligation.reopened",
            Self::MemberObligationRebased(_) => "member_obligation.rebased",
            Self::MemberObligationRolloutBaselined(_) => "member_obligation.rollout_baselined",
            Self::SeededInstructionSourceApplied(_) => "seeded_instruction_source.applied",
        }
    }

    fn aggregate_kind(&self) -> &'static str {
        match self {
            Self::AgentRunStarted(_) | Self::AgentRunClosed(_) => "agent_run",
            Self::MemberContextProvisioned(_) => "member_context",
            Self::InstructionBindingCreated(_)
            | Self::InstructionBindingChanged(_)
            | Self::InstructionBindingEnabled(_)
            | Self::InstructionBindingDisabled(_)
            | Self::InstructionBindingReordered(_)
            | Self::InstructionBindingRemoved(_) => "instruction_binding",
            Self::OnboardingProgrammeCreated(_)
            | Self::OnboardingProgrammeChanged(_)
            | Self::ProgrammeGenerationPublished(_) => "onboarding_programme",
            Self::OnboardingProgrammeSourceAdded(_)
            | Self::OnboardingProgrammeSourceChanged(_)
            | Self::OnboardingProgrammeSourceReordered(_)
            | Self::OnboardingProgrammeSourceRemoved(_) => "onboarding_programme_source",
            Self::MemberObligationActivated(_)
            | Self::MemberObligationProgressed(_)
            | Self::MemberObligationResolved(_)
            | Self::MemberObligationReopened(_)
            | Self::MemberObligationRebased(_)
            | Self::MemberObligationRolloutBaselined(_) => "member_obligation",
            Self::SeededInstructionSourceApplied(_) => "seeded_instruction_source",
        }
    }

    fn to_json(&self) -> Result<String> {
        Ok(match self {
            Self::AgentRunStarted(value) => serde_json::to_string(value)?,
            Self::AgentRunClosed(value) => serde_json::to_string(value)?,
            Self::MemberContextProvisioned(value) => serde_json::to_string(value)?,
            Self::InstructionBindingCreated(value) | Self::InstructionBindingChanged(value) => {
                serde_json::to_string(value)?
            }
            Self::InstructionBindingEnabled(value) | Self::InstructionBindingDisabled(value) => {
                serde_json::to_string(value)?
            }
            Self::InstructionBindingReordered(value) => serde_json::to_string(value)?,
            Self::InstructionBindingRemoved(value) => serde_json::to_string(value)?,
            Self::OnboardingProgrammeCreated(value) | Self::OnboardingProgrammeChanged(value) => {
                serde_json::to_string(value)?
            }
            Self::OnboardingProgrammeSourceAdded(value)
            | Self::OnboardingProgrammeSourceChanged(value)
            | Self::OnboardingProgrammeSourceReordered(value) => serde_json::to_string(value)?,
            Self::OnboardingProgrammeSourceRemoved(value) => serde_json::to_string(value)?,
            Self::ProgrammeGenerationPublished(value) => {
                let mut canonical = value.clone();
                canonical.audience_account_ids.sort();
                canonical.audience_account_ids.dedup();
                canonical.requested_account_ids.sort();
                canonical.requested_account_ids.dedup();
                serde_json::to_string(&canonical)?
            }
            Self::MemberObligationActivated(value)
            | Self::MemberObligationRolloutBaselined(value) => serde_json::to_string(value)?,
            Self::MemberObligationProgressed(value) => serde_json::to_string(value)?,
            Self::MemberObligationResolved(value) => serde_json::to_string(value)?,
            Self::MemberObligationReopened(value) => serde_json::to_string(value)?,
            Self::MemberObligationRebased(value) => serde_json::to_string(value)?,
            Self::SeededInstructionSourceApplied(value) => serde_json::to_string(value)?,
        })
    }
}

fn encode_aggregate_parts(parts: &[&str]) -> String {
    let mut encoded = String::from("v1");
    for part in parts {
        encoded.push(':');
        encoded.push_str(&part.len().to_string());
        encoded.push(':');
        encoded.push_str(part);
    }
    encoded
}

/// Canonical, unambiguous identity for a programme/source pair. Length-prefix
/// encoding prevents ids containing punctuation from aliasing another pair.
pub fn programme_source_aggregate_id(programme_id: &str, source_record_id: &str) -> String {
    encode_aggregate_parts(&[programme_id, source_record_id])
}

/// Canonical identity for one member obligation generation.
pub fn member_obligation_aggregate_id(
    account_id: &str,
    programme_id: &str,
    generation: i64,
) -> String {
    encode_aggregate_parts(&[account_id, programme_id, &generation.to_string()])
}

#[derive(Debug, Clone)]
pub(crate) struct NewControlEvent {
    pub(crate) idempotency_key: String,
    pub(crate) aggregate_id: String,
    pub(crate) actor: String,
    pub(crate) run_key: Option<String>,
    pub(crate) reason: String,
    pub(crate) payload: ControlEventPayload,
}

impl NewControlEvent {
    pub(crate) fn authored(
        idempotency_key: impl Into<String>,
        aggregate_id: impl Into<String>,
        actor: impl Into<String>,
        run_key: Option<String>,
        reason: impl Into<String>,
        payload: ControlEventPayload,
    ) -> Result<Self> {
        let actor = actor.into();
        if actor.starts_with("engine:") {
            return Err(Error::engine(
                "authored control events cannot claim an engine actor",
            ));
        }
        if matches!(
            &payload,
            ControlEventPayload::OnboardingProgrammeCreated(value)
                if value.legacy_baseline_before.is_some()
        ) {
            return Err(Error::engine(
                "legacy_baseline_before is available only through the engine programme creation path",
            ));
        }
        Ok(Self {
            idempotency_key: idempotency_key.into(),
            aggregate_id: aggregate_id.into(),
            actor,
            run_key,
            reason: reason.into(),
            payload,
        })
    }

    /// Engine-owned provisioning inside a fresh/current portable database.
    /// This path can never introduce a legacy rollout cutoff.
    pub(crate) fn engine_provisioned(
        idempotency_key: impl Into<String>,
        aggregate_id: impl Into<String>,
        reason: impl Into<String>,
        payload: ControlEventPayload,
    ) -> Result<Self> {
        if matches!(
            &payload,
            ControlEventPayload::OnboardingProgrammeCreated(value)
                if value.legacy_baseline_before.is_some()
        ) {
            return Err(Error::engine(
                "engine provisioning cannot introduce a legacy rollout cutoff",
            ));
        }
        Ok(Self {
            idempotency_key: idempotency_key.into(),
            aggregate_id: aggregate_id.into(),
            actor: "engine:provisioning".into(),
            run_key: None,
            reason: reason.into(),
            payload,
        })
    }
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "control event {label} cannot be empty"
        )));
    }
    Ok(())
}

fn positive(label: &str, value: i64) -> Result<()> {
    if value < 1 {
        return Err(Error::engine(format!(
            "control event {label} must be positive"
        )));
    }
    Ok(())
}

fn timestamp(label: &str, value: &str) -> Result<()> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| Error::engine(format!("control event {label} must be RFC3339")))
}

fn decode<T: DeserializeOwned>(event: &ControlEventRow) -> Result<T> {
    serde_json::from_str(&event.payload).map_err(|error| {
        Error::engine(format!(
            "control event {} ({}) has invalid v{} payload: {error}",
            event.id, event.event_type, event.schema_version
        ))
    })
}

fn validate_binding(value: &InstructionBindingStatePayload) -> Result<()> {
    for (label, value) in [
        ("binding id", value.id.as_str()),
        ("binding scope id", value.scope_id.as_str()),
        ("binding source record id", value.source_record_id.as_str()),
        ("binding created_by", value.created_by.as_str()),
    ] {
        nonblank(label, value)?;
    }
    if !matches!(value.scope_kind.as_str(), "database" | "account") {
        return Err(Error::engine("control event binding scope_kind is unknown"));
    }
    timestamp("binding created_at", &value.created_at)?;
    timestamp("binding updated_at", &value.updated_at)
}

fn validate_programme(value: &OnboardingProgrammeStatePayload) -> Result<()> {
    for (label, value) in [
        ("programme id", value.id.as_str()),
        ("programme trigger_key", value.trigger_key.as_str()),
        ("programme created_by", value.created_by.as_str()),
    ] {
        nonblank(label, value)?;
    }
    positive("programme generation", value.generation)?;
    if let Some(cutoff) = &value.legacy_baseline_before {
        timestamp("programme legacy_baseline_before", cutoff)?;
    }
    timestamp("programme created_at", &value.created_at)?;
    timestamp("programme updated_at", &value.updated_at)
}

fn validate_source(value: &OnboardingProgrammeSourcePayload) -> Result<()> {
    nonblank("programme source programme_id", &value.programme_id)?;
    nonblank("programme source record_id", &value.source_record_id)?;
    if !matches!(
        value.source_role.as_str(),
        "guidance" | "completion_criteria"
    ) {
        return Err(Error::engine(
            "control event programme source role is unknown",
        ));
    }
    Ok(())
}

fn validate_obligation(value: &MemberObligationStatePayload) -> Result<()> {
    nonblank("obligation account_id", &value.account_id)?;
    nonblank("obligation programme_id", &value.programme_id)?;
    positive("obligation generation", value.generation)?;
    if !matches!(value.state.as_str(), "pending" | "completed" | "declined") {
        return Err(Error::engine("control event obligation state is unknown"));
    }
    timestamp("obligation created_at", &value.created_at)?;
    timestamp("obligation updated_at", &value.updated_at)
}

fn validate_progress(value: &MemberObligationProgressedPayload) -> Result<()> {
    nonblank("obligation account_id", &value.account_id)?;
    nonblank("obligation programme_id", &value.programme_id)?;
    positive("obligation generation", value.generation)?;
    if !matches!(
        value.phase.as_str(),
        "anchor_established"
            | "route_selected"
            | "artifact_previewed"
            | "artifact_written"
            | "value_delivered"
            | "deferred"
    ) {
        return Err(Error::engine("progressed obligation phase is unknown"));
    }
    timestamp("obligation updated_at", &value.updated_at)?;
    if !value.evidence.is_object() {
        return Err(Error::engine(
            "progressed obligation evidence must be an object",
        ));
    }
    if serde_json::to_vec(&value.evidence)?.len() > MAX_OBLIGATION_PROGRESS_EVIDENCE_BYTES {
        return Err(Error::engine(
            "progressed obligation evidence exceeds 4096 bytes",
        ));
    }
    let exact_evidence = match value.phase.as_str() {
        "anchor_established" => {
            value.evidence == serde_json::json!({"basis":"user_stated"})
                || value.evidence == serde_json::json!({"basis":"user_confirmed"})
                || value.evidence
                    == serde_json::json!({"basis":"user_confirmed","checkpoint":"artifact_written"})
                || value.evidence
                    == serde_json::json!({"basis":"user_confirmed","checkpoint":"reset_invalid_artifact"})
        }
        "route_selected" => {
            let object = value.evidence.as_object().expect("validated above");
            object.len() == 1
                && object
                    .get("route_id")
                    .and_then(Value::as_str)
                    .is_some_and(valid_quickstart_route_id)
        }
        "artifact_previewed" => {
            let object = value.evidence.as_object().expect("validated above");
            let digest = object.get("content_digest").and_then(Value::as_str);
            object.len() == 4
                && object
                    .get("explicit_member_consent")
                    .and_then(Value::as_bool)
                    == Some(true)
                && object
                    .get("content_event_floor_seq")
                    .and_then(Value::as_i64)
                    .is_some_and(|seq| seq >= 0)
                && object.get("existing_artifact_id").is_some_and(|value| {
                    value.is_null() || value.as_str().is_some_and(|id| !id.trim().is_empty())
                })
                && digest.is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        }
        "artifact_written" => value.evidence == serde_json::json!({}),
        "value_delivered" => value.evidence == serde_json::json!({"basis":"user_confirmed"}),
        "deferred" => value.evidence == serde_json::json!({"basis":"explicit_member_request"}),
        _ => false,
    };
    if !exact_evidence {
        return Err(Error::engine(
            "progressed obligation evidence does not match the phase-specific audit schema",
        ));
    }
    match value.phase.as_str() {
        "deferred" => {
            if let Some(resume_after) = &value.resume_after {
                timestamp("obligation resume_after", resume_after)?;
            }
            if value.artifact_id.is_some() {
                return Err(Error::engine(
                    "deferred progress cannot introduce an artifact",
                ));
            }
        }
        "artifact_written" => {
            if value.resume_after.is_some() {
                return Err(Error::engine(
                    "artifact_written progress cannot set resume_after",
                ));
            }
            nonblank(
                "obligation artifact_id",
                value.artifact_id.as_deref().unwrap_or_default(),
            )?;
        }
        _ => {
            if value.resume_after.is_some() || value.artifact_id.is_some() {
                return Err(Error::engine(
                    "only deferred progress accepts resume_after and only artifact_written accepts artifact_id",
                ));
            }
        }
    }
    Ok(())
}

fn expected_aggregate_kind(event_type: &str) -> Option<&'static str> {
    match event_type {
        value if value.starts_with("agent_run.") => Some("agent_run"),
        "member_context.provisioned" => Some("member_context"),
        value if value.starts_with("instruction_binding.") => Some("instruction_binding"),
        value if value.starts_with("onboarding_programme_source.") => {
            Some("onboarding_programme_source")
        }
        value if value.starts_with("onboarding_programme.") => Some("onboarding_programme"),
        value if value.starts_with("member_obligation.") => Some("member_obligation"),
        "seeded_instruction_source.applied" => Some("seeded_instruction_source"),
        _ => None,
    }
}

fn validate_source_aggregate(
    event: &ControlEventRow,
    programme_id: &str,
    source_record_id: &str,
) -> Result<()> {
    if event.aggregate_id != programme_source_aggregate_id(programme_id, source_record_id) {
        return Err(Error::engine(
            "programme source aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}

fn validate_obligation_aggregate(
    event: &ControlEventRow,
    account_id: &str,
    programme_id: &str,
    generation: i64,
) -> Result<()> {
    if event.aggregate_id != member_obligation_aggregate_id(account_id, programme_id, generation) {
        return Err(Error::engine(
            "member obligation aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}

pub fn validate_control_event(event: &ControlEventRow) -> Result<()> {
    positive("sequence", event.seq)?;
    for (label, value) in [
        ("id", event.id.as_str()),
        ("idempotency key", event.idempotency_key.as_str()),
        ("type", event.event_type.as_str()),
        ("aggregate kind", event.aggregate_kind.as_str()),
        ("aggregate id", event.aggregate_id.as_str()),
        ("actor", event.actor.as_str()),
        ("reason", event.reason.as_str()),
    ] {
        nonblank(label, value)?;
    }
    timestamp("created_at", &event.created_at)?;
    if event.schema_version != CONTROL_EVENT_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "unsupported control event schema version {} for {} (supported: {})",
            event.schema_version, event.event_type, CONTROL_EVENT_SCHEMA_VERSION
        )));
    }
    let expected = expected_aggregate_kind(&event.event_type).ok_or_else(|| {
        Error::engine(format!("unknown control event type: {}", event.event_type))
    })?;
    if event.aggregate_kind != expected {
        return Err(Error::engine(format!(
            "control event {} requires aggregate kind {expected}, found {}",
            event.event_type, event.aggregate_kind
        )));
    }
    match event.event_type.as_str() {
        "agent_run.started.v1" => {
            let value: AgentRunStartedPayload = decode(event)?;
            nonblank("agent run activity_id", &value.activity_id)?;
            nonblank("agent run account_id", &value.account_id)?;
            timestamp("agent run started_at", &value.started_at)?;
            if event.aggregate_id != value.activity_id {
                return Err(Error::engine(
                    "agent run aggregate id does not match activity_id",
                ));
            }
            if event.actor != value.account_id {
                return Err(Error::engine(
                    "agent run start actor does not match account_id",
                ));
            }
            if !matches!(
                crate::runkey::validate_full(event.run_key.as_deref()),
                crate::runkey::KeyOutcome::Valid(_)
            ) {
                return Err(Error::engine(
                    "agent run start requires a valid full run key",
                ));
            }
        }
        "agent_run.closed.v1" => {
            let value: AgentRunClosedPayload = decode(event)?;
            nonblank("agent run activity_id", &value.activity_id)?;
            timestamp("agent run ended_at", &value.ended_at)?;
            if event.aggregate_id != value.activity_id {
                return Err(Error::engine(
                    "agent run aggregate id does not match activity_id",
                ));
            }
            if !matches!(
                crate::runkey::validate_full(event.run_key.as_deref()),
                crate::runkey::KeyOutcome::Valid(_)
            ) {
                return Err(Error::engine(
                    "agent run closure requires a valid full run key",
                ));
            }
        }
        "member_context.provisioned" => {
            let value: MemberContextProvisionedPayload = decode(event)?;
            nonblank("member context account_id", &value.account_id)?;
            nonblank("member context person_record_id", &value.person_record_id)?;
            nonblank("member context root_record_id", &value.root_record_id)?;
            timestamp("member context created_at", &value.created_at)?;
            if event.aggregate_id != value.account_id {
                return Err(Error::engine(
                    "member context aggregate id does not match account_id",
                ));
            }
        }
        "instruction_binding.created" | "instruction_binding.changed" => {
            let value: InstructionBindingStatePayload = decode(event)?;
            validate_binding(&value)?;
            if event.aggregate_id != value.id {
                return Err(Error::engine(
                    "instruction binding aggregate id does not match payload",
                ));
            }
        }
        "instruction_binding.enabled" | "instruction_binding.disabled" => {
            let value: InstructionBindingTogglePayload = decode(event)?;
            timestamp("binding updated_at", &value.updated_at)?;
        }
        "instruction_binding.reordered" => {
            let value: InstructionBindingReorderedPayload = decode(event)?;
            timestamp("binding updated_at", &value.updated_at)?;
        }
        "instruction_binding.removed" => {
            let _: EmptyPayload = decode(event)?;
        }
        "onboarding_programme.created" | "onboarding_programme.changed" => {
            let value: OnboardingProgrammeStatePayload = decode(event)?;
            validate_programme(&value)?;
            if event.aggregate_id != value.id {
                return Err(Error::engine(
                    "programme aggregate id does not match payload",
                ));
            }
            if event.event_type == "onboarding_programme.created"
                && value.legacy_baseline_before.is_some()
                && !matches!(event.actor.as_str(), "engine:seed" | "engine:migration")
            {
                return Err(Error::engine(
                    "legacy_baseline_before is engine-owned and requires an engine seed or migration actor",
                ));
            }
        }
        "onboarding_programme_source.added"
        | "onboarding_programme_source.changed"
        | "onboarding_programme_source.reordered" => {
            let value: OnboardingProgrammeSourcePayload = decode(event)?;
            validate_source(&value)?;
            validate_source_aggregate(event, &value.programme_id, &value.source_record_id)?;
        }
        "onboarding_programme_source.removed" => {
            let value: OnboardingProgrammeSourceRemovedPayload = decode(event)?;
            nonblank("programme source programme_id", &value.programme_id)?;
            nonblank("programme source record_id", &value.source_record_id)?;
            validate_source_aggregate(event, &value.programme_id, &value.source_record_id)?;
        }
        "onboarding_programme.generation_published" => {
            let value: ProgrammeGenerationPublishedPayload = decode(event)?;
            positive("programme previous_generation", value.previous_generation)?;
            positive("programme generation", value.generation)?;
            let expected_generation =
                value.previous_generation.checked_add(1).ok_or_else(|| {
                    Error::engine("published programme generation cannot advance beyond i64::MAX")
                })?;
            if value.generation != expected_generation {
                return Err(Error::engine(
                    "published programme generation must advance exactly once",
                ));
            }
            timestamp("programme updated_at", &value.updated_at)?;
            if value
                .audience_digest
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(Error::engine("programme audience digest cannot be empty"));
            }
            if value.audience_kind.as_ref().is_some_and(|value| {
                !matches!(value.as_str(), "all" | "terminal" | "pending" | "accounts")
            }) {
                return Err(Error::engine("programme audience kind is unknown"));
            }
            if value
                .audience_account_ids
                .iter()
                .any(|id| id.trim().is_empty())
            {
                return Err(Error::engine(
                    "programme audience account id cannot be empty",
                ));
            }
            if value
                .audience_account_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(Error::engine(
                    "programme audience account ids must be unique and canonically sorted",
                ));
            }
        }
        "member_obligation.activated" | "member_obligation.rollout_baselined" => {
            let value: MemberObligationStatePayload = decode(event)?;
            validate_obligation(&value)?;
            let expected_state = if event.event_type == "member_obligation.activated" {
                "pending"
            } else {
                "completed"
            };
            if value.state != expected_state {
                return Err(Error::engine(format!(
                    "{} requires state {expected_state}",
                    event.event_type
                )));
            }
            validate_obligation_aggregate(
                event,
                &value.account_id,
                &value.programme_id,
                value.generation,
            )?;
        }
        "member_obligation.progressed" => {
            let value: MemberObligationProgressedPayload = decode(event)?;
            validate_progress(&value)?;
            validate_obligation_aggregate(
                event,
                &value.account_id,
                &value.programme_id,
                value.generation,
            )?;
        }
        "member_obligation.resolved" => {
            let value: MemberObligationResolvedPayload = decode(event)?;
            nonblank("obligation account_id", &value.account_id)?;
            nonblank("obligation programme_id", &value.programme_id)?;
            positive("obligation generation", value.generation)?;
            if !matches!(value.state.as_str(), "completed" | "declined") {
                return Err(Error::engine(
                    "resolved obligation must be completed or declined",
                ));
            }
            timestamp("obligation updated_at", &value.updated_at)?;
            if value.evidence.is_null() {
                return Err(Error::engine("resolved obligation evidence is required"));
            }
            validate_obligation_aggregate(
                event,
                &value.account_id,
                &value.programme_id,
                value.generation,
            )?;
        }
        "member_obligation.reopened" => {
            let value: MemberObligationReopenedPayload = decode(event)?;
            nonblank("obligation account_id", &value.account_id)?;
            nonblank("obligation programme_id", &value.programme_id)?;
            positive("obligation generation", value.generation)?;
            if !matches!(value.previous_state.as_str(), "completed" | "declined") {
                return Err(Error::engine(
                    "reopened obligation previous_state must be terminal",
                ));
            }
            timestamp("obligation updated_at", &value.updated_at)?;
            if value.evidence.is_null() {
                return Err(Error::engine("reopened obligation evidence is required"));
            }
            validate_obligation_aggregate(
                event,
                &value.account_id,
                &value.programme_id,
                value.generation,
            )?;
        }
        "member_obligation.rebased" => {
            let value: MemberObligationRebasedPayload = decode(event)?;
            nonblank("obligation account_id", &value.account_id)?;
            nonblank("obligation programme_id", &value.programme_id)?;
            positive("obligation previous_generation", value.previous_generation)?;
            positive("obligation generation", value.generation)?;
            if value.generation <= value.previous_generation {
                return Err(Error::engine("rebased obligation generation must advance"));
            }
            timestamp("obligation created_at", &value.created_at)?;
            timestamp("obligation updated_at", &value.updated_at)?;
            validate_obligation_aggregate(
                event,
                &value.account_id,
                &value.programme_id,
                value.generation,
            )?;
        }
        "seeded_instruction_source.applied" => {
            let value: SeededInstructionSourceAppliedPayload = decode(event)?;
            nonblank("seed source record_id", &value.source_record_id)?;
            nonblank("seed template_key", &value.template_key)?;
            nonblank("seed digest", &value.last_applied_digest)?;
            positive("seed template_version", value.template_version)?;
            timestamp("seed last_applied_at", &value.last_applied_at)?;
            if value.operation.as_ref().is_some_and(|operation| {
                !matches!(
                    operation.as_str(),
                    "apply_seeded_default" | "reset_seeded_default"
                )
            }) {
                return Err(Error::engine("seed operation is unknown"));
            }
            if value
                .expected_body_digest
                .as_ref()
                .is_some_and(|digest| digest.trim().is_empty())
            {
                return Err(Error::engine("seed expected body digest cannot be empty"));
            }
            if event.aggregate_id != value.source_record_id {
                return Err(Error::engine(
                    "seed source aggregate id does not match payload",
                ));
            }
        }
        _ => unreachable!("unknown types rejected above"),
    }
    Ok(())
}

async fn require_one(
    result: sqlx::sqlite::SqliteQueryResult,
    event: &ControlEventRow,
) -> Result<()> {
    if result.rows_affected() != 1 {
        return Err(Error::engine(format!(
            "control event {} ({}) did not match exactly one projection row",
            event.id, event.event_type
        )));
    }
    Ok(())
}

async fn require_current_programme_generation(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
    programme_id: &str,
    generation: i64,
) -> Result<()> {
    let current: Option<i64> =
        sqlx::query_scalar("SELECT generation FROM onboarding_programmes WHERE id=?")
            .bind(programme_id)
            .fetch_optional(&mut *conn)
            .await?;
    if current != Some(generation) {
        return Err(Error::engine(format!(
            "control event {} ({}) targets programme generation {generation}, current is {}",
            event.id,
            event.event_type,
            current.map_or_else(|| "missing".into(), |value| value.to_string())
        )));
    }
    Ok(())
}

/// Apply one canonical event. Already-applied event ids are a no-op; every
/// other event either completes its projection and marker together in the
/// caller's transaction or returns an error.
async fn project_control(conn: &mut SqliteConnection, event: &ControlEventRow) -> Result<()> {
    validate_control_event(event)?;
    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM control_event_applications WHERE event_id = ?)",
    )
    .bind(&event.id)
    .fetch_one(&mut *conn)
    .await?;
    if applied {
        return Ok(());
    }

    match event.event_type.as_str() {
        "agent_run.started.v1" => {
            let value: AgentRunStartedPayload = decode(event)?;
            sqlx::query(
                "INSERT INTO agent_runs
                 (activity_id,run_key,account_id,started_at,start_event_id,start_event_seq)
                 VALUES(?,?,?,?,?,?)",
            )
            .bind(value.activity_id)
            .bind(event.run_key.as_deref().expect("validated run key"))
            .bind(value.account_id)
            .bind(value.started_at)
            .bind(&event.id)
            .bind(event.seq)
            .execute(&mut *conn)
            .await?;
        }
        "agent_run.closed.v1" => {
            let value: AgentRunClosedPayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE agent_runs
                    SET ended_at=?,close_event_id=?,close_event_seq=?
                  WHERE activity_id=? AND run_key=? AND account_id=? AND ended_at IS NULL
                    AND started_at<=?",
            )
            .bind(&value.ended_at)
            .bind(&event.id)
            .bind(event.seq)
            .bind(value.activity_id)
            .bind(event.run_key.as_deref().expect("validated run key"))
            .bind(&event.actor)
            .bind(&value.ended_at)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "member_context.provisioned" => {
            let value: MemberContextProvisionedPayload = decode(event)?;
            sqlx::query(
                "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
                 VALUES(?,?,?,?)",
            )
            .bind(value.account_id)
            .bind(value.person_record_id)
            .bind(value.root_record_id)
            .bind(value.created_at)
            .execute(&mut *conn)
            .await?;
        }
        "instruction_binding.created" => {
            let value: InstructionBindingStatePayload = decode(event)?;
            sqlx::query(
                "INSERT INTO instruction_bindings
                 (id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?)",
            )
            .bind(value.id)
            .bind(value.scope_kind)
            .bind(value.scope_id)
            .bind(value.source_record_id)
            .bind(value.position)
            .bind(value.enabled)
            .bind(value.created_by)
            .bind(value.created_at)
            .bind(value.updated_at)
            .execute(&mut *conn)
            .await?;
        }
        "instruction_binding.changed" => {
            let value: InstructionBindingStatePayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE instruction_bindings
                    SET scope_kind=?,scope_id=?,source_record_id=?,position=?,enabled=?,updated_at=?
                  WHERE id=? AND created_by=? AND created_at=?",
            )
            .bind(value.scope_kind)
            .bind(value.scope_id)
            .bind(value.source_record_id)
            .bind(value.position)
            .bind(value.enabled)
            .bind(value.updated_at)
            .bind(value.id)
            .bind(value.created_by)
            .bind(value.created_at)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "instruction_binding.enabled" | "instruction_binding.disabled" => {
            let value: InstructionBindingTogglePayload = decode(event)?;
            let enabled = event.event_type == "instruction_binding.enabled";
            let result =
                sqlx::query("UPDATE instruction_bindings SET enabled=?,updated_at=? WHERE id=?")
                    .bind(enabled)
                    .bind(value.updated_at)
                    .bind(&event.aggregate_id)
                    .execute(&mut *conn)
                    .await?;
            require_one(result, event).await?;
        }
        "instruction_binding.reordered" => {
            let value: InstructionBindingReorderedPayload = decode(event)?;
            let result =
                sqlx::query("UPDATE instruction_bindings SET position=?,updated_at=? WHERE id=?")
                    .bind(value.position)
                    .bind(value.updated_at)
                    .bind(&event.aggregate_id)
                    .execute(&mut *conn)
                    .await?;
            require_one(result, event).await?;
        }
        "instruction_binding.removed" => {
            let result = sqlx::query("DELETE FROM instruction_bindings WHERE id=?")
                .bind(&event.aggregate_id)
                .execute(&mut *conn)
                .await?;
            require_one(result, event).await?;
        }
        "onboarding_programme.created" => {
            let value: OnboardingProgrammeStatePayload = decode(event)?;
            sqlx::query(
                "INSERT INTO onboarding_programmes
                 (id,trigger_key,generation,position,enabled,created_by,legacy_baseline_before,created_at,updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?)",
            )
            .bind(value.id)
            .bind(value.trigger_key)
            .bind(value.generation)
            .bind(value.position)
            .bind(value.enabled)
            .bind(value.created_by)
            .bind(value.legacy_baseline_before)
            .bind(value.created_at)
            .bind(value.updated_at)
            .execute(&mut *conn)
            .await?;
        }
        "onboarding_programme.changed" => {
            let value: OnboardingProgrammeStatePayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE onboarding_programmes
                    SET trigger_key=?,position=?,enabled=?,updated_at=?
                  WHERE id=? AND generation=? AND created_by=?
                    AND legacy_baseline_before IS ? AND created_at=?",
            )
            .bind(value.trigger_key)
            .bind(value.position)
            .bind(value.enabled)
            .bind(value.updated_at)
            .bind(value.id)
            .bind(value.generation)
            .bind(value.created_by)
            .bind(value.legacy_baseline_before)
            .bind(value.created_at)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "onboarding_programme_source.added" => {
            let value: OnboardingProgrammeSourcePayload = decode(event)?;
            sqlx::query(
                "INSERT INTO onboarding_programme_sources
                 (programme_id,source_record_id,source_role,position) VALUES(?,?,?,?)",
            )
            .bind(value.programme_id)
            .bind(value.source_record_id)
            .bind(value.source_role)
            .bind(value.position)
            .execute(&mut *conn)
            .await?;
        }
        "onboarding_programme_source.changed" => {
            let value: OnboardingProgrammeSourcePayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE onboarding_programme_sources SET source_role=?,position=?
                  WHERE programme_id=? AND source_record_id=?",
            )
            .bind(value.source_role)
            .bind(value.position)
            .bind(value.programme_id)
            .bind(value.source_record_id)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "onboarding_programme_source.reordered" => {
            let value: OnboardingProgrammeSourcePayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE onboarding_programme_sources SET position=?
                  WHERE programme_id=? AND source_record_id=? AND source_role=?",
            )
            .bind(value.position)
            .bind(value.programme_id)
            .bind(value.source_record_id)
            .bind(value.source_role)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "onboarding_programme_source.removed" => {
            let value: OnboardingProgrammeSourceRemovedPayload = decode(event)?;
            let result = sqlx::query(
                "DELETE FROM onboarding_programme_sources
                  WHERE programme_id=? AND source_record_id=?",
            )
            .bind(value.programme_id)
            .bind(value.source_record_id)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "onboarding_programme.generation_published" => {
            let value: ProgrammeGenerationPublishedPayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE onboarding_programmes SET generation=?,updated_at=?
                  WHERE id=? AND generation=?",
            )
            .bind(value.generation)
            .bind(value.updated_at)
            .bind(&event.aggregate_id)
            .bind(value.previous_generation)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "member_obligation.activated" | "member_obligation.rollout_baselined" => {
            let value: MemberObligationStatePayload = decode(event)?;
            if event.event_type == "member_obligation.activated" {
                require_current_programme_generation(
                    conn,
                    event,
                    &value.programme_id,
                    value.generation,
                )
                .await?;
            }
            sqlx::query(
                "INSERT INTO member_obligations
                 (account_id,programme_id,generation,state,created_at,updated_at,updated_by,updated_run_key,reason)
                 VALUES(?,?,?,?,?,?,?,?,?)",
            )
            .bind(value.account_id)
            .bind(value.programme_id)
            .bind(value.generation)
            .bind(value.state)
            .bind(value.created_at)
            .bind(value.updated_at)
            .bind(&event.actor)
            .bind(&event.run_key)
            .bind(&event.reason)
            .execute(&mut *conn)
            .await?;
        }
        "member_obligation.resolved" => {
            let value: MemberObligationResolvedPayload = decode(event)?;
            let result = sqlx::query(
                "UPDATE member_obligations
                    SET state=?,updated_at=?,updated_by=?,updated_run_key=?,reason=?
                  WHERE account_id=? AND programme_id=? AND generation=? AND state='pending'",
            )
            .bind(value.state)
            .bind(value.updated_at)
            .bind(&event.actor)
            .bind(&event.run_key)
            .bind(&event.reason)
            .bind(value.account_id)
            .bind(value.programme_id)
            .bind(value.generation)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "member_obligation.progressed" => {
            let value: MemberObligationProgressedPayload = decode(event)?;
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM member_obligations
                  WHERE account_id=? AND programme_id=? AND generation=? AND state='pending')",
            )
            .bind(&value.account_id)
            .bind(&value.programme_id)
            .bind(value.generation)
            .fetch_one(&mut *conn)
            .await?;
            if !pending {
                return Err(Error::engine(format!(
                    "control event {} ({}) requires a pending obligation",
                    event.id, event.event_type
                )));
            }
            let previous = sqlx::query(
                "SELECT phase,artifact_id,selected_route_id FROM member_obligation_progress
                  WHERE account_id=? AND programme_id=? AND generation=?",
            )
            .bind(&value.account_id)
            .bind(&value.programme_id)
            .bind(value.generation)
            .fetch_optional(&mut *conn)
            .await?;
            let previous_phase = previous
                .as_ref()
                .map(|row| row.try_get::<String, _>("phase"))
                .transpose()?;
            let previous_artifact = previous
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("artifact_id"))
                .transpose()?
                .flatten();
            let previous_route = previous
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("selected_route_id"))
                .transpose()?
                .flatten();
            if !valid_obligation_progress_transition(previous_phase.as_deref(), &value.phase) {
                return Err(Error::engine(format!(
                    "control event {} ({}) has invalid progress transition {} -> {}",
                    event.id,
                    event.event_type,
                    previous_phase.as_deref().unwrap_or("new"),
                    value.phase
                )));
            }
            if value.phase == "value_delivered" && previous_route.is_none() {
                return Err(Error::engine(format!(
                    "control event {} ({}) requires a selected QuickStart route before value delivery",
                    event.id, event.event_type
                )));
            }
            if previous_phase.as_deref() == Some("deferred")
                && value.phase == "anchor_established"
                && !matches!(
                    value.evidence,
                    serde_json::Value::Object(ref object)
                        if object.get("basis") == Some(&serde_json::json!("user_confirmed"))
                )
            {
                return Err(Error::engine(format!(
                    "control event {} ({}) requires user_confirmed evidence to resume deferred onboarding",
                    event.id, event.event_type
                )));
            }
            if value.evidence.get("checkpoint").is_some()
                && !(previous_phase.as_deref() == Some("deferred")
                    && value.phase == "anchor_established"
                    && previous_artifact.is_some())
            {
                return Err(Error::engine(format!(
                    "control event {} ({}) used checkpoint evidence outside deferred retained-artifact resume",
                    event.id, event.event_type
                )));
            }
            let mut projected_phase = value.phase.clone();
            let mut projected_evidence = value.evidence.clone();
            let mut projected_artifact = value.artifact_id.clone();
            let mut projected_route = previous_route;
            if value.phase == "route_selected" {
                projected_route = value
                    .evidence
                    .get("route_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            if matches!(
                value.phase.as_str(),
                "deferred" | "route_selected" | "value_delivered"
            ) {
                projected_artifact = previous_artifact.clone();
            }
            if previous_phase.as_deref() == Some("deferred")
                && value.phase == "anchor_established"
                && previous_artifact.is_some()
            {
                match value.evidence.get("checkpoint").and_then(Value::as_str) {
                    Some("artifact_written") => {
                        projected_phase = "artifact_written".into();
                        projected_evidence = serde_json::json!({});
                        projected_artifact = previous_artifact;
                    }
                    Some("reset_invalid_artifact") => {
                        projected_artifact = None;
                    }
                    _ => {
                        return Err(Error::engine(format!(
                            "control event {} ({}) must encode restore or reset for its retained artifact checkpoint",
                            event.id, event.event_type
                        )));
                    }
                }
            }
            sqlx::query(
                "INSERT INTO member_obligation_progress
                 (account_id,programme_id,generation,phase,evidence,resume_after,artifact_id,
                  selected_route_id,updated_at,updated_by,updated_run_key,reason)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                 ON CONFLICT(account_id,programme_id,generation) DO UPDATE SET
                   phase=excluded.phase,evidence=excluded.evidence,
                   resume_after=excluded.resume_after,
                   artifact_id=excluded.artifact_id,
                   selected_route_id=excluded.selected_route_id,
                   updated_at=excluded.updated_at,updated_by=excluded.updated_by,
                   updated_run_key=excluded.updated_run_key,reason=excluded.reason",
            )
            .bind(value.account_id)
            .bind(value.programme_id)
            .bind(value.generation)
            .bind(projected_phase)
            .bind(serde_json::to_string(&projected_evidence)?)
            .bind(value.resume_after)
            .bind(projected_artifact)
            .bind(projected_route)
            .bind(value.updated_at)
            .bind(&event.actor)
            .bind(&event.run_key)
            .bind(&event.reason)
            .execute(&mut *conn)
            .await?;
        }
        "member_obligation.reopened" => {
            let value: MemberObligationReopenedPayload = decode(event)?;
            sqlx::query(
                "DELETE FROM member_obligation_progress
                  WHERE account_id=? AND programme_id=? AND generation=?",
            )
            .bind(&value.account_id)
            .bind(&value.programme_id)
            .bind(value.generation)
            .execute(&mut *conn)
            .await?;
            let result = sqlx::query(
                "UPDATE member_obligations
                    SET state='pending',updated_at=?,updated_by=?,updated_run_key=?,reason=?
                  WHERE account_id=? AND programme_id=? AND generation=? AND state=?",
            )
            .bind(value.updated_at)
            .bind(&event.actor)
            .bind(&event.run_key)
            .bind(&event.reason)
            .bind(value.account_id)
            .bind(value.programme_id)
            .bind(value.generation)
            .bind(value.previous_state)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "member_obligation.rebased" => {
            let value: MemberObligationRebasedPayload = decode(event)?;
            require_current_programme_generation(
                conn,
                event,
                &value.programme_id,
                value.generation,
            )
            .await?;
            let deleted = sqlx::query(
                "DELETE FROM member_obligations
                  WHERE account_id=? AND programme_id=? AND generation=? AND state='pending'",
            )
            .bind(&value.account_id)
            .bind(&value.programme_id)
            .bind(value.previous_generation)
            .execute(&mut *conn)
            .await?;
            require_one(deleted, event).await?;
            sqlx::query(
                "INSERT INTO member_obligations
                 (account_id,programme_id,generation,state,created_at,updated_at,updated_by,updated_run_key,reason)
                 VALUES(?,?,?,'pending',?,?,?,?,?)",
            )
            .bind(value.account_id)
            .bind(value.programme_id)
            .bind(value.generation)
            .bind(value.created_at)
            .bind(value.updated_at)
            .bind(&event.actor)
            .bind(&event.run_key)
            .bind(&event.reason)
            .execute(&mut *conn)
                .await?;
        }
        "seeded_instruction_source.applied" => {
            let value: SeededInstructionSourceAppliedPayload = decode(event)?;
            let result = sqlx::query(
                "INSERT INTO seeded_instruction_sources
                 (source_record_id,template_key,template_version,last_applied_digest,last_applied_at)
                 VALUES(?,?,?,?,?)
                 ON CONFLICT(source_record_id) DO UPDATE SET
                   template_version=excluded.template_version,
                   last_applied_digest=excluded.last_applied_digest,
                   last_applied_at=excluded.last_applied_at
                 WHERE seeded_instruction_sources.template_key=excluded.template_key
                   AND seeded_instruction_sources.template_version <= excluded.template_version",
            )
            .bind(value.source_record_id)
            .bind(value.template_key)
            .bind(value.template_version)
            .bind(value.last_applied_digest)
            .bind(value.last_applied_at)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        _ => unreachable!("validated event type"),
    }

    sqlx::query(
        "INSERT INTO control_event_applications(event_id,event_seq,applied_at) VALUES(?,?,?)",
    )
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn row_from_sql(row: sqlx::sqlite::SqliteRow) -> Result<ControlEventRow> {
    Ok(ControlEventRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        idempotency_key: row.try_get("idempotency_key")?,
        event_type: row.try_get("type")?,
        schema_version: row.try_get("schema_version")?,
        aggregate_kind: row.try_get("aggregate_kind")?,
        aggregate_id: row.try_get("aggregate_id")?,
        actor: row.try_get("actor")?,
        run_key: row.try_get("run_key")?,
        reason: row.try_get("reason")?,
        payload: row.try_get("payload")?,
        created_at: row.try_get("created_at")?,
    })
}

async fn read_by_idempotency_key(
    conn: &mut SqliteConnection,
    key: &str,
) -> Result<Option<ControlEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at
           FROM control_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut *conn)
    .await?
    .map(row_from_sql)
    .transpose()
}

/// Append and synchronously project within an existing write transaction.
/// Reusing an idempotency key with an identical command returns the original
/// event; reusing it for different intent fails visibly. `run_key` is excluded
/// from intent equality so a command retried in a later agent run converges on
/// its first durable event (and retains that event's original audit run).
async fn append_control_event_on(
    conn: &mut SqliteConnection,
    input: NewControlEvent,
) -> Result<ControlEventRow> {
    nonblank("idempotency key", &input.idempotency_key)?;
    nonblank("aggregate id", &input.aggregate_id)?;
    nonblank("actor", &input.actor)?;
    nonblank("reason", &input.reason)?;
    let event_type = input.payload.event_type().to_string();
    let aggregate_kind = input.payload.aggregate_kind().to_string();
    let payload = input.payload.to_json()?;
    if let Some(existing) = read_by_idempotency_key(conn, &input.idempotency_key).await? {
        let same = existing.event_type == event_type
            && existing.schema_version == CONTROL_EVENT_SCHEMA_VERSION
            && existing.aggregate_kind == aggregate_kind
            && existing.aggregate_id == input.aggregate_id
            && existing.actor == input.actor
            && existing.reason == input.reason
            && existing.payload == payload;
        if !same {
            return Err(Error::engine(format!(
                "control event idempotency key '{}' was reused for different intent",
                input.idempotency_key
            )));
        }
        project_control(conn, &existing).await?;
        return Ok(existing);
    }
    let mut event = ControlEventRow {
        seq: 1,
        id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: input.idempotency_key,
        event_type,
        schema_version: CONTROL_EVENT_SCHEMA_VERSION,
        aggregate_kind,
        aggregate_id: input.aggregate_id,
        actor: input.actor,
        run_key: input.run_key,
        reason: input.reason,
        payload,
        created_at: now_iso(),
    };
    validate_control_event(&event)?;
    event.seq = sqlx::query_scalar(
        "INSERT INTO control_events
         (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.idempotency_key)
    .bind(&event.event_type)
    .bind(event.schema_version)
    .bind(&event.aggregate_kind)
    .bind(&event.aggregate_id)
    .bind(&event.actor)
    .bind(&event.run_key)
    .bind(&event.reason)
    .bind(&event.payload)
    .bind(&event.created_at)
    .fetch_one(&mut *conn)
    .await?;
    project_control(conn, &event).await?;
    Ok(event)
}

/// Compose a control append into a wider atomic content/policy/identity write.
/// Accepting a transaction rather than a bare connection makes it impossible
/// for public callers to persist the canonical event without its projection.
pub(crate) async fn append_control_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    input: NewControlEvent,
) -> Result<ControlEventRow> {
    append_control_event_on(tx, input).await
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AgentRunLifecycle {
    pub activity_id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub changed: bool,
}

/// Admit an intentful run exactly once. The run key is its visible continuity
/// handle; the random activity id remains the stable relational key for joins.
/// Neither establishes authentication or exclusive possession.
pub(crate) async fn ensure_agent_run(
    db: &Db,
    run_key: &str,
    account_id: &str,
) -> Result<AgentRunLifecycle> {
    if !matches!(
        crate::runkey::validate_full(Some(run_key)),
        crate::runkey::KeyOutcome::Valid(_)
    ) {
        return Err(Error::engine(
            "set_intent requires a valid full run key for durable activity",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if let Some(row) = sqlx::query(
        "SELECT activity_id,account_id,started_at,ended_at FROM agent_runs WHERE run_key=?",
    )
    .bind(run_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let bound: String = row.try_get("account_id")?;
        if bound != account_id {
            return Err(Error::engine(
                "run key is already bound to another authenticated account",
            ));
        }
        let ended_at: Option<String> = row.try_get("ended_at")?;
        if ended_at.is_some() {
            return Err(Error::engine(
                "set_intent cannot redeclare a closed durable activity",
            ));
        }
        let state = AgentRunLifecycle {
            activity_id: row.try_get("activity_id")?,
            started_at: row.try_get("started_at")?,
            ended_at,
            changed: false,
        };
        tx.rollback().await?;
        return Ok(state);
    }

    let activity_id = uuid::Uuid::new_v4().to_string();
    let started_at = now_iso();
    append_control_event_in(
        &mut tx,
        NewControlEvent::authored(
            format!("agent-run-start:{run_key}"),
            &activity_id,
            account_id,
            Some(run_key.to_string()),
            "Admit the first successful intent declaration for this run.",
            ControlEventPayload::AgentRunStarted(AgentRunStartedPayload {
                activity_id: activity_id.clone(),
                account_id: account_id.to_string(),
                started_at: started_at.clone(),
            }),
        )?,
    )
    .await?;
    tx.commit().await?;
    Ok(AgentRunLifecycle {
        activity_id,
        started_at,
        ended_at: None,
        changed: true,
    })
}

/// Close the caller-bound run explicitly. Repeating the same closure is a
/// read-only success; no timeout, claim, task or transport state calls here.
pub(crate) async fn close_agent_run(
    db: &Db,
    run_key: &str,
    account_id: &str,
) -> Result<AgentRunLifecycle> {
    if !matches!(
        crate::runkey::validate_full(Some(run_key)),
        crate::runkey::KeyOutcome::Valid(_)
    ) {
        return Err(Error::engine("close_run requires a valid full run key"));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let row = sqlx::query(
        "SELECT activity_id,account_id,started_at,ended_at FROM agent_runs WHERE run_key=?",
    )
    .bind(run_key)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine("close_run requires a successful prior set_intent"))?;
    let bound: String = row.try_get("account_id")?;
    if bound != account_id {
        return Err(Error::engine(
            "close_run cannot close a run bound to another authenticated account",
        ));
    }
    let activity_id: String = row.try_get("activity_id")?;
    let started_at: String = row.try_get("started_at")?;
    if let Some(ended_at) = row.try_get::<Option<String>, _>("ended_at")? {
        tx.rollback().await?;
        return Ok(AgentRunLifecycle {
            activity_id,
            started_at,
            ended_at: Some(ended_at),
            changed: false,
        });
    }
    let ended_at = now_iso();
    append_control_event_in(
        &mut tx,
        NewControlEvent::authored(
            format!("agent-run-close:{activity_id}"),
            &activity_id,
            account_id,
            Some(run_key.to_string()),
            "Record the caller's explicit run closure.",
            ControlEventPayload::AgentRunClosed(AgentRunClosedPayload {
                activity_id: activity_id.clone(),
                ended_at: ended_at.clone(),
            }),
        )?,
    )
    .await?;
    tx.commit().await?;
    Ok(AgentRunLifecycle {
        activity_id,
        started_at,
        ended_at: Some(ended_at),
        changed: true,
    })
}

/// Standalone append/project convenience. Commands that also author content or
/// policy state should use [`append_control_event_in`] inside their wider
/// transaction instead.
#[cfg(test)]
pub(crate) async fn append_control_event(
    db: &Db,
    input: NewControlEvent,
) -> Result<ControlEventRow> {
    let mut tx = begin_write(db.write_pool()).await?;
    let event = append_control_event_in(&mut tx, input).await?;
    tx.commit().await?;
    Ok(event)
}

pub async fn read_all_control_events(conn: &mut SqliteConnection) -> Result<Vec<ControlEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at
           FROM control_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(row_from_sql)
    .collect()
}

pub(crate) async fn replay_control(
    conn: &mut SqliteConnection,
    events: &[ControlEventRow],
) -> Result<()> {
    let mut tx = conn.begin().await?;
    for event in events {
        sqlx::query(
            "INSERT INTO control_events
             (seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
              actor,run_key,reason,payload,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(event.seq)
        .bind(&event.id)
        .bind(&event.idempotency_key)
        .bind(&event.event_type)
        .bind(event.schema_version)
        .bind(&event.aggregate_kind)
        .bind(&event.aggregate_id)
        .bind(&event.actor)
        .bind(&event.run_key)
        .bind(&event.reason)
        .bind(&event.payload)
        .bind(&event.created_at)
        .execute(&mut *tx)
        .await?;
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM control_events
                WHERE seq=? AND id=? AND idempotency_key=? AND type=? AND schema_version=?
                  AND aggregate_kind=? AND aggregate_id=? AND actor=? AND run_key IS ?
                  AND reason=? AND payload=? AND created_at=?
             )",
        )
        .bind(event.seq)
        .bind(&event.id)
        .bind(&event.idempotency_key)
        .bind(&event.event_type)
        .bind(event.schema_version)
        .bind(&event.aggregate_kind)
        .bind(&event.aggregate_id)
        .bind(&event.actor)
        .bind(&event.run_key)
        .bind(&event.reason)
        .bind(&event.payload)
        .bind(&event.created_at)
        .fetch_one(&mut *tx)
        .await?;
        if !exact {
            return Err(Error::engine(format!(
                "control replay event {} conflicts with the authoritative log",
                event.id
            )));
        }
        project_control(&mut tx, event).await?;
    }
    tx.commit().await?;
    Ok(())
}

const CONTROL_OBJECTS: [&str; 16] = [
    "control_events",
    "idx_control_events_aggregate",
    "control_events_no_update",
    "control_events_no_delete",
    "agent_runs",
    "idx_agent_runs_account_started",
    "member_contexts",
    "instruction_bindings",
    "idx_instruction_bindings_source",
    "onboarding_programmes",
    "onboarding_programme_sources",
    "member_obligations",
    "idx_member_obligations_one_pending",
    "member_obligation_progress",
    "seeded_instruction_sources",
    "control_event_applications",
];

/// Fold a complete control log through the canonical SQLite projector and
/// return its deterministic product-state snapshot. Postgres uses this as the
/// shared transition oracle rather than maintaining a second implementation
/// of the control state machine — and is its only caller, so the function
/// compiles only with the adapter.
#[cfg(feature = "postgres")]
pub(crate) async fn canonical_projection_snapshot(
    events: &[ControlEventRow],
    record_ids: &[String],
) -> Result<Value> {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await?;
    conn.execute("PRAGMA foreign_keys = ON").await?;
    conn.execute("CREATE TABLE records(id TEXT PRIMARY KEY)")
        .await?;
    for record_id in record_ids {
        sqlx::query("INSERT INTO records(id) VALUES(?)")
            .bind(record_id)
            .execute(&mut conn)
            .await?;
    }
    for statement in DDL_STATEMENTS {
        if CONTROL_OBJECTS.iter().any(|name| {
            statement.starts_with(&format!("CREATE TABLE {name}"))
                || statement.starts_with(&format!("CREATE INDEX {name}"))
                || statement.starts_with(&format!("CREATE UNIQUE INDEX {name}"))
                || statement.starts_with(&format!("CREATE TRIGGER {name}"))
        }) {
            conn.execute(statement).await?;
        }
    }
    replay_control(&mut conn, events).await?;

    let agent_runs = sqlx::query(
        "SELECT activity_id,run_key,account_id,started_at,ended_at,start_event_id,start_event_seq,close_event_id,close_event_seq FROM agent_runs ORDER BY activity_id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "activity_id": row.try_get::<String, _>("activity_id")?,
            "run_key": row.try_get::<String, _>("run_key")?,
            "account_id": row.try_get::<String, _>("account_id")?,
            "started_at": row.try_get::<String, _>("started_at")?,
            "ended_at": row.try_get::<Option<String>, _>("ended_at")?,
            "start_event_id": row.try_get::<String, _>("start_event_id")?,
            "start_event_seq": row.try_get::<i64, _>("start_event_seq")?,
            "close_event_id": row.try_get::<Option<String>, _>("close_event_id")?,
            "close_event_seq": row.try_get::<Option<i64>, _>("close_event_seq")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let member_contexts = sqlx::query(
        "SELECT account_id,person_record_id,root_record_id,created_at FROM member_contexts ORDER BY account_id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "account_id": row.try_get::<String, _>("account_id")?,
            "person_record_id": row.try_get::<String, _>("person_record_id")?,
            "root_record_id": row.try_get::<String, _>("root_record_id")?,
            "created_at": row.try_get::<String, _>("created_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let instruction_bindings = sqlx::query(
        "SELECT id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at FROM instruction_bindings ORDER BY id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "id": row.try_get::<String, _>("id")?,
            "scope_kind": row.try_get::<String, _>("scope_kind")?,
            "scope_id": row.try_get::<String, _>("scope_id")?,
            "source_record_id": row.try_get::<String, _>("source_record_id")?,
            "position": row.try_get::<i64, _>("position")?,
            "enabled": row.try_get::<bool, _>("enabled")?,
            "created_by": row.try_get::<String, _>("created_by")?,
            "created_at": row.try_get::<String, _>("created_at")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let onboarding_programmes = sqlx::query(
        "SELECT id,trigger_key,generation,position,enabled,created_by,legacy_baseline_before,created_at,updated_at FROM onboarding_programmes ORDER BY id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "id": row.try_get::<String, _>("id")?,
            "trigger_key": row.try_get::<String, _>("trigger_key")?,
            "generation": row.try_get::<i64, _>("generation")?,
            "position": row.try_get::<i64, _>("position")?,
            "enabled": row.try_get::<bool, _>("enabled")?,
            "created_by": row.try_get::<String, _>("created_by")?,
            "legacy_baseline_before": row.try_get::<Option<String>, _>("legacy_baseline_before")?,
            "created_at": row.try_get::<String, _>("created_at")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let onboarding_programme_sources = sqlx::query(
        "SELECT programme_id,source_record_id,source_role,position FROM onboarding_programme_sources ORDER BY programme_id,source_record_id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "programme_id": row.try_get::<String, _>("programme_id")?,
            "source_record_id": row.try_get::<String, _>("source_record_id")?,
            "source_role": row.try_get::<String, _>("source_role")?,
            "position": row.try_get::<i64, _>("position")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let member_obligations = sqlx::query(
        "SELECT account_id,programme_id,generation,state,created_at,updated_at,updated_by,updated_run_key,reason FROM member_obligations ORDER BY account_id,programme_id,generation",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "account_id": row.try_get::<String, _>("account_id")?,
            "programme_id": row.try_get::<String, _>("programme_id")?,
            "generation": row.try_get::<i64, _>("generation")?,
            "state": row.try_get::<String, _>("state")?,
            "created_at": row.try_get::<String, _>("created_at")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
            "updated_by": row.try_get::<Option<String>, _>("updated_by")?,
            "updated_run_key": row.try_get::<Option<String>, _>("updated_run_key")?,
            "reason": row.try_get::<Option<String>, _>("reason")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let member_obligation_progress = sqlx::query(
        "SELECT account_id,programme_id,generation,phase,evidence,resume_after,artifact_id,selected_route_id,updated_at,updated_by,updated_run_key,reason FROM member_obligation_progress ORDER BY account_id,programme_id,generation",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        let evidence = serde_json::from_str::<Value>(&row.try_get::<String, _>("evidence")?)?;
        Ok(json!({
            "account_id": row.try_get::<String, _>("account_id")?,
            "programme_id": row.try_get::<String, _>("programme_id")?,
            "generation": row.try_get::<i64, _>("generation")?,
            "phase": row.try_get::<String, _>("phase")?,
            "evidence": evidence,
            "resume_after": row.try_get::<Option<String>, _>("resume_after")?,
            "artifact_id": row.try_get::<Option<String>, _>("artifact_id")?,
            "selected_route_id": row.try_get::<Option<String>, _>("selected_route_id")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
            "updated_by": row.try_get::<String, _>("updated_by")?,
            "updated_run_key": row.try_get::<Option<String>, _>("updated_run_key")?,
            "reason": row.try_get::<String, _>("reason")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let seeded_instruction_sources = sqlx::query(
        "SELECT source_record_id,template_key,template_version,last_applied_digest,last_applied_at FROM seeded_instruction_sources ORDER BY source_record_id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok(json!({
            "source_record_id": row.try_get::<String, _>("source_record_id")?,
            "template_key": row.try_get::<String, _>("template_key")?,
            "template_version": row.try_get::<i64, _>("template_version")?,
            "last_applied_digest": row.try_get::<String, _>("last_applied_digest")?,
            "last_applied_at": row.try_get::<String, _>("last_applied_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;

    Ok(json!({
        "agent_runs": agent_runs,
        "member_contexts": member_contexts,
        "instruction_bindings": instruction_bindings,
        "onboarding_programmes": onboarding_programmes,
        "onboarding_programme_sources": onboarding_programme_sources,
        "member_obligations": member_obligations,
        "member_obligation_progress": member_obligation_progress,
        "seeded_instruction_sources": seeded_instruction_sources,
    }))
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expected_objects() -> BTreeMap<&'static str, (&'static str, String)> {
    CONTROL_OBJECTS
        .into_iter()
        .map(|name| {
            let statement = DDL_STATEMENTS
                .iter()
                .find(|statement| {
                    statement.starts_with(&format!("CREATE TABLE {name}"))
                        || statement.starts_with(&format!("CREATE INDEX {name}"))
                        || statement.starts_with(&format!("CREATE UNIQUE INDEX {name}"))
                        || statement.starts_with(&format!("CREATE TRIGGER {name}"))
                })
                .unwrap_or_else(|| panic!("frozen DDL contains {name}"));
            let kind = if statement.starts_with("CREATE TABLE") {
                "table"
            } else if statement.starts_with("CREATE TRIGGER") {
                "trigger"
            } else {
                "index"
            };
            (name, (kind, normalized_schema_sql(statement)))
        })
        .collect()
}

pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut snapshot = db.write_pool().begin().await?;
    let mut violations = state_violations_on(&mut snapshot).await?;
    snapshot.rollback().await?;
    if violations.is_empty() {
        let diff = crate::conformance::rebuild_and_diff_control(db).await?;
        for table in diff
            .tables
            .into_iter()
            .filter(|table| table.live != table.rebuilt || !table.mismatches.is_empty())
        {
            violations.push(format!(
                "control projection drift in {} (live {}, rebuilt {}): {}",
                table.table,
                table.live,
                table.rebuilt,
                table
                    .mismatches
                    .into_iter()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    Ok(violations)
}

pub async fn state_violations_on(conn: &mut SqliteConnection) -> Result<Vec<String>> {
    let expected = expected_objects();
    let actual = sqlx::query(
        "SELECT type,name,sql FROM sqlite_schema
          WHERE lower(name) = 'control_events'
             OR lower(name) GLOB 'control_events_*'
             OR lower(name) = 'control_event_applications'
             OR lower(name) IN (
               'agent_runs','idx_agent_runs_account_started','member_contexts','instruction_bindings','onboarding_programmes',
               'onboarding_programme_sources','member_obligations',
               'member_obligation_progress','seeded_instruction_sources','idx_instruction_bindings_source',
               'idx_member_obligations_one_pending','idx_control_events_aggregate')
          ORDER BY name,type",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("name")?,
            row.try_get::<String, _>("type")?,
            row.try_get::<Option<String>, _>("sql")?,
        ))
    })
    .collect::<Result<Vec<_>>>()?;
    let mut violations = Vec::new();
    for (name, (expected_type, expected_sql)) in &expected {
        match actual.iter().find(|(candidate, _, _)| candidate == name) {
            None => violations.push(format!("required {expected_type} missing: {name}")),
            Some((_, actual_type, _)) if actual_type != expected_type => violations.push(format!(
                "reserved object {name} must be a {expected_type}, found {actual_type}"
            )),
            Some((_, _, Some(actual_sql)))
                if normalized_schema_sql(actual_sql) != *expected_sql =>
            {
                violations.push(format!(
                    "reserved object {name} does not match the frozen schema-16 definition"
                ));
            }
            Some((_, _, None)) => violations.push(format!("reserved object {name} has no SQL")),
            Some(_) => {}
        }
    }
    for (name, kind, _) in &actual {
        if !expected.contains_key(name.as_str()) {
            violations.push(format!(
                "unexpected reserved instruction-control object: {kind} {name}"
            ));
        }
    }
    if !violations.is_empty() {
        return Ok(violations);
    }

    let events = read_all_control_events(conn).await?;
    for (index, event) in events.iter().enumerate() {
        let expected_seq = index as i64 + 1;
        if event.seq != expected_seq {
            violations.push(format!(
                "control event sequence is not contiguous: expected {expected_seq}, found {}",
                event.seq
            ));
        }
        if let Err(error) = validate_control_event(event) {
            violations.push(format!("control event {} is malformed: {error}", event.id));
        }
    }
    let applications =
        sqlx::query("SELECT event_id,event_seq FROM control_event_applications ORDER BY event_seq")
            .fetch_all(&mut *conn)
            .await?;
    if applications.len() != events.len() {
        violations.push(format!(
            "control event application count differs from log: {} applications for {} events",
            applications.len(),
            events.len()
        ));
    }
    for (index, row) in applications.iter().enumerate() {
        let Some(event) = events.get(index) else {
            break;
        };
        let event_id: String = row.try_get("event_id")?;
        let event_seq: i64 = row.try_get("event_seq")?;
        if event_id != event.id || event_seq != event.seq {
            violations.push(format!(
                "control event application at position {} does not match canonical event {}",
                index + 1,
                event.id
            ));
        }
    }
    Ok(violations)
}
