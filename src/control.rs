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

pub(crate) mod alpha_tab_provenance;
#[cfg(test)]
pub(crate) mod alpha_tab_provenance_tests;
pub use alpha_tab_provenance::{
    alpha_tab_pin_digest, AlphaTabAdoptionProvenance, AlphaTabUpdatePayload,
};

pub(crate) use alpha_tab_provenance::complete_update_in as complete_alpha_tab_update_in;

pub const CONTROL_EVENT_SCHEMA_VERSION: i64 = 1;

pub const CONTROL_EVENT_TYPES: [&str; 32] = [
    "agent_run.started.v1",
    "agent_run.started.v2",
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
    "alpha_tab.installed",
    "alpha_tab.updated",
    "alpha_tab.import_reset",
    "alpha_tab.disabled",
    "alpha_tab.restored",
    "alpha_tab.removed",
    "alpha_tab.order_set",
    "alpha_tab.adopted.v2",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunStartedPayload {
    pub activity_id: String,
    pub account_id: String,
    pub started_at: String,
    /// Transport observed by the server on the admitting `set_intent` call.
    /// Older start events have no such observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<crate::provenance::Channel>,
    /// Self-asserted MCP client name from the admitting call's
    /// `params._meta["io.modelcontextprotocol/clientInfo"]`. Absent means the
    /// admitting call carried no `clientInfo` — never a default string, never
    /// `"unknown"`. `Some("")` is a client that sent an empty string and stays
    /// distinguishable from absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_mcp_client_name: Option<String>,
    /// Self-asserted MCP client version, same provenance as the name above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_mcp_client_version: Option<String>,
    /// Declared model. Stamped from the optional `model` argument on the
    /// admitting `set_intent` call: the model's own claim about itself, stored
    /// exactly as given (clamped to [`MAX_REPORTED_RUN_IDENTITY_BYTES`]) and
    /// never normalised against a model list. The field and column exist so a
    /// future reader attributing the run's work has the claim on record; no
    /// engine path reads it to decide anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_model: Option<String>,
}

/// Upper bound in bytes for each stored self-asserted run-identity string.
///
/// `validate_implementation` checks `clientInfo` types and URIs but not
/// lengths, so admission clamps before stamping. 256 bytes leaves wide
/// headroom for real client names/versions (tens of bytes) while bounding row
/// growth from a chatty or adversarial client. Clamping truncates on a UTF-8
/// boundary rather than rejecting admission: a long self-assertion must not
/// become a denial of run admission.
pub(crate) const MAX_REPORTED_RUN_IDENTITY_BYTES: usize = 256;

/// Client-asserted identity stamped once, at run admission, inside the same
/// transaction that writes the run's canonical start event. A later differing
/// `clientInfo` never overwrites the admitted values, and neither does a
/// later differing declared model — the divergence is refused in the
/// `set_intent` response instead, so a claim that was in fact ignored can
/// never look acknowledged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReportedRunIdentity {
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub model: Option<String>,
}

impl ReportedRunIdentity {
    fn clamp_text(value: Option<String>) -> Option<String> {
        value.map(|mut text| {
            let mut end = text.len().min(MAX_REPORTED_RUN_IDENTITY_BYTES);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text
        })
    }

    /// Clamp every populated field to [`MAX_REPORTED_RUN_IDENTITY_BYTES`].
    pub(crate) fn clamped(self) -> Self {
        Self {
            client_name: Self::clamp_text(self.client_name),
            client_version: Self::clamp_text(self.client_version),
            model: Self::clamp_text(self.model),
        }
    }

    /// Attach the model's self-declared name carried by the `set_intent`
    /// `model` argument. Stored exactly as given (up to the clamp): an
    /// unrecognised string is still the claim that was made, so it is never
    /// normalised or rejected against a model list here.
    pub(crate) fn with_model(mut self, model: Option<String>) -> Self {
        self.model = model;
        self
    }
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
    /// The workspace act this event was stamped with, or `None` for legacy
    /// pre-cutover rows whose transaction grouping is permanently unknown.
    /// Replay must preserve this value verbatim — allocating a fresh act
    /// would fabricate grouping the decision behind acts forbids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<i64>,
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

/// Personal alpha-tab install state (task 26ba75a, design
/// `docs/alpha-tab-install-state.md` §4).
///
/// One canonical event per transition; the `alpha_tab_installs` projection
/// folds them into one row per installed tab per account. Status is carried
/// by the event type, not the payload: `installed | disabled | restored |
/// removed` map to projection statuses `installed | disabled | installed |
/// removed`. `previous_event_id` is the CAS token — `None` starts a fresh
/// install chain (first install, or reinstall after `removed`); transitions
/// carry the projection row's current token, which the projector checks
/// against the row before moving it.
///
/// `adoption` records how the install was adopted. The only attainable
/// value in this slice is `caller_asserted`: the calling credential
/// asserted adoption through the tool. There is deliberately no verified
/// shell preview/adopt gesture behind it — no preview happened, or the
/// tool cannot prove one did. A verified-gesture value is a named
/// follow-up (`26ba75a-adopt-gesture`); the tier rejects any other string
/// rather than storing an unverified claim under a stronger name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabStatePayload {
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub consented_source_revision: String,
    pub declaration_digest: String,
    pub consented_declaration: Value,
    pub adoption: String,
    /// Display-only request text recorded at install (E3, task `f1d80b0`):
    /// what the installer asked for, echoed on adoption. Never authority.
    /// `None` for installs predating the field and for callers that omit it.
    #[serde(default)]
    pub request: Option<String>,
    pub previous_event_id: Option<String>,
}

/// Canonical import's durable consent boundary. It preserves the complete pin
/// and status but never receiver eligibility. Ordinary append paths refuse it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabImportResetPayload {
    pub pin: AlphaTabStatePayload,
    pub status: String,
    pub adoption_provenance: Option<Value>,
}

/// The only adoption provenance the backend can honestly stamp in this
/// slice: asserted by the calling credential, with no verified shell
/// preview/adopt gesture behind it.
pub const ALPHA_TAB_ADOPTION_CALLER_ASSERTED: &str = "caller_asserted";

/// Verified shell preview/adopt gesture (task `26ba75a` adopt-confirm
/// slice): a same-origin browser session presenting a live, unconsumed,
/// unexpired server-held preview receipt bound to the exact account plus
/// the full pin, with CAS on the install's current event. Minted only by
/// the `alpha_tab.adopted` control event below — never caller-supplied.
/// The physical click remains a trusted-shell-UI assumption, not a server
/// proof (`docs/alpha-tab-install-slice3-adopt-gesture.md` §3.1).
pub const ALPHA_TAB_ADOPTION_VERIFIED: &str = "shell_adopt.v1";

/// Honest shell auto-adoption (plan `100d273` E1, task `f1d80b0`): the
/// desktop shell adopts a revision its own pane agent authored, over a
/// cookie session plus trusted-Origin same-origin POST, with no preview
/// receipt. Pane binding — that the install really came from the shell's
/// own pane agent — is enforced by the desktop app, not the engine: the
/// engine records the claimed launch as provenance, labelled asserted.
/// Never stamped by chaining preview+adopt, which would forge a receipt
/// claiming a sample preview nobody saw.
pub const ALPHA_TAB_ADOPTION_SHELL_AUTO: &str = "shell_auto.v1";

/// Bound on display-only alpha-tab request text, in characters.
pub const ALPHA_TAB_REQUEST_MAX_CHARS: usize = 500;

/// Bound on client-asserted shell-auto provenance fields, in characters.
pub const ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS: usize = 256;

/// Adopt-confirm payload for `alpha_tab.adopted`: the full consented pin
/// echoed field-for-field, the verified adoption value, the CAS token it
/// chains from, and — for `shell_adopt.v1` only — the server-held preview
/// receipt that authorized it.
/// Carrying the receipt id plus the pin is what lets idempotency-key
/// convergence distinguish a retried adopt (same receipt, same intent)
/// from a conflicting reuse (different receipt, visible error), and what
/// keeps the audit trail naming which preview authorized the adoption.
///
/// `shell_auto.v1` carries no receipt fields (`None`): instead it carries
/// client-asserted `launch_id` / `authored_run_key` provenance plus the
/// install's `request` echo. The two kinds are mutually exclusive by
/// construction — a payload carrying both a receipt and authored fields is
/// refused — so one event can never claim two consent bases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabAdoptPayload {
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub consented_source_revision: String,
    pub declaration_digest: String,
    pub consented_declaration: Value,
    pub adoption: String,
    pub previous_event_id: String,
    /// Server-held preview receipt authorizing a `shell_adopt.v1` adopt.
    /// `None` for `shell_auto.v1`, which has no preview and no receipt.
    #[serde(default)]
    pub receipt_id: Option<String>,
    /// Preview session the receipt was minted in. `None` for `shell_auto.v1`.
    #[serde(default)]
    pub preview_session: Option<String>,
    /// Client-asserted shell-auto provenance (E1): opaque launch handle
    /// from the desktop shell. `None` for `shell_adopt.v1` and for older
    /// rows. Documented as asserted, never verified.
    #[serde(default)]
    pub launch_id: Option<String>,
    /// Client-asserted shell-auto provenance (E1): run key of the pane
    /// agent that authored the adopted revision. `None` for
    /// `shell_adopt.v1` and for older rows.
    #[serde(default)]
    pub authored_run_key: Option<String>,
    /// Install's `request` text echoed at adoption (E3). `None` for
    /// `shell_adopt.v1` rows and when the install carries no request.
    #[serde(default)]
    pub request: Option<String>,
}

/// Private historical structural evidence; not authenticated producer proof.
/// Only the request-bound trusted producer emits new feature evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabBodyReadAdmission {
    pub need: String,
    pub scope: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabAdoptV2Payload {
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub consented_source_revision: String,
    pub declaration_digest: String,
    pub consented_declaration: Value,
    pub adoption: String,
    pub previous_event_id: String,
    /// Server-held preview receipt authorizing a `shell_adopt.v1` adopt.
    /// `None` for `shell_auto.v1`, which has no preview and no receipt.
    #[serde(default)]
    pub receipt_id: Option<String>,
    /// Preview session the receipt was minted in. `None` for `shell_auto.v1`.
    #[serde(default)]
    pub preview_session: Option<String>,
    /// Client-asserted shell-auto provenance (E1): opaque launch handle
    /// from the desktop shell. `None` for `shell_adopt.v1` and for older
    /// rows. Documented as asserted, never verified.
    #[serde(default)]
    pub launch_id: Option<String>,
    /// Client-asserted shell-auto provenance (E1): run key of the pane
    /// agent that authored the adopted revision. `None` for
    /// `shell_adopt.v1` and for older rows.
    #[serde(default)]
    pub authored_run_key: Option<String>,
    /// Install's `request` text echoed at adoption (E3). `None` for
    /// `shell_adopt.v1` rows and when the install carries no request.
    #[serde(default)]
    pub request: Option<String>,
    pub runtime: String,
    pub bundle_sha256: String,
    pub body_read_admission: AlphaTabBodyReadAdmission,
}

/// Personal alpha-tab order (task `c5d3820`).
///
/// One row per account in `alpha_tab_orders`: the viewer's full tab-strip
/// order as an array of tab ids (shell built-ins such as `agents` plus
/// `pending:<package>` for installs). The event carries complete state —
/// last writer wins, with no CAS token — because a tab order is a
/// preference, not a lifecycle transition: two concurrent reorders serialize
/// in the write transaction and the later one stands. Callers that care
/// should `list` first and reorder from what they saw.
///
/// The tier validates shape only (non-blank account, bounded entries); the
/// `manage_alpha_tabs` tool validates vocabulary (known built-ins,
/// installed-or-disabled packages, no duplicates) before appending.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabOrderPayload {
    pub account_id: String,
    pub tab_order: Vec<String>,
}

/// Bound on stored tab-order entries: four shell built-ins plus headroom
/// for installs. The tool refuses longer orders before appending.
pub const ALPHA_TAB_ORDER_MAX_ENTRIES: usize = 64;

/// Bound on one stored tab id: `pending:` plus a 128-char package id, with
/// headroom for future built-in ids.
pub const ALPHA_TAB_ORDER_MAX_ENTRY_CHARS: usize = 160;

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
    AlphaTabInstalled(AlphaTabStatePayload),
    AlphaTabUpdated(Box<AlphaTabUpdatePayload>),
    AlphaTabImportReset(AlphaTabImportResetPayload),
    AlphaTabDisabled(AlphaTabStatePayload),
    AlphaTabRestored(AlphaTabStatePayload),
    AlphaTabRemoved(AlphaTabStatePayload),
    AlphaTabAdopted(AlphaTabAdoptPayload),
    AlphaTabAdoptedV2(AlphaTabAdoptV2Payload),
    AlphaTabOrderSet(AlphaTabOrderPayload),
}

impl ControlEventPayload {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::AgentRunStarted(_) => "agent_run.started.v2",
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
            Self::AlphaTabInstalled(_) => "alpha_tab.installed",
            Self::AlphaTabUpdated(_) => "alpha_tab.updated",
            Self::AlphaTabImportReset(_) => "alpha_tab.import_reset",
            Self::AlphaTabDisabled(_) => "alpha_tab.disabled",
            Self::AlphaTabRestored(_) => "alpha_tab.restored",
            Self::AlphaTabRemoved(_) => "alpha_tab.removed",
            Self::AlphaTabAdopted(_) => "alpha_tab.adopted",
            Self::AlphaTabAdoptedV2(_) => "alpha_tab.adopted.v2",
            Self::AlphaTabOrderSet(_) => "alpha_tab.order_set",
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
            Self::AlphaTabImportReset(_)
            | Self::AlphaTabUpdated(_)
            | Self::AlphaTabInstalled(_)
            | Self::AlphaTabDisabled(_)
            | Self::AlphaTabRestored(_)
            | Self::AlphaTabRemoved(_)
            | Self::AlphaTabAdopted(_)
            | Self::AlphaTabAdoptedV2(_)
            | Self::AlphaTabOrderSet(_) => "alpha_tab",
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
            Self::AlphaTabInstalled(value)
            | Self::AlphaTabDisabled(value)
            | Self::AlphaTabRestored(value)
            | Self::AlphaTabRemoved(value) => serde_json::to_string(value)?,
            Self::AlphaTabUpdated(value) => serde_json::to_string(value)?,
            Self::AlphaTabImportReset(value) => serde_json::to_string(value)?,
            Self::AlphaTabAdopted(value) => serde_json::to_string(value)?,
            Self::AlphaTabAdoptedV2(value) => serde_json::to_string(value)?,
            Self::AlphaTabOrderSet(value) => serde_json::to_string(value)?,
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

/// Canonical identity for one personal alpha-tab install chain: the
/// viewer's database-local account plus the reverse-dns package id.
/// Length-prefix encoding prevents account or package ids containing
/// punctuation from aliasing another pair.
pub fn alpha_tab_aggregate_id(account_id: &str, package: &str) -> String {
    encode_aggregate_parts(&[account_id, package])
}

/// Canonical identity for one account's alpha-tab order: the viewer's
/// database-local account alone. Length-prefix encoding keeps the aggregate
/// namespace disjoint from install chains even if an account id ever
/// contained punctuation.
pub fn alpha_tab_order_aggregate_id(account_id: &str) -> String {
    encode_aggregate_parts(&[account_id])
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
        value if value.starts_with("alpha_tab.") => Some("alpha_tab"),
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

fn valid_sha256_hex(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::engine(format!(
            "control event {label} must be 64 lowercase hex characters"
        )));
    }
    Ok(())
}

/// Display-only alpha-tab request text (E3): optional, 1..=500 characters
/// when present. The tool rejects over-long input before appending; the
/// tier enforces the same bound so a forged long request can never be
/// written directly.
fn validate_alpha_tab_request(request: Option<&str>) -> Result<()> {
    if let Some(text) = request {
        let chars = text.chars().count();
        if text.trim().is_empty() || chars > ALPHA_TAB_REQUEST_MAX_CHARS {
            return Err(Error::engine(format!(
                "control event alpha tab request must be 1..={} characters",
                ALPHA_TAB_REQUEST_MAX_CHARS
            )));
        }
    }
    Ok(())
}

/// One client-asserted shell-auto provenance field (E1): optional,
/// 1..=256 characters when present. Asserted, never verified — the bound
/// keeps the provenance column honest, not authoritative.
fn validate_alpha_tab_authored_field(label: &str, value: Option<&str>) -> Result<()> {
    if let Some(text) = value {
        let chars = text.chars().count();
        if text.trim().is_empty() || chars > ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS {
            return Err(Error::engine(format!(
                "control event alpha tab {label} must be 1..={} characters",
                ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS
            )));
        }
    }
    Ok(())
}

fn validate_alpha_tab(event: &ControlEventRow, value: &AlphaTabStatePayload) -> Result<()> {
    for (label, text) in [
        ("alpha tab account_id", value.account_id.as_str()),
        ("alpha tab package", value.package.as_str()),
        ("alpha tab version", value.version.as_str()),
        ("alpha tab digest", value.digest.as_str()),
        ("alpha tab artifact_id", value.artifact_id.as_str()),
        (
            "alpha tab consented_source_revision",
            value.consented_source_revision.as_str(),
        ),
        (
            "alpha tab declaration_digest",
            value.declaration_digest.as_str(),
        ),
    ] {
        nonblank(label, text)?;
    }
    let Some(digest_hex) = value.digest.strip_prefix("sha256:") else {
        return Err(Error::engine(
            "control event alpha tab digest must start with 'sha256:'",
        ));
    };
    valid_sha256_hex("alpha tab digest", digest_hex)?;
    valid_sha256_hex("alpha tab declaration_digest", &value.declaration_digest)?;
    if value.adoption != ALPHA_TAB_ADOPTION_CALLER_ASSERTED
        && value.adoption != ALPHA_TAB_ADOPTION_VERIFIED
    {
        return Err(Error::engine(
            "control event alpha tab adoption is unknown: only caller_asserted and shell_adopt.v1 are attainable",
        ));
    }
    if !value.consented_declaration.is_object() {
        return Err(Error::engine(
            "control event alpha tab consented_declaration must be an object",
        ));
    }
    crate::alpha_tab_sessions::validate_declaration_sessions(&value.consented_declaration)
        .map_err(|reason| {
            Error::engine(format!(
                "control event alpha tab consented_declaration sessions invalid: {reason}"
            ))
        })?;
    validate_alpha_tab_request(value.request.as_deref())?;
    if let Some(previous) = value.previous_event_id.as_deref() {
        nonblank("alpha tab previous_event_id", previous)?;
    }
    if event.aggregate_id != alpha_tab_aggregate_id(&value.account_id, &value.package) {
        return Err(Error::engine(
            "alpha tab aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}

/// Validate an `alpha_tab.order_set` event: shape only. The entry vocabulary
/// (known built-ins, installed packages, no duplicates) is the tool's check
/// (`manage_alpha_tabs reorder`); the tier refuses only what no honest tool
/// would append — a blank account, an over-long order, or a blank or
/// over-long entry — plus a wrong aggregate id, so a forged order can never
/// be written directly under another account's aggregate.
fn validate_alpha_tab_order(event: &ControlEventRow, value: &AlphaTabOrderPayload) -> Result<()> {
    nonblank("alpha tab account_id", &value.account_id)?;
    if value.tab_order.len() > ALPHA_TAB_ORDER_MAX_ENTRIES {
        return Err(Error::engine(format!(
            "control event alpha tab order holds {} entries (max {})",
            value.tab_order.len(),
            ALPHA_TAB_ORDER_MAX_ENTRIES
        )));
    }
    for entry in &value.tab_order {
        if entry.trim().is_empty() || entry.len() > ALPHA_TAB_ORDER_MAX_ENTRY_CHARS {
            return Err(Error::engine(
                "control event alpha tab order entry must be 1..160 characters",
            ));
        }
    }
    if event.aggregate_id != alpha_tab_order_aggregate_id(&value.account_id) {
        return Err(Error::engine(
            "alpha tab order aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}

/// Validate an `alpha_tab.adopted` event: the full consented pin echoed
/// field-for-field, the closed-vocabulary verified adoption (and nothing
/// else — a caller-asserted adopt is a contradiction in terms), the CAS
/// token it chains from, and the proof for its kind: the receipt that
/// authorized a `shell_adopt.v1` adopt, or the asserted provenance (and no
/// receipt) for a `shell_auto.v1` one. The receipt's
/// own liveness, account/pin binding, and single-use are the tool's check
/// (`verify_alpha_tab_adopt_confirm`); the tier checks what the event
/// claims, so a forged verified adoption can never be written directly.
fn validate_alpha_tab_adopt(event: &ControlEventRow, value: &AlphaTabAdoptPayload) -> Result<()> {
    for (label, text) in [
        ("alpha tab account_id", value.account_id.as_str()),
        ("alpha tab package", value.package.as_str()),
        ("alpha tab version", value.version.as_str()),
        ("alpha tab digest", value.digest.as_str()),
        ("alpha tab artifact_id", value.artifact_id.as_str()),
        (
            "alpha tab consented_source_revision",
            value.consented_source_revision.as_str(),
        ),
        (
            "alpha tab declaration_digest",
            value.declaration_digest.as_str(),
        ),
        (
            "alpha tab previous_event_id",
            value.previous_event_id.as_str(),
        ),
    ] {
        nonblank(label, text)?;
    }
    let Some(digest_hex) = value.digest.strip_prefix("sha256:") else {
        return Err(Error::engine(
            "control event alpha tab digest must start with 'sha256:'",
        ));
    };
    valid_sha256_hex("alpha tab digest", digest_hex)?;
    valid_sha256_hex("alpha tab declaration_digest", &value.declaration_digest)?;
    // The consent basis is exactly one of the two verified kinds, and each
    // kind carries only its own proof: a receipt adopt never carries
    // authored fields or a request echo, and an authored adopt never
    // carries receipt fields.
    if value.adoption == ALPHA_TAB_ADOPTION_VERIFIED {
        for (label, field) in [
            ("alpha tab receipt_id", value.receipt_id.as_deref()),
            (
                "alpha tab preview_session",
                value.preview_session.as_deref(),
            ),
        ] {
            let Some(text) = field else {
                return Err(Error::engine(format!(
                    "control event {label} is required for shell_adopt.v1"
                )));
            };
            nonblank(label, text)?;
        }
        if value.launch_id.is_some() || value.authored_run_key.is_some() || value.request.is_some()
        {
            return Err(Error::engine(
                "control event alpha tab shell_adopt.v1 carries no authored fields or request echo",
            ));
        }
    } else if value.adoption == ALPHA_TAB_ADOPTION_SHELL_AUTO {
        if value.receipt_id.is_some() || value.preview_session.is_some() {
            return Err(Error::engine(
                "control event alpha tab shell_auto.v1 carries no receipt fields",
            ));
        }
        validate_alpha_tab_authored_field("launch_id", value.launch_id.as_deref())?;
        validate_alpha_tab_authored_field("authored_run_key", value.authored_run_key.as_deref())?;
        validate_alpha_tab_request(value.request.as_deref())?;
    } else {
        return Err(Error::engine(
            "control event alpha tab adoption is unknown: alpha_tab.adopted carries only shell_adopt.v1 and shell_auto.v1",
        ));
    }
    if !value.consented_declaration.is_object() {
        return Err(Error::engine(
            "control event alpha tab consented_declaration must be an object",
        ));
    }
    crate::alpha_tab_sessions::validate_declaration_sessions(&value.consented_declaration)
        .map_err(|reason| {
            Error::engine(format!(
                "control event alpha tab consented_declaration sessions invalid: {reason}"
            ))
        })?;
    if event.aggregate_id != alpha_tab_aggregate_id(&value.account_id, &value.package) {
        return Err(Error::engine(
            "alpha tab aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}

/// Immutable adopted.v2 audit and frozen structural commitment validation.
// Intrinsically versioned frozen proof; also used by private outcome recovery.
pub(crate) fn validate_alpha_tab_adopt_v2(
    event: &ControlEventRow,
    value: &AlphaTabAdoptV2Payload,
) -> Result<()> {
    for (label, text) in [
        ("alpha tab account_id", value.account_id.as_str()),
        ("alpha tab package", value.package.as_str()),
        ("alpha tab version", value.version.as_str()),
        ("alpha tab digest", value.digest.as_str()),
        ("alpha tab artifact_id", value.artifact_id.as_str()),
        (
            "alpha tab consented_source_revision",
            value.consented_source_revision.as_str(),
        ),
        (
            "alpha tab declaration_digest",
            value.declaration_digest.as_str(),
        ),
        (
            "alpha tab previous_event_id",
            value.previous_event_id.as_str(),
        ),
    ] {
        nonblank(label, text)?;
    }
    let Some(digest_hex) = value.digest.strip_prefix("sha256:") else {
        return Err(Error::engine(
            "control event alpha tab digest must start with 'sha256:'",
        ));
    };
    valid_sha256_hex("alpha tab digest", digest_hex)?;
    valid_sha256_hex("alpha tab declaration_digest", &value.declaration_digest)?;
    // The consent basis is exactly one of the two verified kinds, and each
    // kind carries only its own proof: a receipt adopt never carries
    // authored fields or a request echo, and an authored adopt never
    // carries receipt fields.
    if value.adoption == "shell_adopt.v1" {
        for (label, field) in [
            ("alpha tab receipt_id", value.receipt_id.as_deref()),
            (
                "alpha tab preview_session",
                value.preview_session.as_deref(),
            ),
        ] {
            let Some(text) = field else {
                return Err(Error::engine(format!(
                    "control event {label} is required for shell_adopt.v1"
                )));
            };
            nonblank(label, text)?;
        }
        if value.launch_id.is_some() || value.authored_run_key.is_some() || value.request.is_some()
        {
            return Err(Error::engine(
                "control event alpha tab shell_adopt.v1 carries no authored fields or request echo",
            ));
        }
    } else if value.adoption == "shell_auto.v1" {
        if value.receipt_id.is_some() || value.preview_session.is_some() {
            return Err(Error::engine(
                "control event alpha tab shell_auto.v1 carries no receipt fields",
            ));
        }
        validate_v2_optional_text("launch_id", value.launch_id.as_deref(), 256)?;
        validate_v2_optional_text("authored_run_key", value.authored_run_key.as_deref(), 256)?;
        validate_v2_optional_text("request", value.request.as_deref(), 500)?;
    } else {
        return Err(Error::engine(
            "control event alpha tab adoption is unknown: alpha_tab.adopted.v2 carries only shell_adopt.v1 and shell_auto.v1",
        ));
    }
    if !value.consented_declaration.is_object() {
        return Err(Error::engine(
            "control event alpha tab consented_declaration must be an object",
        ));
    }
    use crate::alpha_tab_body_admission_v1 as frozen;
    if value.body_read_admission.need != "records.body.read.v1"
        || value.body_read_admission.scope != "viewer-visible-current-bodies"
        || !frozen::has_body_descriptor(&value.consented_declaration)?
    {
        return Err(Error::engine(
            "invalid frozen body read admission descriptor",
        ));
    }
    if value.runtime != "native.html.v1" {
        return Err(Error::engine(
            "body admission runtime must be native.html.v1",
        ));
    }
    valid_sha256_hex("alpha tab bundle_sha256", &value.bundle_sha256)?;
    if frozen::declaration_digest(&value.consented_declaration)? != value.declaration_digest
        || frozen::install_digest(
            &value.bundle_sha256,
            &value.declaration_digest,
            &value.runtime,
        ) != value.digest
    {
        return Err(Error::engine(
            "frozen body admission pin commitment mismatch",
        ));
    }
    // New feature evidence is intrinsically an engine-created event generation.
    // No marker identity is accepted in the payload or synthesized on replay.
    for id in [&event.id, &value.previous_event_id] {
        if uuid::Uuid::parse_str(id)
            .map(|uuid| uuid.to_string())
            .ok()
            .as_ref()
            != Some(id)
        {
            return Err(Error::engine(
                "body admission event/CAS identity must be a canonical UUID",
            ));
        }
    }
    if event.aggregate_id != alpha_tab_aggregate_id(&value.account_id, &value.package) {
        return Err(Error::engine(
            "alpha tab aggregate id does not match its canonical payload identity",
        ));
    }
    Ok(())
}
// Frozen v2 audit string bounds from26f5a47; independent of current adoption helpers.
fn validate_v2_optional_text(label: &str, value: Option<&str>, max_chars: usize) -> Result<()> {
    if value.is_some_and(|s| s.trim().is_empty() || s.chars().count() > max_chars) {
        return Err(Error::engine(format!(
            "frozen body adoption {label} exceeds its text bound"
        )));
    }
    Ok(())
}

/// Validate new appends. Historical replay uses the tolerant stored validator,
/// so tightening restore admission does not rewrite legacy event semantics.
pub fn validate_control_event(event: &ControlEventRow) -> Result<()> {
    if event.event_type == "alpha_tab.import_reset" {
        return Err(Error::engine(
            "alpha tab import reset is reserved for canonical import",
        ));
    }
    if event.event_type == "alpha_tab.restored"
        && decode::<AlphaTabStatePayload>(event)?.adoption != ALPHA_TAB_ADOPTION_CALLER_ASSERTED
    {
        return Err(Error::engine(
            "new alpha tab restore must require fresh adoption",
        ));
    }
    validate_stored_control_event(event)
}

pub(crate) fn validate_stored_control_event(event: &ControlEventRow) -> Result<()> {
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
        "agent_run.started.v1" | "agent_run.started.v2" => {
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
        "alpha_tab.installed"
        | "alpha_tab.disabled"
        | "alpha_tab.restored"
        | "alpha_tab.removed" => {
            let value: AlphaTabStatePayload = decode(event)?;
            validate_alpha_tab(event, &value)?;
        }
        "alpha_tab.import_reset" => {
            let value: AlphaTabImportResetPayload = decode(event)?;
            validate_alpha_tab(event, &value.pin)?;
            if value.pin.adoption != ALPHA_TAB_ADOPTION_CALLER_ASSERTED
                || value.adoption_provenance.is_some()
                || value.pin.previous_event_id.is_none()
                || !matches!(value.status.as_str(), "installed" | "disabled" | "removed")
            {
                return Err(Error::engine("alpha tab import reset must preserve status and require fresh adoption with NULL provenance"));
            }
            alpha_tab_provenance::alpha_tab_pin_digest(&value.pin)?;
        }
        "alpha_tab.updated" => {
            let value: AlphaTabUpdatePayload = decode(event)?;
            alpha_tab_provenance::validate_update(event, &value)?;
        }
        "alpha_tab.adopted" => {
            let value: AlphaTabAdoptPayload = decode(event)?;
            validate_alpha_tab_adopt(event, &value)?;
        }
        "alpha_tab.adopted.v2" => {
            let value: AlphaTabAdoptV2Payload = decode(event)?;
            validate_alpha_tab_adopt_v2(event, &value)?;
        }
        "alpha_tab.order_set" => {
            let value: AlphaTabOrderPayload = decode(event)?;
            validate_alpha_tab_order(event, &value)?;
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
pub(crate) async fn project_control(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
) -> Result<()> {
    validate_stored_control_event(event)?;
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
        "agent_run.started.v1" | "agent_run.started.v2" => {
            let value: AgentRunStartedPayload = decode(event)?;
            sqlx::query(
                "INSERT INTO agent_runs
                 (activity_id,run_key,account_id,started_at,reported_mcp_client_name,reported_mcp_client_version,reported_model,start_event_id,start_event_seq)
                 VALUES(?,?,?,?,?,?,?,?,?)",
            )
            .bind(value.activity_id)
            .bind(event.run_key.as_deref().expect("validated run key"))
            .bind(value.account_id)
            .bind(value.started_at)
            .bind(value.reported_mcp_client_name)
            .bind(value.reported_mcp_client_version)
            .bind(value.reported_model)
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
        "alpha_tab.import_reset" => {
            alpha_tab_provenance::fold_import_reset(conn, event).await?;
        }
        "alpha_tab.updated" => {
            alpha_tab_provenance::fold_update(conn, event).await?;
        }
        "alpha_tab.installed" => {
            let value: AlphaTabStatePayload = decode(event)?;
            let existing: Option<(String, String)> = sqlx::query_as(
                "SELECT status, event_id FROM alpha_tab_installs
                  WHERE account_id=? AND package=?",
            )
            .bind(&value.account_id)
            .bind(&value.package)
            .fetch_optional(&mut *conn)
            .await?;
            match (&existing, &value.previous_event_id) {
                (None, None) => {}
                (Some((status, token)), Some(previous))
                    if status == "removed" && token == previous => {}
                (Some((status, _)), _) => {
                    return Err(Error::engine(format!(
                        "control event {} ({}) cannot install package {} with status {status}",
                        event.id, event.event_type, value.package
                    )));
                }
                _ => {
                    return Err(Error::engine(format!(
                        "control event {} ({}) carries a CAS token that does not match its install chain",
                        event.id, event.event_type
                    )));
                }
            }
            sqlx::query(
                "INSERT INTO alpha_tab_installs
                 (account_id,package,version,digest,artifact_id,consented_source_revision,
                  declaration_digest,consented_declaration,adoption,request,status,event_id,event_seq,updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                 ON CONFLICT(account_id,package) DO UPDATE SET
                   version=excluded.version,digest=excluded.digest,
                   artifact_id=excluded.artifact_id,
                   consented_source_revision=excluded.consented_source_revision,
                   declaration_digest=excluded.declaration_digest,
                   consented_declaration=excluded.consented_declaration,
                   adoption=excluded.adoption,
                   adoption_provenance=NULL,body_read_admission_event_id=NULL,
                   request=excluded.request,
                   status='installed',event_id=excluded.event_id,
                   event_seq=excluded.event_seq,updated_at=excluded.updated_at",
            )
            .bind(value.account_id)
            .bind(value.package)
            .bind(value.version)
            .bind(value.digest)
            .bind(value.artifact_id)
            .bind(value.consented_source_revision)
            .bind(value.declaration_digest)
            .bind(serde_json::to_string(&value.consented_declaration)?)
            .bind(value.adoption)
            .bind(value.request)
            .bind("installed")
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
        }
        "alpha_tab.disabled" => {
            let value: AlphaTabStatePayload = decode(event)?;
            let Some(previous) = value.previous_event_id.as_deref() else {
                return Err(Error::engine(format!(
                    "control event {} ({}) disables without a CAS token",
                    event.id, event.event_type
                )));
            };
            let result = sqlx::query(
                "UPDATE alpha_tab_installs
                    SET status='disabled',event_id=?,event_seq=?,updated_at=?
                  WHERE account_id=? AND package=? AND status='installed' AND event_id=?",
            )
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .bind(value.account_id)
            .bind(value.package)
            .bind(previous)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "alpha_tab.restored" => {
            let value: AlphaTabStatePayload = decode(event)?;
            let Some(previous) = value.previous_event_id.as_deref() else {
                return Err(Error::engine(format!(
                    "control event {} ({}) restores without a CAS token",
                    event.id, event.event_type
                )));
            };
            let result = sqlx::query(
                "UPDATE alpha_tab_installs
                    SET version=?,digest=?,artifact_id=?,consented_source_revision=?,
                        declaration_digest=?,consented_declaration=?,adoption=?,
                        request=?,adoption_provenance=NULL,body_read_admission_event_id=NULL,status='installed',event_id=?,event_seq=?,updated_at=?
                  WHERE account_id=? AND package=? AND status='disabled' AND event_id=?",
            )
            .bind(value.version)
            .bind(value.digest)
            .bind(value.artifact_id)
            .bind(value.consented_source_revision)
            .bind(value.declaration_digest)
            .bind(serde_json::to_string(&value.consented_declaration)?)
            .bind(value.adoption)
            .bind(value.request)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .bind(value.account_id)
            .bind(value.package)
            .bind(previous)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "alpha_tab.adopted" => {
            let value: AlphaTabAdoptPayload = decode(event)?;
            // Adopt flips a live install to verified adoption without
            // changing its pin: the event's pin must equal the stored row's
            // pin field-for-field (a receipt for another pin can never adopt
            // this install), the CAS token must name the current event, and
            // only `installed` rows adopt — a disabled tab restores first.
            // The receipt's own liveness and single-use are the tool's
            // check; the projection refuses anything the tool should never
            // have appended.
            let result = sqlx::query(
                "UPDATE alpha_tab_installs
                    SET version=?,digest=?,artifact_id=?,consented_source_revision=?,
                        declaration_digest=?,consented_declaration=?,adoption=?,
                        request=COALESCE(?,request),adoption_provenance=?,
                        status='installed',body_read_admission_event_id=NULL,event_id=?,event_seq=?,updated_at=?
                   WHERE account_id=? AND package=? AND status='installed' AND event_id=?
                     AND version=? AND digest=? AND artifact_id=?
                     AND consented_source_revision=? AND declaration_digest=?",
            )
            .bind(value.version.clone())
            .bind(value.digest.clone())
            .bind(value.artifact_id.clone())
            .bind(value.consented_source_revision.clone())
            .bind(value.declaration_digest.clone())
            .bind(serde_json::to_string(&value.consented_declaration)?)
            .bind(value.adoption.clone())
            .bind(value.request.clone())
            .bind(alpha_tab_provenance::direct_provenance_json(conn, event, &value).await?)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .bind(value.account_id.clone())
            .bind(value.package.clone())
            .bind(value.previous_event_id.clone())
            .bind(value.version)
            .bind(value.digest)
            .bind(value.artifact_id)
            .bind(value.consented_source_revision)
            .bind(value.declaration_digest)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "alpha_tab.order_set" => {
            let value: AlphaTabOrderPayload = decode(event)?;
            // Complete-state preference write: last event wins, no CAS.
            // An empty order is a reset — the row stays (so the event keeps
            // its projection) and readers fall back to the default order.
            sqlx::query(
                "INSERT INTO alpha_tab_orders
                  (account_id,tab_order,event_id,event_seq,updated_at)
                  VALUES(?,?,?,?,?)
                  ON CONFLICT(account_id) DO UPDATE SET
                    tab_order=excluded.tab_order,event_id=excluded.event_id,
                    event_seq=excluded.event_seq,updated_at=excluded.updated_at",
            )
            .bind(value.account_id)
            .bind(serde_json::to_string(&value.tab_order)?)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
        }
        "alpha_tab.adopted.v2" => {
            let value: AlphaTabAdoptV2Payload = decode(event)?;
            // Adopt flips a live install to verified adoption without
            // changing its pin: the event's pin must equal the stored row's
            // pin field-for-field (a receipt for another pin can never adopt
            // this install), the CAS token must name the current event, and
            // only `installed` rows adopt — a disabled tab restores first.
            // The receipt's own liveness and single-use are the tool's
            // check; the projection refuses anything the tool should never
            // have appended.
            // Control replay has inert record identities, not retained app bytes.
            // Bind to the exact prior installed declaration and full pin here;
            // the later genuine issuer and per-page resolver must verify source bytes.
            let prior: Option<String> = sqlx::query_scalar(
                "SELECT consented_declaration FROM alpha_tab_installs
                 WHERE account_id=? AND package=? AND status='installed' AND event_id=?",
            )
            .bind(&value.account_id)
            .bind(&value.package)
            .bind(&value.previous_event_id)
            .fetch_optional(&mut *conn)
            .await?;
            let Some(prior) = prior else {
                return Err(Error::engine(
                    "body admission has no matching current install/CAS",
                ));
            };
            let prior: Value = serde_json::from_str(&prior)?;
            if prior != value.consented_declaration
                || crate::alpha_tab_body_admission_v1::declaration_digest(&prior)?
                    != value.declaration_digest
            {
                return Err(Error::engine(
                    "body admission prior declaration linkage mismatch",
                ));
            }
            let result = sqlx::query(
                "UPDATE alpha_tab_installs
                    SET version=?,digest=?,artifact_id=?,consented_source_revision=?,
                        declaration_digest=?,consented_declaration=?,adoption=?,
                        request=COALESCE(?,request),adoption_provenance=?,
                        status='installed',body_read_admission_event_id=?,event_id=?,event_seq=?,updated_at=?
                   WHERE account_id=? AND package=? AND status='installed' AND event_id=?
                     AND version=? AND digest=? AND artifact_id=?
                     AND consented_source_revision=? AND declaration_digest=?",
            )
            .bind(value.version.clone())
            .bind(value.digest.clone())
            .bind(value.artifact_id.clone())
            .bind(value.consented_source_revision.clone())
            .bind(value.declaration_digest.clone())
            .bind(serde_json::to_string(&value.consented_declaration)?)
            .bind(value.adoption.clone())
            .bind(value.request.clone())
            .bind(alpha_tab_provenance::direct_v2_provenance_json(conn, event, &value).await?)
            .bind(&event.id)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .bind(value.account_id.clone())
            .bind(value.package.clone())
            .bind(value.previous_event_id.clone())
            .bind(value.version)
            .bind(value.digest)
            .bind(value.artifact_id)
            .bind(value.consented_source_revision)
            .bind(value.declaration_digest)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
        }
        "alpha_tab.removed" => {
            let value: AlphaTabStatePayload = decode(event)?;
            let Some(previous) = value.previous_event_id.as_deref() else {
                return Err(Error::engine(format!(
                    "control event {} ({}) removes without a CAS token",
                    event.id, event.event_type
                )));
            };
            let result = sqlx::query(
                "UPDATE alpha_tab_installs
                    SET status='removed',adoption_provenance=NULL,body_read_admission_event_id=NULL,event_id=?,event_seq=?,updated_at=?
                   WHERE account_id=? AND package=?
                     AND status IN ('installed','disabled') AND event_id=?",
            )
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .bind(value.account_id)
            .bind(value.package)
            .bind(previous)
            .execute(&mut *conn)
            .await?;
            require_one(result, event).await?;
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
        act: row.try_get("act")?,
    })
}

async fn read_by_idempotency_key(
    conn: &mut SqliteConnection,
    key: &str,
) -> Result<Option<ControlEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at,act
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
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<ControlEventRow> {
    if matches!(input.payload, ControlEventPayload::AlphaTabImportReset(_)) {
        return Err(Error::engine(
            "alpha tab import reset is reserved for canonical import",
        ));
    }
    append_control_event_on_internal(conn, input, act_alloc).await
}

async fn append_control_event_on_internal(
    conn: &mut SqliteConnection,
    input: NewControlEvent,
    act_alloc: &mut crate::act::ActAllocation,
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
        act: None,
    };
    if event.event_type == "alpha_tab.import_reset" {
        validate_stored_control_event(&event)?;
    } else {
        validate_control_event(&event)?;
    }
    let act = act_alloc.get_or_allocate(conn).await?;
    event.seq = sqlx::query_scalar(
        "INSERT INTO control_events
         (id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at,act)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
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
    .bind(act)
    .fetch_one(&mut *conn)
    .await?;
    event.act = Some(act);
    project_control(conn, &event).await?;
    Ok(event)
}

/// Compose a control append into a wider atomic content/policy/identity write.
/// Accepting a transaction rather than a bare connection makes it impossible
/// for public callers to persist the canonical event without its projection.
pub(crate) async fn append_control_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    input: NewControlEvent,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<ControlEventRow> {
    append_control_event_on(tx, input, act_alloc).await
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
///
/// `reported` carries the admitting call's self-asserted client identity and
/// is stamped inside the same transaction as the start event. A run that
/// already exists keeps its admitted values: a later differing `clientInfo`
/// never overwrites them, and a later differing declared model never
/// overwrites them either. The divergence is refused at the response level
/// instead — see the `set_intent` handler — because an unverified value must
/// never decide whether the intent declaration itself succeeds. Repeating the
/// recorded model value is benign. Clamping applies before anything is
/// compared or stamped, so an overlong repeat of the recorded value still
/// matches what admission stored.
#[cfg(test)]
pub(crate) async fn ensure_agent_run(
    db: &Db,
    run_key: &str,
    account_id: &str,
    reported: ReportedRunIdentity,
) -> Result<AgentRunLifecycle> {
    ensure_agent_run_with_channel(
        db,
        run_key,
        account_id,
        reported,
        crate::provenance::Channel::Unknown,
    )
    .await
}

/// Admit a run with the server-observed transport of its first declaration.
pub(crate) async fn ensure_agent_run_with_channel(
    db: &Db,
    run_key: &str,
    account_id: &str,
    reported: ReportedRunIdentity,
    channel: crate::provenance::Channel,
) -> Result<AgentRunLifecycle> {
    if !matches!(
        crate::runkey::validate_full(Some(run_key)),
        crate::runkey::KeyOutcome::Valid(_)
    ) {
        return Err(Error::engine(
            "set_intent requires a valid full run key for durable activity",
        ));
    }
    let reported = reported.clamped();
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
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
                channel: (channel != crate::provenance::Channel::Unknown).then_some(channel),
                reported_mcp_client_name: reported.client_name,
                reported_mcp_client_version: reported.client_version,
                reported_model: reported.model,
            }),
        )?,
        &mut act_alloc,
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
    let mut act_alloc = crate::act::ActAllocation::new();
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
        &mut act_alloc,
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

/// Run-scoped read of one admitted run's self-asserted identity: client name,
/// client version, declared model. `Ok(None)` is no admitted run for the key;
/// a populated identity whose fields are `None` is a run admitted by a call
/// that carried nothing. No display join, no behaviour keys off the result —
/// the consumers are verification (tests), the `set_intent` response
/// confirmation (which echoes what is actually recorded), and the
/// contribution projection (which surfaces the client fields, never the
/// model, and never to decide anything).
pub(crate) async fn read_agent_run_reported_identity(
    db: &Db,
    run_key: &str,
) -> Result<Option<ReportedRunIdentity>> {
    let mut conn = db.write_pool().acquire().await?;
    read_agent_run_reported_identity_in(&mut conn, run_key).await
}

/// Run-scoped read of one admitted run's self-asserted identity, inside the
/// caller's own read transaction. Same facts as
/// [`read_agent_run_reported_identity`], but the contribution projection reads
/// it on the transaction that is already open for the record, so a request
/// that hydrates many acts over one snapshot never opens a second connection
/// per act.
pub(crate) async fn read_agent_run_reported_identity_in(
    conn: &mut sqlx::SqliteConnection,
    run_key: &str,
) -> Result<Option<ReportedRunIdentity>> {
    let row = sqlx::query(
        "SELECT reported_mcp_client_name,reported_mcp_client_version,reported_model
           FROM agent_runs WHERE run_key=?",
    )
    .bind(run_key)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(ReportedRunIdentity {
            client_name: row.try_get("reported_mcp_client_name")?,
            client_version: row.try_get("reported_mcp_client_version")?,
            model: row.try_get("reported_model")?,
        })
    })
    .transpose()
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
    let mut act_alloc = crate::act::ActAllocation::new();
    let event = append_control_event_in(&mut tx, input, &mut act_alloc).await?;
    tx.commit().await?;
    Ok(event)
}

pub async fn read_all_control_events(conn: &mut SqliteConnection) -> Result<Vec<ControlEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at,act
           FROM control_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(row_from_sql)
    .collect()
}

/// The control-only act-range reader: exactly the rows whose `act` falls in the
/// half-open interval `(from_exclusive, to_inclusive]`, in `seq` order, decoded
/// by the same [`row_from_sql`] the full reader uses. Legacy rows whose act is
/// `NULL` never satisfy the strict `act > ?` predicate and are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn control_events_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<ControlEventRow>> {
    sqlx::query(
        "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,
                actor,run_key,reason,payload,created_at,act
           FROM control_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
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
              actor,run_key,reason,payload,created_at,act)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
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
        .bind(event.act)
        .execute(&mut *tx)
        .await?;
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM control_events
                WHERE seq=? AND id=? AND idempotency_key=? AND type=? AND schema_version=?
                  AND aggregate_kind=? AND aggregate_id=? AND actor=? AND run_key IS ?
                  AND reason=? AND payload=? AND created_at=? AND act IS ?
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
        .bind(event.act)
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

/// The sealed witness can only be constructed by canonical import, after
/// rebuilding its unpublished staging projections. No MCP/member-copy path
/// can author this boundary; authenticated primary standby replay may fold it.
pub(crate) async fn reset_imported_alpha_tabs_in(
    conn: &mut SqliteConnection,
    _import: crate::interchange::CanonicalImportConsentBoundary,
) -> Result<()> {
    let rows = sqlx::query("SELECT * FROM alpha_tab_installs ORDER BY account_id,package")
        .fetch_all(&mut *conn)
        .await?;
    let mut allocation = crate::act::ActAllocation::new();
    for row in rows {
        let mut pin = alpha_tab_provenance::projection_pin(&row)?;
        pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
        pin.previous_event_id = Some(row.try_get("event_id")?);
        let payload = AlphaTabImportResetPayload {
            pin: pin.clone(),
            status: row.try_get("status")?,
            adoption_provenance: None,
        };
        let input = NewControlEvent::authored(
            uuid::Uuid::new_v4().to_string(),
            alpha_tab_aggregate_id(&pin.account_id, &pin.package),
            "canonical_import",
            None,
            "Imported workspace requires fresh browser Preview → Adopt",
            ControlEventPayload::AlphaTabImportReset(payload),
        )?;
        append_control_event_on_internal(conn, input, &mut allocation).await?;
    }
    Ok(())
}

/// Alpha-tab projections are omitted from canonical interchange. Rebuild only
/// this family in unpublished import staging so conformance can validate history.
/// Imported event claims alone are not receiver consent: canonical import must
/// append its durable reset boundaries immediately after this rebuild.
/// Carried markers for other control projections stay intact.
pub(crate) async fn rebuild_alpha_tab_projections_in(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query("DELETE FROM alpha_tab_installs")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM alpha_tab_orders")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM control_event_applications WHERE event_id IN (SELECT id FROM control_events WHERE aggregate_kind='alpha_tab')")
        .execute(&mut *conn).await?;
    let mut after: Option<i64> = None;
    loop {
        let event = sqlx::query("SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at,act FROM control_events WHERE aggregate_kind='alpha_tab' AND (? IS NULL OR seq>?) ORDER BY seq LIMIT 1")
            .bind(after).bind(after).fetch_optional(&mut *conn).await?.map(row_from_sql).transpose()?;
        let Some(event) = event else {
            break;
        };
        project_control(conn, &event).await?;
        after = Some(event.seq);
    }
    Ok(())
}

const CONTROL_OBJECTS: [&str; 19] = [
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
    "alpha_tab_installs",
    "idx_alpha_tab_installs_artifact",
    "alpha_tab_orders",
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
        "SELECT activity_id,run_key,account_id,started_at,reported_mcp_client_name,reported_mcp_client_version,reported_model,ended_at,start_event_id,start_event_seq,close_event_id,close_event_seq FROM agent_runs ORDER BY activity_id",
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
            "reported_mcp_client_name": row.try_get::<Option<String>, _>("reported_mcp_client_name")?,
            "reported_mcp_client_version": row.try_get::<Option<String>, _>("reported_mcp_client_version")?,
            "reported_model": row.try_get::<Option<String>, _>("reported_model")?,
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
    let alpha_tab_installs = sqlx::query(
        "SELECT account_id,package,version,digest,artifact_id,consented_source_revision,declaration_digest,consented_declaration,adoption,adoption_provenance,body_read_admission_event_id,request,status,event_id,event_seq,updated_at FROM alpha_tab_installs ORDER BY account_id,package",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        let declaration = serde_json::from_str::<Value>(&row.try_get::<String, _>("consented_declaration")?)?;
        Ok(json!({
            "account_id": row.try_get::<String, _>("account_id")?,
            "package": row.try_get::<String, _>("package")?,
            "version": row.try_get::<String, _>("version")?,
            "digest": row.try_get::<String, _>("digest")?,
            "artifact_id": row.try_get::<String, _>("artifact_id")?,
            "consented_source_revision": row.try_get::<String, _>("consented_source_revision")?,
            "declaration_digest": row.try_get::<String, _>("declaration_digest")?,
            "consented_declaration": declaration,
            "adoption": row.try_get::<String, _>("adoption")?,
            "adoption_provenance": row.try_get::<Option<String>, _>("adoption_provenance")?.map(|text| serde_json::from_str::<Value>(&text)).transpose()?,
            "body_read_admission_event_id": row.try_get::<Option<String>, _>("body_read_admission_event_id")?,
            "request": row.try_get::<Option<String>, _>("request")?,
            "status": row.try_get::<String, _>("status")?,
            "event_id": row.try_get::<String, _>("event_id")?,
            "event_seq": row.try_get::<i64, _>("event_seq")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
        }))
    })
    .collect::<Result<Vec<_>>>()?;
    let alpha_tab_orders = sqlx::query(
        "SELECT account_id,tab_order,event_id,event_seq,updated_at FROM alpha_tab_orders ORDER BY account_id",
    )
    .fetch_all(&mut conn)
    .await?
    .into_iter()
    .map(|row| {
        let tab_order = serde_json::from_str::<Value>(&row.try_get::<String, _>("tab_order")?)?;
        Ok(json!({
            "account_id": row.try_get::<String, _>("account_id")?,
            "tab_order": tab_order,
            "event_id": row.try_get::<String, _>("event_id")?,
            "event_seq": row.try_get::<i64, _>("event_seq")?,
            "updated_at": row.try_get::<String, _>("updated_at")?,
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
        "alpha_tab_installs": alpha_tab_installs,
        "alpha_tab_orders": alpha_tab_orders,
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
                'alpha_tab_installs','idx_alpha_tab_installs_artifact','alpha_tab_orders',
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
        if let Err(error) = validate_stored_control_event(event) {
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
